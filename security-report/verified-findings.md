# Verified Findings — LabyrinthDNS

Phase 3 output: deduplicated, reachability-checked findings from the 5 cluster hunts (web-auth, dns-resolver, injection-crypto, frontend-headers, infra-cicd). False-positive elimination performed by collapsing duplicates (e.g. setup-wizard, self-update, WS InsecureSkipVerify each surfaced by 2-3 cluster agents → one canonical finding) and dropping checks that the codebase already mitigates.

## Confidence calibration
- **Confirmed (95+)**: Code path verified, exploit primitive obvious, low ambiguity.
- **High (75-94)**: Defect verified; reachability requires a specific deployment posture.
- **Medium (50-74)**: Defect verified; impact depends on configuration / threat model.

## Finding Counts (after dedupe)
| Severity | Count |
|----------|-------|
| Critical | 4 |
| High     | 14 |
| Medium   | 17 |
| Low      | 11 |
| Info     | 4 |
| **Total**| **50** |

---

## CRITICAL

### C-1 — Unauthenticated setup wizard allows post-install admin takeover
**Confidence**: 95 (Confirmed — found independently by 3 cluster agents).
**CWE**: 306, 862.
**Files**: `web/api_setup.go:39-98`, `web/server.go:50,90-112,389-390`, `main_runtime_helpers.go:46`.
**Reachability**: Unauthenticated network attacker can reach the admin HTTP listener (default `127.0.0.1:8080`, but commonly bound externally).
**Defect**: `setupDone` is a runtime `bool` on `AdminServer`, only flipped inside the wizard handler itself. `NewAdminServer` never seeds it from the on-disk config. On every restart of an already-provisioned server, `POST /api/setup/complete` is reachable and `writeConfigYAML("labyrinth.yaml", …)` overwrites the live config with attacker-supplied `auth.username` + bcrypt hash. Next restart, the attacker owns admin → leveraged with C-2 → unauthenticated → RCE.
**Mitigation gap eliminated false-positive theory that the in-memory config protects auth — the file is rewritten regardless, and operators do restart.**

### C-2 — Self-update applies unsigned binary fetched over HTTP/JSON-from-GitHub
**Confidence**: 95 (Confirmed by 3 cluster agents).
**CWE**: 494, 345.
**Files**: `web/api_update.go:51,174-304,308`, `web/update_unix.go:14`.
**Defect**: `handleApplyUpdate` calls `http.Get(BrowserDownloadURL)` (default client → **no timeout**, no body cap), `chmod 0755`s the temp file, `os.Rename`s over the running binary, then `syscall.Exec`s. There is **no signature, no checksum, no TLS pinning** — the SHA-256 manifest at `release.yml:97` is produced but never consumed.
**Reachability**: Authenticated admin click of `Apply Update`; combined with C-1, completely unauthenticated.
**Trust failures**: a) compromise of `api.github.com` JSON; b) compromise of the asset CDN; c) compromise of any release-token; d) bad CA on the operator's box.

### C-3 — `install.sh` (curl-pipe-to-bash) and release advertising do not verify checksums or signatures
**Confidence**: 95.
**CWE**: 494, 829.
**Files**: `install.sh:98-110`, `.github/workflows/release.yml:97,104-108`.
**Defect**: The release pipeline produces `checksums.txt` but the installer ships nothing that fetches and verifies it. The release body templated into every GitHub Release encourages `curl -sSL …/main/install.sh | bash`, pinned to **the latest `main`**, so a malicious commit on `main` retroactively poisons every existing release page.
**Reachability**: Every fresh install in the wild, run as root.

### C-4 — DNSSEC `Querier` sends DNSKEY/DS queries directly to root → validation silently degrades to "Insecure" for every non-root zone
**Confidence**: 95.
**CWE**: 345.
**File**: `resolver/resolver.go:183-186` (`func (r *Resolver) QueryDNSSEC`).
**Defect**: `QueryDNSSEC` randomly picks a root server and fires the DNSKEY/DS query at it. Root replies with a referral; `Validator.fetchDNSKEYs` (`dnssec/validator.go:402-410`) gets zero keys, caches the empty set, returns `Insecure` for the whole zone. The resolver labels the answer "insecure" (`resolver/resolver.go:357-359`) and serves it.
**Impact**: DNSSEC validation is *off* for every signed zone below the root — bogus and unsigned answers are accepted indistinguishably. The entire DNSSEC code path is decorative.

---

## HIGH

### H-1 — Auth bypass when `web.auth.username == ""`
**CWE**: 306. **File**: `web/middleware.go:21-25`, `web/api_setup.go:152-156`.
`requireAuth` short-circuits to `next` whenever `Username == ""`. The setup wizard's `writeConfigYAML` only emits the `auth:` block when `cfg.Username != ""`, so a wizard run with an empty username produces a config with **no auth and the middleware allows everything**.

### H-2 — WebSocket upgrade accepts arbitrary Origin (`InsecureSkipVerify: true`)
**CWE**: 1385. **Files**: `web/api_queries.go:43-50`, `web/timeseries_ws.go:121-128`.
Both `/api/queries/stream` and `/api/stats/timeseries/ws` set `InsecureSkipVerify: true`, disabling nhooyr's same-origin enforcement. Once a token is leaked (URL/Referer/log/XSS), a hostile origin can stream live DNS query telemetry — a meaningful confidentiality loss (every domain every client resolves).

### H-3 — No HTTP security headers anywhere on the admin UI
**CWE**: 693, 1021. **Files**: `web/middleware.go`, `web/embed.go:15-51`, `web/server.go:271-287`.
`grep` for `w.Header().Set(` returns only `Content-Type`, `Cache-Control`, `Retry-After`, `Alt-Svc`. No CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS. Clickjacking against cache-flush, blocklist toggles, password change, and the upcoming "Apply Update" button is one frame away. No CSP fallback for any future XSS, and JWT-in-localStorage means same-origin XSS is full account take-over.

### H-4 — `?token=` query-string auth accepted on every route — JWT leakage + cross-origin replay
**CWE**: 598, 352. **Files**: `web/middleware.go:36-39`, `web/ui/src/api/client.ts:244-260`.
`requireAuth` accepts the JWT in the query string for HTTP and WebSocket. JWTs in URLs land in `Referer`, browser history, proxy/CDN access logs, and DevTools. There is no Origin/Referer check on state-changing endpoints, so once observed the token replays cross-origin. The fix combines: drop `?token=` for HTTP, move WS auth onto `Sec-WebSocket-Protocol`.

### H-5 — Pool buffer returned to `sync.Pool` while caller still holds a slice into it (use-after-free / data race)
**CWE**: 416, 362. **Files**: `server/handler.go:241-248, 425, 536-537, 607-615, 654-661, 692-700, 796-800, 816-823, 873-880`.
`packed` is a sub-slice of the pooled buffer's backing array. `pool.PutBuffer(bufPtr)` happens before `WriteTo`/`Write`. Concurrent goroutines pull the same buffer, `dns.Pack` over it, and the first goroutine ships corrupted bytes — **response substitution between concurrent clients on the same server**, occasional panics, TC/RCODE corruption. Recommended fix: `out := append([]byte(nil), packed...); pool.PutBuffer(bufPtr); return out`.

### H-6 — Cache-hit path skips `FilterPrivateAddresses` → DNS-rebinding mitigation bypassed via cache
**CWE**: 942. **Files**: `server/handler.go:381-405,469,664-670`.
`FilterPrivateAddresses` is applied only inside `buildResponse` (slow path). `Resolve` writes unfiltered records into the cache; `buildCacheResponse` never invokes the filter. A first query that admits a private IP poisons the cache for every later client, defeating the documented rebinding protection. Apply the filter at the cache **write** site (or read site).

### H-7 — Only KSK-2017 is hardcoded; KSK-2024 missing → DNSSEC darkness at rollover
**CWE**: 321, 1394. **File**: `dnssec/trustanchor.go:16-23`.
Only key tag 20326 is present. IANA's KSK-2024 (key tag 38696, RSASHA256, SHA-256 digest `683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16`) is not. When the root zone is signed exclusively with the new KSK, the validator returns Bogus → SERVFAIL for everything. Fallback resolvers are intentionally bypassed when DNSSEC fails (`resolver/fallback.go:82-85`). The resolver effectively goes dark across the network.

### H-8 — Crafted RRSIG/NSEC RDATA panics in `make([]byte, …)` due to negative `sigLen`/`bitmapLen`
**CWE**: 130, 20. **File**: `dns/record.go:108-128, 130-143`.
`UnpackRR` decodes a compressed name inside RDATA via `DecodeName(msg, …)` (which walks the **whole message**, not the RDATA window) and computes `sigLen := newOffset - nameEnd` without sign-checking. When `nameEnd > newOffset`, the slice cap goes negative and `make` panics. The udp/tcp goroutine `recover()` catches it, but every panic logs+allocates → log/CPU amplification on every poisoning attempt; fragile against any future refactor that drops the recovery.

### H-9 — PID file: symlink-followable + non-exclusive write + `StopDaemon` signals whatever PID it reads
**CWE**: 59, 367, 672. **Files**: `daemon/pidfile.go:11-14`, `daemon/daemon_unix.go:57-74`, `main_runtime_helpers.go:235-245`.
`os.WriteFile(path, …, 0644)` follows symlinks and lacks `O_EXCL`/`O_NOFOLLOW`. Default path `/var/run/labyrinth.pid`. `StopDaemon` signals the integer it reads with no liveness or process-identity check. Cleanup only on graceful SIGTERM, so crashes leave a stale PID file → after PID reuse, `labyrinth daemon stop` (often run as root) becomes an arbitrary-process kill primitive. Combined with the symlink case, an unprivileged local user gets root-process termination + arbitrary-target file overwrite.

### H-10 — Blocklist HTTP client follows redirects to any scheme/host with no SSRF guard
**CWE**: 918. **Files**: `blocklist/manager.go:108-110, 283-307, 309-324`.
Default redirect policy (10 hops, any host). No scheme allow-list, no private-IP / metadata-IP block. URLs are operator-supplied today, but a malicious upstream blocklist publisher (or compromised CDN) can redirect to `http://127.0.0.1:8080/api/...` or `169.254.169.254`. Parser error strings + rule counts surface via `/api/blocklist/lists`, leaking internal-service shape. The 50 MiB body cap is good but doesn't address the redirect target.

### H-11 — `http.Get` with default client (no timeout) used for update flow
**CWE**: 400. **Files**: `web/api_update.go:51, 308, 375`.
`updateHTTPGet = http.Get`. `http.DefaultClient` has no timeout. A slow/hung GitHub or mirror pins a goroutine and a temp file indefinitely. Every authenticated update poll plus the periodic `StartUpdateChecker` is exposed.

### H-12 — Release workflow grants `contents: write` + `packages: write` to every job
**CWE**: 272. **File**: `.github/workflows/release.yml:7-9`.
`permissions:` lives at workflow scope, so `test`, `build`, `release`, `docker` all inherit. The `test` job runs `go test ./...` (arbitrary user code) under those permissions — a malicious dependency or a script-injection vector in any job gets a token that can rewrite release assets and push container images.

### H-13 — Third-party / official Actions pinned by mutable tag, not commit SHA
**CWE**: 829. **Files**: both workflow files.
`actions/checkout@v5`, `softprops/action-gh-release@v2`, `docker/build-push-action@v6`, etc. — every `uses:` is by tag. `softprops/action-gh-release` in particular is third-party and runs at the most privileged moment of the pipeline. A force-pushed tag or a maintainer-account compromise (cf. `tj-actions/changed-files`) replaces the action body. Recommendation: SHA-pin every action.

### H-14 — Release artifacts unsigned; no SBOM, no SLSA provenance
**CWE**: 345, 1395. **File**: `.github/workflows/release.yml:85-112`.
The pipeline produces binaries + `checksums.txt` + Docker image. None are signed (`sigstore/cosign-installer`), no `actions/attest-build-provenance`, no SBOM. Downstream consumers cannot verify build provenance. Same root cause as C-2/C-3.

---

## MEDIUM

### M-1 — Forward and fallback DNS responses bypass bailiwick + 0x20 case-randomization but are still cached
**CWE**: 345. **Files**: `resolver/forward.go:78-98,142-213`, `resolver/fallback.go:14-68`, `server/handler.go:467-475`.
A compromised forwarder (or a fallback resolver auto-engaged on SERVFAIL) populates the shared cache with arbitrary off-bailiwick records.

### M-2 — Per-IP rate-limiter map (`security/ratelimit.go`) grows unbounded under spoofed source addresses
**CWE**: 770, 400. The rate-limiter itself becomes the DoS surface. UDP source spoofing → millions of fresh `tokenBucket`s; cleanup runs every 5 min.

### M-3 — RRL key includes attacker-controlled qname → unbounded map growth
**CWE**: 770. **File**: `security/rrl.go:21-72`. Same shape as M-2; cleanup blocks the entire response path under the lock.

### M-4 — Bailiwick filter is permissive when `currentZone == ""` for **every** first iteration, not just priming
**CWE**: 345. **Files**: `security/bailiwick.go:21-74`, `resolver/resolver.go:317`. The classic priming carve-out is applied too broadly; a compromised root response (or off-path injection) can stuff Answers with arbitrary records that flow into the cache.

### M-5 — Glue cache write at delegation time replaces multi-record A/AAAA RRsets with a single record
**CWE**: 345. **File**: `resolver/resolver.go:438-460`. Truncates RRsets, resets TTL, narrows attack surface to the single attacker-influenced glue IP and extends its lifetime.

### M-6 — DNS Cookie fallback secret becomes literal `"labyrinth-secret"` if `crypto/rand` fails
**CWE**: 330, 798. **File**: `server/handler.go:100-107`. RFC 7873 cookies degrade to plaintext checksums on RNG failure. Should fail closed.

### M-7 — DoH endpoint has no rate limit / per-client quota
**CWE**: 770. **Files**: `web/server.go:432-434`, `web/api_doh.go:17-70`. When `dohEnabled`, `/dns-query` is wired with no middleware. Acts as an unauthenticated recursive-DNS amplifier and CPU/egress sink.

### M-8 — DoH `Cache-Control` lacks `private`, no `Vary`, no clamp on `max-age`
**CWE**: 525, 345. **File**: `web/api_doh.go:62-69, 129-191`. CDN/proxy caches may serve one client's answer to another. Crafted upstream `0xFFFFFFFF` TTL → ~136 yr `max-age` cache poisoning at intermediates.

### M-9 — `GET /api/config/raw` returns the bcrypt password hash to any token holder
**CWE**: 200. **File**: `web/api_config.go:317-335`. Hijacked session → offline cracking.

### M-10 — JSON endpoints accept arbitrary-size bodies (no `MaxBytesReader`)
**CWE**: 770. **Files**: `web/auth.go:196,269`, `web/api_setup.go:51`, `web/api_config.go:294,338`, `web/api_blocklist.go:62,84`, `web/api_dashboard_layout.go:117`. Memory-pressure DoS; `/api/config/raw` PUT especially.

### M-11 — JWT secret not rotated on password change → 24h post-compromise window
**CWE**: 613. **Files**: `web/server.go:75-79,99`, `web/auth.go:294-308`. Password rotation does not log out other sessions.

### M-12 — JWT in `localStorage` + tokens in WS URLs
**CWE**: 522, 598. **Files**: `web/ui/src/api/client.ts:22-43,241-260`, `web/ui/src/App.tsx:44-52,74-84`. Reachable from any same-origin script; logged everywhere.

### M-13 — CSV exporters do not neutralise spreadsheet formula prefixes
**CWE**: 1236. **Files**: `web/ui/src/pages/QueriesPage.tsx:204-233`, `CachePage.tsx:223-245`, `BlocklistPage.tsx:163-186`, `ReportsPage.tsx:139-178`. Attacker-influenced qnames (`q.qname`, `q.client`) and upstream error strings flow into Excel cells starting `=`, `+`, `-`, `@`. DDE / `=HYPERLINK` exfil on admin's machine.

### M-14 — Update binary in-place rename loses original mode/owner/file-capabilities (e.g. `cap_net_bind_service`)
**CWE**: 732. **File**: `web/api_update.go:224-282`. After successful update, port :53 binding silently breaks under non-root deployments.

### M-15 — `writeFileAtomically` leaves a permanent `labyrinth.yaml.bak` containing the previous bcrypt hash
**CWE**: 732. **File**: `web/api_config.go:380-429`. After every password rotation, the old hash persists at a deterministic path on disk.

### M-16 — JSON error responses build body via string concat with raw `err.Error()`
**CWE**: 116. **File**: `web/api_tls.go:54`. Quotes/newlines in autocert errors break JSON; future header-write of the same string would CRLF-inject.

### M-17 — Setup-wizard YAML escaping is hand-rolled (`escYAML`) and not RFC-1123-safe
**CWE**: 91. **File**: `web/api_setup.go:109-114`. Falls back to `fmt.Sprintf("%q", s)` (Go-style, not YAML-style) and skips quoting for many control characters. Combined with C-1 lets an attacker who reaches `/api/setup/complete` inject arbitrary YAML keys.

---

## LOW

### L-1 — Weak password floor (8 chars, no complexity, bcrypt 72-byte truncation undisclosed)  — `web/auth.go:146-167`. CWE-521.
### L-2 — `writeConfigYAML` creates the bcrypt-hash-bearing config at default umask (0644) — `web/api_setup.go:101-159`. CWE-732.
### L-3 — Fallback resolver / root-server selection uses unseeded `math/rand/v2` — `resolver/fallback.go:19`, `resolver/resolver.go:117,184`. CWE-338.
### L-4 — Single-attempt fallback accepts NXDOMAIN → negative cache poisoning surface — `resolver/fallback.go:42-67`. CWE-345.
### L-5 — Cluster-fanout cache flush authenticates with the local admin JWT instead of a peer secret — `web/api_cache.go:233-277`. CWE-345.
### L-6 — `parseSemverParts` accepts garbage tag-names silently → `Atoi` errors collapse to 0 — `web/api_update.go:399-434`. CWE-20.
### L-7 — Login endpoint allocates arbitrary-size password strings before the rate limiter triggers — `web/auth.go:175-226`. CWE-770.
### L-8 — SPA's hard 401 → `window.location.href = '/login'` is fragile (could become open redirect on refactor) — `web/ui/src/api/client.ts:77-81`. CWE-601.
### L-9 — `release_url` from GitHub API rendered as `<a href={url}>` without scheme validation; `DashboardPage.tsx:569-578` lacks `target="_blank"` and `rel`, so `javascript:` would execute — `web/ui/src/pages/AboutPage.tsx:286-294`, `DashboardPage.tsx:569-578`. CWE-601, 79.
### L-10 — release workflow has no `concurrency:` block; concurrent tag pushes race on asset upload — `.github/workflows/release.yml`. CWE-405.
### L-11 — Information disclosure on `/api/system/version` (unauthenticated) leaks Go runtime, build time, OS, arch — `web/api_system.go:31-45`. CWE-200.

---

## INFO

### I-1 — `dns.ParseOPT` does not validate EDNS version, does not surface ExtRCODE — `dns/edns.go:24-54`. CWE-20. Masks legitimate upstream errors.
### I-2 — Zabbix passive-agent listener is unauthenticated **by protocol design** — `web/api_zabbix.go:111-173`. Document deployment guidance (loopback or firewall ACL).
### I-3 — Dockerfile follows good practices (multi-stage, non-root, `.dockerignore`) — captured for completeness.
### I-4 — SIGHUP advertised as reload but only logs; `ExecReload=SIGUSR1` flushes cache instead — `signals_unix.go:31-36`, `labyrinth.service:12`. Operator confusion. CWE-440.

---

## False positives / non-findings (eliminated during verification)
- **`dangerouslySetInnerHTML`, `eval`, inline scripts**: absent from the React SPA.
- **JWT `alg` confusion / "none"**: the validator pins `alg=HS256` and uses `hmac.Equal` — confirmed safe.
- **TXID predictability**: `crypto/rand` for upstream TXIDs (`resolver/upstream.go:262`) — confirmed safe.
- **Source-port randomization**: kernel-assigned via `net.DialTimeout("udp", ...)` — confirmed safe.
- **0x20 case randomization & question echo on iterative responses**: enforced (`resolver/upstream.go:118-126`) — confirmed safe.
- **Name decoder bounds**: 63-byte label, 255-byte name caps, backward-only pointers, depth ≤128 — confirmed safe.
- **RFC 8482 minimal-ANY**: enforced — confirmed safe.
- **DoH POST body limit**: 64 KiB via `io.LimitReader` — confirmed safe.
- **Blocklist body limit**: 50 MiB — confirmed safe (separate from the SSRF redirect issue).
- **UDP downstream truncation honors the RFC 6891 §6.2.5 floor of 512** — confirmed safe (recent commit).
- **No `os/exec` of attacker-controlled data** (only re-exec of self for daemonize / Windows update helper) — confirmed safe.
- **`http.FileServer(http.FS(embedFS))` for SPA** — embed.FS rejects path traversal natively.
- **No `crypto/md5`, `crypto/des`, `crypto/rc4` in non-DNSSEC code paths**.
- **bcrypt cost 10 + dummy-hash timing absorber + login limiter** — confirmed safe brute-force posture.
- **AllowSHA1 default `false`** — confirmed safe.
- **NSEC3 iteration cap at 100** — confirmed safe.

These were all candidate findings raised by checklists that the codebase already satisfies; explicitly recording them so future scans don't redundantly flag.
