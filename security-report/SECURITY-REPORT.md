# LabyrinthDNS — Security Audit Report

**Scan date**: 2026-05-03
**Target**: `D:\CODEBOX\PROJECTS\LabyrinthDNS` @ `main` (HEAD `2fecca7`)
**Pipeline**: security-check 4-phase (Recon → Hunt → Verify → Report)
**Reviewer**: AI security pipeline (Claude Code), 5 parallel cluster agents

---

## Executive Summary

LabyrinthDNS is a pure-Go recursive resolver with an embedded React/TS management UI. The core DNS protocol implementation is **carefully written** — TXIDs are crypto-random, source ports kernel-randomized, name decoder bounds are tight, RFC 8482 ANY-handling is enforced, DoH bodies are bounded, NSEC3 iteration is capped, and bcrypt + login-limiter + dummy-hash timing-absorber give a solid brute-force posture.

The audit nevertheless surfaces **four critical issues** that, in combination, allow unauthenticated remote code execution against any deployment that exposes the management port externally:

1. The **setup wizard** is reachable on every restart (a runtime `bool` is never seeded from disk) and overwrites `labyrinth.yaml` — including the bcrypt-hash field.
2. The **self-update** path downloads and `syscall.Exec`s a binary with no signature, no checksum, and no body cap.
3. The **`install.sh` / `curl-pipe-to-bash`** distribution channel ships `checksums.txt` but never verifies it.
4. **DNSSEC validation is silently disabled** for every zone below the root because the `Querier` sends DNSKEY/DS queries to root servers, which only return referrals.

Combined risk score: **9.4 / 10 (Critical)** for any deployment with the admin port reachable from the network and `auto_update` enabled, or for downstream consumers of unsigned releases. Even with admin port loopback-bound, C-4 (DNSSEC) renders one of the project's marquee security guarantees inert today.

---

## Risk Score
| Component | Rating |
|-----------|--------|
| **Combined CVSS-style severity** | 9.4 (Critical) |
| Confidentiality impact | High |
| Integrity impact | Critical |
| Availability impact | High |
| Attack vector | Network (UDP/53, TCP/53, HTTPS admin) |
| Attack complexity | Low (C-1 → C-2 = single POST + single click) |
| Privileges required | None (C-1, C-3, C-4); Low (C-2 alone) |
| User interaction | None |
| Scope | Changed (admin RCE → DNS substitution → tenant compromise) |

---

## Scan Statistics
| Metric | Value |
|--------|-------|
| Files scanned (Go) | ~120 source files (excludes `*_test.go`, `node_modules/`, `dist/`) |
| Files scanned (TS/TSX) | ~55 files (`web/ui/src/**` only; `website/` excluded) |
| Cluster agents dispatched | 5 (web-auth, dns-resolver, injection-crypto, frontend-headers, infra-cicd) |
| Skills exercised | 38 of 48 (no PHP/Rust/Java/C#/Python language scanners required) |
| Raw findings produced | 70 |
| Verified findings (after dedupe + reachability check) | 50 |
| False positives / mitigated checks captured | 16 |

---

## Findings by Severity

| Severity | Count | Issues |
|----------|-------|--------|
| **Critical** | 4 | Setup-wizard takeover (C-1); unsigned self-update (C-2); unsigned `install.sh` (C-3); DNSSEC silent failure (C-4) |
| **High** | 14 | Auth bypass on empty username (H-1); WS InsecureSkipVerify (H-2); no security headers (H-3); `?token=` query auth (H-4); pool-buffer UAF (H-5); cache skips private-IP filter (H-6); KSK-2024 missing (H-7); RDATA decompression panic (H-8); pidfile race + `StopDaemon` arbitrary-PID kill (H-9); blocklist SSRF (H-10); update default `http.Get` (H-11); CI permissions over-scoped (H-12); GH Actions tag-pinned (H-13); releases unsigned, no SBOM (H-14) |
| **Medium** | 17 | Forward/fallback bypass bailiwick (M-1); rate-limiter unbounded growth (M-2,3); empty-zone bailiwick (M-4); glue overwrite (M-5); cookie secret literal fallback (M-6); DoH unbounded (M-7,8); `password_hash` exposure (M-9); JSON body size (M-10); JWT secret not rotated (M-11); JWT in localStorage (M-12); CSV formula injection (M-13); update perms loss (M-14); persistent .bak file (M-15); raw err in JSON (M-16); hand-rolled YAML escape (M-17) |
| **Low** | 11 | Password floor (L-1); 0644 config (L-2); math/rand selection (L-3,4); cluster fanout JWT reuse (L-5); semver parser laxity (L-6); login body size (L-7); SPA hard redirect (L-8); release_url scheme not validated (L-9); release workflow concurrency (L-10); /version info leak (L-11) |
| **Info** | 4 | EDNS version not validated (I-1); Zabbix unauth by design (I-2); Dockerfile good practices (I-3); SIGHUP semantics (I-4) |

Detailed entries with file:line references and recommendations are in
`security-report/verified-findings.md`.

---

## Top 10 Issues (Ranked)

| # | ID | Title | Sev | Effort to fix |
|---|----|-------|-----|---------------|
| 1 | C-1 | Setup wizard reachable post-install → unauthenticated config rewrite | Critical | S — seed `setupDone` from config in `NewAdminServer` |
| 2 | C-2 | Self-update: no signature/checksum verification → RCE | Critical | M — embed cosign/minisign pubkey, verify detached sig |
| 3 | C-3 | `install.sh` doesn't verify `checksums.txt` | Critical | S — add `sha256sum -c` block before `mv` |
| 4 | C-4 | DNSSEC silently broken for non-root zones | Critical | M — route DNSKEY/DS through full iterative resolution |
| 5 | H-5 | sync.Pool buffer use-after-return → response substitution | High | S — copy `packed` before `PutBuffer`, in 9 sites |
| 6 | H-9 | Pidfile symlink race + `StopDaemon` arbitrary-PID kill | High | S — `O_NOFOLLOW|O_EXCL` + verify cmdline before kill |
| 7 | H-7 | Only KSK-2017 trust anchor; KSK-2024 absent | High | S — add KSK-2024 anchor (key tag 38696) |
| 8 | H-2 | WS `InsecureSkipVerify: true` → CSWSH | High | S — set `OriginPatterns` from `cfg.Web` |
| 9 | H-3 | No security response headers | High | S — single header middleware over the mux |
| 10 | H-1 | Auth bypass on empty `web.auth.username` | High | S — refuse to start, OR require explicit anon flag |

---

## Remediation Roadmap

### Phase 1 — Stop the bleeding (within 1 sprint, all Critical + Top-Highs)
1. **C-1 fix**: in `NewAdminServer`, set `setupDone = cfg.Web.Auth.Username != "" && cfg.Web.Auth.PasswordHash != ""`. Refuse `/api/setup/complete` if a usable config exists at `s.configFilePath()`. Bind `/api/setup/*` to loopback until first-run is complete.
2. **C-2 fix**: ship a release-signing key (cosign keyless via `id-token: write` already enabled; or minisign/ed25519). Embed the public key in the binary. Make `handleApplyUpdate` fetch + verify a detached signature *and* the SHA-256 from `checksums.txt`. Replace `http.Get` with a `*http.Client{Timeout: 60s}` and wrap the body in a size-bounded reader.
3. **C-3 fix**: extend `install.sh` to fetch `checksums.txt` and run `sha256sum -c labyrinth-<arch>` before `mv`. Pin the release notes URL to `${{ github.ref_name }}`, not `main`.
4. **C-4 fix**: in `Resolver.QueryDNSSEC`, route DNSKEY/DS through `resolveIterative` (with DO bit forced on) instead of a root-server lookup. Add an end-to-end test that validates a real signed zone (e.g. `iana.org` DNSKEY) against the trust anchor.
5. **H-5 fix**: across the 9 sites in `server/handler.go`, change to `out := append([]byte(nil), packed...); pool.PutBuffer(bufPtr); return out`. Add a race-test under `go test -race`.
6. **H-7 fix**: add KSK-2024 (key tag 38696, alg 8 RSASHA256, digest type 2 SHA-256, digest `683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16`). Optionally implement RFC 5011 automated rollover.
7. **H-9 fix**: open the pidfile with `O_CREATE|O_WRONLY|O_EXCL|O_NOFOLLOW`, mode 0640. In `StopDaemon`, verify `/proc/<pid>/comm` (or cmdline) before signalling. Add `defer daemon.RemovePID(pidFile)` at process entry so non-graceful exits clean up.
8. **H-1 fix**: refuse to start the admin server when `web.Enabled && web.Auth.Username == ""` unless an explicit `web.auth.allow_anonymous: true` is set; log a startup error.

### Phase 2 — Defence in depth (1-2 sprints)
- **H-2/H-3/H-4 (frontend/headers/auth)**: add a global middleware that emits CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS (when TLS active). Drop the `?token=` HTTP fallback. Move WS auth onto `Sec-WebSocket-Protocol`. Set `OriginPatterns` on both WS endpoints.
- **H-6 (cache vs private-address filter)**: apply `FilterPrivateAddresses` at the cache **write** site (`server/handler.go:467-475`).
- **H-8 (RDATA panic)**: clamp `nameEnd ≤ newOffset` in `dns/record.go`; reject (or `copyRData`) malformed RRSIG/NSEC. Add fuzz tests.
- **H-10 (SSRF)**: install a `CheckRedirect` on the blocklist client that rejects RFC 1918 / loopback / link-local / IPv4-mapped / multicast destinations and disallows scheme changes; cap redirects at 3.
- **H-11 / M-7 / M-10**: add a `*http.Client{Timeout: 60s}` for outbound, add `http.MaxBytesReader` to every JSON endpoint (1 MiB default, 8 MiB for `/api/config/raw`), add a per-IP rate limit to `/dns-query`.
- **H-12 / H-13 / H-14**: scope GH Action permissions per job; SHA-pin every `uses:`; sign releases with cosign keyless and emit SLSA build provenance + CycloneDX SBOM.

### Phase 3 — Hardening (2-4 sprints)
- **M-1, M-2, M-3, M-4, M-5**: harden the resolver layer — apply `SanitizeBailiwick` to forward/fallback responses, cap rate-limiter / RRL maps with random eviction, gate the `currentZone == ""` permissive bailiwick on a `priming` flag, merge glue records into existing RRsets instead of overwriting.
- **M-6**: fail closed on `crypto/rand` errors; never substitute a literal cookie secret.
- **M-9**: redact `password_hash` from `GET /api/config/raw`; the editor doesn't need to see it (PUT already enforces "hash unchanged").
- **M-11 / M-12**: rotate `jwtSecret` (or bump per-user `iat` floor) on password change; switch dashboard auth to `HttpOnly; Secure; SameSite=Strict` cookie; remove tokens from URLs.
- **M-13**: prefix any CSV cell starting with `=`, `+`, `-`, `@`, `\t`, `\r` with `'` and quote-wrap.
- **M-14**: preserve original mode/uid/gid + xattrs (`security.capability`) across the in-place update rename.
- **M-15**: remove `labyrinth.yaml.bak` after a successful rename, or rotate it; never leave the previous bcrypt hash on disk.
- **M-17**: replace hand-rolled `escYAML` with a real YAML encoder.

### Phase 4 — Long-term posture (continuous)
- Wire `govulncheck ./...` and `npm audit` into the `release.yml` test job (fail-on-critical).
- Pin Docker base images to digests; add HEALTHCHECK.
- Modernise the systemd unit (`CapabilityBoundingSet`, `RestrictAddressFamilies`, `SystemCallFilter`, `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictNamespaces`, `RuntimeDirectory`, `ProtectProc=invisible`). Target `systemd-analyze security ≤ 2.0`.
- Reconcile in-repo `labyrinth.service` with `install.sh`-generated unit (drift today: `ReadOnlyPaths` vs `ReadWritePaths` for `/etc/labyrinth`).
- Implement real `SIGHUP` config reload (or remove `ExecReload`).
- Add Dependabot for `package-ecosystem: github-actions` so SHA pins stay current.
- Migrate `nhooyr.io/websocket` (archived) → `coder/websocket` (drop-in fork).
- Verify `lucide-react@^1.7.0` in `web/ui/package.json` resolves to a real published version (current upstream is 0.x).
- Add a release-signing & SBOM step. Publish `cosign verify-blob` instructions in the install path.

---

## Phase Outputs (artifacts produced by this scan)
- `security-report/architecture.md` — codebase architecture + entry points
- `security-report/dependency-audit.md` — Go module + npm dependency review
- `security-report/hunt-web-auth-results.md`
- `security-report/hunt-dns-resolver-results.md`
- `security-report/hunt-injection-crypto-results.md`
- `security-report/hunt-frontend-headers-results.md`
- `security-report/hunt-infra-cicd-results.md`
- `security-report/verified-findings.md` — consolidated, deduplicated, false-positive-eliminated findings
- `security-report/SECURITY-REPORT.md` — this report

---

## Notes on Methodology
- The audit is **static** (no runtime exploit, no fuzzing run beyond what the project ships in `dns/wire_fuzz_test.go` and `resolver/classify_fuzz_test.go`). Recommend executing `govulncheck`, `go test -race ./...`, and the existing fuzz corpora during CI.
- Reachability calls were verified by tracing data flow through the code; no findings are based on pattern-matching alone.
- Three findings (C-1, C-2/C-3, H-9) are reinforced by being reported independently by multiple cluster agents from different starting points — confidence is therefore high.
- The `website/` marketing tree was excluded as a low-value target (GitHub Pages, no privileged surface).
- DNS protocol behaviour was verified against RFC 1035, 2181, 2308, 4034/4035 (DNSSEC), 5011 (anchor rollover), 6891 (EDNS0), 7873 (cookies), 8020 (NXDOMAIN cuts), 8482 (ANY), 8499 (terminology), 9156 (QNAME minimization).
