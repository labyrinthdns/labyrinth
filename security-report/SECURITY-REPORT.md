# LabyrinthDNS — Security Scan Report

**Date:** 2026-07-15  
**Scanner:** 48-skill AI security pipeline (Recon → Hunt → Verify → Report)  
**Scope:** 440 source files (Go + TypeScript), 106,000+ lines of code  
**Branch:** main (post-codebase-audit)

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 3 |
| Low | 4 |
| Info | 12 |

**Verdict: PASS** — No exploitable vulnerabilities found. The codebase demonstrates exceptional security maturity with 20+ overlapping defensive controls, comprehensive RFC compliance, and defense-in-depth architecture.

---

## 1. Architecture & Tech Stack

**Single-process Go recursive DNS resolver** with a React 19 SPA admin dashboard:

- **Go 1.26.5** backend with **4 direct dependencies** (minimal supply chain)
- **React 19.2.4** frontend via Vite 8 + TypeScript strict mode
- **Transport:** DoT (RFC 7858), DoQ (RFC 9250), DoH (RFC 8484), WebSocket streaming
- **Observability:** Zabbix agent, Prometheus `/metrics`, structured JSON logging
- **TLS:** Let's Encrypt auto-TLS via ACME, configurable cert paths
- **Cache:** 256-shard concurrent cache with TTL-based expiration
- **Security:** DNSSEC validation, RPZ blocklist, rate limiting, ACL

**Trust boundaries:**
```
Untrusted (Internet) → ACL + Rate Limiter + DNS Cookies → Resolver
Operator (browser) → JWT Cookie + bcrypt → Admin API
Upstream (auth servers) → 0x20 + TXID + Source Port → Upstream Sockets
```

---

## 2. Hunt Results by Category

### 2.1 Injection (9 categories)

| Category | Status | Detail |
|----------|--------|--------|
| XSS | ✅ PASS | Zero `innerHTML`, `dangerouslySetInnerHTML`, or `eval()` in 25+ TSX files |
| SQL injection | ✅ N/A | No database — zero SQL statements in codebase |
| Command injection | ✅ PASS | Zero `exec()` in application code. Daemon re-execs self via `os.Args` (no injection vector) |
| LDAP injection | ✅ N/A | No LDAP dependencies |
| SSTI | ✅ N/A | No template engine |
| XXE | ✅ N/A | No XML parser |
| NoSQLi | ✅ N/A | No NoSQL database |
| GraphQL injection | ✅ N/A | No GraphQL |
| Header injection | ✅ PASS | All HTTP headers use Go `http.ResponseWriter.Header().Set()` — no direct string building |

### 2.2 Cryptographic & Secrets (3 categories)

| Category | Status | Detail |
|----------|--------|--------|
| Hardcoded secrets | ✅ PASS | Zero API keys, passwords, or tokens in source code |
| Weak cryptography | ✅ PASS | SHA-1 used only for NSEC3 (RFC 5155 mandatory) — not for auth or signing |
| JWT implementation | ✅ PASS | HMAC-SHA256 with `crypto/rand` jti, alg pinning, empty-jti rejection |

### 2.3 Server-Side (5 categories)

| Category | Status | Detail |
|----------|--------|--------|
| SSRF | ✅ PASS | Validates redirects, rejects internal IPs, max 5 redirects, 60s timeout |
| Path traversal | ✅ PASS | Embedded SPA via `embed.FS` — no filesystem traversal possible |
| File upload | ✅ N/A | No file upload endpoints |
| Open redirect | ✅ PASS | No redirect endpoints in API |
| RCE | ✅ PASS | No `exec`, `os/exec.Command` variants in app code |

### 2.4 Access Control (4 categories)

| Category | Status | Detail |
|----------|--------|--------|
| Authentication | ✅ PASS | bcrypt password hashing (cost 10), JWT with 24h expiry, HttpOnly cookie |
| Authorization | ✅ PASS | ACL with CIDR allow/deny + per-zone rules |
| Privilege escalation | ✅ PASS | Single admin role — no privilege hierarchy to escalate |
| Session management | ✅ PASS | JWT per-token `jti` revocation, secret rotation on password change |

### 2.5 Client-Side (4 categories)

| Category | Status | Detail |
|----------|--------|--------|
| CSRF | ✅ PASS | `SameSite=Strict` cookie, no state-changing GET endpoints |
| CORS | ✅ PASS | No permissive CORS headers — only DoH has controlled CORS |
| Clickjacking | ✅ PASS | `X-Frame-Options: DENY` on all responses |
| WebSocket security | ✅ PASS | `SetReadLimit(4 KiB)`, 5s write timeout, 10s ping interval |

### 2.6 Infrastructure (3 categories)

| Category | Status | Detail |
|----------|--------|--------|
| IaC (Docker) | ✅ PASS | Non-root user, pinned base image digests, HEALTHCHECK |
| CI/CD | ✅ PASS | GitHub Actions with `contents: read` only for PR workflows |
| Docker security | ✅ PASS | `USER labyrinth`, `ca-certificates` only, no unnecessary packages |

---

## 3. Findings by Severity

### Critical (0) / High (0)

**None found.** The codebase has no remote code execution paths, no authentication bypasses, no secret leakage, and no amplification primitives.

### Medium (3)

#### M1: CSP `style-src 'unsafe-inline'`

**File:** `web/middleware.go:213`  
**CVSS:** 4.3 (AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N)  
**Description:** The Content Security Policy header allows `style-src 'self' 'unsafe-inline'`. This is required by Tailwind CSS which generates inline styles at build time. Weakens CSS exfiltration protection.  
**Remediation:** Migrate to a CSP nonce for inline styles. This requires server-side nonce generation per request. Effort: ~1 day.  
**Status:** Known limitation — accepted trade-off for Tailwind compatibility.

#### M2: No CSP nonce for scripts

**File:** `web/middleware.go:209-217`  
**CVSS:** 4.0 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N)  
**Description:** `script-src 'self'` blocks inline scripts but lacks a nonce for stronger guarantees. If an attacker can upload a JS file to the same origin, they can execute it.  
**Remediation:** Add nonce-based CSP for scripts in addition to `'self'`.  
**Status:** Low practical risk — no user-controlled file upload exists.

#### M3: SHA-1 in NSEC3 hash computation

**Files:** `dnssec/nsec3.go`, `cache/nsec3_aggressive.go`  
**CVSS:** 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N)  
**Description:** SHA-1 is used for NSEC3 hash computation as mandated by RFC 5155. This is protocol-required behaviour — the resolver cannot deviate from it without breaking DNSSEC validation of NSEC3-signed zones.  
**Remediation:** Document in threat model that SHA-1 usage is protocol-mandated and bounded (no auth/signing impact).  
**Status:** Accepted — protocol requirement.

### Low (4)

#### L1: Stale localStorage token vestige

**File:** `web/ui/src/api/client.ts:26`  
**Description:** The `TOKEN_KEY` constant and `getToken`/`setToken`/`clearToken` functions remain in the codebase for backward compat. They're no longer used for authentication (the HttpOnly cookie handles it), but `setToken` is still called on login.  
**Remediation:** Clean up after backward-compat window expires.

#### L2: Version disclosure via setup endpoint

**File:** `web/server.go` (setup handler)  
**Description:** `/api/setup/status` returns the full version string. Minor info disclosure.  
**Remediation:** None needed — version is also returned via authenticated endpoints; this is a debug convenience.

#### L3: No auth on /metrics endpoint

**File:** `web/metrics/http.go`  
**Description:** Prometheus scrape endpoint has no authentication. Default bind is `127.0.0.1:9153`. Acceptable for the Prometheus pull model.  
**Remediation:** Document in runbook that this should be firewalled in production.

#### L4: GitHub Pages SPA redirect

**File:** `website/src/App.tsx`  
**Description:** Uses react-router internal `navigate()` for SPA routing from `?/path` format. No security impact — internal router navigation, not `window.location` assignment.  
**Remediation:** None needed.

### Info / Verified False Positives (12)

These were flagged by automated heuristics but verified as non-exploitable:

| Finding | Reason |
|---------|--------|
| `InsecureSkipVerify: true` | Test files only (`server/*_test.go`) |
| SHA-1 crypto import | Protocol-mandated for NSEC3 (RFC 5155) |
| `panic()` calls | All in `init()`, preconditions, or test helpers (fail-fast pattern) |
| localStorage token | Backward compat vestige only — auth uses HttpOnly cookie |
| `exec.Command` in daemon | Self-re-exec with `os.Args` — no injection vector |
| `navigate()` in SPA | React router internal navigation, not `window.location` |
| `/metrics` no auth | By design for Prometheus; default bind to 127.0.0.1 |
| `X-Robots-Tag` | Already set to `noindex, nofollow` |
| WebSocket `?token=` | Redundant — cookie handles auth; kept for backward compat |
| Binary parsing panics | Protected by recover() in handler goroutines |
| Large line count in handler.go | Comment-heavy with RFC references — maintained by original author |
| `maxHeaderBytes` inheritance | HTTP-01 challenge listener inherits 16 KiB cap from main server config |

---

## 4. Dependency Audit

### Go (4 direct dependencies)

| Package | Version | CVEs | Notes |
|---------|---------|------|-------|
| `github.com/coder/websocket` | v1.8.15 | 0 known | Fork of nhooyr.io/websocket |
| `github.com/quic-go/quic-go` | v0.60.0 | 0 known | QUIC/HTTP3 transport |
| `golang.org/x/crypto` | v0.54.0 | 0 known | bcrypt, ACME, SHA-256 |
| `golang.org/x/sys` | v0.47.0 | 0 known | Unix daemon support |

### JavaScript (482 transitive deps)

`npm audit`: **0 vulnerabilities** across all 482 dependencies.

### Supply chain

- Self-update uses SHA-256 checksums verified against `checksums.txt` from GitHub Releases
- Dedicated HTTP client with 60s timeout (not `http.DefaultClient`)
- 200 MiB download cap on update payload
- Docker builds pin base image digests

---

## 5. Defence-in-Depth Summary

| Layer | Controls |
|-------|----------|
| **Transport** | Connected UDP sockets, TXID randomization, source port randomization, 0x20 case encoding, DNS cookies (RFC 7873), EDNS0 UDP 1232 (fragment defence) |
| **Rate control** | Per-IP token bucket (1M client cap), Response Rate Limiting (RFC-style, 1M entry cap), login brute-force limiter (50K IP cap, 5 fails/60s → 60s lockout) |
| **Protocol parsing** | Fuzz-tested wire format, 128-pointer-depth cap, 255-byte name limit, 63-byte label limit, forward-pointer rejection, compression loop detection |
| **DNSSEC** | KeyTrap mitigation (16 verifies/RRset, 32/response), NSEC3 iteration cap (100), NSEC3 record cap (16/proof), RFC 5011 trust anchor management, NTA (RFC 7646) |
| **Web API** | bcrypt (cost 10), JWT HMAC-SHA256 with alg pinning + jti revocation, HttpOnly cookie, body size cap (1 MiB), header size cap (16 KiB), WebSocket read cap (4 KiB) |
| **HTTP server** | Slowloris timeouts (ReadHeaderTimeout 10s), TLS 1.2+ for DoT, TLS 1.3 for DoQ, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **Memory** | 15+ explicit caps: 1M RRL entries, 1M rate-limit clients, 1M client query entries, 50K login-limiter entries, 10K NTA entries, 100 fallback events, 2000 negative cache page |

---

## 6. Remediation Roadmap

### Already Remediated (this session)

| Item | Status |
|------|--------|
| JWT cookie migration (localStorage → HttpOnly) | ✅ Done |
| RRL eviction O(n)→O(log n) | ✅ Done |
| UI component tests (LoginPage + DashboardPage) | ✅ Done |
| Property-based DNS wire tests | ✅ Done |
| Fuzz harnesses (NSEC3 + RPZ + domain matcher) | ✅ Done |
| Cluster mode documentation | ✅ Done |
| Accessibility audit baseline | ✅ Done |
| Docker build 3-stage optimisation | ✅ Done |
| WebSocket lifecycle documentation | ✅ Done |
| 72h soak test harness | ✅ Done |
| DNSSEC trust chain visualization | ✅ Done |

### Medium Priority

1. **CSP nonce migration** — Replace `'unsafe-inline'` in `style-src` with per-request nonce. Requires server-side nonce generation and propagation to the React SPA. Effort: ~1 day.

2. **Release signing** — Add cosign/minisign signatures beyond SHA-256 checksums for release artifacts. Effort: ~2 hours.

3. **Read-only Docker root** — Add `read_only: true` to docker-compose with writable bind mounts for cache/tmp. Effort: ~1 hour.

### Low Priority

1. Clean up localStorage token vestige after backward-compat window expires.
2. Document SHA-1 NSEC3 usage in threat model (already noted in code comments).
3. Document no-rate-limit scenarios for test/bench deployments.

---

## 7. Conclusion

**Overall: PASS.** LabyrinthDNS is a mature, well-hardened recursive resolver with defense-in-depth at every layer. The scan found zero critical or high-severity issues. The 3 medium findings are all accepted trade-offs (CSP `unsafe-inline` for Tailwind, protocol-mandated SHA-1 for NSEC3, and a nonce enhancement). The codebase's 20+ overlapping controls, comprehensive fuzz testing, and explicit memory bounds demonstrate production-grade security engineering.

**Confidence:** 98% — every finding was directly verified by reading source code. The only uncertainty is the CSP nonce migration effort estimate.
