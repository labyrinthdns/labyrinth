# LabyrinthDNS — Threat Model

_Date: 2026-07-13 · Corresponds to PLAN.md M7.4_

This document identifies threats to LabyrinthDNS, the security controls
that mitigate them, and residual risks. It follows the STRIDE
classification (Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, Elevation of Privilege).

---

## 1. Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| **DNS response data** | Answers to client queries (could include existence/non-existence of internal hostnames) | Medium — query-log data from resolvers has been used in exfiltration attacks |
| **Cache contents** | In-memory cache of resolved domains | Low — cached public DNS data; no private data stored |
| **Admin credentials** | JWT token + bcrypt password hash | High — admin access controls the resolver |
| **Config file** | `labyrinth.yaml` with passwords, upstream IPs, TLS certs | High |
| **TLS private keys** | DoT/DoH server keys | Critical |
| **Process memory** | In-flight query state, cache entries | Low-Medium |
| **Query log buffer** | Recent queries in memory ring buffer | Medium — contains client IPs and query names |

---

## 2. Trust Boundaries

```
  Untrusted Network (Internet)
  ┌─────────────────────────────────────────┐
  │  DNS Clients (UDP/TCP)                  │
  │  Web Dashboard users (HTTPS)            │
  │  Upstream authoritative servers         │
  └──────────────────┬──────────────────────┘
                     │
                     ▼
  ┌─────────────────────────────────────────┐
  │           Trust Boundary                │
  │  (ACL + rate limiter + bailiwick +     │
  │   private filter + cookie validation)  │
  └──────────────────┬──────────────────────┘
                     │
                     ▼
  ┌─────────────────────────────────────────┐
  │  LabyrinthDNS Process                   │
  │  ┌──────────┐ ┌──────────┐ ┌────────┐ │
  │  │ Resolver │ │  Cache   │ │  Web   │ │
  │  │ Engine   │ │ (256 shard)│ │Dashboard│ │
  │  │ DNSSEC   │ │ NSEC/    │ │ JWT    │ │
  │  │ Validator│ │ NSEC3 idx│ │ Auth   │ │
  │  └──────────┘ └──────────┘ └────────┘ │
  └─────────────────────────────────────────┘
                     │
                     ▼
  ┌─────────────────────────────────────────┐
  │  Admin / Monitoring Network             │
  │  (Prometheus, Zabbix, system admin)     │
  └─────────────────────────────────────────┘
```

**Key trust boundaries:**
1. **Network edge** (untrusted clients → resolver): ACL, rate limiting, RRL
2. **Upstream channel** (auth servers → resolver): connected UDP sockets, 0x20, DNS cookies, DNSSEC
3. **Admin API** (operator → web dashboard): JWT auth, bcrypt passwords
4. **Monitoring** (Prometheus/Zabbix → metrics): no auth on /metrics (by design)

---

## 3. Threat Agents

| Agent | Capability | Motivation |
|-------|-----------|------------|
| **Off-path attacker** | Can send spoofed UDP packets with forged source IP | Cache poisoning, amplification |
| **On-path attacker** | Can observe and modify traffic between resolver and auth servers | Response injection, eavesdropping |
| **Malicious client** | Can send arbitrary DNS queries | DoS, cache probing, amplification |
| **Compromised upstream** | Runs a malicious authoritative DNS server | Data injection, slow-loris, KeyTrap |
| **Insider (admin)** | Has config file or JWT access | Misconfiguration, data exfiltration |
| **Remote unauthenticated user** | Can reach the web dashboard port | Credential brute-force, API probing |

---

## 4. Threat Scenarios

### S — Spoofing

| ID | Threat | Impact | Mitigation | Residual Risk |
|----|--------|--------|------------|---------------|
| S1 | **Off-path UDP spoofing**: attacker sends forged DNS responses before the real auth server | Cache poisoning, client redirection | Connected UDP sockets (4-tuple kernel filter) + 16-bit TXID + 12+ bits source-port entropy + 0x20 case randomization (~28 bits total anti-spoofing entropy) | Low — entropy budget makes successful spoofing probabilistically infeasible within the query window |
| S2 | **DNS cache poisoning via fragment injection**: oversized UDP response with crafted fragment | Same as S1 | EDNS0 buffer clamped to 1232 (Flag Day 2020) — no IP fragmentation on DNS | Negligible — no fragments exist |
| S3 | **SAD-DNS side channel**: attacker probes PMTU cache to infer source port | Reduces anti-spoofing entropy | `IP_PMTUDISC_OMIT` on upstream UDP sockets (Linux); connected sockets | Low — Linux-only mitigation; macOS/BSD lack this protection |
| S4 | **Spoofed admin login**: attacker guesses or brute-forces JWT/bcrypt | Full admin control | bcrypt password hashing; JWT 24h expiry; rate-limited login endpoint; MinPasswordLength enforcement | Low — strong passwords make brute-force infeasible |

### T — Tampering

| ID | Threat | Impact | Mitigation | Residual Risk |
|----|--------|--------|------------|---------------|
| T1 | **On-path response injection**: attacker modifies DNS response in transit | Client served forged data | DNSSEC validation (RRSIG verification against trusted root KSK); connected UDP sockets; DoT/DoH for client-to-resolver link | Low — DNSSEC-secure zones reject tampered data; unsigned zones have no integrity protection |
| T2 | **CNAME chain manipulation**: attacker injects fake CNAME to redirect resolution to malicious NS | Redirection to attacker-controlled host | Bailiwick enforcement (RFC 5452 §3); CNAME target must be in-zone; max CNAME depth (10) limits chain length | Medium — unsigned delegations have no chain-of-trust protection |
| T3 | **Config file tampering**: attacker modifies labyrinth.yaml | Full resolver compromise | filesystem permissions (systemd `ProtectSystem=strict`); `ReadWritePaths` scoped to `/etc/labyrinth` and `/opt/labyrinth/bin` | Low — requires local access |

### R — Repudiation

| ID | Threat | Impact | Mitigation | Residual Risk |
|----|--------|--------|------------|---------------|
| R1 | **Operator denies making config change** | No audit trail for forensic analysis | Structured JSON logging with timestamps; `CHANGELOG.md` for manual tracking; config hot-reload via API is logged | Medium — no cryptographic audit log; operator with API access can clear logs (stdout/stderr) |
| R2 | **Admin user denies action** | No accountability for admin operations | Login events logged; password changes logged | Low — JWT issuance and password rotation are logged |

### I — Information Disclosure

| ID | Threat | Impact | Mitigation | Residual Risk |
|----|--------|--------|------------|---------------|
| I1 | **DNS query sniffing**: passive observer sees which domains clients resolve | Privacy leak — query patterns reveal user activity | DoT/DoH for client-to-resolver encryption; EDNS padding (RFC 7830 + 8467) prevents response-length fingerprinting on encrypted transports | Low — padding only on DoT/DoH (RFC 8467 §6 forbids padding on plaintext); UDP queries are visible |
| I2 | **Timing side-channel**: response size reveals query type even over encrypted channel | Query-type fingerprinting | EDNS padding rounds response size to 468-byte blocks on DoT/DoH | Low — padding block matches RFC 8467 §4.1 recommendation |
| I3 | **Cache-based probing**: attacker can measure query timing to determine cached vs uncached state | Detects which domains other clients have resolved | Cache timing differences are inherent (not mitigated) | Medium — inherent to shared-cache resolver design; use forward secrecy at network layer |
| I4 | **Prometheus /metrics exposure**: unauthenticated endpoint leaks query rates and cache composition | Operational intelligence for attacker | Default bind to 127.0.0.1:9153; documented warning to not expose /metrics publicly | Low — operator responsibility to firewall |

### D — Denial of Service

| ID | Threat | Impact | Mitigation | Residual Risk |
|----|--------|--------|------------|---------------|
| D1 | **UDP amplification**: attacker sends small queries with spoofed source IP to get large responses | Bandwidth exhaustion at victim | Response Rate Limiting (RRL): token bucket per (/24 or /56, qname, type) with SLIP+TC; EDNS0 buffer capped at 1232 limits response size | Low — RRL bounds amplification factor |
| D2 | **Query flood (water torture)**: attacker sends many queries for distinct random subdomains | Cache miss flood → upstream link saturation | Per-client rate limiter (token bucket); `MaxQueriesPerRequest` (200) limits fan-out per request; request timeout (20s) | Medium — rate limiter bounds single-client impact; distributed attack still reaches upstream |
| D3 | **KeyTrap (CVE-2023-50387)**: crafted DNSSEC response with excessive cryptographic work | CPU exhaustion on resolver | Crypto budget: 16 verifies per RRset, 32 per response; NSEC3 100-iteration cap, 16-record cap, 600-unit hash budget | Low — budgets are conservative (competitor comparison: PowerDNS 30/query, Unbound 16 suspensions) |
| D4 | **NXNSAttack (CVE-2020-8616)**: delegation pointing to many glueless NS names | Query fan-out amplification | Sequential NS resolution (not parallel) with first-success short-circuit; `MaxQueriesPerRequest` budget caps total queries across all sub-resolutions | Low — sequential + budget bounds amplification to ~1 |
| D5 | **TCP connection exhaustion (slowloris)**: attacker opens many slow TCP connections | Connection-slot exhaustion → new clients denied | Global `MaxTCPConns` cap (default 256) + idle timeout (default 5s) + per-connection read/write deadline (10s) | Medium — per-source-IP cap not implemented; one host can fill all 256 slots |
| D6 | **Memory exhaustion via cache growth**: attacker queries many distinct names | Cache grows beyond available RAM | `MaxEntries` cap (default 100K, max clamp 10M); LRU eviction within each shard; `clampConfigBounds` prevents operator-typo OOM | Low — cap is enforced; 10M entries ~2-3 GB worst case |
| D7 | **Memory exhaustion via rate-limiter maps**: attacker queries from many spoofed sources | RRL/rate-limiter maps grow unbounded | `MaxRRLEntries` (1M) with LRU eviction; rate-limiter cap with LRU eviction; periodic cleanup goroutines | Low — caps are bounded and actively evicted |

### E — Elevation of Privilege

| ID | Threat | Impact | Mitigation | Residual Risk |
|----|--------|--------|------------|---------------|
| E1 | **JWT secret rotation failure**: attacker exploits stale JWT after password change | Stale token remains valid | `crypto/rand.Read` error is checked and aborts the operation on failure; revoked tokens list is cleared on rotation | Low — error handling is correct (verified) |
| E2 | **Config hot-reload bypass**: operator plants pathological values via API | OOM / stall | All integer/duration config values clamped by `clampConfigBounds()` before use; negative/zero values floored to safe defaults | Low — clamps prevent even intentional bypass |
| E3 | **Path traversal in update mechanism**: self-update writes binary outside intended path | Arbitrary file write | Update path is hardcoded; `updateRemove` cleans up temp files on error | Low — limited by systemd `ProtectSystem` and `ReadWritePaths` |

---

## 5. Attack Surface

| Component | Port/Endpoint | Protocol | Exposure |
|-----------|--------------|----------|----------|
| UDP DNS listener | 53/udp | DNS | Public (by default) |
| TCP DNS listener | 53/tcp | DNS (RFC 7766) | Public (by default) |
| DoT listener | 853/tcp | DNS-over-TLS | Conditional (opt-in) |
| Web dashboard | 9153/tcp | HTTP/HTTPS | Localhost (default); can be bound publicly |
| DoH endpoint | 9153/tcp | HTTPS (RFC 8484) | Conditional (opt-in) |
| DoH3 endpoint | 9153/udp | HTTP/3 | Conditional (opt-in) |
| Zabbix agent | 10050/tcp | Zabbix protocol | Conditional (opt-in) |
| Prometheus /metrics | 9153/tcp | HTTP | Same as web dashboard |
| Admin REST API | 9153/tcp | HTTPS + JWT | Same as web dashboard |
| WebSocket stream | 9153/tcp | WSS | Same as web dashboard |

### Attack surface reduction

- UDP DNS listener is the primary attack surface. All security controls
  (ACL, rate limiter, RRL, cookies, connected sockets, anti-spoofing
  entropy) are active on this path.
- Web dashboard defaults to `127.0.0.1:9153` — not exposed to the network
  unless explicitly configured.
- DoT/DoH require TLS certificates and explicit config — not active by
  default.
- Zabbix agent is opt-in, off by default.

---

## 6. Security Controls Summary

| Layer | Control | RFC / Reference | Threats Covered |
|-------|---------|-----------------|-----------------|
| **Transport** | Connected UDP sockets (4-tuple kernel filter) | — | S1, T1 |
| **Transport** | EDNS0 buffer 1232 (no IP fragments) | Flag Day 2020, RFC 9018 | S2 |
| **Transport** | `IP_PMTUDISC_OMIT` on Linux upstream UDP | — | S3 |
| **Transport** | TCP fallback for truncated responses | RFC 7766 | D5 (partial) |
| **Transport** | DoT/DoH with TLS 1.3 | RFC 7858, 8484 | I1 |
| **Anti-spoofing** | Random source port + 0x20 case + random TXID | RFC 5452 | S1 |
| **Anti-spoofing** | DNS Cookies (server cookies + client echo) | RFC 7873 | S1, D1 |
| **Anti-spoofing** | SipHash-2-4 for cookie hashing | RFC 7873 | S1 |
| **Integrity** | DNSSEC validation (RRSIG, trust chain, NSEC/NSEC3) | RFC 4033-4035 | T1, T2 |
| **Integrity** | DNSSEC crypto budgets (16/RRset, 32/response) | KeyTrap mitigation | D3 |
| **Integrity** | Bailiwick enforcement | RFC 5452 §3 | T2 |
| **Integrity** | Private address filter (RFC 1918 stripping) | — | T1 (rebinding) |
| **Rate-limiting** | Per-client query rate limiter (token bucket) | — | D2 |
| **Rate-limiting** | Response Rate Limiting (token bucket per /24 + qname + type) | — | D1 |
| **Rate-limiting** | Per-request query budget (200) + deadline (20s) | NXNS mitigation | D4 |
| **Access control** | ACL (allow/deny lists, per-zone rules) | RFC 5358 | — |
| **Access control** | Recursion ACL (who may query) | RFC 5358 | — |
| **Cache safety** | MaxEntries clamp at 10M | — | D6 |
| **Cache safety** | RRL entry cap at 1M with LRU eviction | — | D7 |
| **Cache safety** | NSEC3 hash budgets (600/query, 150/cache) | CVE-2023-50868 | D3 |
| **Config safety** | `clampConfigBounds` for all integer/duration fields | — | E2 |
| **Config safety** | Lower-bound floors for make() inputs | — | E2 |
| **Auth** | bcrypt password hashing | — | S4 |
| **Auth** | JWT (HMAC-SHA256, 24h expiry, secret rotation on password change) | — | S4, E1 |
| **Process** | systemd `ProtectSystem=strict`, `NoNewPrivileges=true` | — | T3 |
| **Process** | Non-root user (`labyrinth`) | — | E3 |
| **Privacy** | EDNS padding (468-byte block on DoT/DoH, never on plaintext) | RFC 7830, 8467 | I1, I2 |

---

## 7. Residual Risks

| Risk | Severity | Rationale | Future direction |
|------|----------|-----------|-----------------|
| **No per-source-IP TCP connection cap** | Medium | One host can fill the 256-slot TCP connection pool with slow connections, preventing other clients from using TCP. The idle timeout (5s) bounds the hold time per connection, but an attacker with ~1300 concurrent connections (5s / rtt) can keep slots occupied. | Add `MaxTCPConnsPerClient` config knob with default ~16. |
| **DNS-over-QUIC not implemented (RFC 9250)** | Medium | No DoQ means clients on QUIC-only networks (future mobile, some enterprise) cannot reach the resolver directly. | Implement `transport/doq/` package. |
| **No TSIG support (RFC 8945)** | Medium | Zone transfer authentication not available — prevents secure AXFR/IXFR for secondary-resolver or catalog-zone scenarios. | Implement TSIG signing/verification. |
| **Plaintext UDP for client queries** | Medium | Client queries are visible to passive observers on the local network unless the client uses DoT/DoH upstream. | Out of scope for a recursive resolver — client encryption is the stub's responsibility. |
| **Cache timing side-channel** | Medium | Attacker can probe whether a domain is cached by timing query latency. | Inherent to shared-cache design; use network-layer forward secrecy (IPsec/WireGuard) if critical. |
| **No 72h soak test** | Low | Long-running memory/resource leaks may not surface in unit tests. | Add `cmd/labyrinth-soak/` or use existing bench coordinator for soak runs. |
| **No property-based testing** | Low | Fuzz tests exist but no QuickCheck-style invariant testing for core DNS wire format. | Add `testing/quick` or `rapid` tests for pack/unpack roundtrips. |

---

## 8. Incident Response

### If a vulnerability is reported

1. Reporter submits via SECURITY.md process (GitHub Advisory or email).
2. Maintainer acknowledges within 48 hours.
3. Assessment and fix developed within 14 days for HIGH/CRITICAL.
4. Fix ships as a patch release with CHANGELOG entry.
5. CVE assigned if applicable.

### If a compromise is suspected

1. Isolate the resolver from the network.
2. Preserve logs (`journalctl -u labyrinth`).
3. Capture memory (`SIGQUIT` to dump goroutine stacks).
4. Check config file integrity.
5. Rotate admin password and JWT secret.
6. Review cache for poisoned entries (flush cache with `SIGUSR1`).
7. Restore from known-good backup.

---

## 9. Related Documents

- `SECURITY.md` — Vulnerability disclosure policy and security feature reference
- `docs/architecture-deep-dive.md` — Component architecture and data flow
- `docs/operator-runbook.md` — Operational security hardening checklist
- `docs/rfc-compliance-matrix.md` — RFC coverage with test references
- `docs/resolver-hardening-gap-analysis-2026-06.md` — Cross-resolver gap analysis
- `config/config.go` `clampConfigBounds` — Configuration safety clamps
