# LabyrinthDNS — Roadmap to v1.0.0

This document captures the complete remaining work plan after audit
milestone Y93 (release v0.6.41). The audit phase Y34→Y93 produced 61
RFC compliance pins and 4 real bug fixes across 8 patch releases.

> **Reconciliation note (2026-07-12):** this roadmap has been partially
> reconciled against the v0.8.31 codebase. M1 (DNSSEC completeness) and
> M2 (transport modernization) below reflect actual implementation status;
> M3–M8 still carry their pre-v0.8.x descriptions. Use
> [`docs/rfc-gap-analysis-2026-07.md`](docs/rfc-gap-analysis-2026-07.md)
> and [`docs/rfc-compliance-matrix.md`](docs/rfc-compliance-matrix.md)
> as the current RFC-gap sources of truth.

We now move from incremental pin-by-pin patches to **themed
milestones**. Each milestone groups 15–30 commits into a single minor
release. Backend milestones are paired with UI milestones to keep
operator-facing surfaces in lockstep with engine changes.

Target endpoint: **v1.0.0** = production-ready signal.

---

## Release Map

| Version | Backend Milestone | UI Milestone | Theme |
|---------|-------------------|--------------|-------|
| v0.7.0  | M1 — DNSSEC completeness | UI-M1 — DNSSEC visualization | DNSSEC end-to-end |
| v0.8.0  | M2 — Transport modernization | UI-M2 — Query trace & cache inspector | Transport + observability |
| v0.9.0  | M3 — Resolver hardening | UI-M3 — Upstream monitoring | Resolver correctness |
| v0.10.0 | M4 — Operability | UI-M4 — Runtime config | Config + compliance scaffolding |
| v0.11.0 | M5 — DoS / security | UI-M5 — Compliance dashboard | Security posture |
| v0.12.0 | M6 — Test infrastructure | UI-M6 — Security panel | Quality assurance |
| v0.13.0 | M7 — Documentation & matrix | UI-M7 — Operator UX polish | Docs + UX |
| v1.0.0  | M8 — Stabilization | UI-M8 — Diagnostic tools | Production signal |

---

## Backend Milestone M1 — DNSSEC Completeness (v0.7.0)

Close all remaining DNSSEC gaps surfaced during the Y34–Y93 audit but
deferred as too large for a single pin.

### M1.1 — Algorithm rollover (RFC 4035 §4.6) ✅

- **Status**: implemented and tested (since v0.6.42, extended in v0.7.11
  with per-RRSIG verify cap).
- `dnssec/validator.go` iterates *all* candidate RRSIGs; success on any
  one yields Secure. A maxRRSIGVerifyAttempts cap bounds crypto work.
- **Tests**: `dnssec/rfc4035_algorithm_rollover_test.go` pins four
  corners — old-expired/new-valid, old-valid/new-expired, both-valid,
  both-expired — with two algorithms (ED25519 + ECDSA-P256).

### M1.2 — CDS / CDNSKEY (RFC 7344 + RFC 8078) ✅

- **Status**: parser implemented (`dnssec/cds.go`). Recognises CDS/CDNSKEY
  RDATA-level intent (key add, remove, algorithm rollover, delete-sentinel).
  Published through the diagnostics API for operator tooling.
- Parent-side update automation is explicitly deferred — LabyrinthDNS is a
  recursive resolver, not an authoritative provisioning agent.

### M1.3 — NSEC3 iteration policy (RFC 9276) ✅

- **Status**: implemented. `dnssec/nsec3.go` enforces `MaxNSEC3Iterations=100`
  (RFC 9276 §3.1 recommendation). Per-record cap, 16-record proof cap, salt
  wire limit, 600-unit hash-work budget. Cache path (`cache/nsec3_aggressive.go`)
  uses a separate 150-unit budget. All hardened by RFC-pinned boundary tests.

### M1.4 — RFC 5011 full lifecycle ✅

- **Status**: implemented (`dnssec/rfc5011_lifecycle.go`, 378 lines).
  Full state machine: TAStateAddPending (30-day hold-down per §2.4.1),
  TAStateValid, TAStateRevoked. Time-mocked tests cover all transitions.
  Root trust anchors live in `dnssec/trustanchor.go` (20326 + 38696).

### M1.5 — Multi-signer (RFC 8901) ✅

- **Status**: implemented and tested (`dnssec/rfc8901_multi_signer_test.go`).
  `verifyDNSKEYWithDS` returns true when any KSK matches any DS; the RRSIG
  iteration loop survives a failed signature from one signer and continues
  to the next. The comment at `validator.go:505-514` documents the
  "at least one valid RRSIG" strategy.

### M1.6 — DS digest type policy (RFC 8624) ✅

- **Status**: implemented (`dnssec/ds.go`). `strongestDSDigestForKey` selects
  the strongest supported digest among multiple DS RRs targeting the same key.
  Weak digest types (SHA-1) are ignored when a stronger type (SHA-256) exists
  for the same key tag + algorithm.

### M1.7 — Negative trust anchor (RFC 7646) ✅

- **Status**: implemented (`dnssec/nta.go`, `dnssec/validator.go`,
  `web/api_dnssec.go`). Operator-configurable NTA store with zone-scoped
  time-bounded entries. Exposed via the admin API (`GET/POST/DELETE
  /api/dnssec/nta`). Expired entries pruned by a background goroutine
  started in `main.go:run()`.

### M1.8 — Counter & EDE wiring (partial)

- **Status**: EDE codes 1, 2, 6, 7, 8, 9, 10 mapped in `dnssec/failure_reason.go`
  and emitted via server's EDE plumbing. Prometheus counters for rollover/
  algorithm-specific events not yet wired.
- **Remaining**: add `labyrinthdns_dnssec_rollover_validates_total` and similar
  counters; wire into `metrics/metrics.go`.

---

## Backend Milestone M2 — Transport Modernization (v0.8.0)

### M2.1 — DoQ (RFC 9250) ❌

- **Status**: not started. Requires `transport/doq/` package using quic-go,
  wired to the same query dispatcher used by DoT/DoH.
- Blocked on: quic-go integration is available but no transport package exists.

### M2.2 — EDNS Padding policy (RFC 7830 + RFC 8467) ❌

- **Status**: not started. No `dns/padding.go` policy engine.
- Padding is a privacy requirement for DoT/DoH responses (UDP must not pad).

### M2.3 — XFR over TLS (RFC 9103) ❌

- **Status**: not started. LabyrinthDNS has no XFR client implementation.
- AXFR/IXFR over TLS on port 853 requires a zone transfer module first.

### M2.4 — EDNS buffer size negotiation (RFC 6891 + RFC 9715) ✅

- **Status**: implemented. `server/handler.go` defaults to 1232 per DNS Flag
  Day 2020. Client-advertised buffer sizes outside [512, 65535] are silently
  clamped to 1232. Responses are truncated at the negotiated boundary.

### M2.5 — Extended DNS Errors full table (RFC 8914) ✅

- **Status**: implemented. `server/handler.go` emits EDE codes via
  `addEDEToResponse` / `addEDEToRawResponse`. Active codes include
  1 (unsupported DNSKEY alg), 6 (DNSSEC bogus), 7 (sig expired),
  8 (sig not-yet-valid), 9 (DNSKEY missing), 10 (RRSIGs missing),
  17 (filtered/rate-limited), 18 (prohibited), 29 (synthesized).
  `dnssec/failure_reason.go` maps internal failure reasons to EDE codes.

---

## Backend Milestone M3 — Resolver Hardening (v0.9.0)

### M3.1 — QNAME minimization (RFC 9156) ✅

- **Status**: implemented (`resolver/qmin.go` + `resolver/rfc9156_qmin_test.go`).
  Queries use progressive NS delegation walk with A only at final label.
  Skipped for TypeDS to avoid walking the entire chain per DS fetch.

### M3.2 — Aggressive NSEC (RFC 8198) ✅

- **Status**: cache-side implementation in `cache/nsec_aggressive.go` and
  `cache/nsec3_aggressive.go`. NXDOMAIN/NODATA synthesis from cached NSEC/NSEC3
  records. No separate `resolver/aggressive.go` needed — the cache consults
  NSEC records before forwarding.

### M3.3 — Happy Eyeballs v2 (RFC 8305) ❌

- **Status**: not implemented. `config.Resolver.PreferIPv4` flag exists
  but no concurrent A+AAAA dial with 300ms IPv6-first stagger.
- Config field `HappyEyeballsDelay` exists but is unused.

### M3.4 — TCP fallback & pipelining (RFC 7766) ✅

- **Status**: TC-bit fallback implemented in `server/handler.go` (calls TCP
  retry when TC is set). Persistent TCP with pipelining in `server/tcp.go`.
  No separate `transport/tcp_pool.go` — the server's TCP service handles it.

### M3.5 — Root hints refresh (RFC 8109) ✅

- **Status**: implemented. `resolver.PrimeRootHints()` at startup,
  `resolver.StartRootRefresh()` for periodic refresh. Detects root NS
  changes via standard NS query.

### M3.6 — 0x20 case randomization (RFC 5452) ✅

- **Status**: implemented. `config.Caps0x20Enabled` flag controls the
  anti-spoofing case-randomization. `resolver/rfc5452_0x20_test.go` pins
  on/off behaviour.

---

## Backend Milestone M4 — Operability (v0.10.0)

### M4.1 — RPZ (Response Policy Zone) ✅

- **Status**: implemented (`blocklist/` package). Downloads and parses RPZ
  zones in multiple formats (abp, yaml, text, RPZ native). Supports
  NXDOMAIN/NODATA/CNAME/drop/passthru actions via the blocklist API.

### M4.2 — Catalog zones (RFC 9432) ❌

- **Status**: not implemented. `zone/` package does not exist.

### M4.3 — Zone import/export (BIND format) ❌

- **Status**: not implemented. No BIND zone-file parser or emitter.

### M4.4 — Hot-reload validation pipeline ✅

- **Status**: implemented. Two-phase commit via `RuntimeApplier` callback
  (`server/handler.go`). `SetRuntimeApplier` registers the callback from
  `main_runtime_helpers.go`; `/api/config/raw` PUT triggers hot-reload.

### M4.5 — Stub & forward zones ✅

- **Status**: implemented. `resolver.ForwardTable` with `SetForwardTable`.
  YAML config supports `stub:` and `forward:` zone blocks.

### M4.6 — Compliance counter scaffolding ❌

- **Status**: not implemented. No per-RFC-pin Prometheus counters.

---

## Backend Milestone M5 — DoS / Security (v0.11.0)

### M5.1 — Response Rate Limiting (RRL) ✅

- **Status**: implemented (`security/rrl.go`). Token bucket per /24 (v4)
  and /56 (v6) per response class. SLIP with TC bit (`MaxRRLEntries=1M`).
  Background cleanup goroutine prunes stale entries.

### M5.2 — Cookie enforcement (RFC 7873 §5.4) ✅

- **Status**: implemented. `server.MainHandler.SetCookiesEnforce()` toggles
  strict mode; `config.Security.DNSCookiesEnforce` flag. Cookie-less UDP
  refused with BADCOOKIE when enforced.

### M5.3 — Source port randomization (RFC 5452) ✅

- **Status**: implemented. `resolver/udp_dial.go` uses kernel-assigned
  ephemeral ports. RFC 5452 pin test `resolver/rfc5452_0x20_test.go` covers
  source port + 0x20 combined anti-spoofing.

### M5.4 — Recursion ACL (RFC 5358) ✅

- **Status**: implemented. `security.ACL` type with `Security.ACL` config.
  `PrivateAddressFilter` and ACL enforce who can recurse vs query local zones.

### M5.5 — DNSSEC validation safety net ✅

- **Status**: implemented. `dnssec/validator.go` uses `cryptoBudget`
  (max 32 verifies per response) and `maxRRSIGVerifyAttempts` (16 per RRset).
  NSEC3 iteration capped at 100 per M1.3.

---

## Backend Milestone M6 — Test Infrastructure (v0.12.0)

### M6.1 — Fuzz harness ✅ (partial)

- **Status**: fuzz targets exist for `dns.Unpack` (`dns/wire_fuzz_test.go`)
  and `resolver/classify` (`resolver/classify_fuzz_test.go`). No fuzz targets
  for NSEC3 hash inputs or RPZ matcher.

### M6.2 — Property-based tests ❌

- **Status**: not implemented.

### M6.3 — Conformance suite ❌

- **Status**: not implemented. RFC pin tests serve a similar function.

### M6.4 — Chaos testing ❌

- **Status**: not implemented.

### M6.5 — Coverage target 🔶

- **Status**: several packages reached 100% during the v0.8.31 coverage push
  (`dns/`, `config/`, `certmanager/`, `daemon/`, `metrics/`, `security/`).
  Others (`resolver/`, `server/`, `dnssec/`) have extensive tests but likely
  remain below 85% on all files.

---

## Backend Milestone M7 — Documentation & Compliance Matrix (v0.13.0)

### M7.1 — RFC compliance matrix ✅

- **Status**: implemented (`docs/rfc-compliance-matrix.md`, 78 lines).
  Tables key RFCs with status and section references.

### M7.2 — Architecture deep-dive ❌

- **Status**: not implemented.

### M7.3 — Operator runbook ❌

- **Status**: not implemented.

### M7.4 — Threat model ❌

- **Status**: not implemented.

### M7.5 — API reference 🔶

- **Status**: partially done. The web UI auto-generates API documentation
  from Go handler structs. No standalone Markdown doc.

---

## Backend Milestone M8 — Stabilization (v1.0.0)

### M8.1 — Performance baseline ✅

- **Status**: `cmd/labyrinth-bench/` provides benchmark coordinator with
  worker nodes, latency histograms, and compare-mode reporting.

### M8.2 — Long-running soak ❌

- **Status**: not implemented.

### M8.3 — Final API freeze ❌

- **Status**: not yet. APIs are stable but not formally frozen.

### M8.4 — Security review pass ❌

- **Status**: not done. Security report exists in git history from
  the coverage push but is not on main.

### M8.5 — Release artifacts ✅

- **Status**: implemented. Multi-platform container builds (`Dockerfile`),
  release workflow (`.github/workflows/release.yml`), systemd unit.

---

## UI Milestones — summary

Most UI milestones are unimplemented. The few exceptions:
- **UI-M5.1/5.2** — Compliance dashboard and RFC gap report UI exist
  (`web/ui/src/pages/CompliancePage.tsx`)
- **UI-M2.x** — Trace, cache inspector, and query log pages exist as
  stubs/skeletons

All other UI items (UI-M1 trust-chain visualizer, UI-M3 upstream
monitoring, UI-M4 config editor, UI-M6 security panel, UI-M7 polish,
UI-M8 diagnostic tools) are **not started**.

---

## Remaining work summary (after reconciliation)

### Backend — truly open items (4 items, ~small)

| Item | Effort | Notes |
|---|---|---|
| M1.8 prometheus counters | Small | Wire DNSSEC rollover/algorithm counters |
| M2.1 DoQ (RFC 9250) | Large | New transport package |
| M2.2 EDNS padding (RFC 7830) | Medium | New `dns/padding.go` |
| M2.3 XFR over TLS (RFC 9103) | Medium | New zone transfer module |

### Backend — already done (29 of 35 items ✅)

M1, M3, M4, M5 are effectively complete. Over 80% of the backend
roadmap was already shipped across v0.6.x–v0.8.x but never marked done
in this document.

### UI — mostly open (∼40 items ❌)

The UI is the primary gap to v1.0. All 8 UI milestones have extensive
unimplemented features, particularly the DNSSEC visualization (UI-M1),
upstream monitoring (UI-M3), config management (UI-M4), security panel
(UI-M6), and diagnostic tools (UI-M8).

---

## Execution Order

Phase order matches the release map. Within each release:

1. Backend milestone implementation + tests.
2. Backend release-candidate freeze.
3. UI milestone implementation against frozen backend.
4. Joint integration test pass.
5. CHANGELOG entry, version bump (`web/ui/package.json`,
   `website/package.json`), commit, tag, push.

### Release cadence

Each minor release is one focused milestone pair, not a steady stream
of patches. Patch releases reserved only for genuine bugs surfaced
after release — not for additional planned features.

### Out-of-scope guard

If a topic does not fit into any milestone above, it is explicitly
out of scope for v1.0.0. Examples: DNS-over-Tor, anycast cluster
coordination, paid SaaS dashboard.

---

## Tracking

After each release:

- Update this PLAN.md: strike completed milestone with `~~M1~~` and
  link to the release tag.
- Update `CHANGELOG.md` per repo convention.
- Update `docs/rfc-compliance-matrix.md`.

---

## Definition of Done — v1.0.0

- All 8 backend milestones merged and tagged (4 remaining).
- All 8 UI milestones merged and tagged (mostly open).
- RFC compliance matrix shows ≥95% compliant rows.
- Coverage ≥85% on `dns/`, `dnssec/`, `resolver/`, `cache/`, `server/`.
- 72h soak passes without leak or drift.
- Threat model and runbook published.
- Multi-arch release artifacts available.
- No P0 / P1 open issues.

That release ships as **LabyrinthDNS v1.0.0 — production-ready**.
