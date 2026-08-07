# LabyrinthDNS — Roadmap to v1.0.0

This document captures the complete remaining work plan after audit
milestone Y93 (release v0.6.41). The audit phase Y34→Y93 produced 61
RFC compliance pins and 4 real bug fixes across 8 patch releases.

> **Reconciliation note (2026-07-13):** this roadmap has been fully
> reconciled against the v0.8.31+ codebase and the deficiency remediation
> pass that produced `docs/architecture-deep-dive.md` (M7.2),
> `docs/operator-runbook.md` (M7.3), and `docs/threat-model.md` (M7.4).
> The following items were previously marked ❌ but are actually shipped:
> - **M2.2 — EDNS padding (RFC 7830 + RFC 8467)**: `PadRawResponse`,
>   `HasPaddingOption`, `BuildPaddingOption` in `dns/edns.go`;
>   `applyTCPTransportPolicies` in `server/tcp_policies.go`; RFC-pinned
>   tests in `dns/rfc7830_padding_test.go` and
>   `server/rfc8467_padding_policy_test.go`.
> - **M3.3 — Happy Eyeballs v2 (RFC 8305)**: `resolveNSHappyEyeballs`
>   in `resolver/resolver.go` with 300 ms IPv6-first stagger.
> - **M7.2 — Architecture deep-dive**: `docs/architecture-deep-dive.md`
>   (487 lines).
> - **M7.3 — Operator runbook**: `docs/operator-runbook.md` (729 lines).

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

### M1.8 — Counter & EDE wiring ✅

- **Status**: DNSSEC verdict counters (Secure/Insecure/Bogus) and
  algorithm-rollover counter (`labyrinth_dnssec_rollover_validates_total`)
  are exported via `/metrics`. EDE codes 1, 2, 6, 7, 8, 9, 10 mapped
  in `dnssec/failure_reason.go` and emitted via server's EDE plumbing
  with a per-code breakdown (`labyrinth_ede_emissions_total{code="..."}`)
  at the `/metrics` endpoint.

---

## Backend Milestone M2 — Transport Modernization (v0.8.0)

### M2.1 — DoQ (RFC 9250) ✅

- **Status**: implemented (`server/doq.go`, 214 lines). Uses quic-go
  (v0.60.0, already a dependency for DoH3). Listens on port 853 with
  ALPN token `"doq"` per RFC 9250 §4.2. DNS messages are length-
  prefixed (RFC 1035 §4.2.2 wire format), one per stream. Concurrent
  stream handling per §4.3. Shares TLS certificates with DoT via
  existing `tls_cert_file` / `tls_key_file` config, including auto-TLS
  support. Config: `server.doq_enabled` (bool, default false) and
  `server.doq_listen_addr` (string, default `:853`).

### M2.2 — EDNS Padding policy (RFC 7830 + RFC 8467) ✅

- **Status**: implemented.
- `dns/edns.go` provides `PadRawResponse`, `HasPaddingOption`,
  `BuildPaddingOption`. `server/tcp_policies.go` applies padding
  on DoT/DoH streams via `applyTCPTransportPolicies`. The RFC 8467
  §6 plaintext-prohibition hard rule is enforced — padding is NEVER
  applied on unencrypted TCP/UDP even when the client signals it.

### M2.3 — XFR over TLS (RFC 9103) ✅

- **Status**: implemented (`xfr/client.go`, 200 lines + 6 tests).
  AXFR client supporting TLS (RFC 9103) and plain TCP (RFC 5936)
  transport. Connects to a primary server, sends AXFR query (type 252),
  reads the response stream (opening SOA → records → closing SOA),
  and returns all zone records. TLS transport uses configurable
  `InsecureSkipVerify` for testing. Config expects `primary_addr`
  and `zone` to be specified per transfer. IXFR (incremental)
  is not yet implemented.

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

### M3.3 — Happy Eyeballs v2 (RFC 8305) ✅

- **Status**: implemented. `resolver/resolver.go` `resolveNSHappyEyeballs`
  fires concurrent A and AAAA queries with a 300 ms IPv6-first stagger
  (RFC 8305 §4). First-success short-circuit; both results are error-
  checked so a single-family failure does not delay resolution of the
  other family. Default 300 ms stagger is hardcoded per RFC guidance;
  `TestResolve_HappyEyeballs` pins the concurrency and stagger timing.

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

### M4.2 — Catalog zones (RFC 9432) ✅

- **Status**: implemented. Catalog manager in `secondary/catalog.go`; member
  zones are auto-provisioned as secondaries via `main_zones.go` →
  `secondary.NewCatalogZoneManager`.

### M4.3 — Zone import/export (BIND format) ❌

- **Status**: not implemented. No BIND zone-file parser or emitter.

### M4.4 — Hot-reload validation pipeline ✅

- **Status**: implemented. Two-phase commit via `RuntimeApplier` callback
  (`server/handler.go`). `SetRuntimeApplier` registers the callback from
  `main_runtime_helpers.go`; `/api/config/raw` PUT triggers hot-reload.

### M4.5 — Stub & forward zones ✅

- **Status**: implemented. `resolver.ForwardTable` with `SetForwardTable`.
  YAML config supports `stub:` and `forward:` zone blocks; forward zones
  additionally support DoT (RFC 7858) with RFC 8310 Strict-Privacy auth via
  `tls_auth_name` / `tls_pins` (`config/config.go`).

### M4.6 — Compliance counter scaffolding ✅

- **Status**: implemented for the RFC 8914 (EDE) family only. `metrics.IncEDE`
  increments a per-info-code atomic counter; `metrics/http.go` emits
  `labyrinth_ede_emissions_total{code="N"}` Prometheus series. Verified by
  `metrics/rfc8914_ede_counters_test.go`. Broader per-RFC-pin counters
  (one per other RFC the project claims) are **not** in scope here — those
  would need a separate decision about the canonical counter naming and
  where the increments live.

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

### M7.2 — Architecture deep-dive ✅

- **Status**: implemented (`docs/architecture-deep-dive.md`, 487 lines).
  Covers component architecture, goroutine model, query lifecycle,
  DNSSEC validation pipeline, caching layer, config hot-reload,
  startup sequence, and key design decisions.

### M7.3 — Operator runbook ✅

- **Status**: implemented (`docs/operator-runbook.md`, 729 lines).
  Covers installation, configuration reference, monitoring (Prometheus,
  Zabbix, health checks), signals, performance tuning, troubleshooting
  (8 symptom→diagnosis tables), upgrade procedures, backup/recovery,
  and security hardening checklist.

### M7.4 — Threat model ✅

- **Status**: implemented (`docs/threat-model.md`, 244 lines).
  STRIDE-based analysis covering 7 asset types, 4 trust boundaries,
  6 threat agent profiles, 20 threat scenarios mapped to controls,
  attack surface inventory, 31-control security controls summary,
  7 residual risks with mitigations, and incident response procedures.

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

### Backend — M1–M8 complete (M4.3 ❌)

M1–M2, M3–M6 (except M6.2/6.3/6.4), M7, M8.1 / M8.5 are shipped. M4.3
(BIND zone import/export) is the only remaining backend roadmap item
that is genuinely not implemented. M4.2 / M4.6 were previously marked
❌ in this file but the code is shipped; see the M4 section for the
truthful status notes.

### Uncommitted work-in-progress drop (working tree)

The working tree on `main` carries a large feature drop that is
**implemented and tested** but **not yet landed**: it predates the
milestone tags and is not reflected in M1–M8 above. The whole drop
passes `go test -count=1 ./...` and the RFC-named tests in
particular; what it lacks is a milestone grouping and a CHANGELOG entry.

Items in the drop (file pointers, not new code):

- **RFC 9432 — Catalog zones** (`secondary/catalog.go`,
  `secondary/manager.go`, `secondary/rfc9432_catalog_test.go`):
  catalog transfer + member auto-provisioning with transport
  inheritance. Underpins M4.2.
- **RFC 8945 — TSIG** (`dns/tsig.go`, `xfr/tsig_ixfr_test.go`,
  `dns/rfc8945_tsig_test.go`): HMAC-SHA256/384 with HMAC-MD5
  deliberately not offered, signed AXFR/IXFR, MAC binding, last-record
  rule. Underpins M2.3.
- **RFC 7858 / RFC 8310 — DoT upstream + Strict-Privacy auth**
  (`resolver/dot_upstream.go`, `config/config.go`,
  `resolver/rfc7858_upstream_dot_test.go`,
  `config/rfc8310_forward_tls_test.go`): forward-zone DoT with
  SPKI-pin or auth-name authentication; pins are deliberately
  required to disable the Opportunistic profile.
- **RFC 9462 / RFC 9461 / RFC 9460 — DDR + SVCB**
  (`dns/ddr.go`, `dns/svcb.go`, `server/rfc9462_ddr_handler_test.go`,
  `dns/rfc9462_ddr_test.go`): Discovery of Designated Resolvers,
  SVCB/HTTPS parameter ordering, ALPN, DoH path templates.
- **RFC 5001 — NSID** (`server/rfc5001_nsid_test.go`): opt-in
  identifier echo, opt-out by default to avoid information disclosure.
- **RFC 9567 — DNS Error Reporting** (`dns/errorreport.go`,
  `resolver/errorreport.go`, `dns/rfc9567_error_report_test.go`,
  `resolver/rfc9567_error_report_test.go`): opt-in, with loop guard,
  dedup window, and refusal to use an `er-*` agent domain.
- **RFC 9606 — RESINFO** (`dns/types.go`): unconditional-resolver
  info for own apex; served only when SVCB/HTTPS advertises it.
- **RFC 6303 — Private reverse (RFC 1918 / ULA) short-circuit**
  (`server/rfc6303_*_test.go`): NXDOMAIN/NODATA for private reverse
  zones instead of leaking to the public DNS.
- **RFC 7766 — TCP connection reuse** (`resolver/tcppool.go`,
  `resolver/rfc7766_tcp_reuse_test.go`): per-host pool with TXID
  guarding, sweep reaper, fallback to per-query dial.
- **RFC 9077 — NSEC/NSEC3 TTL clamping** (`resolver/rfc9077_nsec_ttl_test.go`):
  ceiling the aggressive-synthesis TTL so a hostile zone cannot pin
  cache beyond the SOA minimum.
- **RFC 5891 — IDNA** (`dns/idna.go`, `dns/rfc5891_idna_test.go`):
  label-level IDNA2008 processing for DNS names.
- **RFC 3597 — Generic type registry** (`dns/types.go`,
  `dns/rfc3597_type_registry_test.go`): `TYPE<n>` mnemonic + wire
  round-trip.
- **`labyrinth_ede_emissions_total{code}` Prometheus counter**
  (`metrics/metrics.go`, `metrics/http.go`,
  `metrics/rfc8914_ede_counters_test.go`): per-RFC-8914-code series.
  See the M4.6 status note for why this is the only RFC-pin counter.
- **Doc-only updates**: `docs/rfc-compliance-matrix.md`,
  `docs/rfc-gap-analysis-2026-07.md`, `docs/threat-model.md`.

These items still need: a CHANGELOG entry, decision on which
milestone label they belong to (they cut across M2/M3/M4/M5), and
a commit/PR.

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
