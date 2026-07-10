# LabyrinthDNS — RFC Gap Analysis Follow-up

_Date: 2026-07-08 · Scope: RFC/compliance docs, roadmap, changelog, and targeted implementation paths._

This follow-up reconciles the current codebase with:

- `docs/rfc-compliance-matrix.md`
- `docs/resolver-hardening-gap-analysis-2026-06.md`
- `PLAN.md`
- `CHANGELOG.md`
- RFC-pinned tests under `dns/`, `dnssec/`, `resolver/`, `server/`, `cache/`, `metrics/`, and `web/`

No source changes are implied by this document. It is an implementation-status and planning report.

---

## Executive summary

LabyrinthDNS has a broad RFC-pinned recursive resolver surface. The current compliance matrix lists 40+ implemented RFCs, and the repository contains 100+ `rfcNNNN_*_test.go` files.

Several gaps from the June resolver-hardening report are now closed in the codebase and changelog:

- Global per-request outbound-query budget
- Wall-clock per-request deadline
- Global per-response DNSSEC crypto budget
- NSEC3 records-per-proof cap
- SAD-DNS connected UDP + Linux `IP_PMTUDISC_OMIT`
- IPv4-mapped IPv6 private-address normalization

The remaining RFC-level gaps are concentrated in newer transport/provisioning features and hardening polish, not base DNS resolver correctness.

Highest-impact remaining items:

1. **RFC 8945 — TSIG**: not implemented.
2. **RFC 9250 — DNS over QUIC (DoQ)**: not implemented.
3. **RFC 9103 — XFR-over-TLS**: not implemented; zone-transfer infrastructure appears absent.
4. **RFC 9432 — Catalog Zones**: not implemented.
5. **RFC 8305 — Happy Eyeballs v2**: not implemented.
6. **NSEC3 per-query hash/salt budget**: partially addressed by iteration and records-per-proof caps, but not fully bounded by a hash-computation budget.
7. **Per-source TCP/DoT connection caps**: global caps exist, per-client caps appear absent.
8. **Targeted outstanding-fetch caps**: no BIND-style `fetches-per-zone` / `fetches-per-server` equivalent found.
9. **Docs/roadmap drift**: `PLAN.md` still lists many items as future even though several are now implemented.

---

## Closed items from the June hardening report

### Global per-request outbound-query budget

Older status: P0 gap.

Current evidence:

- `resolver/resolver.go` defines `MaxQueriesPerRequest`.
- `resolver/resolver.go` charges outbound queries against a shared request budget.
- `resolver/req_budget_test.go` pins query-cap behavior and budget sharing across sub-resolution.
- `config/config.go` documents `resolver.max_queries_per_request`.
- `CHANGELOG.md` states this shipped in `v0.8.29`.

Status: **implemented**.

### Wall-clock per-request deadline

Older status: P1 gap.

Current evidence:

- `resolver/resolver.go` defines `RequestTimeout`.
- `resolver/req_budget_test.go` pins deadline behavior.
- `config/config.go` documents `resolver.request_timeout`.
- `CHANGELOG.md` states this shipped in `v0.8.29`.

Status: **implemented**.

### Global per-response DNSSEC crypto budget

Older status: P0 gap.

Current evidence:

- `dnssec/validator.go` defines `maxCryptoVerifyPerResponse = 32`.
- `dnssec/validator.go` defines and threads `cryptoBudget`.
- `CHANGELOG.md` states this shipped in `v0.8.29`.

Status: **implemented**.

### NSEC3 records-per-proof cap

Older status: P1 gap.

Current evidence:

- `dnssec/nsec3.go` defines `MaxNSEC3RecordsPerProof = 16`.
- `dnssec/validator.go` rejects denial proofs above the cap.
- `CHANGELOG.md` states this shipped in `v0.8.29`.

Status: **partially implemented**. Records-per-proof is closed; per-query hash-computation and salt-length budgets remain open.

### SAD-DNS UDP hardening

Older status: P1 verification item.

Current evidence:

- `resolver/upstream.go` uses the `dialUDP` path for upstream UDP.
- `resolver/udp_dial.go` documents connected UDP socket behavior.
- `resolver/udp_pmtu_linux.go` sets Linux `IP_PMTUDISC_OMIT` / `IPV6_PMTUDISC_OMIT` best-effort.
- `CHANGELOG.md` states this shipped in `v0.8.30`.

Status: **implemented on Linux, best-effort elsewhere**.

### IPv4-mapped IPv6 private-address normalization

Older status: P2 verification item.

Current evidence:

- `security/private.go` unwraps IPv4-mapped IPv6 via `ip.To4()` before range checks.
- `security/private_test.go` includes mapped-IPv6 coverage.

Status: **implemented**.

---

## Confirmed missing RFCs

These are explicitly listed as missing or future work in `docs/rfc-compliance-matrix.md` and were not found in implementation paths during targeted scan.

| RFC | Capability | Status | Notes |
|-----|------------|--------|-------|
| RFC 8945 | DNS Transaction Signatures (TSIG) | Missing | Required for authenticated DNS transactions and common XFR interop. |
| RFC 9250 | DNS over QUIC (DoQ) | Missing | `quic-go` is present for HTTP/3/DoH3 usage, but no DoQ listener or `transport/doq/` package was found. |
| RFC 9103 | Zone Transfer over TLS | Missing | No zone-transfer infrastructure or `zone/` package was found. |
| RFC 9432 | Catalog Zones | Missing | No catalog-zone watcher/parser was found. |
| RFC 8305 | Happy Eyeballs v2 | Missing | No staggered dual-stack upstream dialer was found. |

### Recommended implementation order

1. **RFC 9250 DoQ** if transport parity is the near-term goal.
2. **RFC 8945 TSIG** if authenticated operator/zone-transfer interop is the near-term goal.
3. **RFC 9103 XFR-over-TLS** only after deciding whether zone-transfer support is in scope for a recursive-first resolver.
4. **RFC 9432 Catalog Zones** after a zone model exists.
5. **RFC 8305 Happy Eyeballs v2** as resolver performance/operability hardening.

---

## Known behavioural gaps (live-traffic verified 2026-07-10)

The items below were found by driving the running resolver against live
signed zones, not by static scan. The two critical ones are fixed; the third
is a documented minor limitation.

### FIXED — DNSSEC false-Bogus on signed multi-record RRsets (RFC 4034 §6.3)

`dnssec/verify.go` `canonicalRRSetWire` sorted RRs by the full canonical RR
wire form (which includes the per-record RDLENGTH) instead of by the RDATA
alone. Any RRset containing a shorter-but-lexicographically-greater RDATA was
reordered relative to the signer, so the signature hash mismatched and the
resolver returned SERVFAIL + EDE 6 for valid signed data. Reproduced live
against `cloudflare.com CAA` and `cloudflare.com MX`; positive answers,
denials, and genuinely-bogus zones were unaffected. Fixed to key the sort on
canonical RDATA only. Regression pin: `dnssec/rfc4034_rrset_order_test.go`.

### FIXED — malformed responses (two OPT RRs) on cold EDNS answers (RFC 6891 §6.1.1)

`server/handler.go` `buildResponse` appended the resolver's OPT to a section
(`ResolveResult.Additional`) that already carried the upstream authoritative
server's relayed OPT, so every cold positive answer to an EDNS client shipped
two OPT records — malformed per RFC 6891 §6.1.1, flagged by `dig`. The cache
path was clean. Fixed by stripping any inbound OPT before generating the
single server OPT. Regression pins: `server/rfc6891_single_opt_test.go`.

### FIXED — DS query for an unsigned (opt-out) delegation returned SERVFAIL

A direct client `DS` query for an unsigned zone delegated under an opt-out TLD
(`google.com`, `amazon.com`, … under `.com`) is answered with NODATA proven by
an opt-out NSEC3 span. The generic NSEC3 NODATA proof needs a *matching* NSEC3
with the DS bit clear, which an opt-out delegation lacks, so `validateDenial-
Response` fell through to Bogus → SERVFAIL where every mainstream validator
returns NOERROR/Insecure. Fixed with a `TypeDS`-scoped fallback to the already-
trusted `VerifyNSEC3DenialDSAbsent` proof, returning Insecure (opt-out) while a
non-opt-out cover still stays Bogus. Regression pin:
`dnssec/rfc5155_ds_optout_insecure_test.go`.

### FIXED — AD bit dropped from direct DNSKEY/DS answers after cache warmup

A direct client `DNSKEY` (signed zone) or `DS` (signed delegation) query
validated correctly on a cold cache but could return AD=0 once the shared cache
had been warmed by an internal chain-validation fetch: `resolver.QueryDNSSEC`
(validator-driven, validation skipped) stores the DNSKEY/DS RRset into the
shared cache without a "secure" status, and a later direct client query was
served that unvalidated entry. The handler now treats a `DNSKEY`/`DS` cache hit
with no DNSSEC status as a miss (validator-active only), forcing a full
validating resolution whose result is re-cached with its status. No change to
the chain-walk cache that `fetchDS` depends on. [server/handler.go].

## Partial / likely missing hardening work

### NSEC3 hash-computation and salt budgets

Current state:

- Per-record iteration cap exists: `MaxNSEC3Iterations = 100`.
- Records-per-proof cap exists: `MaxNSEC3RecordsPerProof = 16`.
- Aggressive NSEC3 cache synthesis exists.

Remaining gap:

- No clear per-query NSEC3 hash-computation budget was found.
- No clear max salt-length policy was found.
- Aggressive NSEC3 cache hashing should have a separate bounded-cost policy.

Recommendation:

- Add a query-scoped NSEC3 hash budget.
- Add an aggressive-cache NSEC3 hash budget.
- Add salt-length cap aligned with RFC 9276 guidance.
- Keep the current 100-iteration ceiling unless a separate compatibility decision lowers it.

### Per-source TCP/DoT connection cap

Current state:

- `server/tcp.go` has a global `maxConns` semaphore.
- `server/dot.go` has a global `maxConns` semaphore.

Remaining gap:

- No per-source-IP cap was found.

Recommendation:

- Add per-source counters for TCP and DoT.
- Default around 8–16 connections per source, configurable.
- Add tests for one-source saturation and multi-source fairness.

### Targeted outstanding-fetch caps

Current state:

- Per-request query budget exists.
- Rate limiting and response rate limiting exist.

Remaining gap:

- No BIND-style `fetches-per-zone` / `fetches-per-server` equivalent was found.

Recommendation:

- Track concurrent outbound fetches by zone and upstream server.
- Drop or defer excess fetches rather than amplifying SERVFAIL storms.
- Expose metrics for operators.

### Per-delegation NS-name cap

Current state:

- Request budget mitigates runaway delegation behavior.

Remaining gap:

- No explicit `maxNSNamesPerDelegation` cap was found.

Recommendation:

- Add an explicit cap around 13–16 NS names per delegation.
- Emit a metric or debug log when the cap truncates a candidate set.

---

## Documentation and planning drift

`PLAN.md` is no longer fully aligned with the implementation state. Several items listed as future work appear implemented and released in the v0.8.x hardening series.

Examples:

- DNSSEC rollover and multi-signer behavior have RFC-pinned tests.
- NTA support and cleanup exist.
- Global work-budget hardening landed in `v0.8.29` / `v0.8.30`.
- Compliance UI/data exists under `web/ui/src/pages/CompliancePage.tsx` and `web/ui/src/data/rfcCompliance.ts`.

Recommendation:

1. Treat `docs/rfc-compliance-matrix.md` plus the changelog as the current source of truth.
2. Update `PLAN.md` to strike or annotate completed items.
3. Reconcile RFC claims in `README.md`, `PLAN.md`, and the compliance matrix.
4. Add matrix rows for RFCs claimed elsewhere but absent from the matrix, such as RFC 8078, RFC 9715, RFC 5358, RFC 8375, and RFC 8659 where applicable.

---

## v1.0 readiness gaps

`PLAN.md` defines v1.0 completion criteria beyond RFC feature coverage. These remain unverified by this scan:

- All backend/UI milestones merged and tagged.
- RFC compliance matrix shows at least 95% compliant rows.
- Coverage at or above 85% on `dns/`, `dnssec/`, `resolver/`, `cache/`, and `server/`.
- 72-hour soak passes without leak or drift.
- Threat model published.
- Operator runbook published.
- Multi-arch release artifacts available.
- No P0/P1 open issues.

Recommendation:

- Run package coverage and record current baselines.
- Add or update threat model and operator runbook.
- Add a release-readiness checklist that links to evidence for each criterion.

---

## Prioritized next steps

### P0 — make planning accurate

1. Update `PLAN.md` to mark completed v0.8.x hardening and RFC items.
2. Reconcile `README.md` RFC claims with `docs/rfc-compliance-matrix.md`.
3. Add matrix rows for every RFC claim with status and test evidence.

### P1 — close missing RFC functionality

1. Implement RFC 9250 DoQ or explicitly defer it past v1.0.
2. Implement RFC 8945 TSIG or explicitly scope it to future zone-transfer work.
3. Decide whether RFC 9103 XFR-over-TLS and RFC 9432 Catalog Zones are in scope for a recursive-first resolver.
4. Implement RFC 8305 Happy Eyeballs v2 for dual-stack upstream selection.

### P2 — hardening polish

1. Add NSEC3 hash/salt budgets.
2. Add per-source TCP/DoT connection caps.
3. Add fetches-per-zone/server outstanding caps.
4. Add explicit NS names per delegation cap.

### P3 — release readiness

1. Measure package coverage against the v1.0 targets.
2. Run or define the 72-hour soak plan.
3. Publish threat model and operator runbook.
4. Validate multi-arch release artifacts.
