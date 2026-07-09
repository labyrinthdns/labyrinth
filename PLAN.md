# LabyrinthDNS — Roadmap to v1.0.0

This document captures the complete remaining work plan after audit
milestone Y93 (release v0.6.41). The audit phase Y34→Y93 produced 61
RFC compliance pins and 4 real bug fixes across 8 patch releases.

> **Current status note (2026-07-08):** this roadmap predates several
> v0.8.x hardening releases. Use
> [`docs/rfc-gap-analysis-2026-07.md`](docs/rfc-gap-analysis-2026-07.md)
> and [`docs/rfc-compliance-matrix.md`](docs/rfc-compliance-matrix.md)
> as the current RFC-gap sources of truth until this roadmap is fully
> reconciled.

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

### M1.1 — Algorithm rollover (RFC 4035 §4.6)

- During a key rollover, a zone publishes RRSIGs covering the same
  RRset under two different algorithms (the outgoing and the incoming).
- Current validator picks the first matching DNSKEY/RRSIG pair. If
  that pair fails for any reason (expired, missing key), validation
  bogus'es even though another valid pair exists.
- **Implementation**: extend `dnssec/validator.go` so RRSIG selection
  iterates *all* candidates; success on any one yields secure.
- **Tests**: pin a dual-algorithm zone (e.g. RSASHA256 + ECDSAP256SHA256)
  with one stale RRSIG and one fresh — must validate.

### M1.2 — CDS / CDNSKEY (RFC 7344 + RFC 8078)

- Child zone signals parent of intended DS update via CDS/CDNSKEY
  records at the zone apex.
- RFC 8078 §3 defines bootstrap rules (acceptance policy, multiple
  signers, deletion via 0-algorithm).
- **Implementation**: parser for CDS/CDNSKEY rtypes, validator that
  enforces signing by current DNSKEY, exposure via API for operators
  using LabyrinthDNS as authoritative-aware resolver.
- **Tests**: parse fixtures, accept/reject policy per §3.1–§3.3.

### M1.3 — NSEC3 iteration policy (RFC 9276)

- RFC 9276 §3.1 recommends 0 iterations; >100 is treated as insecure
  by major validators.
- **Implementation**: `dnssec/nsec3.go` adds `IterationPolicy` enum
  (Strict/Tolerant/Lax). Strict rejects >150 with EDE 27 "Unsupported
  NSEC3 Iterations Value".
- **Tests**: synthetic zone with iterations=200 → policy=Strict
  returns SERVFAIL+EDE; policy=Tolerant downgrades to insecure.

### M1.4 — RFC 5011 full lifecycle

- The REVOKE bit pin landed earlier covers only the bit semantics.
- Missing: add-pending state with 30-day hold-down timer, removal of
  trust anchors that disappear without REVOKE, automatic re-priming
  on root rollover.
- **Implementation**: `dnssec/trustanchor.go` state machine
  (Start → AddPending → Valid → Missing → Removed → Revoked) with
  persistence to disk.
- **Tests**: time-mocked state transitions covering all edges.

### M1.5 — Multi-signer (RFC 8901)

- A zone signed by two independent operators each maintaining their
  own ZSKs. Both DNSKEY sets must be in the apex DNSKEY RRset and the
  validator must accept RRSIGs from either signer.
- **Implementation**: validator already iterates DNSKEYs, but ensure
  the DS chain accepts a parent-provided DS for any one signer.
- **Tests**: dual-signer fixture.

### M1.6 — DS digest type policy (RFC 8624)

- SHA-1 DS should be ignored if a SHA-256 DS exists for the same key.
- **Implementation**: `dnssec/ds.go` digest selection prefers strongest.
- **Tests**: parent DS RRset with SHA-1 + SHA-256 → SHA-1 ignored.

### M1.7 — Negative trust anchor (RFC 7646)

- Operator can disable validation for a specific zone for a bounded
  time window (incident response).
- **Implementation**: `dnssec/nta.go` with config-driven list +
  expiry; validator short-circuits to insecure for matching qnames.
- **Tests**: NTA scoped to `example.test.` only — sibling zones still
  validate.

### M1.8 — Counter & EDE wiring

- All M1 features emit prometheus counters
  (`labyrinthdns_dnssec_rollover_dual_sig_validates_total`, etc.) and
  EDE codes where applicable.

**Estimated commits**: 25. **Test additions**: ~30 cases.

---

## Backend Milestone M2 — Transport Modernization (v0.8.0)

### M2.1 — DoQ (RFC 9250)

- DNS over QUIC. Reuse existing TLS cert infrastructure.
- **Implementation**: `transport/doq/` using `quic-go`. Wire to same
  query dispatcher used by DoT/DoH.
- **Tests**: integration test against a local QUIC client.

### M2.2 — EDNS Padding policy (RFC 7830 + RFC 8467)

- Block-padding strategy: pad client→server to 128 bytes, server→client
  to 468 bytes.
- **Implementation**: `dns/padding.go` policy engine, applied to
  DoT/DoH responses only (UDP must not pad).
- **Tests**: response size assertions per policy.

### M2.3 — XFR over TLS (RFC 9103)

- AXFR/IXFR encrypted on port 853.
- **Implementation**: zone transfer module already exists (if any) —
  audit and wrap TLS.
- **Tests**: AXFR round-trip over TLS.

### M2.4 — EDNS buffer size negotiation (RFC 6891 + RFC 9715)

- Default 1232 (DNS Flag Day 2020 + 2025 path-MTU recommendation).
- **Implementation**: respect client's advertised buffer; fall back
  to 1232 if unspecified or >4096.
- **Tests**: response truncation at correct boundary.

### M2.5 — Extended DNS Errors full table (RFC 8914)

- Audit which of codes 0–29 are currently emitted; backfill missing
  ones (5 stale answer, 9 DNSKEY missing, 18 prohibited, etc.).
- **Implementation**: `dns/ede.go` table-driven emission.
- **Tests**: each code path triggers correct EDE.

**Estimated commits**: 20.

---

## Backend Milestone M3 — Resolver Hardening (v0.9.0)

### M3.1 — QNAME minimization audit (RFC 9156)

- Verify current implementation: query for NS at progressively deeper
  labels, A only at the final label. Fallback on broken authoritatives.
- **Tests**: instrumented resolver run captures exact query sequence
  for `a.b.c.example.com` — assert NS-queries-then-A pattern.

### M3.2 — Aggressive NSEC in iterative path

- Auth-side aggressive use (Y82, Y84) is done. Resolver-side: when
  upstream returns NSEC for `b.example.`, future queries for
  `a.example.` (alphabetically before `b`) should synthesize NXDOMAIN
  locally without upstream call.
- **Implementation**: `resolver/aggressive.go` consults cache NSEC
  records before forwarding.
- **Tests**: second query hits synthesized response, upstream counter
  unchanged.

### M3.3 — Happy Eyeballs v2 (RFC 8305)

- For AAAA+A dual-stack upstream selection: prefer IPv6, fall back to
  IPv4 if AAAA times out within 300ms.
- **Implementation**: `resolver/dialer.go` concurrent dial with
  staggered start.

### M3.4 — TCP fallback & pipelining (RFC 7766)

- On TC bit set, retry over TCP. Persistent TCP connection per
  upstream with pipelining (RFC 7766 §6.2.1).
- **Implementation**: `transport/tcp_pool.go`.

### M3.5 — Root hints refresh / priming (RFC 8109)

- Send NS `.` query at startup; refresh weekly. Detect changes in
  root NS set and persist.
- **Implementation**: `resolver/priming.go` scheduler.

### M3.6 — 0x20 source case randomization

- Randomize case of qname in upstream query as cheap anti-spoofing.
- **Implementation**: `resolver/case_random.go` wrapping outbound
  qname; validate response case matches.

**Estimated commits**: 22.

---

## Backend Milestone M4 — Operability (v0.10.0)

### M4.1 — RPZ (Response Policy Zone)

- ISC/Knot-compatible blocklist DSL via zone records.
- **Implementation**: `policy/rpz.go` zone loader + matcher; supports
  NXDOMAIN, NODATA, CNAME redirect, drop, passthru.
- **Tests**: each action type with both qname and IP triggers.

### M4.2 — Catalog zones (RFC 9432)

- A zone whose contents enumerate other zones to serve.
- **Implementation**: `zone/catalog.go` watcher.

### M4.3 — Zone import/export (BIND format)

- BIND zone-file parser + emitter for operator interop.
- **Implementation**: `zone/bind_format.go`.

### M4.4 — Hot-reload validation pipeline

- Live config reload exists. Add: validate-before-apply, reject on
  syntax/semantic error, preserve old state.
- **Implementation**: `config/reload.go` two-phase commit.

### M4.5 — Stub & forward zones

- Per-zone forwarder routing.
- **Implementation**: `resolver/forwarder_map.go`.

### M4.6 — Compliance counter scaffolding

- Counters per RFC pin tag — `labyrinthdns_rfc4035_ttl_clamps_total`
  etc. — to surface in M5 dashboard.

**Estimated commits**: 25.

---

## Backend Milestone M5 — DoS / Security (v0.11.0)

### M5.1 — Response Rate Limiting (RRL)

- BIND/Knot-compatible RRL: token bucket per /24 (v4) and /56 (v6)
  per response class (NXDOMAIN, error, referral, identical-answer).
- **Implementation**: `security/rrl.go` with SLIP (RFC-style:
  every Nth blocked response gets TC bit so legitimate clients can
  retry over TCP).
- **Tests**: burst test verifies drops + SLIP TC responses.

### M5.2 — Cookie enforcement mode (RFC 7873 §5.4)

- Operator-selectable mode where cookie-less UDP queries are refused
  with BADCOOKIE.
- **Implementation**: config flag `cookies.enforce: true`.

### M5.3 — Source port randomization audit (RFC 5452)

- Confirm outbound UDP source ports are fully random across the
  ephemeral range, not skewed by OS defaults.
- **Tests**: 10k outbound queries, χ² test for uniformity.

### M5.4 — Refusal of recursion from non-allowed clients (RFC 5358)

- Audit ACL: who can recurse vs who can only query local zones.
- **Tests**: ACL matrix.

### M5.5 — DNSSEC validation safety net

- Cap CPU per validation; reject queries that would trigger
  pathological NSEC3 iteration (combined with M1.3 policy).

**Estimated commits**: 18.

---

## Backend Milestone M6 — Test Infrastructure (v0.12.0)

### M6.1 — Fuzz harness

- `go test -fuzz=Fuzz...` targets for: `dns.Unpack`, `ParseCookieOption`,
  RR rdata parsers, NSEC3 hash inputs, RPZ matcher.
- **Implementation**: `*_fuzz_test.go` files with seed corpora.

### M6.2 — Property-based tests

- Using `gopter` or `testing/quick`: RRSIG canonical form roundtrip,
  name compression decompression, EDNS option order independence.

### M6.3 — Conformance suite

- Docker-based: spin up Knot + BIND + Unbound + LabyrinthDNS, query
  same fixtures, diff responses. Differences logged for review.

### M6.4 — Chaos testing

- Network failure injection (`toxiproxy`): upstream timeout, partial
  response, truncated packets, RST.

### M6.5 — Coverage target

- Push core packages (`dns/`, `dnssec/`, `resolver/`, `cache/`,
  `server/`) to ≥85% line coverage. Document uncovered lines.

**Estimated commits**: 20.

---

## Backend Milestone M7 — Documentation & Compliance Matrix (v0.13.0)

### M7.1 — RFC compliance matrix

- Single Markdown table: RFC number, section, behavior, test file,
  release version, status (compliant/partial/N/A).
- **Implementation**: `docs/rfc-matrix.md` generated from test tags.

### M7.2 — Architecture deep-dive

- Resolver state machine diagram (mermaid), cache layer diagram,
  DNSSEC validation flow.

### M7.3 — Operator runbook

- "How to deploy to production" — TLS certs, monitoring, capacity
  planning, common errors and their fixes.

### M7.4 — Threat model

- STRIDE-style analysis of attack surfaces and defenses.

### M7.5 — API reference

- All HTTP endpoints + WebSocket messages, request/response schemas.

**Estimated commits**: 15.

---

## Backend Milestone M8 — Stabilization (v1.0.0)

### M8.1 — Performance baseline

- Benchmark suite: QPS at varying cache sizes, DNSSEC overhead %,
  memory footprint over 24h soak.

### M8.2 — Long-running soak

- 72h test with synthetic + replay traffic; assert no leaks, latency
  drift, or cache pathology.

### M8.3 — Final API freeze

- Mark all public APIs stable; deprecation policy documented.

### M8.4 — Security review pass

- External-style review checklist completion.

### M8.5 — Release artifacts

- Multi-arch container images, deb/rpm packages, Windows MSI,
  systemd unit, sample configs.

**Estimated commits**: 12.

---

## UI Milestone UI-M1 — DNSSEC Visualization (v0.7.0)

### UI-M1.1 — Trust-chain visualizer

- Input: qname. Output: visual chain root → TLD → zone with each
  link colored by DS/DNSKEY/RRSIG status (secure/insecure/bogus/
  indeterminate). Click a node → see records, key tags, algorithms,
  signature expiry.
- **Component**: `web/ui/src/components/dnssec/TrustChain.tsx`.

### UI-M1.2 — DNSKEY inspector

- Per-zone table: KSK/ZSK split, algorithm, key tag, flags
  (SEP, REVOKE), creation/expiry estimate, rollover state.

### UI-M1.3 — NSEC / NSEC3 aggressive synthesis panel

- Hit/miss counter, recent synthesized denials, range coverage map.
- Toggle to dump cache NSEC3 chain for a zone.

### UI-M1.4 — Validation timeline

- For a selected recent query, show per-step duration:
  DS-fetch / DNSKEY-fetch / RRSIG-verify / NSEC-denial / chain-build.

### UI-M1.5 — EDE viewer enhancements

- Existing diagnostic trace UI gets EDE code dropdown filter, code
  reference tooltip.

**Estimated commits**: 22.

---

## UI Milestone UI-M2 — Query Trace & Cache Inspector (v0.8.0)

### UI-M2.1 — Live query log

- Streaming table with filters (qname regex, qtype, client IP, status).
- Pause/resume, export to JSON/CSV.

### UI-M2.2 — Per-query timeline

- Click a log row → modal with timeline: cache lookup → upstream
  selection → wire dial → response parse → DNSSEC validate → reply.
- Each phase shows ms, upstream addr, response bytes.

### UI-M2.3 — Cache browser

- Paginated table of cache entries: owner, type, TTL remaining,
  source upstream, hit count.
- Search + filter; per-entry expand for raw RDATA.

### UI-M2.4 — Manual purge

- Single-entry purge, zone-prefix purge, full flush (with
  confirmation modal).

### UI-M2.5 — Cache heatmap

- 24h heatmap: hit rate, miss rate, eviction rate. Click a cell to
  drill in.

### UI-M2.6 — Stale-served counter widget

- Top stale-served qnames + ratio.

**Estimated commits**: 25.

---

## UI Milestone UI-M3 — Upstream Monitoring (v0.9.0)

### UI-M3.1 — Per-upstream health card grid

- Each upstream: latency p50/p95/p99, success %, timeout %, last
  failure time, transport (UDP/TCP/DoT/DoH/DoQ).

### UI-M3.2 — Circuit breaker state

- Closed / Half-Open / Open with reason and elapsed time in current
  state. Manual override (force-open / force-close).

### UI-M3.3 — Transport breakdown chart

- Stacked area: QPS per transport over time window.

### UI-M3.4 — Manual failover controls

- Toggle upstream active/disabled.

### UI-M3.5 — Upstream latency histogram

- Per-upstream histogram (powers of 2 buckets).

**Estimated commits**: 20.

---

## UI Milestone UI-M4 — Runtime Configuration (v0.10.0)

### UI-M4.1 — Config editor

- Monaco-based YAML editor with schema validation. Diff against
  current applied config. Apply button → backend two-phase commit.

### UI-M4.2 — Config history & rollback

- List of last N applied configs with timestamp + diff. One-click
  rollback.

### UI-M4.3 — Zone manager

- CRUD UI for forward, stub, local zones.

### UI-M4.4 — RPZ rule editor

- Visual rule builder: pattern, action, priority. Test-against-qname
  field.

### UI-M4.5 — Forwarder map

- Per-zone forwarder assignment UI.

**Estimated commits**: 27.

---

## UI Milestone UI-M5 — Compliance Dashboard (v0.11.0)

### UI-M5.1 — RFC compliance matrix view

- Rendered version of `docs/rfc-matrix.md` with column filters,
  search, per-row link to commit + test file.

### UI-M5.2 — Per-RFC counter widgets

- For each pinned RFC behavior: live counter from prometheus metric
  with sparkline.

### UI-M5.3 — Audit timeline

- Vertical timeline Y34 → latest with each pin/release marked,
  click-through to commit.

### UI-M5.4 — Compliance export

- Export current state as JSON/PDF for sharing with auditors.

**Estimated commits**: 18.

---

## UI Milestone UI-M6 — Security Panel (v0.12.0)

### UI-M6.1 — RRL dashboard

- Limited prefixes table, SLIP rate, TC-only response count, drop
  count. Live and per-window.

### UI-M6.2 — Cookie stats

- BADCOOKIE issued, validated, rebind blocked. Trend chart.

### UI-M6.3 — EDE breakdown

- Pie + table of EDE codes emitted, with code reference.

### UI-M6.4 — Anomaly detector

- Heuristic-flagged events: reflection attempt, ANY flood, NXDOMAIN
  flood. Each event shows offending source + window.

### UI-M6.5 — Source port randomization audit widget

- Histogram of recent outbound source ports; χ² uniformity badge.

**Estimated commits**: 18.

---

## UI Milestone UI-M7 — Operator UX Polish (v0.13.0)

### UI-M7.1 — Keyboard shortcuts

- `/` search, `g+c` cache, `g+u` upstreams, `?` help.

### UI-M7.2 — Universal export

- Every table gets a CSV/JSON download button.

### UI-M7.3 — Saved views

- Per-page filter+sort presets stored in localStorage.

### UI-M7.4 — Mobile responsive layout

- All pages collapse cleanly to ≥360px width.

### UI-M7.5 — Internationalization

- i18n framework + English + Turkish translations.

### UI-M7.6 — Theme polish

- Dark/light toggle audit; contrast pass; accessible color palette.

**Estimated commits**: 22.

---

## UI Milestone UI-M8 — Diagnostic Tools (v1.0.0)

### UI-M8.1 — Built-in dig

- Form: qname, qtype, mode (recursive/iterative/no-dnssec). Output:
  raw + parsed + DNSSEC chain link.

### UI-M8.2 — Reverse lookup

- IP input → PTR result + source zone identification.

### UI-M8.3 — Trace mode

- `dig +trace` equivalent: step-by-step resolution from root with
  each upstream visible.

### UI-M8.4 — Recent packets dump

- Per-qname last N raw packets (debug aid).

### UI-M8.5 — One-shot capture

- Time-bounded packet capture filtered by qname; download pcap.

**Estimated commits**: 20.

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
of patches. Patch releases (v0.7.1, etc.) reserved only for genuine
bugs surfaced after release — not for additional planned features.

### Out-of-scope guard

If a topic does not fit into any milestone above, it is explicitly
out of scope for v1.0.0. Examples: DNS-over-Tor, anycast cluster
coordination, paid SaaS dashboard. Track those in a separate
`POSTPONED.md` if proposed.

---

## Tracking

After each release:

- Update this PLAN.md: strike completed milestone with `~~M1~~` and
  link to the release tag.
- Update `CHANGELOG.md` per repo convention.
- Update `docs/rfc-matrix.md` (once it exists from M7.1).

---

## Definition of Done — v1.0.0

- All 8 backend milestones merged and tagged.
- All 8 UI milestones merged and tagged.
- RFC compliance matrix shows ≥95% compliant rows.
- Coverage ≥85% on `dns/`, `dnssec/`, `resolver/`, `cache/`, `server/`.
- 72h soak passes without leak or drift.
- Threat model and runbook published.
- Multi-arch release artifacts available.
- No P0 / P1 open issues.

That release ships as **LabyrinthDNS v1.0.0 — production-ready**.
