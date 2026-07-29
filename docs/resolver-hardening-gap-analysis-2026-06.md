# LabyrinthDNS — Resolver Hardening & RFC-Compliance Gap Analysis

_Date: 2026-06-26 · Scope: recursive-resolver security + RFC interop, cross-referenced against Unbound, BIND 9, Knot Resolver, PowerDNS Recursor._

This is a **gap analysis**, not a status report: it lists where competitors fixed a class of
attack/edge-case and where LabyrinthDNS is currently behind, with code evidence and concrete
limits to adopt. Items already handled are summarised at the end so we don't redo them.

**Posture up front:** LabyrinthDNS already has an unusually complete RFC surface — 150+
RFC-pinned tests, KeyTrap *per-RRset* cap, NSEC3 iteration cap, compact-denial/black-lies
handling, aggressive NSEC (RFC 8198), DNS cookies, 0x20, EDNS-1232, serve-stale, RFC 9520
failure caching, and an extensive config lower-bound-clamp family. The gaps below are mostly
**global budgets** that bound work *across* a whole response/request, which is exactly the
class of fix the 2020 (NXNS) and 2024 (KeyTrap) advisories forced every competitor to add.

---

## Priority backlog

| # | Gap | Sev | Evidence | Competitor fix (numbers) |
|---|-----|-----|----------|--------------------------|
| 1 | DNSSEC crypto budget is **per-RRset only**, not per-response | **P0** | `dnssec/validator.go:31` (`maxRRSIGVerifyAttempts=16`, scoped per-RRset, line 20 comment) | PowerDNS `max-signature-validations-per-query=30`; Unbound 16 *global* suspensions; BIND per-answer work budget + thread offload |
| 2 | **No global per-request outbound-query budget** (NXNS / water-torture / loop backstop) | **P0** | no counter found; only `MaxDepth` (depth, cap 1024) | Unbound `max-sent-count=32` / `MAX_GLOBAL_QUOTA=200`; BIND `max-recursion-queries=32`; PowerDNS `max-qperq=50` |
| 3 | NSEC3: no per-query hash budget, no records-per-proof cap, no salt-length cap; iter default 100 | **P1** | `dnssec/nsec3.go:26` (`MaxNSEC3Iterations=100`, per-record only) | Knot iter **50**, refuse >8 NSEC3; PowerDNS `nsec3-max-iterations=50`, `max-nsec3s-per-record=10`, `max-nsec3-hash-computations-per-query=600` |
| 4 | No **wall-clock per-request deadline** backstop | **P1** | per-upstream timeout exists; no whole-request budget | Knot `KR_RESOLVE_TIME_LIMIT=10000ms`; PowerDNS `max-total-msec=7000` |
| 5 | SAD-DNS: confirm **connected UDP sockets + ignore ICMP PMTU** on upstream | **P1** | needs verification in `resolver/upstream.go` | Unbound disabled IPv6 PMTU for UDP (≥1.13.2); PowerDNS `IP_PMTUDISC_OMIT` |
| 6 | Per-delegation **NS-name resolution cap** (NXNS MaxFetch) | **P2** | `resolver/resolver.go:1045` resolves NS sequentially + short-circuits (good), but no explicit count cap | PowerDNS `max-ns-per-resolve=13`; BIND 4 NS-addr fetches/domain; Unbound `MAX_TARGET_COUNT=64`/`MAX_DP_TARGET_COUNT=16` |
| 7 | Per-source-IP **TCP/DoT connection cap** (slowloris) | **P2** | global TCP conn cap exists; no per-source cap | none of the big-3 expose it either — a differentiator to add; PowerDNS `max-tcp-per-client` |
| 8 | Rebinding filter: verify **IPv4-mapped-IPv6 normalisation** + full-chain CNAME eval | **P2** | `security/private_*.go` (filter exists, default off) | Unbound ships `::ffff:0:0/96` in `private-address`; BIND splits `deny-answer-aliases` for chains |
| 9 | DNS-over-QUIC (RFC 9250) absent | **P2** | no DoQ listener | Knot/Unbound ship DoQ; BIND experimental |
| 10 | `fetches-per-zone` / `fetches-per-server` style targeted PRSD caps | **P2** | RRL + rate-limit exist (response-side); no per-zone outstanding-fetch cap | BIND `fetches-per-zone`/`fetches-per-server`; Unbound `ratelimit`/`ip-ratelimit` |

---

## P0 — fix before the next security release

### 1. DNSSEC verification budget must be **per-response**, not per-RRset (KeyTrap completeness)

**What we have.** [dnssec/validator.go:31](dnssec/validator.go#L31) caps expensive signature checks at
`maxRRSIGVerifyAttempts = 16`, but the counter (`verifyAttempts`, validator.go:489-641) is **reset for
each RRset** — the doc comment itself says "for a single RRset" (line 20).

**Why it's a gap.** The KeyTrap disclosure (CVE-2023-50387, ATHENE 2024) showed that a **per-RRset cap
leaks**: one malicious response can carry many RRsets (DNSKEY, DS, several NSEC3, the answer), each
granted its own 16-verify budget, so the attacker multiplies the global crypto cost by the number of
RRsets. Every competitor's fix is a **global, per-response/per-query** counter:
- PowerDNS Recursor: `max-signature-validations-per-query=30` (+ `max-dnskeys=2`, `max-ds-per-zone=8`).
- Unbound 1.19.1: ≤4 key-tag collisions, ≤8 validations/RRset, **≤16 total suspensions per query** (global).
- BIND 9.18.24: per-answer work budget **+ validation offloaded to threads** (≤½ CPU even past limits).

**Recommendation.** Thread a single `cryptoBudget` counter through `ValidateResponse*` for the whole
response (not reset per RRset); hard-cap total asymmetric verifications at **~16–32**; keep the
per-RRset 16 as a sub-limit. Add `maxDNSKEYsPerRRSIG ≈ 4` (key-tag collision cap) and `maxDSPerZone ≈ 8`.
On budget exhaustion return SERVFAIL + EDE. (LabyrinthDNS already runs each query in its own goroutine,
so the BIND-style "offload off the I/O loop" property is partly there — but a global budget is still
needed because N concurrent malicious queries each cost the per-query budget.)

**Edge case:** legitimate multi-algorithm rollover has several DNSKEYs/RRSIGs — keep the global cap ≥16.

### 2. Add a **global per-request outbound-query budget** (NXNS + water-torture + loop backstop)

**What we have.** `MaxDepth` (default 30, clamp 1024) bounds recursion *depth*; `MaxCNAMEDepth` bounds
chain length; NS targets are resolved **sequentially** with first-success short-circuit
([resolver/resolver.go:1045](resolver/resolver.go#L1045)) — which already keeps NXNS amplification far
below the parallel-fan-out resolvers (CZ.NIC measured sequential ≈48× PAF vs BIND-parallel ≈1000×).

**Why it's still a gap.** There is **no cap on total outbound queries per client request**. A crafted
nested-delegation tree (NXNS) or a deep glueless chain can still issue an unbounded number of
sub-queries within the depth limit. This is the single universal backstop every competitor added:
Unbound `max-sent-count=32` + `MAX_GLOBAL_QUOTA=200`; BIND `max-recursion-queries=32` (lowered from 100
after CVE-2023-2911); PowerDNS `max-qperq=50` + `max-ns-address-qperq=10`.

**Recommendation.** Thread a per-request `queryBudget` (atomic counter on the resolution context) across
the whole iterative resolution including all CNAME hops and NS-address sub-resolutions; cap at **~50–100**;
return SERVFAIL + EDE 22 on exhaustion. Pair with item 4 (wall-clock deadline) — the strongest designs
(Knot, PowerDNS) have **both** a count budget and a time budget.

---

## P1 — next hardening pass

### 3. NSEC3 work caps beyond per-record iterations

[dnssec/nsec3.go:26](dnssec/nsec3.go#L26) caps **per-record** iterations at `MaxNSEC3Iterations=100` and
errors above it. Missing, relative to Knot/PowerDNS:
- **Per-query SHA-1 hash budget** (PowerDNS `max-nsec3-hash-computations-per-query=600`) — a random-subdomain
  flood with iter=100 still costs 100 hashes × many names; bound the total per query.
- **NSEC3 records-per-proof cap** (Knot refuses >8; PowerDNS `max-nsec3s-per-record=10`).
- **Salt-length cap** (RFC 9276 wants 0; reject over-long salts).
- Consider lowering the iteration default **100 → 50** (Knot/PowerDNS default; RFC 9276 keeps ≤100
  interoperable as "treat-as-insecure"). Note the aggressive-NSEC cache path (RFC 8198) also hashes —
  bound it separately (PowerDNS `aggressive-cache-max-nsec3-hash-cost=150`).

### 4. Wall-clock per-request deadline

Per-upstream timeouts (default 2s, clamp 60s) bound a single hop, not the whole request. Add a
context deadline for the entire client query (Knot 10s, PowerDNS 7s) so a pathological
delegation/CNAME tree cannot hold a worker for minutes. Also the DNSBomb (CVE-2024-33655) finding:
a *long* outbound timeout is itself an amplifier — keep the per-hop timeout tight and add the
whole-request cap.

### 5. Verify SAD-DNS UDP hardening

Confirm `resolver/upstream.go` uses **connected UDP sockets** and **ignores ICMP-driven PMTU updates**
for upstream UDP (SAD DNS / CVE-2020-25705 + CVE-2021-20322 use the global ICMP rate limit / PMTU
exception cache as a side channel to infer the source port). In Go: `net.DialUDP` (connected) + on
Linux set `IP_PMTUDISC_OMIT`/`IPV6_PMTUDISC_OMIT` via `syscall`. 0x20 + cookies already raise the bar;
this closes the port-inference channel. **Action: verify; add if absent.**

---

## P2 — opportunistic / differentiators

- **6. Per-delegation NS-name cap** — sequential resolution already mitigates NXNS; add an explicit
  `maxNSNamesPerDelegation ≈ 13` so an all-bogus delegation can't walk a long list.
- **7. Per-source-IP TCP/DoT connection cap** — none of Unbound/BIND/Knot expose this; adding it
  (e.g. 8–16 conns/IP) is a genuine slowloris differentiator on top of the existing global cap.
- **8. Rebinding filter** — verify the private-address filter normalises **IPv4-mapped IPv6**
  (`::ffff:10.0.0.1`) before range-checking and evaluates the **final** address of a CNAME chain, not
  just the apex. Also consider a query-side `dont-query` guard (don't send recursion to RFC1918
  nameservers) distinct from the answer-side filter.
- **9. DoQ (RFC 9250)** — feature/privacy parity with Knot/Unbound.
- **10. Targeted PRSD caps** — `fetches-per-zone`/`-server`-style outstanding-fetch caps that *drop*
  (not SERVFAIL, to avoid self-amplification) complement the response-side RRL.

---

## Already strong (do NOT redo)

- **DNSSEC validation**: full RFC 4034/4035/6840 surface, DS digest-0 reject, strongest-DS selection,
  algorithm rollover, clock skew, signer bailiwick, wildcard proofs, RFC 6605 algo/hash pairing,
  RFC 8624 MUST-NOT algos, RFC 5011 lifecycle + revoke, RFC 7646 NTA, **compact denial / black lies**
  (`dnssec/compact_denial_test.go`), KeyTrap *per-RRset* cap, NSEC3 iter cap, trust-chain depth cap.
- **Aggressive NSEC/NSEC3** (RFC 8198) incl. opt-out exclusion + delegation rejection.
- **Caching**: RFC 2308 negative TTL (min(SOA.MIN, SOA TTL)), RFC 8767 serve-stale, RFC 9520 failure
  caching (1s floor / 30s cap, SERVFAIL-only gate, EDE 13), ECS-scoped keys.
- **Anti-spoofing**: 0x20 (default on), TXID + source-port entropy, DNS cookies (RFC 7873/9018) with
  rotation grace + IP binding + BADCOOKIE retry, EDNS-1232 (Flag Day 2020).
- **Resolution correctness**: QNAME minimisation (RFC 9156), DNAME bailiwick + synthesis, RFC 2181
  single-CNAME / NS-not-aliased, lame-delegation tracking, NS-CNAME-redirect refusal, root priming
  (RFC 8109), special-use names (RFC 6761/7686/8375), RFC 6303 locally-served reverse.
- **Resource clamps**: the v0.8.x lower-bound-clamp family (every black-holing config field floored),
  LRU caps on every unbounded map (infra, RRL, rate-limiter, DNSKEY, NTA, query-log, lame-zones),
  HTTP slowloris guards (ReadHeaderTimeout, MaxHeaderBytes), TCP idle/read timeouts + pipeline cap.
- **Transport**: RFC 7766 TCP (incl. the v0.8.28 stream-no-truncate fix), keepalive (7828), padding
  (7830/8467, encrypted-only), EDE (8914) broad code coverage, minimal-ANY (8482).

---

## Sources (research, 2026-06)

KeyTrap/NSEC3: ATHENE paper (arxiv 2406.03133), NLnet Labs Unbound 1.19.1, ISC CVE-2023-50387/50868,
Knot Resolver 5.7.1, PowerDNS 4.8.6/4.9.3/5.0.2, RFC 9276, RFC 8198. ·
NXNS/water-torture/poisoning: Afek et al. USENIX'20 (NXNSAttack), CVE-2020-8616/12662/12667/10995,
SAD DNS (saddns.net, CVE-2020-25705 / CVE-2021-20322), DNS Flag Day 2020 (1232), RFC 8900/9715,
DNSBomb CVE-2024-33655. ·
RFC interop: RFC 9156/8020/2308/9520/8767/6891/7873/7766/7828/7830/8467/8914/5011/8109/6303/7793/
6761/7686/8375/4035/6840/6672/2181/8198, Cloudflare black-lies / RFC 9824, vendor docs for
Unbound/BIND/Knot/PowerDNS defaults.
