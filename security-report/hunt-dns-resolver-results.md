# Hunt: DNS Resolver Security

## Summary
14 findings: 1 critical, 4 high, 6 medium, 2 low, 1 info

Scope: `dns/`, `resolver/`, `cache/`, `security/`, `dnssec/`, `server/`, `main.go`,
and `web/api_doh.go`. Methodology: traced taint from network listeners
(`server/udp.go`, `server/tcp.go`, `web/api_doh.go`) through `dns.Unpack` into
the resolver and cache, validated each candidate by re-reading the implicated
control flow.

Key strengths confirmed (no findings filed):
- Transaction IDs are sourced from `crypto/rand` (`resolver/upstream.go:262`),
  questions are echoed and 0x20-checked on iterative responses
  (`resolver/upstream.go:118-126`), bailiwick filter runs on every iterative
  response (`resolver/resolver.go:317,339`), name decoder caps label/name length
  and rejects forward pointers (`dns/name.go:51-67`), source-port randomization
  is delegated to the kernel via `net.DialTimeout("udp",...)`, DoH POST has a
  64KiB body limit (`web/api_doh.go:93`), RFC 8482 minimal-ANY is enforced
  (`server/handler.go:361`), private-IP filter is comprehensive
  (`security/private.go:12-44`), NSEC3 iterations are capped at 100
  (`dnssec/nsec3.go:26`), AllowSHA1 default is `false`
  (`config/defaults.go:29`), and downstream UDP-truncation honors a 512-byte
  floor (`server/handler.go:717-721`).

## Findings

### [CRITICAL] DNSSEC Querier sends DNSKEY/DS queries directly to root, breaking the chain of trust  (CWE-345)
**File**: `resolver/resolver.go:183-186`
**Skill**: dns-specific / sc-crypto
**Description**: `Resolver.QueryDNSSEC` is the implementation of
`dnssec.Querier` used by the validator to fetch DNSKEY and DS records.
It hard-codes the upstream as a randomly chosen **root server**:
```go
func (r *Resolver) QueryDNSSEC(name string, qtype uint16, qclass uint16) (*dns.Message, error) {
    idx := rand.IntN(len(r.rootServers))
    return r.queryUpstream(r.rootServers[idx].IPv4, name, qtype, qclass)
}
```
A root server is authoritative only for the root zone. A query such as
`example.com DNSKEY` returns a referral to `.com` with an empty Answer
section. `Validator.fetchDNSKEYs` (`dnssec/validator.go:402-410`) then
collects zero DNSKEYs and caches an empty key set; the validator returns
`Insecure` for every signed zone below the root and the resolver labels
the answer `"insecure"` (`resolver/resolver.go:357-359`).
**Impact**: DNSSEC validation is silently disabled for every zone other
than the root itself — bogus and unsigned answers are accepted as
indistinguishable from genuine ones, defeating the entire DNSSEC chain
of trust and any downstream policy that depends on the `DNSSECStatus`
field (`shouldFallback`, EDE bogus signaling, metrics).
**Recommendation**: Query DNSKEY/DS through a full iterative resolution
that reaches the actual authoritative servers — e.g. delegate to
`Resolver.resolveIterative` with the DO bit forced on, or expose a
dedicated path that walks the delegation but preserves the validator
context. Add a unit test that validates a known-good real zone end-to-end.

### [HIGH] Pool buffer is returned to `sync.Pool` while caller still holds a slice into it (use-after-free / data race)  (CWE-416 / CWE-362)
**File**: `server/handler.go:241-248, 536-537, 607-615, 654-661, 692-700, 796-800, 816-823, 873-880`
**Skill**: sc-race-condition / sc-lang-go
**Description**: Every response builder follows the pattern:
```go
bufPtr := pool.GetBuffer()
buf := *bufPtr
packed, err := dns.Pack(resp, buf)
pool.PutBuffer(bufPtr)        // <-- returned to pool here
...
return packed                  // <-- caller still uses packed (aliases buf)
```
`packed` is a sub-slice of the pooled buffer's backing array. After
`pool.PutBuffer`, another goroutine that calls `GetBuffer()` may receive
the same buffer and `dns.Pack` over it (or `copy(buf, ...)`) while the
first goroutine is still using `packed` to write to the UDP socket
(`server/udp.go:92`) or TCP stream (`server/tcp.go:143`). With UDP the
visible effect is corrupted on-wire bytes; under contention this can
also poison cache writes through `addEDEToRawResponse`/`addCookieToResponse`
because both unpack-modify-repack chains free their buffer before the
next handler stage consumes the bytes. The `defer pool.PutBuffer` form
(`buildError` line 537, stale-serve block line 425) has the same bug
with deterministic timing — the buffer is recycled the moment the
function returns, before the bytes reach the wire.
**Impact**: Concurrent queries can receive each other's response bytes
(question/answer mixing across clients), TC-bit / RCODE corruption,
truncated or partially-written UDP packets, and rare panics in
`dns.Pack` if the underlying buffer is mutated mid-write. With targeted
load this is exploitable as response substitution between clients on
the same server.
**Recommendation**: Either return a fresh `make([]byte, n)` copy of
`packed` before calling `pool.PutBuffer`, or defer the `PutBuffer` until
after the bytes have been written to the socket (move pooling into the
caller that owns the wire write). The simplest safe fix is `out := append([]byte(nil), packed...); pool.PutBuffer(bufPtr); return out`.

### [HIGH] Cache-hit path bypasses the private-address (DNS-rebinding) filter  (CWE-942)
**File**: `server/handler.go:381-405,664-670`
**Skill**: sc-data-exposure / dns-specific
**Description**: `FilterPrivateAddresses` is applied only inside
`buildResponse` (line 668), which runs on the slow path (`Resolve()`
returning fresh data). `Resolve` writes the *unfiltered* answers into
the cache (`server/handler.go:469`), and subsequent queries hit
`buildCacheResponse` (line 586) which never invokes the filter. A first
client that lacks the filter (or a brief race) plus an attacker domain
returning a public IP that later resolves to RFC 1918 / 127.0.0.1 ends
up storing the private record permanently in cache.
Because the filter is a privacy/rebinding defence rather than a strict
parse rule, the absent enforcement on cached entries means once any
private address is admitted to the cache the protection is silently
bypassed for every later client, including those for whom the operator
explicitly enabled rebinding protection.
**Impact**: Defeats the documented DNS-rebinding mitigation for any
victim served from cache; an attacker's first query can be the seeding
query (no filter at write-time), all subsequent victims receive the
private IP transparently.
**Recommendation**: Either filter answers before `cache.Store`
(`server/handler.go:467-475`) or apply `FilterPrivateAddresses` inside
`buildCacheResponse` on the records pulled from cache. The latter also
covers cache pre-warming and query-log correctness.

### [HIGH] Stale 2017 root KSK is the only DNSSEC trust anchor — no provision for KSK-2024 rollover  (CWE-321 / CWE-1394)
**File**: `dnssec/trustanchor.go:16-23`
**Skill**: sc-crypto
**Description**: `RootDSRecords` hardcodes only key tag 20326
(KSK-2017). IANA published KSK-2024 (key tag 38696) and the rollover is
in progress; resolvers must trust both anchors during the transition
and switch to the new one when the 2017 key is retired. With only the
2017 anchor present, the validator returns `Bogus` (or `Indeterminate`)
the moment the root zone is signed exclusively with the new KSK, and
there is no operator-visible mechanism (config, file, RFC 5011) to
extend or replace it without a code change.
**Impact**: Forced operational outage of DNSSEC validation at the next
KSK rollover; for every signed response the resolver returns SERVFAIL
(`resolver/resolver.go:360-362`) and the fallback resolver path is
intentionally **not** taken when DNSSEC fails (`resolver/fallback.go:82-85`),
so the entire resolver effectively goes dark.
**Recommendation**: Add KSK-2024 (key tag 38696, RSASHA256, SHA-256
digest `683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16`)
to `RootDSRecords`, or load anchors from `/etc/trusted-key.key` /
`root.key` at startup. Consider an RFC 5011 automated trust-anchor
rollover client.

### [HIGH] Unbounded RDATA-name decompression panics on negative `sigLen`/`bitmapLen` for crafted RRSIG/NSEC  (CWE-130 / CWE-20)
**File**: `dns/record.go:108-128, 130-143`
**Skill**: sc-deserialization / dns-specific
**Description**: For RRSIG and NSEC records, `UnpackRR` decodes a
compressed name inside RDATA by calling `DecodeName(msg, rdataStart+18)`
and then computes `sigLen := newOffset - nameEnd` (line 116) /
`bitmapLen := newOffset - nameEnd` (line 135). `DecodeName` walks the
**entire message buffer**, not the RDATA window: an RR can declare
`RDLENGTH=20` while embedding labels that extend past `rdataStart+RDLENGTH`
before reaching the first compression pointer (pointers must point
backward, but plain labels can run forward into the next RR). When
`nameEnd > newOffset`, `sigLen`/`bitmapLen` is negative and
`make([]byte, 18+len(nameBytes)+sigLen)` panics with `makeslice: cap out of range`.
The UDP/TCP servers `recover()` at the goroutine boundary
(`server/udp.go:77-81`), so the process survives, but every panic logs,
allocates, and aborts the resolution — repeated crafted responses from
an attacker-controlled authoritative server cause goroutine churn and
elevated log volume on every poisoning attempt.
**Impact**: Remote-triggerable parser panic in the resolver hot path;
log/CPU amplification, potential to mask other parse errors, and any
later refactor that drops the recovery becomes a remote DoS.
**Recommendation**: Clamp `nameEnd` to `newOffset` and reject the RR
(or copy raw via `copyRData`) when `nameEnd > newOffset`. Consider
restricting `DecodeName` to a `[start, end)` window when called for
RDATA-internal names.

### [MEDIUM] Forward and fallback responses bypass bailiwick filter and 0x20 case validation but are still cached  (CWE-345)
**File**: `resolver/forward.go:78-98,142-213`, `resolver/fallback.go:14-68`, `server/handler.go:467-475`
**Skill**: dns-specific
**Description**: Forward-zone (`queryForward`) and global-fallback
(`queryFallback`) responses are validated only for TXID and question
echo; no `SanitizeBailiwick` call is made and 0x20 case randomization is
disabled (`sendQueryWithRD` does not call `randomizeCase`). The result
flows back through `Resolve` and into `cache.Store`
(`server/handler.go:469`), so a compromised or malicious forwarder can
populate the resolver cache with arbitrary off-bailiwick records
(e.g. an A record for `*.bank.example` returned alongside a query for
`unrelated.example`). For configured forwarders this is the documented
trust boundary, but the *fallback resolver* list (`8.8.8.8`, `1.1.1.1`,
…) is auto-engaged on any SERVFAIL whose status is not `bogus`, so an
attacker who can induce SERVFAIL on the iterative path effectively
chooses to be answered by a fallback whose responses go straight into
the shared cache.
**Impact**: Cache-substitution if the configured fallback resolver is
hostile or compromised; SERVFAIL-induced poisoning amplification.
**Recommendation**: Apply `SanitizeBailiwick` (with empty zone? — no,
with the queried zone) on forward and fallback responses, or at minimum
gate cache writes for `Resolve` results that came from the fallback
path on a flag set by `queryFallback`. Consider 0x20 randomization on
RD=1 forwards as well.

### [MEDIUM] Per-IP rate-limiter map grows unbounded under spoofed source addresses  (CWE-770 / CWE-400)
**File**: `security/ratelimit.go:10-31,40-46,66-85`
**Skill**: sc-rate-limiting / sc-business-logic
**Description**: `RateLimiter.clients` is a `map[string]*tokenBucket`
keyed by the raw client IP string. Every fresh source IP creates a new
bucket (line 41-46) with no upper bound on the map size; idle entries
are reaped every 5 minutes by `StartCleanup`. Over UDP, source addresses
are trivially spoofable, so an attacker can mint millions of fresh keys
per second and force the resolver to allocate a `tokenBucket` per
"client". The lone `sync.Mutex` serialising `Allow` (line 35-36) becomes
a contention bottleneck before OOM, but memory exhaustion is reachable
inside the 5-minute cleanup window.
**Impact**: Memory exhaustion / mutex starvation; the rate-limiter
itself becomes the DoS surface it is meant to defend against.
**Recommendation**: Cap `len(clients)` (e.g. 1M entries) with random
eviction on overflow, or shard the map and bound each shard, or hash the
source-address into a fixed-size lossy counter (count-min sketch /
half-life decay). The same pattern in `RRL.entries`
(`security/rrl.go:21-28`) — also keyed partly by attacker-controlled
qname — has the same vulnerability and should be fixed in the same
sweep.

### [MEDIUM] RRL key includes attacker-controlled qname truncated to 255 bytes — unbounded growth and key explosion  (CWE-770)
**File**: `security/rrl.go:38-72,119-131`
**Skill**: sc-rate-limiting
**Description**: `rrlKey = {prefix, qname, responseType}`. With a
`/24` IPv4 prefix and arbitrary qname (truncated to 255 bytes,
lowercased), an attacker can iterate roughly 2^bits-of-qname keys per
prefix. Each key allocates an `*rrlEntry`. The cleanup loop only fires
every 5 minutes (line 30, 134-157), and entries are kept until they age
out, so a worst-case burst at full UDP packet rate quickly fills RAM.
The cleanup walk is also `O(n)` under the lock — a large map blocks
every legitimate response on the next cleanup tick.
**Impact**: Memory exhaustion; lock-hold pauses for the entire response
path during cleanup. Bypasses the response-rate limiter as a
side-effect: with a sufficiently full map the limiter still permits new
keys (each is "first-seen" → allow).
**Recommendation**: Truncate qname to a coarse identity (e.g. eTLD+1)
or hash to a fixed-width bucket id; cap the number of entries; do
constant-work eviction on insert.

### [MEDIUM] DoH `skipDNSName` accepts non-pointer non-label first-byte and may walk past message end  (CWE-20)
**File**: `web/api_doh.go:173-191`
**Skill**: sc-dos / dns-specific
**Description**: The mini-parser used to compute `Cache-Control: max-age`
checks `length & 0xC0 == 0xC0` (single-byte pointer detection) but
otherwise treats any length byte as a literal label length and adds
`1+length` to the offset. For length values 0x40–0xBF (top bits `01`
or `10`, reserved per RFC 6891 / RFC 2671 Extended Label format), it
advances by up to 1+191 bytes per "label" with no max-iteration bound.
On a malformed or hostile DoH response that the resolver core *did*
parse (since `dns.Unpack` rejects oversized labels), the helper still
runs unbounded, and the resulting `offset+10 > len(response)` check at
the answer-record step catches truncation only after the walk has read
past `len(response)`. The function returns `0` on bad input, which then
becomes `Cache-Control: max-age=0` — relatively benign for DoH clients
but combined with future refactors this is a soft parser that diverges
from `dns.Unpack` and is a foothold for future bugs.
**Impact**: Wasted CPU on malformed responses; downstream caches see
`max-age=0` and never cache. No remote crash today.
**Recommendation**: Reuse `dns.Unpack` (the response is already a
fully-parsed message) and pull TTLs from `msg.Answers`, or add a max
iteration count and reject lengths > 63.

### [MEDIUM] Bailiwick filter is permissive when `currentZone == ""` — root referrals can stuff Answer section with arbitrary records  (CWE-345)
**File**: `security/bailiwick.go:21-74`, `resolver/resolver.go:317`
**Skill**: dns-specific
**Description**: `filterInZone` returns the records unchanged when
`zone == ""` (line 62-63). The first iteration of `resolveIterative`
calls `SanitizeBailiwick(response, currentZone)` with
`currentZone = ""` (line 257, 274-275), and so the **first**
authoritative response from a root server is filtered with the
permissive policy across Answers, Authority *and* Additional. Root
servers normally only return Authority+Additional (referral), but a
malicious or compromised root server (or successful off-path injection
between the resolver and a root) can stuff Answers with any record and
have them flow straight into `cacheCNAME` / `responseAnswer`
classification. This is the classic priming carve-out applied too
broadly: priming queries (`PrimeRootHints`, line 115-143) are the only
case that legitimately needs an empty-zone bailiwick.
**Impact**: A single intercepted root-server response can inject
unbailiwicked Answer records that are then cached and served
indefinitely (`cache.Store` happens via the responseAnswer/CNAME paths).
**Recommendation**: Limit the empty-zone permissive mode to the
`PrimeRootHints` priming call; for normal iterative resolution, use
zone `"."` (the root zone) for the first hop so that Answers must lie
within the root, and Authority records must be `NS` for `.`/TLDs.
Equivalently, gate the permissive branch on a `priming bool` argument.

### [MEDIUM] Glue cache write at delegation time replaces multi-record A/AAAA sets with a single record  (CWE-345)
**File**: `resolver/resolver.go:438-460`
**Skill**: dns-specific
**Description**: When iterating, every referral causes
`r.cache.Store(delNS.Hostname, TypeA, ClassIN, []ResourceRecord{single}, nil)`
to overwrite any prior cached A set for the NS hostname with a single
glue record. If the parent's referral provided one IPv4 (out of several)
and the cache previously held the full A RRset (e.g. from a directly
authoritative response), the multi-record entry is silently truncated.
The replacement also resets the OrigTTL / InsertedAt clocks, lengthening
the lifetime of a single attacker-influenced glue record beyond the
RRset's authoritative TTL.
**Impact**: Reduced redundancy of NS resolution (single point of
failure if the chosen glue IP is unreachable or hijacked); subtle TTL
extension that helps a poisoning window. Not exploitable to swap zones,
but useful for narrowing the attack surface to one of several NS IPs.
**Recommendation**: Either skip the cache write when an existing entry
already has more records, merge the glue into the existing RRset, or
store glue under a separate "glue cache" namespace consulted only for
NS-IP resolution.

### [MEDIUM] DNS Cookie fallback secret is a deterministic literal when `crypto/rand` fails  (CWE-330 / CWE-798)
**File**: `server/handler.go:100-107`
**Skill**: sc-crypto
**Description**:
```go
if _, err := rand.Read(h.cookieSecret); err != nil {
    h.cookieSecret = []byte("labyrinth-secret")
}
```
On the (rare) failure of `crypto/rand` the server cookie secret becomes
a public literal. RFC 7873 cookies are an off-path-spoofing defence, so a
well-known secret reduces them to plaintext checksums and lets an
attacker forge valid server cookies for any client IP.
**Impact**: Cookie validation becomes a no-op, defeating the anti-spoofing
property. Only reachable when `getrandom`/`/dev/urandom` is unavailable
(seccomp, broken VM, container without `/dev`).
**Recommendation**: Fail closed — return the error to the caller,
disable cookies, and log; never substitute a literal.

### [LOW] Fallback resolver `addr` is selected by `math/rand/v2` and trivially predictable  (CWE-338)
**File**: `resolver/fallback.go:19`
**Skill**: sc-crypto
**Description**: `addr := r.config.FallbackResolvers[rand.IntN(len(r.config.FallbackResolvers))]`
uses the unseeded `math/rand/v2` package. The choice between fallback
resolvers is therefore deterministic across builds (and predictable
across runs from any side-channel that observes one selection). For a
threat model that includes an attacker who can DoS one of two configured
fallbacks to coerce the use of the other, the selection is effectively
non-random. `PrimeRootHints` (line 117) and `QueryDNSSEC` (line 184)
have the same property when picking root servers.
**Impact**: Trivial predictability of fallback/root server selection
weakens the "spread risk across multiple resolvers" goal.
**Recommendation**: Use `crypto/rand` for security-relevant selection,
or seed `math/rand/v2` with `crypto/rand` once at startup
(`rand.NewChaCha8(seed)`).

### [LOW] Single-attempt fallback accepts NXDOMAIN from a fallback over the iterative SERVFAIL — expanding cache-injection surface  (CWE-345)
**File**: `resolver/fallback.go:42-67`, `server/handler.go:467-475`
**Skill**: dns-specific
**Description**: `queryFallback` accepts NXDOMAIN as a "successful"
response (only SERVFAIL is rejected) and returns it through `Resolve`,
where the handler caches the negative answer at lines 470-471. A
hostile or compromised fallback resolver therefore can synthesise
NXDOMAIN for any name that the iterative path momentarily returns
SERVFAIL for, poisoning negative cache entries that persist until
`negMaxTTL` (default 3600s).
**Impact**: Targeted negative cache poisoning of names whose iterative
resolution can be perturbed (e.g. by exhausting the parent NS list).
**Recommendation**: Don't write fallback-derived results to the shared
cache, or only write positive answers, or attach a per-entry tag and
treat fallback-cached negatives as non-authoritative for the next
iteration.

### [INFO] EDNS0 ParseOPT does not validate version, ExtRCODE handling, or option-data length sanity  (CWE-20)
**File**: `dns/edns.go:24-54`
**Skill**: dns-specific
**Description**: `ParseOPT` decodes the OPT pseudo-RR but never checks
`Version` (RFC 6891 §6.1.3 requires BADVERS for non-zero versions), and
its option-loop break-on-overflow (line 43-45) silently drops the rest
of the OPT data instead of returning an error. The downstream code then
proceeds as if EDNS0 was well-formed. Combined with the `ExtRCODE`
being read but never reflected back to the client, an upstream returning
an extended RCODE such as BADCOOKIE (23) or BADTRUNC (22) is silently
collapsed to its low 4 bits.
**Impact**: Incorrect EDNS0 version negotiation; loss of extended
RCODE semantics. Not directly exploitable, but masks legitimate upstream
errors and weakens cookie-mismatch detection.
**Recommendation**: Reject OPT records with `Version != 0` (return
BADVERS to the client), surface ExtRCODE through `EDNS0`, and treat
mid-option overflow as a parse error.
