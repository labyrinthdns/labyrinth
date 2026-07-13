# LabyrinthDNS — Architecture Deep-Dive

_Date: 2026-07-13 · Corresponds to PLAN.md M7.2_

This document describes LabyrinthDNS's internal architecture at the
component, goroutine, and data-flow level. It is intended for
contributors, operators doing deep troubleshooting, and anyone
integrating with or extending the resolver.

---

## 1. High-Level Architecture

```
                    ┌──────────────────────────────────────┐
                    │           Labyrinth Binary            │
                    │                                      │
  DNS Clients ─────▶│  UDP/TCP :53  ──▶ Recursive Resolver │
                    │                   ├─ Root Hints       │
                    │                   ├─ QNAME Min        │
                    │                   ├─ DNSSEC Validation│
                    │                   ├─ Blocklist Filter │
                    │                   ├─ Cache (256-shard)│
                    │                   └─ Bailiwick/RRL    │
                    │                                      │
  Web Browser ─────▶│  HTTP :9153 ──▶ Web Dashboard        │
                    │                  ├─ React SPA         │
                    │                  ├─ REST API          │
                    │                  ├─ WebSocket Stream  │
                    │                  └─ JWT Auth          │
                    │                                      │
  Zabbix Server ───▶│  TCP :10050 ──▶ Zabbix Agent        │
                    │                                      │
  Prometheus ──────▶│  /metrics   ──▶ Prometheus Exporter  │
                    └──────────────────────────────────────┘
```

### Process model

LabyrinthDNS is a **single-process, single-binary** recursive resolver.
There is no worker pool or supervisor process. Everything — DNS listener,
resolver engine, cache, DNSSEC validator, blocklist, web dashboard,
metrics exporter, Zabbix agent — lives in one OS process.

### Goroutine model

Components communicate through Go channels and shared data structures
protected by `sync.RWMutex`, `atomic` values, or shard-level locks:

| Goroutine | Count | Purpose |
|-----------|-------|---------|
| UDP listener workers | `MaxUDPWorkers` (default 10,000) | Semaphore-bounded; one goroutine per DNS query read from UDP socket |
| TCP listener | 1 per listener | Accept loop, spawns one goroutine per TCP connection |
| TCP connection handler | 1 per active TCP connection | Reads pipelined queries from one TCP client |
| DoT listener | 1 | Same structure as TCP, with TLS handshake |
| Web dashboard | 1+ | HTTP server (gorilla/mux or net/http), handles REST + WS |
| Cache sweeper | 1 | Periodic expired-entry eviction |
| RRL cleanup | 1 | Periodic RRL entry pruning |
| Rate limiter cleanup | 1 | Periodic rate-limit entry pruning |
| Infra cache cleanup | 1 | Periodic stale NS RTT entry cleanup |
| NTA cleanup | 1 | Periodic NTA expiry pruning (RFC 7646) |
| Root hints refresh | 1 | Periodic root NS set refresh (if configured) |
| Update checker | 1 | Periodic GitHub release check |
| Zabbix agent | 1 | Zabbix native protocol listener |
| Blocklist manager | 1 | Periodic blocklist download + parsing (if enabled) |

Each client DNS query is handled by a single goroutine from start to
finish — there's no request-reply correlation layer or async dispatch
within a query. Sequential NS-address sub-resolutions run one at a time
on the same goroutine (first-success short-circuit).

---

## 2. Query Lifecycle

### 2.1 Wire → Handler

```
UDP Socket  ──read──▶  parseMessage(query) ──▶ MainHandler.Handle()
                                                      │
TCP Stream  ──read──▶  readLengthPrefix()              │
              ──read──▶  parseMessage(query) ───────────┘
```

1. **UDP**: The UDP listener reads a single datagram from `*net.UDPConn`.
   A semaphore channel (`sem <- struct{}{}`) bounds concurrent handlers.
2. **TCP**: The TCP listener reads the 2-byte length prefix (RFC 7766),
   then reads the DNS message body. Pipelining: up to `TCPPipelineMax`
   queries per connection without waiting for responses between reads.
3. **DoT** and **DoH** use the same `Handler` interface but with a TLS
   transport before the DNS framing layer.

### 2.2 Handler Processing

`MainHandler.Handle()` does the following in order:

1. **Access control check** — ACL deny/allow against client address.
   Returns REFUSED (EDE 17/18) if denied.
2. **Request parsing** — `dns.Unpack(query)` into `dns.Message`.
3. **TC/truncation handling** — If this is a TCP/DoT/DoH retry after UDP
   truncation, the second attempt arrives on the stream transport and
   bypasses the `maybeTruncateUDP` call.
4. **DNS cookie validation** (RFC 7873) — If cookies are enabled, validates
   the client cookie; if enforce mode, rejects cookie-less UDP with
   BADCOOKIE.
5. **Cache lookup** — `cache.Get(name, qtype, qclass)` with forced-addition
   of the DO bit for DNSSEC lookups.
6. **Recursive resolution** — On cache miss, calls `resolver.Resolve()`.
7. **Blocklist check** — If the response has an answer, checks the
   response's name against the blocklist. Applies configured action
   (NXDOMAIN, null_ip, custom_ip, or passthru).
8. **Response assembly** — `buildResponse()` packs the DNS message, adds
   OPT record with EDNS0 options, applies EDE codes, strips DNSSEC RRs
   for non-DO clients (RFC 4035 §3.2.1), truncates for UDP (RFC 6891).
9. **Response Rate Limiting** — `rrl.AllowResponse()` decides whether to
   send, drop, or slip (TC=1) the response.

### 2.3 Recursive Resolution

`resolver.Resolve()` implements the iterative resolution algorithm:

```
Resolve(name, qtype, qclass):
  1. Check local zones (static answers bypass recursion)
  2. Check forward/stub zones (delegate to configured upstreams)
  3. Cache check (return cached answer if fresh)
  4. Start from root hints (or cached NS sets)
  
  For each delegation level:
    a. Select best nameserver (lowest RTT from infra cache)
    b. Send query to nameserver (UDP with TCP fallback on TC)
    c. Parse response:
       - Answer section: return on success
       - CNAME/DNAME: follow the chain, resolve target
       - Delegation: extract NS glue, continue from (a)
       - SERVFAIL/REFUSED: try next nameserver or fallback resolver
       - NXDOMAIN: return immediately
    d. Cache NS sets, glue, negative responses
  
  5. DNSSEC validation on the final response
  6. Return ResolveResult to handler
```

**Key design decisions:**

- **Sequential NS resolution**: glueless NS names are resolved one at a
  time with first-success short-circuit. No parallel fan-out.
- **QNAME minimisation** (RFC 9156): queries use progressive NS delegation
  walks sending only the known suffix, not the full qname.
- **0x20 case randomisation** (RFC 5452 §9.2): each outbound query has
  random-cased owner names to detect forged responses.
- **Connected UDP sockets**: each upstream query uses a connected socket
  that drops packets from unrelated source IPs (4-tuple inbound filter).
- **Caps0x20** and **source-port randomness** combine to give ~28+ bits
  of anti-spoofing entropy (TXID 16 + port ~12 + case ~0-4).

### 2.4 DNSSEC Validation Pipeline

```
  ANSWER (from upstream or cache)
       │
       ▼
  is there RRSIG? ──No──▶ Insecure (AD=0, no data)
       │
      Yes
       │
       ▼
  trust chain walk (DNSKEY → DS → parent DNSKEY ... to root KSK)
       │
       ▼
  for each RRSIG on the answer RRset:
       │
       ▼
    key tag match? ──No──▶ next RRSIG
       │
      Yes
       │
       ▼
    cryptoBudget.check() ──exhausted──▶ Bogus (EDE 6)
       │
     available
       │
       ▼
    VerifyRRSIG() ──fail──▶ next RRSIG (algorithm rollover resilience)
       │
     success
       │
       ▼
    Secure (AD=1)

  Additional:
   - NSEC/NSEC3 denial validation for NXDOMAIN/NODATA
   - Compact denial (NSEC3 white lies) detection
   - Opt-out NSEC3 handling for DS queries
   - Negative trust anchor (RFC 7646) override
```

**Safety budgets (all bounded):**

| Budget | Cap | Scope | Defense |
|--------|-----|-------|---------|
| `maxRRSIGVerifyAttempts` | 16 | Per RRset | Limits crypto per RRset |
| `maxCryptoVerifyPerResponse` | 32 | Per response | KeyTrap (CVE-2023-50387) global backstop |
| `MaxNSEC3Iterations` | 100 | Per NSEC3 record | RFC 9276 iteration ceiling |
| `MaxNSEC3RecordsPerProof` | 16 | Per denial proof | CVE-2023-50868 hash-DoS defense |
| `nsec3HashBudget` | 600 units | Per query | NSEC3 hash computation cap |

### 2.5 Caching Layer

The cache is **256-way sharded** by `(name, qtype, qclass, ecsPrefix)`.
Each shard has its own `sync.RWMutex`.

```
  cacheKey = fnv1a(name + qtype + class + ecsPrefix) % 256
                        │
                        ▼
                shard[shardIndex]
                  │        │
               entries    evictionQ (min-heap by expiry)
```

**Features:**
- TTL-based expiry with configurable min/max clamping
- Negative caching (NXDOMAIN/NODATA) with RFC 2308 MIN(SOA TTL, SOA.MINIMUM)
- Serve-stale (RFC 8767): stale entries served while re-fetching in background
- Prefetch: when remaining TTL < 10%, background re-resolution is triggered
- Harden-below-NXDOMAIN (RFC 8020): parent NXDOMAIN blocks sub-domain queries
- Aggressive NSEC/NSEC3 (RFC 8198): NXDOMAIN/NODATA synthesis from cached
  authenticated denial records (NSEC/NSEC3)
- Per-entry DNSSEC status preservation (AD bit fidelity for cached responses)
- Stale-max-age cap (RFC 8767 §3.3): entries past 1-day stale boundary
  are not served

**Eviction:** When a shard exceeds `maxEntries / shardCount`, the entry
with the nearest expiry time (from the min-heap) is evicted. The sweeper
goroutine removes truly expired entries every 60 seconds.

### 2.6 NSEC/NSEC3 Aggressive Cache

When the cache holds authenticated NSEC/NSEC3 records (from a prior
Secure NXDOMAIN or NODATA response), the cache can synthesise answers
for names that fall within the proven gap without re-querying.

```
  nsecIndex (binary search over sorted NSEC intervals)
     ──→ ClosestEncloser check → NXDOMAIN or NODATA

  nsec3Index (per-zone hash-parameter space)
     ──→ Hash qname with zone parameters → binary search
     ──→ Opt-out exclusion → Insecure vs NXDOMAIN/NODATA
```

The NSEC3 aggressive path uses a separate 150-unit hash budget
(`nsec3AggressiveHashBudget`) distinct from the on-wire 600-unit budget
to avoid starving the critical resolution path.

---

## 3. Component Details

### 3.1 `config` Package

Config loading follows a layered priority:

1. **Compiled defaults** (`config/defaults.go`)
2. **YAML file** (`labyrinth.yaml` by default) — custom flat-key parser
   that converts nested YAML into dot-separated keys
3. **Environment variables** (`LABYRINTH_*`)
4. **CLI flags** (`-listen`, `-web`, etc.)

All integer/duration config values that feed into `make()` or loop
conditions are clamped by `clampConfigBounds()` to prevent operator
typos from OOMing or stalling the process.

### 3.2 `dns` Package

Wire-format encoding/decoding for DNS messages. Key design decisions:

- **Buffer pooling**: `internal/pool` provides `[]byte` pools sized at
  512 B, 2 KiB, and 64 KiB to reduce GC pressure.
- **Name compression**: case-insensitive compression dictionary
  (RFC 1035 §2.3.3, names are case-insensitive for pointer matching).
- **No allocation on unpack**: the hot path reuses pointers and slices
  from the parse state.

### 3.3 `resolver` Package

The iterative resolution engine. 1,478 lines in `resolver.go`, supported
by helpers in `cname.go`, `delegation.go`, `fallback.go`, `forward.go`,
`qmin.go`, `dns64.go`, `trace.go`, `infracache.go`, and `failure_cache.go`.

**Request budget system (`reqBudget`)**:

```
  reqBudget.total = MaxQueriesPerRequest (default 200)
  reqBudget.deadline = time.Now().Add(RequestTimeout) (default 20s)

  Every outbound query:
    reqBudget.charge()  ──→ decrements counter
    if expired() ──→ SERVFAIL with "request budget exceeded"
```

The budget is shared across all CNAME hops, QNAME-minimisation steps,
NS-address sub-resolutions, and fallback attempts. It is carried through
the resolution tree via the `visitedSet` map.

**Infra cache**: stores per-nameserver RTT measurements used for
server selection. Periodically cleaned up (10-minute sweep, 1-hour
max entry age).

**Failure cache** (RFC 9520): caches resolution failures to avoid
repeating doomed queries. Configurable per-server failure threshold.

### 3.4 `cache` Package

As described in §2.5. 926 lines covering sharded storage, eviction,
stale-serving, prefetch, and NSEC/NSEC3 index.

### 3.5 `dnssec` Package

Full DNSSEC validation as described in §2.4. 1,832 lines in
`validator.go`, supported by `verify.go`, `nsec.go`, `nsec3.go`,
`ds.go`, `nta.go`, `trustanchor.go`, `cds.go`, `failure_reason.go`,
and `rfc5011_lifecycle.go`.

**Trust anchor management:**
- Root trust anchors (`trustanchor.go`): hardcoded root KSK hashes
  (IDs 20326 and 38696)
- RFC 5011 lifecycle (`rfc5011_lifecycle.go`): full state machine
  with 30-day hold-down, revoke detection

### 3.6 `server` Package

Transport layer for DNS. 1,921 lines in `handler.go`, supported by
`udp.go`, `tcp.go`, `dot.go`, and `tcp_policies.go`.

**TCP connection management:**
- Global `maxTCPConns` semaphore
- idle timeout (RFC 7766 §6.2 recommendation)
- per-connection pipeline limit
- `MaxHeaderBytes` cap on HTTP paths

### 3.7 `security` Package

Multi-layer security:

| Layer | Mechanism | Scope |
|-------|-----------|-------|
| ACL | CIDR allow/deny lists | Per-zone + global |
| Rate Limiter | Token bucket per client IP | QPS per client |
| RRL | Token bucket per (/24, qname, type) | Response amplification |
| Private filter | RFC 1918 / CGNAT stripping | DNS rebinding |
| Bailiwick | RFC 5452 §3 in-bailiwick check | Out-of-bailiwick data |
| Loop detector | Ask-and-check (internal) | Forwarding loops |
| Siphash | Cookie hashing | Secret-based auth |

### 3.8 `web` Package

HTTP server providing:

- **React SPA** (`web/ui/`) — embedded via `//go:embed`
- **REST API** — 30+ endpoints for stats, cache, config, blocklist,
  DNSSEC, system management, Zabbix proxy
- **WebSocket stream** (`/api/queries/stream`) — live DNS query feed
- **DoH endpoint** (`GET/POST /dns-query`) — RFC 8484
- **Prometheus metrics** (`/metrics`)
- **JWT authentication** with bcrypt password hashing

### 3.9 `metrics` Package

Prometheus-compatible metrics with:

- Counter vectors: `labyrinth_queries_total`, `labyrinth_cache_*`
- Histograms: `labyrinth_query_duration_seconds`
- Gauges: `labyrinth_uptime_seconds`, `labyrinth_cache_entries`
- EDE code counters: `labyrinth_ede_responses_total{code="..."}`

### 3.10 `blocklist` Package

Downloads, parses, and applies domain blocklists.

- Supported formats: hosts (Pi-hole), domain lists, AdBlock Plus,
  RPZ native
- Actions: NXDOMAIN, null_ip (0.0.0.0), custom_ip, passthru
- Refresh on configurable interval
- Whitelist support

---

## 4. Config Hot-Reload Architecture

Configuration hot-reload (via `PUT /api/config/raw`) uses a two-phase
commit pattern:

1. **Validate** — `config.Parse()` validates the new YAML. On failure,
   the old config is untouched.
2. **Apply** — The validated config is stored in `s.config.Store()` and
   the `runtimeApplier` callback is called for live-updatable fields.

Fields that CAN be hot-reloaded (all others require process restart):
- `security.private_address_filter`
- `resolver.ecs_enabled`, `resolver.ecs_max_prefix`, `resolver.ecs_max_prefix_v6`

The `runtimeApplier` is registered in `main_runtime_helpers.go` from the
`server.MainHandler` instance. The callback is serialised under
`s.configFileMu` to prevent races with password changes.

---

## 5. Startup Sequence

```
main() / run()
   │
   ├─ Parse CLI flags
   ├─ Check subcommands (check, version, hash, daemon)
   ├─ Daemonize (if --daemon or "daemon start")
   ├─ Load config (file → env → defaults)
   ├─ Apply CLI overrides
   │
   ├─ Initialize logger
   ├─ Initialize metrics
   ├─ Initialize cache (with stale/prefetch support)
   ├─ Initialize rate limiters (RateLimiter, RRL)
   ├─ Initialize ACL
   │
   ├─ Create resolver (ResolverConfig → NewResolver)
   │   ├─ Set local zones
   │   ├─ Set forward/stub zones
   │   └─ Set blocklist (optional)
   │
   ├─ Create handler (MainHandler with resolver, cache, security)
   │
   ├─ Start HTTP services (web dashboard or standalone metrics server)
   ├─ Start DNS servers (UDP + TCP + optional DoT)
   │
   ├─ Start goroutines:
   │   ├─ Cache sweeper
   │   ├─ Rate limiter cleanup
   │   ├─ RRL cleanup
   │   ├─ Infra cache cleanup
   │   ├─ NTA store cleanup
   │   └─ Root hints prime + refresh
   │
   └─ Wait for shutdown signal (SIGINT/SIGTERM/SIGUSR1/SIGUSR2/SIGHUP)
```

---

## 6. Signals

| Signal | Action | Implementation |
|--------|--------|---------------|
| SIGINT/SIGTERM | Graceful shutdown | Cancel context, wait for graceful period, exit |
| SIGUSR1 | Flush cache | `signals_unix.go` handler |
| SIGUSR2 | Dump cache stats to log | `signals_unix.go` handler |
| SIGHUP | Config reload notification | Logged, no action (hot-reload via API) |

---

## 7. Key Design Decisions

### Why 256 cache shards?
256 shards balances lock contention with memory overhead. At >22M
cache reads/sec, a single mutex would be saturated. 256 gives
~86K lookups/sec/shard at peak, well within uncontended `RWMutex`
throughput.

### Why sequential NS resolution?
Sequential glueless NS resolution (try NS1, then NS2, etc.) avoids
the amplification surface of parallel fan-out. NXNSAttack
(CVE-2020-8616) exploits resolvers that resolve all NS targets in
parallel — sequential resolution with first-success short-circuit
limits the amplification factor to 1.

### Why connected UDP sockets?
Connected UDP sockets provide kernel-level 4-tuple filtering:
the kernel drops packets whose source IP:port doesn't match the
expected upstream server. This eliminates an entire class of
off-path spoofing attacks.

### Why custom YAML parser instead of gopkg.in/yaml.v3?
The custom flat-key parser (`config/yaml.go`) converts nested YAML
into a `map[string]string` and applies values via typed setters.
This gives precise control over parsing semantics, type coercion,
and error messages. It also enables the `applyYAML` → `applyEnv`
unified pipeline where environment variables can override any key.
