# Changelog

All notable changes to Labyrinth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.6.0] - 2026-04-06

### Added
- **RFC 5452 — 0x20 case randomization**: opt-in `resolver.caps_for_id` randomly flips the case of each letter in upstream query names and validates the response echoes the same pattern, adding ~26 bits of anti-spoofing entropy on top of TXID + source-port randomization. New `randomizeCase()` and `validateResponseQuestionEx()` with case-sensitive mode.
- **RFC 9018 — SipHash-2-4 DNS server cookies**: server cookie algorithm upgraded from HMAC-SHA256 truncated to 8 bytes to the RFC 9018 interoperable format: Version(1) + Reserved(3) + Timestamp(4) + SipHash-2-4 Hash(8) = 16-byte server cookie. New `security.SipHash24()` implementation with RFC test-vector validation. `validateServerCookie()` performs constant-time comparison with 1-hour timestamp expiry.
- **RFC 8914 — full Extended DNS Errors**: all 25 info codes (0–24) defined as constants. Active EDE attachments: code 3 (Stale Answer) on serve-stale responses, code 6 (DNSSEC Bogus) on validation failure, code 15 (Blocked) on blocklist hits, code 22 (No Reachable Authority) on resolver SERVFAIL, code 23 (Network Error) on upstream errors. New `addEDEToRawResponse()` helper for post-build EDE injection.
- Web UI: Security docs page sections for 0x20 Case Randomization, DNS Cookies (RFC 7873/9018), and Extended DNS Errors (RFC 8914).
- Web UI: Configuration docs page gains full `security` section table (dns_cookies, private_address_filter, rate_limit.*, rrl.*) and `resolver.caps_for_id` row.
- SipHash-2-4 test suite: RFC reference vector, empty message, single byte, different keys, deterministic, and all-lengths (0–63) coverage.
- 0x20 test suite: `randomizeCase` preserves length/non-alpha/case-insensitive equality, produces variation; `validateResponseQuestionEx` case-sensitive/insensitive modes.
- `validateServerCookie` test: fresh cookie acceptance, wrong IP rejection, wrong version rejection, short cookie rejection.

### Changed
- Server cookie total size changed from 16 bytes (8 client + 8 server) to 24 bytes (8 client + 16 server) per RFC 9018.
- Cookie generation uses `security.SipHash24` with raw IP bytes instead of `crypto/hmac` + `crypto/sha256` with string IP.

### Fixed
- **EDE Stale Answer code**: corrected from 1 (Unsupported DNSKEY Algorithm) to 3 (Stale Answer) per RFC 8914.

### Docs
- README RFC compliance table expanded from 9 to 14 entries: added RFC 7873, 8020, 8109, 8914, 9018; updated 8767 coverage from "Optional" to "Full".
- Features component RFC list updated with 5452, 7873, 8914, 9018.
- Overview security bullet point updated with 0x20, DNS Cookies, EDE.
- Caching docs stale-serving note mentions EDE info code 3.

## [0.5.5] - 2026-04-05

### Added
- **Auto-TLS (Let's Encrypt)**: optional automatic certificate provisioning via ACME. Set `web.auto_tls: true` + `web.auto_tls_domain` and Labyrinth handles cert issuance, renewal, and storage. Uses TLS-ALPN-01 (primary) with HTTP-01 fallback on port 80. Staging mode available for testing (`web.auto_tls_staging`).
- New `certmanager` package wrapping `golang.org/x/crypto/acme/autocert` — shared `*tls.Config` for web server, DoH, and DoT.
- `NewDoTServerWithTLSConfig()` constructor for DoT server to accept a pre-built `*tls.Config` from auto-TLS instead of cert file paths.
- **TLS certificate status API**: `GET /api/system/tls` returns cert domain, issuer, expiry, SAN list, and auto-TLS mode; `POST /api/system/tls/renew` forces certificate cache eviction for re-provisioning.
- **Public DNS guide page** at `/guide` (no authentication required) — platform-specific setup instructions for Windows, macOS, Linux, iOS, Android, and browsers (Firefox DoH, Chrome/Edge DoH). Auto-detects server capabilities (DoH URL, DoT hostname) from `GET /api/dns-guide`.
- Operations page: TLS certificate status card showing domain, issuer, expiry countdown (color-coded), SAN list, and "Force Renew" button for auto-TLS.
- Config page: Auto-TLS form section (domain, email, cache dir, staging toggle) that conditionally hides manual cert file inputs when enabled.
- Comprehensive test suite: 10 certmanager unit tests (New, staging, Info, ForceRenew, TLSConfig, HTTPHandler, InfoFromStatic, certIssuer), 7 web API tests (TLS status/renew, DNS guide with DoH URL construction).

### Changed
- Config validation relaxed: `web.tls_enabled` no longer requires cert/key files when `web.auto_tls` is active; DoH3 validation also accepts auto-TLS.
- DoT server startup in `main_runtime_helpers.go` now checks for shared auto-TLS config before falling back to static cert paths.

## [0.5.4] - 2026-04-05

### Added
- **Config page: full-coverage form editor** — all server, resolver, cache, security, web, blocklist, and cluster settings now exposed in the visual config form, including DoT, DNS64, ECS, prefetch, private-address filtering, DNS cookies, auto-update, dashboard panel order, TLS cert/key paths, and fanout blocklist refresh.
- **Operations page: selectable time window** — 15 m / 1 h / 24 h presets with matching bucket intervals (≤ 30 data points); latency threshold reference line on chart.
- `useQueryStream` real-time flush mode (`flushIntervalMs = 0`) — RAF-based loop for zero-latency query rendering on Queries page.
- Typed API client: `StatsResponse`, `CacheStats`, `LoginResponse`, and `HealthResponse` replace `Record<string, unknown>` casts across all pages.

### Fixed
- Negative cache table now uses backend field names (`qtype`, `remaining_ttl`) instead of stale aliases (`type`, `ttl`), fixing empty columns after API alignment.
- `CacheStats` type extended with `hits`, `misses`, `evictions`, `hit_rate` to match actual `/api/cache/stats` payload.
- Setup wizard sends correct field names (`username`, `password`, `web_addr`, `max_cache_size`, `max_depth`) matching current backend API; removed stale `os_arch` display.
- `VersionResponse` split `os_arch` into separate `os` and `arch` fields.
- Dashboard optional-chaining on `profile?.traffic?.last_minute_qps_peak` prevents crash when profile is still loading.
- Removed unused `latencyThresholdMs` state and dead `windowQueries`/`windowErrors` destructuring in Dashboard.

### Changed
- `TimeSeriesBucket.timestamp` field changed from optional to required in type definition.
- Operations page chart data source is now driven by selectable window preset instead of hard-coded 1 h / 1 m.
- `cacheFlush` and `cacheDelete` API return type corrected from `{ ok: boolean }` to `{ status: string }`.

## [0.5.3] - 2026-04-05

### Added
- **Fallback resolver system**: configurable backup DNS resolvers (`resolver.fallback_resolvers`) that activate automatically when primary resolution returns SERVFAIL or a network error. Picks one random resolver per retry, single attempt only — no retry storms.
- `shouldFallback()` guard ensures DNSSEC-bogus responses and normal NXDOMAIN are never retried, preserving security validation semantics.
- `queryFallback()` reuses the existing `sendForwardQueryOnce` path with RD=1, so fallback queries go through the same timeout/connection logic as forward zones.
- Fallback Prometheus metrics: `labyrinth_fallback_queries_total`, `labyrinth_fallback_recoveries_total`.
- Fallback fields in `/api/stats` JSON (`fallback_queries`, `fallback_recoveries`) and `/api/config` (`fallback_resolvers`).
- Config page: new **Fallback Resolvers** string-list editor under Resolver settings to add/remove backup addresses (e.g., `8.8.8.8`, `1.1.1.1`).
- Dashboard: amber banner "Fallback Resolver Active — X/Y recovered" shown when fallback queries are detected.
- Operations page: fallback alert with recovery percentage and root-cause analysis; bottom stats section showing fallback query/recovery counts.
- Comprehensive test suite: 18 unit tests covering all fallback branches — `shouldFallback` truth table, `queryFallback` success/failure/multi-resolver, and end-to-end `Resolve()` integration across iterative, forward-zone, and stub-zone paths.
- Config parser tests for `fallback_resolvers` CSV parsing (single, multiple, empty).
- Web layer tests for fallback metrics in `/api/stats` (non-zero and zero cases).

### Changed
- `Resolve()` restructured to unify iterative, forward-zone, and stub-zone result handling into a single fallback check point, eliminating code duplication.

## [0.5.2] - 2026-04-05

### Added
- **Live time-series chart mode**: real-time 60-second rolling view with 2-second granularity, pushed via WebSocket every 2 seconds.
- **History time-series chart modes**: configurable window (15 m / 1 h / 24 h) with selectable bucket interval (1 m, 2 m, 5 m, 15 m, 30 m, 1 h), pushed via WebSocket every 10 seconds.
- New WebSocket endpoint `GET /api/stats/timeseries/ws` with `mode`, `window`, and `interval` query parameters; supports in-flight subscription updates without reconnect.
- `SnapshotAggregated(window, interval)` method on `TimeSeriesAggregator` for server-side bucket aggregation with weighted-average latency and cache-hit ratio.
- `cache_hit_ratio` field added to time-series bucket JSON responses.
- New `useTimeSeriesStream` React hook for WebSocket-driven chart data.
- Comprehensive test suite for aggregation logic, subscription parsing, HTTP interval param, and WebSocket live/history/update flows (31 new tests).

### Fixed
- Live QPS display no longer plateaus at 30 under heavy traffic; value is now derived from server-side time-series aggregation instead of the 300-entry query stream buffer.

### Changed
- Time-series data retention extended from 1 hour to 24 hours (86 400 one-second buckets, ~5 MB).
- Dashboard chart data source switched from HTTP polling to WebSocket streaming — removes the 5-second polling interval entirely.
- HTTP `/api/stats/timeseries` endpoint now accepts an optional `interval` query parameter for server-side aggregation and supports windows up to 24 h (previously capped at 1 h).
- Chart mode selector redesigned: `[Live] [15m] [1h] [24h]` buttons with a dynamic interval dropdown for history modes.

### Removed
- Frontend HTTP time-series polling (`TIMESERIES_POLL_MS`) and client-side bucket merging logic replaced by server-pushed pre-aggregated data.

## [0.5.1] - 2026-04-05

### Changed
- WebSocket query stream now uses interval-based batch flush instead of per-frame `requestAnimationFrame`, reducing dashboard re-renders from ~60/s to 1 every 5 seconds under heavy traffic.
- Dashboard chart heartbeat interval increased from 1 s to 5 s, synchronized with the time-series polling interval.
- `useQueryStream` accepts a configurable `flushIntervalMs` parameter: dashboard uses 5 s, queries page uses 2 s.

### Fixed
- Live chart bucket window now covers the full heartbeat interval instead of a fixed 1-second slice, so no query data is lost between heartbeat ticks.

## [0.5.0] - 2026-04-04

### Fixed
- Race condition in time-series aggregator: `Snapshot()` used a TOCTOU unlock-relock pattern that could miss or duplicate buckets under concurrent writes; replaced with a single held lock.
- Timer memory leaks in `AboutPage` and `ReportsPage` where `setTimeout` handles were not cleaned up on component unmount.
- `TopTracker` used an exclusive `sync.Mutex` for read-heavy paginated queries; switched to `sync.RWMutex` so concurrent top-list reads no longer block each other.

### Changed
- Dashboard chart computations (`useMemo`) now skip redundant re-renders when the underlying data has not changed.
- Operations page health polling uses a ref-based callback to break a stale-closure dependency cycle that could cause unnecessary re-fetches.
- React `ErrorBoundary` component wraps the entire application, catching render-time crashes with a user-friendly reload prompt instead of a blank screen.

### Internal
- Comprehensive code audit across all Go backend and React frontend modules; verified production-readiness of resolver, cache, security, server, and web subsystems.
- All frontend pages reviewed for hook correctness, cleanup, and dependency arrays.

## [0.4.8] - 2026-04-04

### Added
- Dashboard top list panels now support server-side pagination with larger inspection windows, so operators can browse up to 2000 ranked clients/domains directly from the UI.
- `Top Domains` rows now include inline cache query actions that open a modal and show per-type cache results without leaving the dashboard.

### Changed
- `DNS Resolver Matrix` is now streamlined into a high-signal default view (4 core cards) with optional expand/collapse for secondary metrics.
- `Query Type Counters` redesigned into a compact footprint to reduce visual noise while preserving quick type distribution visibility.
- Dashboard control toolbar (refresh/auto/ws chips) is hidden by default and can be toggled from the title area.
- `Traffic Stability & QPS Over Time` now renders on a 1-second UI heartbeat while keeping backend polling lightweight, reducing chart freeze during high-variance traffic spikes.

### Performance
- Default top tracker retention increased to `2000` for clients/domains (`web.top_clients_limit`, `web.top_domains_limit`) to match high-cardinality operational monitoring needs.
- Time-series aggregation interval moved from 10s to 1s for smoother and more responsive dashboard trend lines.

### Fixed
- Web update endpoint now handles read-only filesystem installs gracefully and returns a clear operator hint instead of a generic temp-file failure.

## [0.4.7] - 2026-04-04

### Added
- Dashboard now includes a DNS-first telemetry composition with richer resolver visuals: `DNS Resolver Matrix`, `Security Snapshot`, and `Response Codes` donut.
- Top list APIs now support pagination metadata and windowing for large lists: `limit`, `offset`, `total`, and `has_more`.
- New backend tests for top-list pagination and API limit/offset behavior.

### Changed
- Dashboard information hierarchy was rebuilt to prioritize live DNS resolver signals over host-level system details.
- Reports page now supports large top-list inspection (`Top limit` up to 1000) with in-table filtering for clients and domains.
- Top tracker retention is now decoupled from small UI card defaults so high-cardinality client/domain rankings remain queryable.

### Performance
- Top list tracking capacity is elevated (minimum 1000 retained keys) to avoid early pruning under active traffic and improve observability depth.

## [0.4.6] - 2026-04-04

### Changed
- Dashboard traffic chart now merges live WebSocket query events into the active 10-second bucket, so QPS/queries/errors move in near real time instead of waiting for the next poll cycle.
- Dashboard aggregate counters continue to use a hybrid model (polled baseline + live delta overlay) for smoother and faster on-screen updates.

### Performance
- Kept high-frequency telemetry on WebSocket stream path while preserving periodic polling only for heavier profile/toplist endpoints.

## [0.4.5] - 2026-04-04

### Changed
- Backend cache eviction path optimized in the sweeper to use shard eviction heaps instead of full shard map scans on each cycle.
- Dashboard system profile now prefers DNS listen addresses for `Primary Listen IP` and listen badges, instead of arbitrary interface order.
- Dashboard and layout theme classes were aligned for light/dark parity to avoid dark-only artifacts in light mode.

### Fixed
- Expired NXDOMAIN sentinel entries are now deleted correctly on lookup miss-expiry path (type-agnostic negative cache key handling).
- Negative cache writes are now tracked in the eviction queue, improving consistency between capacity eviction and sweep eviction.
- Mobile sidebar close button now follows theme-aware hover/text classes in light mode.

### Performance
- Cache sweep complexity for the common case (mostly-fresh cache) reduced by popping only due heap heads per shard.
- Added sweep benchmark (`BenchmarkSweepMostlyFresh`) to guard hot-path regressions.

### Tests
- Cache package coverage raised to 100% with new eviction-heap and fallback sweep tests.
- Added dedicated tests for listen-address resolution and system profile response shape.

## [0.4.4] - 2026-04-04

### Changed
- Web UI dashboard redesigned to restore the high-density telemetry layout with improved top status chips, richer runtime blocks, and network throughput visibility.
- Dashboard traffic visualization improved with smoothing layers (moving average + EMA) to reduce noisy spikes while preserving real-time signal.
- Operations page received UX polish with clearer state chips and explicit last-refresh visibility.
- Reports page improved with faster snapshot feedback and clearer export context.

### Fixed
- `update.sh` now supports forced reinstall behavior even when the installed version matches the target release.
- `install.sh` messaging now clearly reflects same-version reinstall support.

## [0.4.3] - 2026-04-04

### Added
- New Web UI `Operations` page for live reliability monitoring with configurable thresholds (error rate and latency), auto-refresh control, and incident surfacing.
- New Web UI `Reports` page for operational snapshot exports (JSON, CSV, Markdown) including top clients/domains and time-series data.
- Expanded backend and Web API test suites for system profile, update paths, cache APIs, and additional server handlers.

### Changed
- Dashboard server profile panel now prioritizes actionable runtime visibility (CPU, memory, disk, network and traffic snapshot) without adding unnecessary polling load.
- Web UI navigation and layout refined to expose Operations, Reports, and About/Updates more clearly in the main menu.
- Update/version requests in the Web UI client are now deduplicated and short-term cached to reduce repeated API calls.

### Fixed
- Linux install/update flow alignment improved by standardizing release-facing scripts and docs to the latest tagged version.
- WebSocket reconnect behavior now uses exponential backoff to avoid aggressive retry loops under transient network failures.
- Version labeling and About/Update presentation consistency improved across the Web UI.

### Performance
- Frontend API layer now applies request timeouts and shared in-flight request handling for lower UI overhead.
- Dashboard and operations refresh logic avoids unnecessary duplicate calls while preserving near-real-time observability.

### Docs
- Installer/updater usage examples and man-page metadata updated for `0.4.3`.

## [0.4.2] - 2026-04-03

### Added
- New Web UI About page with project overview, build metadata, release links, and integrated update controls.
- Server profile API endpoint (`/api/system/profile`) with runtime, CPU, memory, disk, network, and traffic snapshot data.
- Dashboard server profile card with host/IP/runtime insights and resource usage bars.

### Changed
- Dashboard "Queries Over Time" visualization redesigned with smoother trend line, clearer overlays, and selectable time windows.
- Sidebar navigation refined to include a dedicated `About & Updates` entry.
- Application startup flow refactored by splitting large `main.go` responsibilities into focused modules.

### Fixed
- Version rendering now normalizes prefixed values (`vX.Y.Z`) to prevent duplicated prefixes like `vv0.4.1`.
- Cache eviction behavior improved with heap-based selection to avoid linear scans on larger cache sizes.
- Web UI footer/sidebar clutter reduced for cleaner navigation and more consistent information hierarchy.

## [0.4.1] - 2026-04-03

### Added
- Native DoH over HTTP/3 support on `/dns-query` via `web.doh3_enabled` (QUIC transport on the web listener address).
- Alt-Svc advertisement on HTTPS responses when HTTP/3 is enabled.

### Fixed
- DoT server shutdown reliability: `Accept()` now unblocks promptly on context cancel,
  preventing potential hang during graceful shutdown.
- Startup validation hardened:
  - `server.dot_enabled=true` now requires `server.tls_cert_file` and `server.tls_key_file`
  - `web.tls_enabled=true` now requires `web.tls_cert_file` and `web.tls_key_file`
  - `web.doh3_enabled=true` now requires `web.enabled=true`, `web.tls_enabled=true`, and web TLS cert/key
- YAML parser now supports UTF-8 BOM-prefixed files (common on Windows editors),
  fixing edge cases where the first key could be misparsed.
- Web UI lint issues fixed:
  - `useQueryStream` reconnect callback declaration order
  - synchronous `setState` calls inside effects in dashboard/docs pages

### Changed
- CI now runs frontend lint (`web/ui`, `website`) in addition to builds.
- CI step order adjusted to run Go vet/tests before `npm ci` to avoid `node_modules`
  Go package noise in `go test ./...` scope.
- Runtime warning added when DoH is enabled without web TLS configuration.

### Docs
- Website docs aligned to runtime behavior and config schema:
  - Correct config keys (`listen_addr`, `max_entries`, `qname_minimization`, etc.)
  - Correct WebSocket path (`/api/queries/stream`)
  - Correct health endpoint in web mode (`/api/system/health`)
  - Updated Signals documentation to match current implementation
- README expanded with encrypted DNS transport section (DoH/DoT),
  config examples, and `/dns-query` API documentation.

### Tests
- Added DoT shutdown regression test (`TestDoTServeCancelWithoutConnections`).
- Added YAML BOM parsing test (`TestParseYAMLUTF8BOM`).
- End-to-end smoke checks performed for DoH endpoint and DoT invalid-config fail-fast path.

## [0.3.0] - 2026-04-03

### Added
- Cache lookup `ALL` type — queries all cached record types for a domain in one request
  (default selection in web dashboard dropdown)

### Fixed
- QNAME minimization with `.tr`-style TLDs: when a minimized query (e.g., `net.tr NS`)
  gets NS records in the answer section instead of a proper referral, the resolver now
  retries with the full query name. Fixes resolution of domains like `dgn.net.tr`,
  `hurriyet.com.tr` and similar multi-level `.tr` domains.
- Serve-stale (RFC 8767): now correctly triggers on SERVFAIL results, not only on
  Go-level errors. Previously, upstream SERVFAIL bypassed stale serving entirely.
- EDNS0 FORMERR fallback (RFC 6891 §7): when an upstream server returns FORMERR
  (doesn't support EDNS0), the resolver retries without the OPT record.
- RRL slip now sets TC bit (RFC 1035): rate-limited clients receive a proper truncated
  response forcing TCP retry, instead of an empty NOERROR that looked like NODATA.
- NXDOMAIN now cached per name, not per (name, type) (RFC 2308 §3): a single NXDOMAIN
  response covers all query types for that name, reducing duplicate upstream queries.
- Glue records now cached with their wire TTL instead of hardcoded 3600s (RFC 2181 §5.4.1).
- Response truncation now cuts at record boundaries and zeroes section counts
  instead of slicing mid-record, producing valid DNS messages (RFC 1035 §4.1.1).
- Response classification: unrelated answer records (ANCount > 0 but no match for
  qname/qtype) now fall through to authority section checks instead of being treated
  as a valid answer.
- False loop detection for `.tr` and similar TLD nameserver queries — the same NS IP
  (e.g., `ns1.nic.tr`) serving multiple zone levels (`.tr`, `com.tr`, `net.tr`) was
  mistakenly flagged as a loop. Loop detection key now includes `currentZone`.
- NS address resolution now scans all answer records for A/AAAA instead of only
  checking `Answers[0]`, fixing failures when CNAME records precede the address record.
- QNAME minimization: minimized query returning NXDOMAIN now retries with the full
  query name per RFC 9156 §3, preventing false negatives for valid domains.
- Potential deadlock in NS address resolution when the inflight coalescer held a key
  that the NS hostname resolution also needed (e.g., `ns1.example.tr` while resolving
  under `example.tr`). NS address lookups now bypass the inflight deduplicator.
- Cache lookup in `selectAndResolveNS` now scans all cached records instead of only
  the first entry, fixing failures when the first cached record has corrupt RDATA.
- Upstream response question section validation: responses with mismatched qname/qtype
  are now rejected, hardening against off-path cache poisoning attempts.

### Changed
- Blocklist enabled by default in example configuration (`labyrinth.yaml`)

### Tests
- Comprehensive coverage boost across all core packages:
  security 100%, config 100%, dnssec 100%, dns 99.8%, cache 99.6%,
  blocklist 99.2%, metrics 98.9%, resolver 98.2%
- 100+ new test functions covering DNSSEC validation trust chain, blocklist
  manager lifecycle, cache negative entries, RRSIG/NSEC/NSEC3 pack/unpack,
  resolver edge cases (CNAME loops, ServFail retry, in-bailiwick NS, QMIN)
- Dead code removal in blocklist, cache, dnssec (unreachable defensive guards)
- Fixed flaky Windows TCP port binding in mock DNS test server

## [0.2.0] - 2026-04-03

### Added

#### DNSSEC Validation
- Full DNSSEC signature verification (RSA/SHA-256, ECDSA P-256/P-384, ED25519)
- New DNS record types: DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM
- Trust chain validation from IANA root KSK (key tag 20326) to signer zone
- DS digest verification (SHA-1, SHA-256, SHA-384)
- DO flag on upstream queries when DNSSEC enabled
- Bogus responses return SERVFAIL, Secure responses set AD flag
- DNSSEC metrics: secure/insecure/bogus counters on dashboard
- Config: `resolver.dnssec_enabled` (default: true)

#### DNS Blocklist / Filtering (Pi-hole style)
- Domain blocking with configurable sources (hosts, domain list, AdBlock Plus formats)
- Three blocking modes: NXDOMAIN, null IP (0.0.0.0/::), custom IP
- Wildcard blocking and whitelist overrides
- Periodic list refresh from remote URLs (configurable interval)
- Zero-latency blocking (checked before cache lookup)
- Full web dashboard: list management, quick block/unblock, domain check
- API: `/api/blocklist/{stats,lists,refresh,block,unblock,check}`

#### Analytics & Dashboard
- Top clients leaderboard (by query count, configurable limit)
- Top domains leaderboard (by query count, configurable limit)
- Global and per-client query numbering in live query stream
- Negative cache entries display with NXDOMAIN/NODATA badges
- Blocked queries stat card and DNSSEC status card on dashboard
- DNSSEC shield badges in query stream (green=secure, red=bogus)

#### Self-Update
- Automatic version check against GitHub Releases (configurable interval)
- One-click update from web dashboard with confirmation dialog
- Binary download, replacement, and automatic service restart
- Platform-specific restart: `syscall.Exec` (Unix), process spawn (Windows)
- Windows: rename running exe to `.old` before replacement
- Config: `web.auto_update` (default: true), `web.update_check_interval` (default: 24h)

#### Authentication & Security
- Password change via web UI (Configuration page)
- Minimum 8-character password validation with CLI error messages
- CLI `labyrinth hash` command with usage documentation
- Per-client cache bypass (`cache.no_cache_clients` CIDR list)

#### Operations
- About info: website + GitHub links in sidebar, user menu, CLI banner
- `update.sh` script for one-line server updates with automatic rollback
- Improved `install.sh` with v0.2.0 default config, bench tool download, banner
- Improved `uninstall.sh` with bench binary cleanup

### Fixed
- In-bailiwick NS resolution for TLDs like `.tr`, `.br`, `.uk` where nameserver
  hostnames are within the same zone (e.g., `ns71.ns.tr` for `.tr` zone)
- `formatNumber()` crash on undefined/null values
- Blocklist API returning 400 when feature is disabled (now returns 200 with empty data)
- Top clients/domains API returning raw array instead of `{entries: [...]}` wrapper
- Flaky JWT tampered signature test
- Data race in resolver test closures (atomic counters)

### Tests
- 90+ new tests across blocklist, dnssec, and dns packages
- Blocklist: matcher (16 tests), parser (16 tests) — exact, wildcard, whitelist, concurrency
- DNSSEC: verify (11 tests), DS (8 tests), trust anchor (3 tests), validator (11 tests)
- DNS: 15 DNSSEC record parser tests (DNSKEY, DS, RRSIG, NSEC, NSEC3, type bitmaps)

## [0.1.0] - 2026-04-02

### Added

#### DNS Resolver Core
- Complete recursive DNS resolution engine (root → TLD → authoritative)
- DNS wire protocol: full RFC 1035 message pack/unpack with name compression
- Support for record types: A, AAAA, NS, CNAME, SOA, MX, TXT, SRV, PTR, OPT
- EDNS0 support (RFC 6891) with UDP payload size negotiation and DO flag
- QNAME minimization (RFC 9156) for privacy
- 256-shard concurrent in-memory cache with TTL decay
- Negative caching (RFC 2308) with SOA minimum TTL extraction
- Serve-stale support (RFC 8767) — serve expired cache on upstream failure
- Cache eviction: TTL-based sweeper + max entries enforcement
- Request coalescing (singleflight) for concurrent same-domain queries
- UDP and TCP DNS server with concurrent request handling
- TCP fallback on truncated (TC=1) responses
- Upstream query retry with configurable attempts
- Transaction ID randomization via crypto/rand
- Source port randomization (new socket per upstream query)

#### Security
- Bailiwick enforcement — reject out-of-zone records
- Loop detection — NS visited set + CNAME chain tracking
- Per-IP token bucket rate limiter with cleanup
- Response Rate Limiting (RRL) with slip ratio
- Access Control Lists (CIDR allow/deny)

#### Web Dashboard
- Built-in web dashboard (React 19 + Tailwind CSS 4.1 + Recharts)
- JWT authentication (HMAC-SHA256) with bcrypt password hashing
- Interactive setup wizard for first-time configuration
- Dashboard page: real-time QPS chart, cache hit ratio, response code distribution
- Live DNS query stream via WebSocket (pausable, filterable)
- Cache management: lookup, flush, delete individual entries
- Configuration viewer
- Dark/light theme with responsive sidebar layout
- Embedded SPA via go:embed (single binary)

#### Integrations
- Prometheus-compatible /metrics endpoint
- Zabbix agent: HTTP endpoints + native TCP protocol (ZBXD)
- Health check (/api/system/health) and readiness probe
- Structured logging via slog (JSON and text formats)

#### Operations
- YAML configuration with environment variable overlay
- CLI flags for all common settings
- CLI subcommands: check, version, hash, daemon
- Graceful shutdown with configurable grace period
- SIGUSR1 cache flush / SIGUSR2 stats dump / SIGHUP reload (Unix)
- Daemon mode (Unix setsid + Windows detach)
- One-line installer script (install.sh)
- Uninstaller script (uninstall.sh)
- systemd service file with security hardening
- Dockerfile (multi-stage, non-root user)
- docker-compose.yml
- GitHub Actions CI (Linux/macOS/Windows matrix)
- Makefile with build, test, bench, fuzz, lint, docker, cross targets
- Man page (labyrinth.1)

#### Testing
- 415+ unit, integration, fuzz, and benchmark tests
- 97.6% test coverage (per-package: 4 packages at 100%, 3 at 99%+)
- Fuzz testing for wire protocol, name decoding, response classification
- Benchmark suite exceeding all performance targets
