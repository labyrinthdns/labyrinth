# Changelog

All notable changes to Labyrinth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-04-03

### Fixed
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

### Changed
- Blocklist enabled by default in example configuration (`labyrinth.yaml`)

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
