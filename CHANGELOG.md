# Changelog

All notable changes to Labyrinth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
