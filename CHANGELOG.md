# Changelog

All notable changes to Labyrinth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-04-02

### Added
- Complete recursive DNS resolution engine (root → TLD → authoritative)
- DNS wire protocol: full RFC 1035 message pack/unpack with name compression
- Support for record types: A, AAAA, NS, CNAME, SOA, MX, TXT, SRV, PTR, OPT
- EDNS0 support (RFC 6891) with UDP payload size negotiation
- QNAME minimization (RFC 9156) for privacy
- 256-shard concurrent in-memory cache with TTL decay
- Negative caching (RFC 2308) with SOA minimum TTL extraction
- Serve-stale support (RFC 8767) — serve expired cache on upstream failure
- Cache eviction: TTL-based sweeper + max entries enforcement
- UDP and TCP DNS server with concurrent request handling
- TCP fallback on truncated (TC=1) responses
- Upstream query retry with configurable attempts
- Transaction ID randomization via crypto/rand
- Source port randomization (new socket per upstream query)
- Bailiwick enforcement — reject out-of-zone records
- Loop detection — NS visited set + CNAME chain tracking
- Per-IP token bucket rate limiter with cleanup
- Response Rate Limiting (RRL) with slip ratio
- Access Control Lists (CIDR allow/deny)
- Structured logging via slog (JSON and text formats)
- Prometheus-compatible /metrics endpoint
- Health check (/health) and readiness probe (/ready)
- Root hint priming on startup
- YAML configuration with environment variable overlay
- CLI flags for all common settings
- Graceful shutdown with configurable grace period
- SIGUSR1 cache flush / SIGUSR2 stats dump (Unix)
- Dockerfile (multi-stage, non-root)
- docker-compose.yml
- systemd service file
- GitHub Actions CI (Linux/macOS/Windows)
- Makefile with build, test, bench, fuzz, lint targets
- Comprehensive test suite: unit, integration, fuzz, benchmark
