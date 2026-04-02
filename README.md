# Labyrinth

**Pure Go Recursive DNS Resolver — Zero Dependencies, Single Binary**

*"Follow the thread through the DNS labyrinth."*

---

## Features

- **Zero external dependencies** — only Go standard library
- **Single binary** — `go build` produces one statically compiled binary
- **Recursive only** — navigates root → TLD → authoritative, caches results
- **RFC compliant** — RFC 1035, 2308, 3596, 6891, 8767, 9156
- **Secure** — bailiwick enforcement, loop detection, rate limiting, TXID/port randomization
- **Observable** — structured logging (JSON/text), Prometheus `/metrics`, `/health`, `/ready`
- **Fast** — sharded cache, >22M cache reads/sec, <50µs cache hit latency

## Quick Start

```bash
# Build
go build -o labyrinth .

# Run (listens on :53 UDP+TCP, metrics on :9153)
sudo ./labyrinth

# Test
dig @localhost google.com A
```

## Installation

### From Source

```bash
git clone https://github.com/labyrinth-dns/labyrinth.git
cd labyrinth
go build -ldflags="-s -w" -o labyrinth .
```

### Docker

```bash
docker build -t labyrinth .
docker run -p 53:53/udp -p 53:53/tcp -p 9153:9153 labyrinth
```

### Docker Compose

```bash
docker-compose up -d
```

## Configuration

Labyrinth works with zero configuration. For customization, create `labyrinth.yaml`:

```yaml
server:
  listen_addr: "0.0.0.0:53"
  metrics_addr: "127.0.0.1:9153"

resolver:
  max_depth: 30
  qname_minimization: true

cache:
  max_entries: 100000
  min_ttl: 5
  max_ttl: 86400
  serve_stale: false

security:
  rate_limit:
    enabled: true
    rate: 50
    burst: 100

logging:
  level: info
  format: json
```

Configuration priority: CLI flags > environment variables > YAML file > defaults.

### Environment Variables

```
LABYRINTH_SERVER_LISTEN_ADDR=:53
LABYRINTH_LOGGING_LEVEL=debug
LABYRINTH_CACHE_MAX_ENTRIES=200000
```

### CLI Flags

```
labyrinth [flags]
  -listen       Listen address (default ":53")
  -metrics      Metrics HTTP address (default "127.0.0.1:9153")
  -config       Config file path (default "labyrinth.yaml")
  -log-level    Log level: debug|info|warn|error
  -log-format   Log format: json|text
  -cache-size   Max cache entries
  -version      Print version and exit
```

## Architecture

```
Client Query (UDP/TCP :53)
        │
        ▼
  Rate Limit → DROP (over limit)
        │
  Parse Wire Format
        │
  Cache Lookup → HIT → Response
        │
  Recursive Resolution (Root → TLD → Auth)
        │
  Bailiwick Validation
        │
  Cache Store
        │
  Response → Client
```

### Packages

| Package | Purpose |
|---------|---------|
| `dns/` | Wire format encode/decode, name compression, all RR types |
| `resolver/` | Recursive resolution engine, QNAME minimization |
| `cache/` | 256-shard concurrent cache with TTL decay |
| `security/` | Bailiwick, rate limiting, RRL, ACL |
| `server/` | UDP/TCP listeners, request handler |
| `config/` | YAML parser, env overlay, validation |
| `metrics/` | Prometheus-compatible metrics |
| `log/` | Structured logging via slog |

## Signals (Linux/macOS)

| Signal | Action |
|--------|--------|
| SIGINT/SIGTERM | Graceful shutdown |
| SIGUSR1 | Flush cache |
| SIGUSR2 | Dump cache stats to log |

## Monitoring

- `GET /metrics` — Prometheus text format
- `GET /health` — JSON health check
- `GET /ready` — Readiness probe (200 after root priming)

## Performance

Benchmarked on AMD Ryzen 9 9950X3D:

| Operation | ops/sec | Latency |
|-----------|---------|---------|
| Cache Get | 22M | 45 ns |
| Cache Set | 19M | 53 ns |
| Wire Unpack | 4.4M | 225 ns |
| Wire Pack | 2.6M | 391 ns |
| Name Decode | 22.6M | 44 ns |
| FNV-1a Hash | 331M | 3 ns |

Binary size: **6.2 MB** (stripped, Windows/amd64)

## RFC Compliance

| RFC | Title | Coverage |
|-----|-------|----------|
| 1035 | Domain Names | Full |
| 2181 | DNS Clarifications | Full |
| 2308 | Negative Caching | Full |
| 3596 | DNS IPv6 (AAAA) | Full |
| 5452 | DNS Resilience | Full |
| 6891 | EDNS0 | Full |
| 8767 | Serving Stale Data | Optional |
| 9156 | QNAME Minimization | Full |

## Development

```bash
make build        # Build binary
make test         # Run tests
make bench        # Run benchmarks
make fuzz         # Run fuzz tests (60s)
make lint         # go vet + staticcheck
make docker       # Build Docker image
make cross        # Cross-compile linux/darwin/windows
```

## License

MIT
