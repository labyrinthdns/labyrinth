# LabyrinthDNS — Operator Runbook

_Date: 2026-07-13 · Corresponds to PLAN.md M7.3_

This document covers day-to-day operations, troubleshooting, and
maintenance procedures for LabyrinthDNS.

---

## Table of Contents

1. [Installation & First Run](#1-installation--first-run)
2. [Configuration](#2-configuration)
3. [Starting & Stopping](#3-starting--stopping)
4. [Monitoring](#4-monitoring)
5. [Signals Reference](#5-signals-reference)
6. [Performance Tuning](#6-performance-tuning)
7. [Troubleshooting](#7-troubleshooting)
8. [Upgrading](#8-upgrading)
9. [Backup & Recovery](#9-backup--recovery)
10. [Security Hardening](#10-security-hardening)

---

## 1. Installation & First Run

### Quick Install

```bash
# One-line install (Linux/macOS, as root)
curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | bash

# Open the dashboard:
# http://127.0.0.1:9153
```

The installer:
1. Detects OS/arch and downloads the correct binary from GitHub Releases
2. Installs to `/opt/labyrinth/bin/labyrinth`
3. Creates symlink at `/usr/local/bin/labyrinth`
4. Creates default config at `/etc/labyrinth/labyrinth.yaml`
5. Creates `labyrinth` user and group
6. Installs systemd service
7. Starts the service

### From Source

```bash
git clone https://github.com/labyrinthdns/labyrinth.git
cd labyrinth
cd web/ui && npm ci && npm run build && cd ../..
go build -ldflags="-s -w" -o labyrinth .
sudo ./labyrinth -config /etc/labyrinth/labyrinth.yaml
```

### Docker

The runtime default `web.addr: "127.0.0.1:9153"` is container-local, and the safe default below publishes only DNS. Before publishing the dashboard, set non-empty `web.auth` credentials and `web.addr: "0.0.0.0:9153"` in the mounted config; then add a host binding such as `-p 127.0.0.1:9153:9153` or place it behind an authenticated TLS reverse proxy.

```bash
docker pull ghcr.io/labyrinthdns/labyrinth:latest
docker run -p 53:53/udp -p 53:53/tcp \
  -v ./labyrinth.yaml:/etc/labyrinth/labyrinth.yaml:ro \
  ghcr.io/labyrinthdns/labyrinth:latest \
  -config /etc/labyrinth/labyrinth.yaml
```

### Docker Compose

See `docker-compose.yml` in the repository root.

### First Run — Setup Wizard

On first start with no config, the web dashboard shows an interactive
setup wizard:

1. **Welcome** — Server info and version
2. **Admin Account** — Set username and password
3. **Network** — Configure listen address and dashboard address
4. **DNS Settings** — Cache size, QNAME minimization
5. **Review & Apply** — Writes `labyrinth.yaml` automatically

The wizard is available at `http://127.0.0.1:9153`.

---

## 2. Configuration

### Config File Location

Default: `labyrinth.yaml` in the working directory.
Custom: `labyrinth -config /path/to/labyrinth.yaml`.

### Config Layering

Priority (highest to lowest):
1. CLI flags (`-listen`, `-web`, `-metrics`, `-log-level`, etc.)
2. Environment variables (`LABYRINTH_SERVER_LISTEN_ADDR`, etc.)
3. YAML file
4. Compiled defaults

### Full Config Reference

```yaml
server:
  listen_addr: ":53"            # DNS listener address
  metrics_addr: "127.0.0.1:9153"  # Legacy metrics (when web disabled)
  max_udp_size: 1232            # EDNS0 UDP buffer (Flag Day 2020)
  tcp_timeout: 10s              # Per-request TCP read/write deadline
  max_tcp_connections: 256      # Max concurrent TCP connections
  max_tcp_conns_per_client: 16  # Per-source TCP cap (slow-loris defence)
  max_dot_conns_per_client: 16  # Per-source DoT cap (slow-loris defence)
  tcp_pipeline_max: 100         # Max pipelined queries per TCP conn
  tcp_idle_timeout: 5s          # TCP idle connection timeout
  max_udp_workers: 10000       # Max concurrent UDP query goroutines
  graceful_shutdown: 5s         # Wait time before forced exit
  dot_enabled: false            # DNS-over-TLS (RFC 7858)
  dot_listen_addr: ":853"
  tls_cert_file: ""             # DoT TLS certificate
  tls_key_file: ""              # DoT TLS key

resolver:
  max_depth: 30                 # Max delegation depth
  max_cname_depth: 10           # Max CNAME chain length
  upstream_timeout: 2s          # Per-upstream query deadline
  upstream_retries: 3           # Retries per upstream
  max_queries_per_request: 200  # Total query budget per client request
  request_timeout: 20s          # Wall-clock deadline per request
  max_ns_names_per_delegation: 13  # NS count cap per delegation (NXNS defence)
  qname_minimization: true      # RFC 9156
  caps_for_id: true             # RFC 5452 §9.2 0x20
  prefer_ipv4: true
  dnssec_enabled: true
  dnssec_allow_sha1: false
  harden_below_nxdomain: true   # RFC 8020
  root_hints_refresh: 12h
  ecs_enabled: false            # EDNS Client Subnet (RFC 7871)
  ecs_max_prefix: 24            # IPv4 ECS prefix ceiling
  ecs_max_prefix_v6: 56         # IPv6 ECS prefix ceiling
  dns64_enabled: false          # DNS64/NAT64 synthesis (RFC 6147)
  dns64_prefix: "64:ff9b::/96"
  fallback_resolvers: []        # Backup resolvers (e.g. 8.8.8.8, 1.1.1.1)
  upstream_udp_buffer_size: 1232

cache:
  max_entries: 100000           # Max cache entries (across 256 shards)
  min_ttl: 5                    # Minimum TTL in seconds
  max_ttl: 86400                # Maximum TTL in seconds (1 day)
  negative_max_ttl: 3600        # Max negative cache TTL
  sweep_interval: 60s           # Expiry sweep interval
  serve_stale: false            # RFC 8767 serve-stale
  serve_stale_ttl: 30           # Extra TTL for stale entries
  stale_max_age: 86400          # Max age of stale entries (1 day)
  prefetch: true                # Background re-fetch near expiry
  no_cache_clients: []          # Client CIDRs bypassing cache

security:
  private_address_filter: false # Strip RFC 1918 answers
  rate_limit:
    enabled: true
    rate: 50                    # Queries per second per client
    burst: 100
  rrl:
    enabled: true
    responses_per_second: 5     # Response rate per (/24, qname, type)
    slip_ratio: 2               # 1:N slip ratio (TC=1)
    ipv4_prefix: 24
    ipv6_prefix: 56
  dns_cookies: false            # RFC 7873 server cookies
  dns_cookies_enforce: false    # §5.4 strict mode

web:
  enabled: true
  addr: "127.0.0.1:9153"
  doh_enabled: false            # DNS-over-HTTPS (RFC 8484)
  doh3_enabled: false           # DoH over HTTP/3
  tls_enabled: false
  tls_cert_file: ""
  tls_key_file: ""
  auto_tls: false               # Let's Encrypt auto-TLS
  auto_tls_domain: ""
  auto_tls_email: ""
  query_log_buffer: 1000
  top_clients_limit: 2000
  top_domains_limit: 2000
  alert_error_threshold_pct: 5
  alert_latency_threshold_ms: 250
  auto_update: true
  update_check_interval: 24h
  auth:
    username: ""                # Set during setup or configure explicitly
    password_hash: ""           # Generate with: labyrinth hash <password>

access_control:
  allow: []                     # e.g. 127.0.0.0/8, 10.0.0.0/8
  deny: []
  zones: []                     # Per-zone ACLs

blocklist:
  enabled: false
  lists: []                     # URL|format pairs
  refresh_interval: 24h
  blocking_mode: nxdomain       # nxdomain, null_ip, custom_ip
  custom_ip: ""
  whitelist: []

logging:
  level: info                   # debug, info, warn, error
  format: json                  # json or text

zabbix:
  enabled: false
  addr: ""                      # e.g. "127.0.0.1:10050"

daemon:
  enabled: false
  pid_file: "/var/run/labyrinth.pid"

cluster:
  enabled: false
  role: standalone              # standalone, master, secondary
  node_id: node-1
```

### Generate a Password Hash

```bash
labyrinth hash MySecurePassword123
```

### Validate Config

```bash
labyrinth -config /etc/labyrinth/labyrinth.yaml check
```

---

## 3. Starting & Stopping

### systemd (standard install)

```bash
# Status
systemctl status labyrinth

# Start
systemctl start labyrinth

# Stop
systemctl stop labyrinth

# Restart
systemctl restart labyrinth

# Enable on boot
systemctl enable labyrinth

# View logs
journalctl -u labyrinth -f
```

### Direct (no service)

```bash
# Start
labyrinth -config /etc/labyrinth/labyrinth.yaml

# Daemon mode (legacy flag form)
labyrinth -config /etc/labyrinth/labyrinth.yaml -daemon

# Daemon subcommands; flags must come before the command
labyrinth -config /etc/labyrinth/labyrinth.yaml daemon start
labyrinth -config /etc/labyrinth/labyrinth.yaml daemon stop
labyrinth -config /etc/labyrinth/labyrinth.yaml daemon status
```

### Docker

```bash
docker compose up -d
docker compose down
docker compose logs -f
```

---

## 4. Monitoring

Protected API examples below assume browser cookie authentication. For shell automation, first obtain a JWT from `POST /api/auth/login` and add `-H "Authorization: Bearer $TOKEN"` to protected `/api/*` calls.

### Web Dashboard

Open `http://127.0.0.1:9153` in a browser on the resolver host. The dashboard is loopback-only by default; configure `web.addr` and authentication before enabling remote access.

| Page | What to watch |
|------|--------------|
| **Dashboard** | Query rate, cache hit ratio, error rate, top domains, top clients |
| **Operations** | Per-metric trend lines with configurable thresholds and auto-refresh |
| **Reports** | Exportable snapshots (JSON, CSV, Markdown) |
| **About** | Version, build metadata, update availability |

### Prometheus Metrics

The standalone Prometheus endpoint is served on `server.metrics_addr` only when `web.enabled: false`. With the default web dashboard enabled, use the authenticated `/api/stats` endpoints for dashboard/API monitoring instead.

Standalone endpoint: `http://127.0.0.1:9153/metrics`

**Key metrics:**

| Metric | Type | What it tells you |
|--------|------|-------------------|
| `labyrinth_queries_total` | Counter | Total queries by type |
| `labyrinth_cache_hits_total` | Counter | Cache hit count |
| `labyrinth_cache_misses_total` | Counter | Cache miss count |
| `labyrinth_query_duration_seconds` | Histogram | Query latency distribution |
| `labyrinth_cache_entries` | Gauge | Current cache entry count |
| `labyrinth_uptime_seconds` | Gauge | Process uptime |
| `labyrinth_goroutines` | Gauge | Active goroutines |

### Zabbix

**HTTP Agent mode** (recommended):
```
http://labyrinth:9153/api/zabbix/item?key=labyrinth.cache.hit_ratio
```

**Native Agent mode**: Enable `zabbix.addr` in config for native
Zabbix agent protocol on TCP port 10050.

Available Zabbix keys:
- `labyrinth.queries.total`
- `labyrinth.cache.hits`
- `labyrinth.cache.misses`
- `labyrinth.cache.hit_ratio`
- `labyrinth.cache.entries`
- `labyrinth.upstream.queries`
- `labyrinth.upstream.errors`
- `labyrinth.uptime`
- `labyrinth.goroutines`

### Health Checks

```bash
# Health endpoint (returns 200 + JSON when healthy)
curl http://127.0.0.1:9153/api/system/health

# Readiness check
curl http://127.0.0.1:9153/api/system/version

# Prometheus metrics (standalone metrics mode: web.enabled=false)
curl http://127.0.0.1:9153/metrics
```

### Alert Thresholds

Configure in `labyrinth.yaml`:
```yaml
web:
  alert_error_threshold_pct: 5    # Alert when error rate > 5%
  alert_latency_threshold_ms: 250 # Alert when p99 latency > 250ms
```

---

## 5. Signals Reference

| Signal | Action | Use Case |
|--------|--------|----------|
| SIGINT/SIGTERM | Graceful shutdown | System stop, container stop |
| SIGUSR1 | Flush entire cache | After blocklist update, troubleshooting |
| SIGUSR2 | Log cache stats | Monitoring, debug |
| SIGHUP | No-op (logged) | Config reload hint (use API) |

```bash
# Flush cache
kill -USR1 $(pidof labyrinth)

# Dump cache stats to log
kill -USR2 $(pidof labyrinth)
```

---

## 6. Performance Tuning

### Cache Sizing

The cache is 256-way sharded. Each entry consumes ~200-300 bytes.
At 100K entries: ~20-30 MB. At 10M entries (max clamp): ~2-3 GB.

```yaml
cache:
  max_entries: 500000  # Increase for high-traffic production
  min_ttl: 60          # Longer minimum reduces upstream load
  max_ttl: 604800      # 7 days for stable zones
  prefetch: true       # Keeps popular entries fresh
```

### Worker Sizing

```yaml
server:
  max_udp_workers: 10000     # Concurrent UDP handlers (semaphore)
  max_tcp_connections: 256   # Concurrent TCP connections
  tcp_pipeline_max: 100      # Queries per TCP connection
```

A single resolver on modern hardware handles ~50K QPS on UDP,
~10K QPS on TCP, and ~5K QPS with full DNSSEC validation.

### Latency tuning

```yaml
resolver:
  upstream_timeout: 500ms      # Tight for low-latency environments
  upstream_retries: 2          # Reduce retries for faster failure
  prefer_ipv4: true            # Avoid AAAA latency if IPv6 is slow
```

### Memory

- **Rate limiter**: 1M entry cap (~200 MB worst case)
- **RRL**: 1M entry cap (~200 MB worst case)
- **Top domains/clients**: 2000 entries each (negligible)
- **Query log buffer**: 1000 entries (~1 MB)

---

## 7. Troubleshooting

### Symptom: DNS queries timeout

**Check:**
```bash
# Is the process running?
systemctl status labyrinth

# Is it listening?
ss -tulpn | grep :53

# Can it resolve locally?
dig @127.0.0.1 example.com

# Logs
journalctl -u labyrinth -n 50 --no-pager
```

**Possible causes:**
- Upstream network connectivity issue
- `max_queries_per_request` or `request_timeout` too low
- Rate limiter blocking legitimate traffic (`rate_limit.rate` too low)
- RRL dropping responses (`rrl.responses_per_second` too low)
- Cache poisoned with stale entries (SIGUSR1 to flush)

### Symptom: SERVFAIL for specific domains

**Check:**
```bash
# Test with DNSSEC validation
dig @127.0.0.1 +dnssec example.com

# Test without DNSSEC
dig @127.0.0.1 +nodnssec example.com

# Test specific record type
dig @127.0.0.1 example.com A
dig @127.0.0.1 example.com AAAA
```

**Possible causes:**
- DNSSEC validation failure (check dnssec_reason in logs)
- Blocklist matching (check blocklist stats in dashboard)
- Forward zone misconfiguration
- Upstream timeout during resolution
- Request budget exhausted (CNAME chain too deep)

### Symptom: High memory usage

**Check:**
```bash
# Process memory
ps aux | grep labyrinth

# Cache stats (via API)
curl -s http://127.0.0.1:9153/api/cache/stats | jq

# Go memory profile (if available)
curl -s http://127.0.0.1:9153/debug/pprof/heap > heap.pprof
go tool pprof heap.pprof
```

**Actions:**
- Reduce `cache.max_entries`
- Increase `cache.sweep_interval`
- Reduce `rate_limit.burst` and `rrl.ipv4_prefix` / `rrl.ipv6_prefix`
- Flush cache: `kill -USR1 $(pidof labyrinth)`

### Symptom: Web dashboard unreachable

**Check:**
```bash
curl http://127.0.0.1:9153/api/system/health
curl -s http://127.0.0.1:9153 | head -5
```

**Possible causes:**
- `web.enabled` is false (using legacy metrics server)
- Firewall blocking port 9153
- TLS misconfiguration (`tls_cert_file`/`tls_key_file`)
- Dashboard bound to 127.0.0.1 and you're connecting remotely

### Symptom: High error rate / REFUSED responses

**Check:**
```bash
# Check ACL configuration
curl -s http://127.0.0.1:9153/api/config | jq '.access_control'

# Check rate limiter stats (metrics)
curl -s http://127.0.0.1:9153/metrics | grep labyrinth_rate_limit
```

**Possible causes:**
- ACL misconfiguration (client IP not in allow list)
- Rate limiter too aggressive (reduce rate, increase burst)
- Blocklist false positives (check whitelist)
- DNS cookie enforcement (disable or add client support)

### Symptom: Cache miss ratio too high

**Check:**
```bash
curl -s http://127.0.0.1:9153/api/cache/stats | jq
```

**Actions:**
- Increase `cache.max_entries`
- Enable `cache.prefetch`
- Increase `cache.max_ttl`
- Check `cache.no_cache_clients` list
- Increase `resolver.upstream_udp_buffer_size`

### Symptom: Blocklist not working

**Check:**
```bash
# Blocklist stats
curl -s http://127.0.0.1:9153/api/blocklist/stats | jq

# Test domain
curl -s "http://127.0.0.1:9153/api/blocklist/check?domain=example.com" | jq

# Manual refresh
curl -X POST http://127.0.0.1:9153/api/blocklist/refresh
```

**Possible causes:**
- Blocklist source URL unreachable
- Format mismatch between URL and configured format
- Whitelist overriding the block
- `blocklist.enabled` accidentally false

### Debugging with live pipeline trace

The dashboard's **Diagnostics** page provides a live WebSocket trace
for any name: each iterative step, CNAME chase, and per-RRSIG DNSSEC
verdict streamed in real-time.

Toggle options:
- **Cache bypass** — force a fresh resolution
- **DNSSEC skip** — resolve without DNSSEC validation

---

## 8. Upgrading

### Automatic (via dashboard)

When `web.auto_update: true`, the dashboard checks for new releases
every 24 hours. The **About** page shows available updates and offers
a one-click upgrade (writes the new binary to `/opt/labyrinth/bin/`).

### Manual

```bash
# systemd install
curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | bash

# Docker
docker pull ghcr.io/labyrinthdns/labyrinth:latest
docker compose up -d

# From source
cd labyrinth
git pull
cd web/ui && npm ci && npm run build && cd ../..
go build -ldflags="-s -w" -o labyrinth .
sudo systemctl restart labyrinth
```

### Check version

```bash
labyrinth -version
# or
curl -s http://127.0.0.1:9153/api/system/version | jq
```

---

## 9. Backup & Recovery

### What to back up

| Item | Location | Frequency |
|------|----------|-----------|
| Config file | `/etc/labyrinth/labyrinth.yaml` | After every change |
| Auto-TLS certs | Configured `auto_tls_cache_dir` | Monthly |
| Blocklist data | Re-downloaded on restart | Optional |

### Recovery procedure

1. Reinstall via install.sh or Docker pull
2. Restore `labyrinth.yaml`
3. Start the service
4. Verify: `dig @127.0.0.1 example.com`
5. Open dashboard and check stats

### Data loss considerations

- **Cache is ephemeral** — all entries are in-memory and lost on restart.
  The resolver warms up over ~10 minutes of traffic.
- **Config is persistent** — backed by YAML file on disk.
- **Blocklists re-download** — on next refresh interval after restart.

---

## 10. Security Hardening

### Recommended settings for production

```yaml
security:
  private_address_filter: true    # DNS rebinding protection
  dns_cookies: true               # Anti-amplification
  dns_cookies_enforce: false      # Enable only if all clients support cookies
  rate_limit:
    enabled: true
    rate: 100                     # Adjust to traffic patterns
    burst: 200
  rrl:
    enabled: true
    responses_per_second: 10
    slip_ratio: 2

access_control:
  allow:
    - 10.0.0.0/8                  # Only your networks
    - 172.16.0.0/12
    - 192.168.0.0/16

resolver:
  dnssec_enabled: true            # Always enable DNSSEC
  dnssec_allow_sha1: false        # Reject SHA-1
  caps_for_id: true               # 0x20 anti-spoofing
  harden_below_nxdomain: true     # RFC 8020
  max_queries_per_request: 200    # NXNS defense
  request_timeout: 20s

server:
  max_udp_size: 1232              # Flag Day 2020
```

### Network security

- Run behind a firewall — restrict DNS port (53) and web port (9153)
- Use TLS for the web dashboard (auto_tls or reverse proxy)
- For DoT/DoH, always use valid TLS certificates
- Set up Prometheus alerting for error rate and latency thresholds
- Regularly update dependencies (`go get -u` on core packages)

### Hardening checklist for v1.0.0

- [ ] DNSSEC validation enabled
- [ ] Rate limiting and RRL enabled
- [ ] ACL restricting client access
- [ ] Private address filter enabled (if public-only resolver)
- [ ] DNS cookies enabled
- [ ] Minimal EDNS0 buffer size (1232)
- [ ] QNAME minimization enabled
- [ ] 0x20 case randomization enabled
- [ ] Harden-below-NXDOMAIN enabled
- [ ] Request budgets configured
- [ ] Per-source TCP/DoT connection caps enabled (default 16)
- [ ] Delegation NS-name limit enabled (default 13)
- [ ] Cache prefetch enabled
- [ ] Serve-stale enabled (optional)
- [ ] Web dashboard behind TLS
- [ ] Strong admin password (bcrypt, 12+ characters)
- [ ] Regular security updates
- [ ] Logging at info level or higher
- [ ] Monitoring and alerting configured

---

## Appendix: Useful Commands at a Glance

```bash
# Quick status
systemctl status labyrinth
labyrinth -config /etc/labyrinth/labyrinth.yaml daemon status

# Validate config
labyrinth -config /etc/labyrinth/labyrinth.yaml check

# Generate password hash
labyrinth hash "NewPassword123"

# Flush cache
kill -USR1 $(pidof labyrinth)

# Cache stats
curl http://127.0.0.1:9153/api/cache/stats

# Test resolution
dig @127.0.0.1 +dnssec example.com
dig @127.0.0.1 example.com A +short

# View real-time queries (WebSocket)
# Open http://127.0.0.1:9153/queries

# Export report
curl http://127.0.0.1:9153/api/stats > stats.json

# Check for updates
curl http://127.0.0.1:9153/api/system/update/check

# Prometheus metrics
curl http://127.0.0.1:9153/metrics
```
