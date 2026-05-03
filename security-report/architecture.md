# Architecture Map — LabyrinthDNS

## Project Identity
- **Name**: LabyrinthDNS (`labyrinth`) — Pure-Go recursive DNS resolver with embedded React management UI
- **Version**: web/ui v0.6.1
- **Module**: github.com/labyrinthdns/labyrinth
- **Repo type**: Public OSS, MIT (DNS server + management dashboard + marketing site)

## Tech Stack
| Layer | Stack |
|-------|-------|
| Backend | Go 1.26.1, std net/http, custom DNS wire codec |
| Backend deps | quic-go v0.59.0 (DoQ), nhooyr.io/websocket v1.8.17, golang.org/x/{crypto,net,sys,text} |
| Frontend (admin UI) | React 19.2, TypeScript 5.9, Vite 8, Recharts, react-router-dom 7 |
| Frontend (marketing) | React (separate `website/` tree, GitHub Pages) |
| Build | go build (single binary, embed.go for UI), Vite for UI, Docker (alpine 3.20) |
| CI/CD | GitHub Actions (release.yml, website.yml) |

## Application Type
- DNS server: recursive resolver listening UDP+TCP :53
- HTTP services on the same binary:
  - `/metrics` Prometheus endpoint
  - Web management dashboard (auth-gated, embedded SPA)
  - DoH endpoint (`web/api_doh.go`)
  - Zabbix integration (`web/api_zabbix.go`)
- Daemon mode (Unix double-fork, pidfile)

## Detected Entry Points
- DNS UDP listener (server/udp.go)
- DNS TCP listener (server/tcp.go)
- DNS handler (server/handler.go) — request parse → ACL → rate-limit → cache → resolver
- HTTP routes (web/*.go) — middleware chain in web/middleware.go
- Authentication: bcrypt password hash; session cookie; setup wizard (`web/api_setup.go`)
- Public APIs: `api_queries.go`, `api_system.go`, `api_blocklist.go`, `api_zabbix.go`, `api_doh.go`, `querylog.go` (WebSocket), `update_unix.go`
- CLI subcommands: `version`, `check`, `hash <password>`, `daemon {start|stop|status}`
- Cmd: `cmd/labyrinth-bench` standalone benchmark CLI

## Detected Languages
- Go (server, daemon, DNS protocol, resolver, cache, security, blocklist, dnssec, web API)
- TypeScript / TSX (admin SPA in `web/ui/`, marketing in `website/`)

## Detected Frameworks
- net/http (Go stdlib only)
- nhooyr.io/websocket (WebSocket)
- React 19, react-router-dom 7
- Tailwind CSS 4
- Vitest, @testing-library/react

## Security-Relevant Surface
- DNS wire parser (`dns/`) — high-risk parsing surface, fuzz tests present
- Bailiwick / loop / ACL / rate-limit / RRL (`security/`)
- DNSSEC validation (`dnssec/`)
- Cache (`cache/`) — sharded with TTL decay; cache poisoning vector if parser weak
- Blocklist matcher (`blocklist/`) — host/RPZ feed handling; URL fetching
- Web auth + session (`web/middleware.go`, `web/api_setup.go`)
- Update endpoint (`web/update_unix.go`) — privileged self-update flow
- Daemon (`daemon/`) — pidfile, signal-based reload

## Infrastructure / IaC
- Single-stage Dockerfile (`Dockerfile`) — runs as non-root user `labyrinth`
- GitHub workflows — `release.yml` (binary + Docker publish to ghcr.io), `website.yml` (Pages deploy)
- No Kubernetes manifests, no Terraform

## Build/Deploy Artifacts
- `embed.go` — embeds compiled UI into binary
- `install.sh` — referenced in release notes (not yet read)
- `labyrinth.service` — systemd unit at repo root

## Notes for Hunt Phase
- Skill activations driven by stack: `sc-lang-go`, `sc-lang-typescript`, `sc-docker`, `sc-ci-cd`. No Python/PHP/Rust/Java/C# scanners needed.
- High-risk areas to focus: DNS parsing, cache poisoning vectors (TXID/source-port/bailiwick), upstream verification, web auth/session, DoH endpoint, blocklist URL fetcher, self-update path, pidfile race, signal handling, embedded UI XSS via untrusted data, CSRF on state-changing endpoints.
