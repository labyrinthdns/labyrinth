# Changelog

All notable changes to Labyrinth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.7.50] - 2026-05-28

### Hardened
- **64 KiB cap on cluster fanout peer-response body drain** — `fanoutCacheFlush` drains the response body via `io.Copy(io.Discard, resp.Body)` so the connection can be reused by HTTP keep-alive (Go's HTTP/1.x contract requires the body be drained before close to reuse the conn). Without a size cap, a malicious or buggy cluster peer can stream a multi-gigabyte body and pin the resolver's goroutine + memory until the 5s client timeout fires — possibly after consuming gigabytes of network bandwidth. The drain now wraps the body in `io.LimitReader(resp.Body, 64<<10)`; 64 KiB is well above any legitimate fanout response (a few hundred bytes of JSON status). Pin in [web/api_cache_fanout_cap_test.go](web/api_cache_fanout_cap_test.go) stands up a fake peer streaming 1 MiB and asserts fanout completes in well under the 5s timeout.

## [0.7.49] - 2026-05-28

### Hardened
- **100-connection semaphore cap on the Zabbix ZBXD TCP listener** — the agent's accept loop spawned an unbounded goroutine per accepted connection. Each goroutine lives up to 10 s (the per-conn read deadline), so an attacker opening many concurrent connections could force unbounded goroutine + file-descriptor pressure on the resolver. Production Zabbix deployments poll from 1–3 monitoring stations, so a 100-conn cap is well above any legitimate workload and small enough that the worst-case footprint is bounded. Implemented as a semaphore channel — when full, `Accept()` blocks at `sem <- struct{}{}` rather than spawning new goroutines, and the kernel-side listener backlog absorbs the burst.

## [0.7.48] - 2026-05-28

### Hardened
- **Zabbix ZBXD agent: length cap + no-reflection on unknown keys** — the raw TCP ZBXD listener (the unauthenticated variant of v0.7.47's `/api/zabbix/item`) carried the same two log-injection gaps. It echoed the user-supplied key back through the `ZBX_NOTSUPPORTED\x00<reason>` payload that Zabbix server logs verbatim, and had no length cap (the 1024-byte read buffer was the only bound). Reflection on this listener is materially worse than on the HTTP variant because the listener has NO authentication and is typically reachable from anywhere on the operator's internal network. Now (a) keys longer than `maxZabbixKeyLength` (256 bytes) get an empty ZBXD reply with no payload, and (b) the unknown-key branch emits a generic `ZBX_NOTSUPPORTED\x00unknown key` payload that no longer carries attacker-controlled bytes into Zabbix server logs. Pins in [web/api_zabbix_agent_test.go](web/api_zabbix_agent_test.go) drive the handler via `net.Pipe()` and assert the sentinel string is not present in either response shape.

## [0.7.47] - 2026-05-28

### Hardened
- **`/api/zabbix/item?key=…` — length cap, no-reflection error, no-store header** — the Zabbix item endpoint had three small but real hygiene gaps. (1) No length cap on the `key` query parameter — a multi-MB key would only ever land on the "unknown key" branch but until the cap it was reflected back in the response, billed CPU on the snapshot path, and consumed log/response bandwidth. Now capped at 256 bytes (real Zabbix keys are short identifiers like `labyrinth.queries.total`). (2) Error response used to echo the attacker-controlled key (`"unknown key: <key>"`) — generic `"unknown key"` now. Endpoint is auth-gated so this is defence-in-depth, but reflecting attacker-controlled bytes into text/plain bodies that get piped into Zabbix log lines is a poor habit. (3) `Cache-Control: no-store` on both success and error responses so a scraping pipeline or intermediate proxy cannot serve a stale metric value during an incident. Pins in [web/api_zabbix_item_test.go](web/api_zabbix_item_test.go) cover all three: oversize key rejected, sentinel string never echoed back, no-store on success.

## [0.7.46] - 2026-05-28

### Hardened
- **Method gate + `Cache-Control: no-store` on standalone-mode `/health` and `/ready`** — the legacy standalone metrics server's `/health` and `/ready` handlers (used when the full admin UI is disabled and only Prometheus + a Kubernetes-style probe scrape the resolver) had neither a method check nor a Cache-Control header. POST/PUT/PATCH/DELETE all ran the full cache-stats / IsReady() path, and an intermediate cache could serve a stale "healthy" payload during an incident — a fake green dashboard at the worst possible moment. Both routes now refuse non-GET/HEAD with 405 + `Allow: GET, HEAD` and set `Cache-Control: no-store` on every successful response. Matches the contract already applied to the admin-server siblings (`/api/system/health`, `/api/system/readyz`, `/api/system/livez`).

## [0.7.45] - 2026-05-28

### Hardened
- **`Cache-Control: no-store` on every handler that bypasses `jsonResponse`** — three handlers in `api_tls.go` (TLS status, TLS renew, and the unauthenticated `/api/dns-guide`) wrote their JSON bodies directly via `json.NewEncoder` / `w.Write` rather than through the shared `jsonResponse` helper. That bypassed the `Cache-Control: no-store` header `jsonResponse` had been emitting since v0.7.20, leaving these three responses cacheable by intermediate proxies and the browser. The most operator-visible impact: an admin who flipped TLS/DoH on or off would see the OLD endpoint URL when reopening the setup-guide page, because the browser had cached the live-config payload. All three handlers now set the no-store header. Pin in [web/api_tls_no_store_test.go](web/api_tls_no_store_test.go) locks the contract on `/api/dns-guide`.

## [0.7.44] - 2026-05-28

### Fixed
- **Upstream UDP read buffer now scales with the advertised EDNS UDP size (silent truncation gap)** — `Resolver.queryUDP` had a hardcoded 4096-byte read buffer, but the resolver advertises the operator-configurable `UpstreamUDPBufferSize` (default 1232, capped at 65535) to upstream authoritative servers. When an operator raised the advertised size above 4096, the kernel still delivered only the first 4096 bytes of any compliant authoritative's UDP reply and silently discarded the rest — `dns.Unpack` then either errored on the truncated wire or, worse, parsed a structurally-valid but content-truncated message that the validator trusted. The fix sizes the read buffer to match the advertised EDNS UDP size with a 4096 floor for the legacy default path. Pin in [resolver/rfc6891_upstream_read_buffer_test.go](resolver/rfc6891_upstream_read_buffer_test.go) stands up a fake authoritative replying with a 6000-byte payload over the legacy 4096 cap and asserts the full payload reaches `queryUDP` when the advertised size is 8192.

## [0.7.43] - 2026-05-28

### Hardened
- **Method gate + `Cache-Control: no-store` on the `/metrics` endpoint** — the Prometheus exposition handler had no method check, so a POST/PUT/PATCH/DELETE flood at `/metrics` (which is often deliberately exposed to the public internet for scraping and cannot be authenticated) would still run the full snapshot path including iterating every counter map under the metrics lock. Now refuses anything except GET/HEAD with HTTP 405 + `Allow: GET, HEAD` before touching the lock. Also adds `Cache-Control: no-store` to the response so an intermediate cache cannot serve a stale Prometheus payload during an incident — a fake flat-line dashboard is worse than no data. Pins in [metrics/http_method_test.go](metrics/http_method_test.go) cover (a) POST/PUT/PATCH/DELETE all rejected with 405 + Allow header, (b) GET still produces the exposition body, (c) Cache-Control: no-store on every GET response.

## [0.7.42] - 2026-05-28

### Added
- **`Vary: Accept` header on every DoH response (RFC 8484 §5.1 + RFC 7234 §4.1)** — without this header, an intermediate cache (CDN or forward proxy) keyed on URL+Accept can reuse a stored `application/dns-message` body for a downstream client that asked for `application/dns-json` (or future formats), and the client rejects the payload as malformed. We only support dns-message today, but emitting the Vary header now makes the contract correct for every intermediary and future-proofs against adding dns-json. Pins in [web/api_doh_vary_test.go](web/api_doh_vary_test.go) cover (a) Vary: Accept on the POST response, (b) same on the GET response (independent companion pin in case a future refactor splits the two response-writing blocks).

## [0.7.41] - 2026-05-28

### Hardened
- **Slowloris timeouts on the standalone metrics HTTP server (legacy mode)** — the standalone `cfg.Server.MetricsAddr` listener (used when the admin UI is disabled and only Prometheus scrapes the resolver) was constructed via `http.ListenAndServe(addr, mux)` — the well-known Go footgun that leaves every timeout at zero. An attacker reaching the metrics port (which is often explicitly exposed for Prometheus scrapers, and Prometheus scrapers cannot authenticate) could hold thousands of half-open connections sending one byte every few seconds and exhaust the resolver's file descriptors. Now matches the admin server's timeout regime: `ReadHeaderTimeout: 10s`, `ReadTimeout: 15s`, `WriteTimeout: 30s`, `IdleTimeout: 60s`.

## [0.7.40] - 2026-05-28

### Hardened
- **2000-entry page cap on `/api/cache/negative?limit=…`** — the negative-cache admin endpoint was the only paginated admin route without an upper bound on the `limit` query parameter. The other paginated routes (top-clients, top-domains, recent queries) all carry hard caps because negative-cache iteration is O(n) and the serialised JSON response scales proportionally — a single `?limit=1000000` would force the resolver to iterate millions of entries and balloon both CPU and the response payload. Now clamped to `maxNegativeCachePage` (2000), matching the order of magnitude of the other paginated admin caps. Pin in [web/api_cache_negative_cap_test.go](web/api_cache_negative_cap_test.go) asserts an oversize limit value is clamped and the handler returns 200 without OOM/hang.

## [0.7.39] - 2026-05-28

### Hardened
- **Non-positive `window` / `interval` rejected on `/api/stats/timeseries`** — `time.ParseDuration` happily returns negative or zero durations for inputs like `-5m` or `0s`. The downstream `Snapshot` / `SnapshotAggregated` routines treat those as "no data" or produce empty bucket arrays — leaking the misleading impression to dashboards and Prometheus scrapers that the resolver has no traffic. The endpoint now refuses both with a clean 400 BEFORE the snapshot call rather than returning a silent empty 200. Pins in [web/api_stats_window_test.go](web/api_stats_window_test.go) cover (a) negative window rejected, (b) zero window rejected, (c) negative interval rejected, (d) negative control — a valid `5m` window still succeeds.

## [0.7.38] - 2026-05-28

### Hardened
- **64 KiB cap on the DoH GET `?dns=` parameter (RFC 8484)** — the POST surface was already capped at 65536 raw bytes via `io.LimitReader`, but the GET decode path read `r.URL.Query().Get("dns")` with no length validation. An attacker could `?dns=<megabytes of base64>` and the `base64.RawURLEncoding.DecodeString` call would expand that input to ~75 % of its size in RAM before the DNS parser even saw it — a memory-amplification gap that bypassed the POST cap entirely. `dohDecodeGet` now refuses parameters longer than `dohMaxGetParamBytes` (65536, matching the POST surface) with a clean error before any allocation. Pins in [web/api_doh_get_cap_test.go](web/api_doh_get_cap_test.go) cover (a) over-cap input rejected with a cap-mentioning error, (b) negative control that an under-cap parameter is not caught by the length gate.

## [0.7.37] - 2026-05-28

### Hardened
- **RFC 1035 §2.3.4 length cap on NTA install/remove `zone` parameter** — the negative-trust-anchor admin endpoints (`POST /api/dnssec/nta`, `DELETE /api/dnssec/nta?zone=…`) accepted arbitrary-length zone strings. The NTA store is consulted on every DNSSEC validation decision, so a malformed POST that persisted a multi-megabyte zone string would balloon memory AND make every validation pass slower forever. Both routes now reject anything longer than 255 octets with a clean 400. Pins in [web/api_dnssec_zone_cap_test.go](web/api_dnssec_zone_cap_test.go) cover both routes against a 4 KiB hostile zone.

## [0.7.36] - 2026-05-28

### Changed
- **UI password inputs honour bcrypt 72-byte cap (`maxLength={72}`) on Setup Wizard, Login, and Change Password forms** — pairs with the v0.7.35 backend gate. Without browser-level `maxLength` the user could type a 200-character "extra-secure" passphrase, see the input accept it, then receive a backend rejection on submit — a frustrating UX that hides the real reason. The HTML `maxLength` attribute makes the browser refuse keystrokes past 72, giving immediate feedback aligned with the backend contract. Setup Wizard now reads `8–72 characters` in its placeholder instead of `Minimum 8 characters` so the user understands both bounds. The Change Password form on ConfigPage carries `minLength={8}` + `maxLength={72}` so client-side validation rejects too-short and too-long inputs before the network round trip.

## [0.7.35] - 2026-05-28

### Hardened
- **bcrypt 72-byte truncation gate on password validation** — bcrypt has a hardcoded 72-byte input limit; bytes 73+ never participate in the hash. An operator who chose a 128-char "extra-secure" passphrase would learn only the hard way that the bytes past 72 were never protective, and that two passphrases sharing the same first 72 bytes are functionally interchangeable. `ValidatePassword` (and therefore `HashPassword` plus the setup wizard and `/api/auth/change-password`) now refuses inputs longer than 72 bytes with an explanatory error message that names the bcrypt limit and suggests using a password manager instead of a long passphrase. The mental-model gap was the security issue, not the truncation itself. Pins in [web/auth_password_cap_test.go](web/auth_password_cap_test.go) cover (a) 73-byte input rejected with a bcrypt-mentioning error, (b) 72-byte input at the cap accepted, (c) HashPassword refuses oversized input too (no silent truncation if a caller bypassed ValidatePassword), (d) pre-existing 8-byte minimum still enforced as a negative control.

## [0.7.34] - 2026-05-28

### Hardened
- **RFC 1035 §2.3.4 length cap on `/api/blocklist/{block,unblock,check}` domain inputs + validation moved before subsystem-nil check** — the three blocklist admin endpoints had no length cap on the `domain` field. A 1 MB POST body to `/api/blocklist/block` would persist that string into the in-memory blocklist set forever — balloons resolver memory while never matching a real query (real qnames cannot exceed 255 octets either). `/api/blocklist/check` lookups would also cost time proportional to the key length per call. Validation runs BEFORE the `s.blocklist == nil` check so malformed input is uniformly rejected with 400 regardless of whether the blocklist subsystem is configured (defence in depth — a lazily-initialised blocklist would otherwise silently swallow junk POSTs as success). Pins in [web/api_blocklist_name_cap_test.go](web/api_blocklist_name_cap_test.go) cover all three routes against a 4 KiB hostile domain.

## [0.7.33] - 2026-05-28

### Hardened
- **RFC 1035 §2.3.4 length cap on `/api/cache/lookup` and `/api/cache/entry` name parameters** — a fully-qualified domain name is capped at 255 octets on the wire; the admin cache endpoints previously accepted arbitrary-length query strings, letting a malformed or hostile admin URL feed multi-megabyte name parameters into `Cache.LookupAll`/`Cache.Lookup` and force allocation pressure proportional to the input size. The endpoints now reject any `name` longer than 255 octets with a clean 400 BEFORE normalisation runs. Pins in [web/api_cache_name_cap_test.go](web/api_cache_name_cap_test.go) cover (a) a 4 KiB name is rejected on the lookup route, (b) a name at exactly the 255-octet cap is NOT rejected (negative control — the gate must allow valid edges), (c) the same gate fires on the DELETE entry route.

## [0.7.32] - 2026-05-28

### Hardened
- **`X-Robots-Tag: noindex, nofollow` + `/robots.txt` (admin-surface deindex)** — Labyrinth's admin UI is internal infrastructure and must never appear in a public search index, even if an operator accidentally exposes the management port to the internet during commissioning or runs it on a routable cloud instance. The security headers middleware now emits `X-Robots-Tag: noindex, nofollow` on every response (the HTTP-header equivalent of `<meta name="robots" content="noindex,nofollow">`, honoured by every major crawler), and a new `/robots.txt` route returns the universal `User-agent: *` / `Disallow: /` block — a belt-and-braces approach because crawlers that hit a specific URL before fetching robots.txt still see the header. Pins in [web/robots_test.go](web/robots_test.go) lock both the `/robots.txt` body shape and the security middleware's X-Robots-Tag emission.

## [0.7.31] - 2026-05-28

### Hardened
- **`ReadHeaderTimeout` on both admin HTTP servers (slowloris defence)** — the admin server had `ReadTimeout`/`WriteTimeout`/`IdleTimeout` but no `ReadHeaderTimeout`, and the auto-TLS HTTP-01 challenge listener on `:80` had no timeouts at all. Slowloris attacks exploit the header-read phase: an attacker opens many connections and dribbles one byte every few seconds during HEAD transmission, holding sockets open without ever finishing a request. `ReadTimeout` does not fire mid-header because Go's net/http treats the whole request read as one window. The dedicated `ReadHeaderTimeout` caps the header phase specifically. The fix sets `ReadHeaderTimeout: 10s` (tighter than `ReadTimeout: 15s` so the slowloris-specific guard fires first) on both the admin server AND the previously timeout-free port-80 HTTP-01 listener. Pins in [web/server_timeouts_test.go](web/server_timeouts_test.go) cover (a) struct-level wiring of all four timeouts with ReadHeaderTimeout < ReadTimeout, (b) end-to-end behaviour — a half-open connection sending zero header bytes is closed within the configured window.

## [0.7.30] - 2026-05-28

### Hardened
- **50k cap on the login limiter's entries map (memory-DoS gate)** — `loginLimiter.entries` previously grew without bound: a botnet hitting `/api/auth/login` from a million distinct source IPs would balloon the map until the resolver ran out of RAM, and the 5-minute cleanup tick could not possibly keep up. The `allow()` path now refuses to insert a new IP once `loginMaxEntries` (50,000) is in the map — denying with `lockoutFor` as the Retry-After hint — so the worst-case footprint is bounded. Known IPs already tracked continue to be processed normally so a saturation event does not lock out legitimate operators. The 5-minute eviction tick still runs, so the saturation gate recovers automatically within a few cycles after the flood subsides. Pins in [web/login_limiter_saturation_test.go](web/login_limiter_saturation_test.go) cover (a) new-IP refusal when the map is full, (b) known-IP success while saturated (gate only refuses NEW entries), (c) full recovery after idle eviction fires.

## [0.7.29] - 2026-05-28

### Hardened
- **Body cap closed on the unauthenticated `/api/auth/login`, `/api/setup/status`, `/api/setup/complete` routes** — the 1 MiB body cap installed in v0.7.26 lived inside `requireAuth`, so anonymous routes (login, setup) bypassed it entirely. An unauthenticated attacker could POST a 1 GB JSON blob to `/api/auth/login` and force the resolver to allocate it into RAM before the decoder failed — a trivial OOM DoS that did not even require credentials. The cap is now a separate `withBodyCap` middleware applied at route registration to all three anonymous POST endpoints in addition to remaining inside `requireAuth`. Pins in [web/login_body_cap_test.go](web/login_body_cap_test.go) cover (a) the bare middleware caps reads at the limit, (b) under-cap bodies pass through unchanged, (c) the live `/api/auth/login` route registered on the real ServeMux returns a clean 4xx (not a 500/hang) when given an oversize body.

## [0.7.28] - 2026-05-28

### Added
- **Prometheus exposition `# HELP` + `# TYPE` for every metric family** — the `/metrics` exporter previously emitted bare `metric_name value` lines with no metadata. Without `# TYPE` PromQL's `rate()`, `increase()`, and `histogram_quantile()` functions silently fall back to "untyped" semantics, producing wrong results on counter overflow boundaries; without `# HELP` Grafana auto-doc shows blank descriptions and `promtool check metrics` flags every series as under-specified. The exporter now precedes each family with both lines describing its purpose and Prometheus type (counter/gauge/histogram). Pin in [metrics/http_help_type_test.go](metrics/http_help_type_test.go) walks the full list of 24 declared families and asserts both metadata lines precede their samples — a regression that adds a new series without metadata fails fast.

## [0.7.27] - 2026-05-28

### Hardened
- **Panic recovery at the `MainHandler.Handle` boundary — every transport now returns SERVFAIL on a crashing query path** — the existing `defer recover()` blocks in [server/udp.go](server/udp.go) and [server/tcp.go](server/tcp.go) only LOGGED the panic; the client received nothing (UDP) or a torn-down connection (TCP). On UDP this is a feedback-loop DoS: a deterministic panic causes the client to re-query, panic again, and never see an answer. The handler now wraps its body in `defer func() { if r := recover(); r != nil { ...; resp, err = h.buildError(query, dns.RCodeServFail) } }()` so panics escaping from the resolver, validator, cache, or any third-party transport (DoH/DoT/DoQ) become a clean SERVFAIL the client can actually act on. The SERVFAIL counter is incremented so a panic shows up in `labyrinth_responses_total{rcode="SERVFAIL"}` Prometheus alerts, not just in logs. Pins in [server/panic_recovery_test.go](server/panic_recovery_test.go) trigger a real nil-deref via a deliberately misconfigured handler (nil cache) and assert (a) no panic propagates out of `Handle`, (b) the response is SERVFAIL with QR=1, (c) the SERVFAIL counter increments — pre-recovery this test would crash the test process.

## [0.7.26] - 2026-05-28

### Hardened
- **1 MiB request-body cap on every authenticated API route** — without this gate an attacker (or a buggy automation script) POSTing a 1GB JSON blob would force the resolver to allocate 1GB of RAM before the decoder failed, a trivial OOM DoS against the admin API. The `requireAuth` middleware now wraps every request body with `http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)` so any handler attempting to read past the cap gets a clean `http.MaxBytesError`. 1 MiB is well above any legitimate request (the largest is a few-hundred-byte NTA install or blocklist domain list) and well below the threshold at which a single body would create memory pressure. New pins in [web/middleware_body_cap_test.go](web/middleware_body_cap_test.go) cover both the cap-triggers-error behaviour (positive) and the under-cap-passes-through behaviour (negative control — a regression that mangled small bodies would break every POST flow).

## [0.7.25] - 2026-05-28

### Added
- **`/api/system/livez` — liveness probe (always 200)** — completes the K8s probe pair (`livez` + `readyz`) so operators can wire `livenessProbe` and `readinessProbe` to distinct endpoints. Liveness asks "is the process alive at all"; the HTTP handler answering proves liveness. Tying livez to resolver-ready state would cause K8s to restart pods during slow root priming — the exact failure mode the liveness/readiness split is designed to prevent. Body-less, allocation-zero, no-store. Pins lock the 200-regardless-of-resolver-state contract and the 405 on non-GET.

## [0.7.24] - 2026-05-28

### Added
- **`/api/system/readyz` — body-less status-code-only readiness probe** — the conventional k8s.io/component-base/healthz signal. Returns 200 OK or 503 Service Unavailable with NO body so a Kubernetes-style probe scraping it costs zero JSON-encoder allocations and the response fits in a single TCP segment. Pairs with the existing `/api/system/health` (JSON body for operator-facing surfaces) — the new endpoint is for the hot probe path at 1Hz × pod-count. Pins in [web/api_readyz_test.go](web/api_readyz_test.go) lock the body-less contract, the 503 readiness response, and the no-store header.

## [0.7.23] - 2026-05-28

### Hardened
- **Kubernetes-style readiness contract on `/api/system/health`** — a degraded (resolver not primed) state now returns HTTP 503 Service Unavailable instead of HTTP 200 with `status:"degraded"` in the body. Kubernetes-style readiness probes gate traffic on status code ALONE; without 503 during startup priming a pod would receive client traffic before the resolver had primed the root NS cache, causing every initial query to SERVFAIL. New pin in [web/api_health_status_test.go](web/api_health_status_test.go) locks the 503 contract; pre-existing tests updated to expect either 200 or 503 depending on fixture state.

## [0.7.22] - 2026-05-28

### Added
- **Prometheus export — DNSSEC verdicts, blocked-queries, and per-EDE breakdown** — the existing Prometheus `/metrics` exposition was missing three counter families that observability tooling relies on: DNSSEC verdict ratio (operators alert on "Bogus rate > 0.1%"), blocked-query total (effectiveness of the blocklist surface), and the per-info-code EDE emission breakdown that v0.7.13 wired into the dashboard. New series are `labyrinth_dnssec_verdicts_total{verdict="secure|insecure|bogus"}`, `labyrinth_blocked_queries_total`, and `labyrinth_ede_emissions_total{code="N"}` — one series per code observed (zero-valued series deliberately omitted to keep the scrape lean). Pins in [metrics/http_export_test.go](metrics/http_export_test.go) lock the line shapes AND the negative control that no EDE series appears when none have been emitted.

## [0.7.21] - 2026-05-28

### Added
- **QCLASS != IN refused with EDE 21 (Not Supported)** — RFC 1035 §3.2.4 defines IN/CS/CH/HS classes; Labyrinth supports only IN. The handler previously let non-IN queries fall through to the resolver, which doesn't know about non-IN delegations — the resolution would fail with an unclear error. Now the gate refuses non-IN with REFUSED + EDE 21 so an operator debugging a misrouted client sees the right diagnostic. CHAOS-class probes like `version.bind. CH TXT` (a passive recon vector) are also refused — Labyrinth deliberately does not echo software identification. New [server/rfc1035_qclass_test.go](server/rfc1035_qclass_test.go) pins (a) RCODE = REFUSED, (b) EDE 21 in the response when the client speaks EDNS, (c) the per-EDE counter went up by exactly one, (d) a negative-control IN-class query is not gated.

## [0.7.20] - 2026-05-28

### Hardened
- **`Cache-Control: no-store` on every JSON API response** — without this header an intermediate proxy (Squid, a corporate forward proxy) or a misconfigured browser could serve a 30-second-old `/api/stats` payload as if it were current, masking a real failure during an incident. The single-line change in [web/middleware.go](web/middleware.go) flips `jsonResponse` to emit `no-store` on every reply (success AND error paths — a cached 401 after a successful re-auth would lock out the operator). New pins in [web/api_cache_control_test.go](web/api_cache_control_test.go) lock the header on both 200 and the full set of common error codes (400/401/403/404/500/503).

## [0.7.19] - 2026-05-28

### Added
- **DNSSEC safety-net values surfaced on `/dnssec`** — the two M5.5 caps (`max_rrsig_verify_attempts`, `max_trust_chain_depth`) are now exposed via `/api/dnssec.safety_net` and rendered as a card on the DNSSEC page. Operators can confirm the actual runtime values without grepping source — important when a future tuning patch lands and the operator needs to verify which value is in production. New `dnssec.MaxRRSIGVerifyAttempts()` and `dnssec.MaxTrustChainDepth()` accessors on the validator side keep the constants encapsulated.

## [0.7.18] - 2026-05-28

M5.5 (DNSSEC validation safety net, continued) + M4.6 (EDE counter wiring, integration pin).

### Hardened
- **Trust-chain depth cap (`maxTrustChainDepth = 32`)** — a hostile authoritative can publish an RRSIG whose `SignerName` carries an arbitrary label count; the trust-chain walker in [dnssec/validator.go:649](dnssec/validator.go) would issue a DNSKEY + DS fetch per chain step. A 127-label name (the RFC 1034 §3.1 theoretical maximum) would cost 128 round-trips per validation; an attacker pointing many queries at us could weaponise this. The new cap collapses any chain deeper than 32 to `Indeterminate` *before* the first network call fires. New pins in [dnssec/validation_chain_depth_test.go](dnssec/validation_chain_depth_test.go) confirm: (a) `buildZoneChain` growth is linear with label count, (b) a 200-label zone returns `Indeterminate` against a `nil` querier (cap engaged before any dispatch attempted; a leak would panic), (c) the cap value stays above the realistic-name upper bound so a future tighten-the-cap regression breaks the test.

### Tests
- **EDE counter integration pin** — new [server/rfc8914_ede_counter_integration_test.go](server/rfc8914_ede_counter_integration_test.go) closes the loop between the metrics-level `IncEDE` unit test (added in v0.7.13) and the handler-level emission. Issues an ACL-denied EDNS query against a real `MainHandler` and asserts (a) `EDECodeProhibited` count goes up by exactly 1, (b) NO other EDE counter moved (cross-counter contamination guard), (c) a second refusal increments by exactly 1 more (idempotence — not duplicated, not gated incorrectly).

## [0.7.17] - 2026-05-28

UI-M5.2 from PLAN.md — per-RFC counter widgets. The compliance matrix at `/compliance` now carries live evidence beside the static claims: every RFC entry that has a natural counter source displays its current value inline as a chip on the card.

### Added
- **`metrics` field on `ComplianceEntry`** — optional array of `{ label, source: 'stats'|'security', path }` records that link an RFC entry to one or more live counters. Path is dotted (e.g. `cookies.badcookie_responses`, `ede_counts.6`); the resolver walks one segment at a time and returns `undefined` for any missing/non-numeric leaf so a partial API response can't crash the matrix. Wired with metrics for: RFC 7873 §5.3/§5.4 (cookie cache hits/misses, outbound BADCOOKIE retries, strict-mode BADCOOKIE responses), RFC 8198 §5.2/§5.4 (NSEC + NSEC3 aggressive synth NX/NODATA), RFC 8767 (stale-while-refresh triggers), RFC 9520 (failure cache hits/misses), RFC 8914 (EDE 6/17/18 emission counts).
- **Path resolver helper** — new [web/ui/src/data/complianceMetricResolve.ts](web/ui/src/data/complianceMetricResolve.ts) carries `resolveMetricPath(obj, path)` with 8 vitest pins covering top-level lookup, nested traversal, missing segments, non-numeric leaves, null/undefined roots, and the EDE-counts numeric-key case (the `ede_counts` map uses decimal-string keys like `"6"` and the path `ede_counts.6` must resolve through them).
- **CompliancePage now polls `/api/stats` + `/api/security` every 15s** — failure to fetch is silent so the matrix itself still renders when the API is down; success rehydrates the metric chips. Chip carries the path as a `title=` tooltip so an operator inspecting a value can see the underlying counter name.

## [0.7.16] - 2026-05-28

M2.5 (Extended DNS Errors full table) — closes the remaining gap in the RFC 8914 §4 info-code registry: codes 28 (Unable to Conform to Policy) and 29 (Synthesized) are now defined and round-trip-tested. These two completed the IANA-registered set the resolver may need to surface as its emission paths evolve (policy-rejection of unsigned answers; aggregate signal for RFC 8198/DNS64-synthesised replies).

### Added
- **EDE codes 28 + 29** — new constants `EDECodeUnableToConformToPolicy = 28` and `EDECodeSynthesized = 29` in [dns/edns.go](dns/edns.go) with documentation explaining how each differs from the close-neighbour codes (EDE 28 is distinct from EDE 17 "Filtered" — the latter is the resolver's own policy refusing to forward; the former covers the case where the upstream's response itself violates a local policy gate the resolver enforces post-receipt). The Security page's friendly-name table in [web/ui/src/pages/SecurityPage.tsx](web/ui/src/pages/SecurityPage.tsx) gains the matching entries so any future EDE 28 or 29 emission reads as English to operators rather than "Unknown".
- **Wire-format roundtrip pin for all EDE codes** — new [dns/rfc8914_ede_roundtrip_test.go](dns/rfc8914_ede_roundtrip_test.go) walks the full 0-29 set via `BuildEDEOption` → `ParseEDEOption` and asserts both the numeric code and the extra-text survive the round trip verbatim. A second pin (`TestEDE_ParseRejectsTooShort`) confirms the §2 minimum-length gate (2-byte info code) rejects truncated option data rather than silently returning code 0.
- **IANA table pin extended to 0..29** — the existing [dns/rfc8914_ede_iana_table_test.go](dns/rfc8914_ede_iana_table_test.go) (renamed `TestEDECodes_IANA0Through29`) and its sibling distinctness check now cover the two new codes too.

## [0.7.15] - 2026-05-28

M3.4 partial (TCP fallback hardening) — two real cross-cut fixes on the UDP→TCP retry path.

### Hardened
- **RFC 7873 §5.4 cookie echo now applies to TCP retries** — when a UDP response carries TC=1 the resolver falls back to TCP, re-unpacks the response, and re-validates TXID + question. It did NOT re-validate the cookie. This left a small but real gap: an attacker who could intercept the TCP retry (e.g. on a compromised intermediate) would not be ejected even when the original UDP path was protected by the cookie check. [resolver/upstream.go:298](resolver/upstream.go) now runs `validateResponseCookie` on the TCP response too. The check is cheap (no DNSKEY fetch, just an EDNS option compare) so the overhead is invisible.
- **RFC 7766 §4 — TC=1 over TCP rejected** — RFC 7766 §4 says "The TC flag SHOULD NOT be set for responses arriving over TCP." A confused authoritative might still set TC=1 on its TCP answer; a naive resolver that loops on the TC bit without checking the transport would chain TCP retries forever. The new guard at [resolver/upstream.go:307](resolver/upstream.go) returns an explicit "RFC 7766 §4 violation" error rather than recursing. New pin in [resolver/rfc7766_tcp_fallback_test.go](resolver/rfc7766_tcp_fallback_test.go) stands up a mock auth that intentionally returns TC=1 on both UDP and TCP and asserts (a) the resolver makes exactly ONE TCP attempt (not infinity), (b) the returned error mentions the §4 violation.

## [0.7.14] - 2026-05-28

UI-M5.1 from PLAN.md — RFC compliance matrix as a first-class page.

### Added
- **`/compliance` route — dedicated compliance-matrix page** — the matrix that previously lived as a section on AboutPage is now its own destination, designed for an auditor's workflow: full-text filter, category-pivot chips, sort by RFC number / since-version (newest first) / category, and CSV+JSON export buttons. The data still comes from the single source of truth at [web/ui/src/data/rfcCompliance.ts](web/ui/src/data/rfcCompliance.ts) — the page is a view, not a duplicate. AboutPage's embedded matrix is unchanged so the linked-from-About entry point still works.
- **Compliance export builders** — new [web/ui/src/data/complianceExport.ts](web/ui/src/data/complianceExport.ts) carries `buildComplianceCSV` (RFC 4180 §2.6 quoting + §2.1 CRLF line endings, columns `rfc,section,title,category,category_label,since,summary`) and `buildComplianceJSON` (stamped with `generated_at`, includes the `category_labels` dictionary so a consumer doesn't have to know the internal taxonomy). 10 vitest pins in [web/ui/src/data/complianceExport.test.ts](web/ui/src/data/complianceExport.test.ts) lock the header row, quote-escaping, the missing-section/missing-since empty-cell convention, CRLF termination, and JSON validity.
- **Sidebar navigation** — `Compliance` link with the `BookOpen` icon sits alongside `Audit` in the left nav.

## [0.7.13] - 2026-05-28

M4.6 (Compliance counter scaffolding, partial) + UI-M6.3 (EDE breakdown) — operator-facing per-info-code visibility into Extended DNS Error emissions.

### Added
- **Per-EDE-code emission counters (RFC 8914 §4)** — every time the resolver emits an Extended DNS Error, [server/handler.go:1543](server/handler.go) calls the new `metrics.IncEDE(code)` so an operator can pivot the "what's failing today?" question on the info code rather than the opaque RCODE bucket. A spike on code 6 (DNSSEC Bogus) implicates upstream zones; on code 17 (Filtered) implicates rate-limiting biting real clients; on code 25 (Signature Expired Before Valid, RFC 9606) implicates a broken signer. Counter storage is `map[uint16]*atomic.Int64` with lazy allocation behind a double-checked write lock — bounded by the IANA EDE registry but absorbing future codes without code changes. New [metrics/rfc8914_ede_counters_test.go](metrics/rfc8914_ede_counters_test.go) pins per-code independence, concurrent increment correctness under 32×1000-write contention, and that `EDECounts()` returns a defensive snapshot copy callers can iterate without locks.
- **`/api/security` now carries `ede_counts`** — a `Record<string,number>` where string keys are decimal info codes. Empty map when no EDE has been emitted (the UI distinguishes "not yet seen" from "API broken"). String keys instead of uint16 so JSON consumers across languages can use them as map keys directly.
- **Security page EDE breakdown card** — new card on `/security` lists every observed EDE code sorted by count, with the IANA-registered friendly name next to the numeric code. Friendly-name table covers codes 0–27 (the full RFC 8914 + RFC 9606 + RFC 9539 + RFC 9276 §3.2 set this resolver currently emits). Codes the resolver hasn't emitted yet are absent rather than zero so the operator's eye lands on the active diagnostics.

## [0.7.12] - 2026-05-28

UI-M5.4 from PLAN.md — compliance export.

### Added
- **Audit timeline export (CSV + JSON)** — operators and downstream auditors can now download the full audit timeline directly from `/audit`. Two new buttons sit next to the in-page filter:
  - `Export CSV` produces an RFC 4180 §2.6-compliant CSV with the columns `version,date,theme,rfc,kind,summary` — quote-escaping for embedded commas/quotes/newlines and CRLF line endings (RFC 4180 §2.1) so Excel-style importers don't fold rows together. Filename is timestamped `labyrinth-audit-YYYY-MM-DD.csv`.
  - `Export JSON` produces a pretty-printed JSON object `{generated_at, releases[]}` where `releases` preserves the internal `AuditRelease` shape — downstream compliance tooling gets a stable contract without reverse-engineering the React data model.
  - The export logic lives in [web/ui/src/data/auditExport.ts](web/ui/src/data/auditExport.ts) (separated from the page component so it can be tested headlessly). New pin in [web/ui/src/data/auditExport.test.ts](web/ui/src/data/auditExport.test.ts) carries 12 vitest cases covering RFC 4180 escape rules, header/data-row count, CRLF termination, JSON validity, and timestamp injection.

## [0.7.11] - 2026-05-28

Opens M5.5 (DNSSEC validation safety net) from PLAN.md.

### Hardened
- **RRSIG verify-cap bounds worst-case crypto cost per RRset** — the validator's RFC 4035 §5.3.3 "walk every RRSIG until one validates" strategy is open to a CPU-exhaustion attack: a hostile authoritative can attach an arbitrary number of garbage RRSIGs to an answer, each forcing the validator to do a DNSKEY fetch + asymmetric verify. [dnssec/validator.go](dnssec/validator.go) now caps the number of expensive crypto verifications per RRset at 16 (`maxRRSIGVerifyAttempts`), comfortably above any realistic algorithm-rollover scenario (2 algorithms × 2 keys × incoming+outgoing = 8) while bounding the worst case an attacker can induce. When the cap engages the validator stops the loop and lets the trailing logic settle on Bogus or Indeterminate from the failures already observed — the safe collapse for "we cannot validate further". New pin in [dnssec/rfc4035_verify_cap_test.go](dnssec/rfc4035_verify_cap_test.go) feeds the validator 30 garbage RRSIGs (alg/key-tag/time-window all valid, signature bytes zeroed so VerifyRRSIG fails) and asserts (a) the verdict is Bogus, (b) a `verify-cap` step is emitted in the detailed step log, (c) the number of crypto verifications stayed at or below 16. A second pin (`DoesNotBlockNormalRollover`) checks the cap value is high enough that legitimate 2-algorithm rollovers cannot trip it — guards against a future refactor that tightens the cap too far.

## [0.7.10] - 2026-05-28

M6.2 from PLAN.md — second beat of the test-infrastructure milestone. Where v0.7.8 added fuzz coverage for parser inputs, this release adds *property-based* coverage for one of the most load-bearing transforms in DNSSEC: RFC 4034 §6.2 canonical RDATA.

### Added
- **Property-based pin for canonical RDATA (RFC 4034 §6.2)** — new [dnssec/rfc4034_canonical_property_test.go](dnssec/rfc4034_canonical_property_test.go) uses Go's `testing/quick.Check` to assert two invariants across 200 randomly generated inputs per type:
  - **Idempotence** — `canonicalRData(canonicalRData(x, t), t) == canonicalRData(x, t)`. Iterates random RDATA byte-arrays against every RR type the canonicaliser handles (CNAME, NS, PTR, DNAME, MX, SOA, RRSIG, SRV, NSEC) plus pure-binary types (A, AAAA, TXT) where idempotence is trivial. A regression that introduced an asymmetric transform (e.g. lowercasing only the first byte, or an off-by-one in the embedded-name length-walk) would surface as a counterexample because the second pass would produce different bytes than the first.
  - **Length preservation** — `len(canonicalRData(x, t)) == len(x)`. RFC 4034 §6.2 only permits 1:1 byte substitution (ASCII lowercasing of label payload); a regression that re-encoded names (decompressing pointers, inserting/removing a trailing dot, normalising name length) would break the surrounding RDLENGTH arithmetic on both verify- and sign-side. The pin also confirms the parser-rejection path preserves length — when `lowercaseWireName` fails to parse a malformed wire name, `canonicalRData` returns the original bytes verbatim rather than a truncated copy.

  Property tests sit one layer above unit tests: a unit test pins *known* inputs against *known* outputs, but a property test pins the *invariant* against the *generator*. Both layers are valuable — the unit tests catch known-shape regressions; the property tests catch shape-classes the author didn't think to write a unit test for. Because canonical RDATA is the byte foundation of every signature verify, both invariants are unconditional contracts of the function — a regression in either would silently produce signature failures on otherwise-valid responses.

## [0.7.9] - 2026-05-28

UI-M5.3 from PLAN.md — audit timeline as a first-class UI surface.

### Added
- **`/audit` dashboard page** — chronological per-release record of the RFC pin work. Renders the new hand-curated [web/ui/src/data/auditTimeline.ts](web/ui/src/data/auditTimeline.ts) as a newest-first list of release cards; each card carries `added` / `harden` / `fixed` badges with totals at the top of the page. In-page filter searches across RFC reference, summary, and kind so an operator answering "when did RFC 7646 land?" types `7646` and sees the v0.6.42 release card with one line of context. Source attribution: the data is curated by hand from CHANGELOG.md (which remains canonical); the timeline UI is a scannable index, not a replacement. Linked from the main sidebar via the `History` icon.

## [0.7.8] - 2026-05-28

Opens M6 (Test infrastructure) milestone from PLAN.md.

### Added
- **Fuzz harness for wire-format parsers** — new [dns/fuzz_parsers_test.go](dns/fuzz_parsers_test.go) hosts four `go test -fuzz=...` entry points covering the parsers most directly exposed to attacker-controlled bytes: `FuzzParseCookieOption` (RFC 7873 cookie option), `FuzzUnpackMessage` (top-level DNS wire), `FuzzParseDNSKEY` (DNSKEY RDATA), `FuzzParseDS` (DS RDATA). Each target carries a hand-curated seed corpus (canonical well-formed shapes + intentionally malformed shapes) so the fuzzer's mutation walk starts from both "near-valid" and "garbage" — covering both bug classes (length-field arithmetic errors near the validity edge and crash-on-junk errors). The invariants under test are panic-safety, no-out-of-bounds, and structural length contracts; semantic correctness stays in the dedicated parser tests. Operators can extend coverage by running `go test -fuzz=FuzzParseCookieOption -fuzztime=10m ./dns/` etc. — CI can wire this into a recurring job.

## [0.7.7] - 2026-05-28

### Hardened
- **RFC 8109 — Root hint priming query shape (two-pin set)** — two new pins in [resolver/rfc8109_root_priming_test.go](resolver/rfc8109_root_priming_test.go) lock the priming contract. The first instruments a mock root listener that captures the first inbound query and asserts QNAME = root (`""` or `"."`), QTYPE = NS (2), QCLASS = IN (1); a regression to QTYPE=A or QTYPE=ANY would still draw a NOERROR-empty from a real root but would leave the root NS cache empty, defeating the priming. The second pin (`SetsReadyFlag`) confirms `PrimeRootHints` marks the resolver Ready even when priming itself fails — a regression that gated Ready on cache.Store would deadlock startup under a root NS outage even though normal queries against pre-seeded zones could still serve.

## [0.7.6] - 2026-05-28

### Added
- **RFC compliance matrix refresh** — `web/ui/src/data/rfcCompliance.ts` now lists the seven RFCs added across v0.6.42 → v0.7.5: RFC 4035 §4.6 algorithm rollover, RFC 7344 + 8078 CDS/CDNSKEY, RFC 5011 full lifecycle, RFC 7646 NTA, RFC 8901 multi-signer, RFC 7873 §5.4 strict cookies, RFC 8467 §6 padding-only-on-encrypted. RFC 8914 entry reworded to reflect the IANA-0-through-27 backfill landed in v0.7.1. RFC 5452 entry now notes the v0.7.4 empirical source-port randomisation pin. The matrix is rendered on the About page and is the single user-visible record of what the resolver claims to implement; missing entries here were claims the operator couldn't see. Existing `rfcCompliance.test.ts` (rfc/title/summary/since/uniqueness pins) passes against the additions.

## [0.7.5] - 2026-05-28

UI-M6 (Security panel) — operator-facing visibility into the three
defensive knobs that decide whether the resolver can be turned into
an amplifier: DNS Cookies, per-IP rate limit, and per-prefix RRL.

### Added
- **`/api/security` endpoint** — surfaces cookie / rate-limit / RRL configuration and counters (BADCOOKIE responses, rate-limited drops, ACL-refused, blocklist-blocked) in a single payload. The cookie BADCOOKIE count sums both reasons it can fire (stale post-rotation cookie + §5.4 cookie-less UDP rejection) — disambiguation comes from the `enabled` / `enforce_strict_udp` flags also in the same payload, so the operator can interpret the count from one fetch instead of cross-checking config.
- **Security dashboard page** at `/security` — four cards (Cookies, Rate Limit, RRL, Access Control) with status badges and live counters; nav sidebar entry uses the `ShieldAlert` icon to differentiate from the existing `Shield` (Blocklist) and `ShieldCheck` (DNSSEC) routes. Polls every 10s. Each card carries a short explanatory caption tying the metric to its defensive purpose (e.g. "Per-client token-bucket. Limits user fairness, not amplification — use RRL for that.") so an operator looking at the page for the first time can tell the per-IP limit apart from RRL without leaving the page.

## [0.7.4] - 2026-05-28

### Hardened
- **RFC 5452 §10 — Outbound UDP source port randomisation (empirical pin)** — new pin in [resolver/rfc5452_source_port_test.go](resolver/rfc5452_source_port_test.go) fires 50 outbound `queryUDP` dials against a mock UDP server that captures every observed source port, then asserts at least 30 distinct ports were observed. The weakest invariant that catches every real failure mode (fixed port = 1 distinct, sequential allocation = small distinct, tuple-hashed = few distinct) without committing to a fragile statistical test. Also guards against a regression that bound outbound dials to a privileged port (< 1024) — that would fire the second assertion distinctly from the count assertion.
- **RFC 8901 — Multi-signer model pin** — new pin in [dnssec/rfc8901_multi_signer_test.go](dnssec/rfc8901_multi_signer_test.go) locks the multi-signer validation path: two independent operators each publish their own KSK at the apex; the parent (here represented by the trust-anchor edge) carries TWO DS records, one per operator's KSK; the answer is signed by ONE operator's ZSK and MUST validate. Structurally distinct from the v0.6.42 algorithm-rollover pin (one operator, two ZSKs) — the load-bearing new ground is the two-DS-records-at-the-parent path. Includes a negative control that drops every trust anchor to prove the chain is actually being walked rather than passing by accident.

## [0.7.3] - 2026-05-28

Closes part of M5 (DoS / security) from PLAN.md.

### Added
- **RFC 7873 §5.4 — Strict cookie enforcement mode (`security.dns_cookies_enforce`)** — operator opt-in: when true, a UDP query without a client cookie is answered with BADCOOKIE and the resolver mints a fresh server cookie for the client to replay on retry. This eliminates the last UDP amplification surface — spoofed sources cannot get answers at all until they prove one round trip. UDP-only by design: TCP / DoT / DoH already establish a stateful handshake that provides source validation, so the gate skips them. New `MainHandler.SetCookiesEnforce` setter; `MainHandler.cookiesEnforce` field; new `isUDPAddr` helper that gates on the `Network()` string (robust across DoH/TCP wrappers that surface client addrs as non-standard types). main.go now wires both `EnableCookies()` and `SetCookiesEnforce()` from config — previously the `security.dns_cookies` flag was dead because no caller invoked EnableCookies, so this also fixes a latent gap.
- **Four-corner truth-table pin in [server/rfc7873_cookie_enforce_test.go](server/rfc7873_cookie_enforce_test.go)**: `enforce=false / UDP / no cookie → answered` (default safe), `enforce=true / UDP / no cookie → BADCOOKIE` (the whole point), `enforce=true / UDP / cookie → answered` (client proved itself), `enforce=true / TCP / no cookie → answered` (TCP gate must NOT fire). The 3rd and 4th rows lock against the two most likely regressions: gating regardless of cookie presence (locks out legit clients) and gating regardless of transport (punishes every TCP/DoT/DoH client). Eight-case `isUDPAddr` truth table covers udp/udp4/udp6/tcp/tcp4/tcp6/unix/empty + nil sentinel.

## [0.7.2] - 2026-05-28

### Added
- **Runtime NTA management — `POST /api/dnssec/nta` + `DELETE /api/dnssec/nta?zone=…`** — operator can install / remove an RFC 7646 NTA without editing config and restarting. Request body: `{zone, duration_hours OR expires_at, reason}`. `duration_hours` is clamped to a 30-day ceiling so a UI typo cannot install a multi-year override. Already-past `expires_at` is rejected with 400. If the validator was started with no NTA store (operator did not set `resolver.dnssec_negative_trust_anchors`), the first runtime install lazily creates one — no restart required.
- **DNSSEC dashboard install / remove controls** — `/dnssec` page now shows the **Add Negative Trust Anchor** inline form (zone + hours + reason) and a per-row **Remove** action. Hours input capped at 720 (30 days). Successful add triggers an immediate refresh; remove asks for confirmation.

## [0.7.1] - 2026-05-28

Begins the M2 (Transport Modernization) milestone. The big-ticket
items (DoQ over QUIC, XFR over TLS) are deferred to dedicated point
releases because they introduce external dependencies; this release
delivers the pure-logic backbone.

### Added
- **RFC 8914 EDE codes 25-27 backfill** — three EDE info codes were assigned after the initial RFC 8914 table and were not yet defined locally: `EDECodeSignatureExpiredBeforeValid` (25, RFC 9606 — RRSIG whose Expiration < Inception; a signer bug rather than clock skew), `EDECodeTooEarly` (26, RFC 9539 — 0-RTT path the upstream could not safely replay), and `EDECodeUnsupportedNSEC3IterationsValue` (27, RFC 9276 §3.2 — NSEC3 iteration cap rejection). All-codes-0-through-27 pin in [dns/rfc8914_ede_iana_table_test.go](dns/rfc8914_ede_iana_table_test.go) locks the numeric assignments individually (wire format MUST NOT renumber) plus a uniqueness guard catching copy-paste duplicates on the late backfill.

### Hardened
- **RFC 8467 §6 — Padding never on plaintext transports (truth-table pin)** — four-corner pin in [server/rfc8467_padding_policy_test.go](server/rfc8467_padding_policy_test.go) locks the `applyTCPTransportPolicies` gate: `encrypted=true + client opted in → pad`; `encrypted=true + no opt → no pad`; `encrypted=false + client opted in → no pad` (RFC 8467 §6 hard rule — pad on cleartext is pure overhead and teaches downstream tooling to misclassify channel privacy); `encrypted=false + no opt → no pad`. A regression that flipped the `encrypted` gate would silently leak padding bytes onto plaintext TCP responses.

## [0.7.0] - 2026-05-28 — DNSSEC milestone (M1 + UI-M1)

This release closes out the DNSSEC milestone from `PLAN.md`. Backend
work landed across v0.6.42 (algorithm rollover pin + NTA core) and
v0.6.43 (CDS/CDNSKEY parser + RFC 5011 trust-anchor lifecycle); this
release bundles the operator-facing surface: `/api/dnssec` endpoint
and the new **DNSSEC** dashboard page.

### Added
- **`/api/dnssec` endpoint** — surfaces validator state for the
  operator UI: enabled/disabled, SHA-1 acceptance, active NTA count,
  cumulative `nta_matches` counter, and per-NTA status rows (zone,
  RFC3339 expiry, remaining-seconds window, reason, active vs expired
  flag). Returns 200 with zero-valued payload when DNSSEC is disabled
  so the UI handles "off" cleanly. New shape in [web/api_dnssec.go](web/api_dnssec.go) and matching `DNSSECStatusResponse` / `DNSSECNTAEntry` TS types.
- **DNSSEC dashboard page** — new `/dnssec` route in [web/ui/src/pages/DNSSECPage.tsx](web/ui/src/pages/DNSSECPage.tsx) renders the three M1 observability cards (validator badge, active NTA count, override counter) plus a per-NTA table with the remaining-validity window. Polls `/api/dnssec` every 10s — NTAs change on operator timescales (minutes-to-days), not query timescales, so cheap polling is the right shape. Linked from the main nav as **DNSSEC** via the `ShieldCheck` icon.

## [0.6.43] - 2026-05-28

### Added
- **RFC 7344 / RFC 8078 — CDS / CDNSKEY parser + classifier** — child-zone-signalled DS update support. The new `dnssec/cds.go` exposes `ParseCDSRRset` and `ParseCDNSKEYRRset` (wire format identical to DS / DNSKEY per RFC 7344 §3.1 / §3.2 — `dns.TypeCDS=59`, `dns.TypeCDNSKEY=60`) plus an `CDSUpdateAction` classifier that distinguishes `Publish` (child signalling a desired DS change) from `Delete` (RFC 8078 §4 sentinel: single record with `Algorithm=0` → child wants to take its delegation insecure) from `Unknown` (malformed). Critical anti-hijack guard: a CDS RRset containing the `Algorithm=0` sentinel mixed with normal records is rejected as malformed — without that gate an attacker who injected an extra well-formed CDS alongside a victim's delete intent could hijack the delegation. `CDSUpdate.CDSMatchesParentDS` lets the UI distinguish "no-op signal" from "real rollover signal" against the parent's current DS RRset. 12-case pin matrix across [dnssec/rfc7344_cds_test.go](dnssec/rfc7344_cds_test.go) covers publish (single + multi), delete sentinel, mixed-delete-publish (malformed), empty, wrong-RR-type, the four CDSMatchesParentDS detection cases, the CDNSKEY twin, and the action-string roundtrip.
- **RFC 5011 — Automated trust anchor lifecycle (full state machine)** — supersedes the static root anchor list (which remains the cold-start bootstrap). New `dnssec/rfc5011_lifecycle.go` implements the five-state lifecycle (`AddPending → Valid → Missing → Removed`, plus immediate `Revoked` via the REVOKE bit per §2.1) with default 30-day add and remove hold-down timers (§2.4.1). `TrustAnchorStore.TrackRefresh` is the per-refresh entry point: newly-observed KSKs enter `AddPending` and become `Valid` only after the add hold-down elapses with the key still in the published RRset (prevents premature-add attacks); a `Valid` KSK that disappears enters `Missing` and remains usable through the remove hold-down (prevents premature-remove attacks from transient outages); reappearance resurrects `Missing → Valid` without re-running the add hold-down; a KSK with the REVOKE bit jumps directly to `Revoked`; a same-(KeyTag, Algorithm) record with different bytes is treated as a substitution attack and restarts at `AddPending`. Six-test pin suite in [dnssec/rfc5011_lifecycle_test.go](dnssec/rfc5011_lifecycle_test.go): 30-day add hold-down (three timepoints), 30-day remove hold-down (still-usable-while-Missing assertion), Missing → Valid resurrection, REVOKE bit immediate transition, substitution-attack restart, and the state-string roundtrip used by logs/metrics/UI.

## [0.6.42] - 2026-05-28

### Added
- **RFC 7646 — Negative Trust Anchor (NTA) support** — operators can now disable DNSSEC validation for a specific zone subtree for a bounded time window, the canonical incident-response lever for major-TLD signature outages. New config key `resolver.dnssec_negative_trust_anchors` accepts a comma-separated list of `<zone>|<RFC3339-expiry>|<reason>` entries; expired NTAs are treated as removed per RFC 7646 §6 (bounded lifetime is the entire safety story). The new `dnssec/NTAStore` is suffix-matched (an NTA at `example.test` covers `example.test` and every descendant but never a sibling like `evil-example.test`), case-insensitive, clock-injectable for tests, and exposes `Match`, `Add`, `Remove`, `Cleanup`, `List`. Matches short-circuit the validator to `Insecure` with the new `ReasonNTAOverride` failure reason so the audit trail distinguishes "operator suppressed" from "happened to be Insecure anyway". Validator counter `NTAMatches()` surfaces the cumulative override count for the metrics API. Five-test pin suite in [dnssec/rfc7646_nta_test.go](dnssec/rfc7646_nta_test.go) covers subtree-and-sibling matching (including the `evil-example.test` string-substring trap), expiry transitions via mocked clock, past-expiry rejection on `Add`, `Cleanup` reaping behaviour, the integration override path (Insecure verdict + `ReasonNTAOverride` tag), and the reason-string roundtrip used at the EDE network boundary.

### Hardened
- **RFC 4035 §4.6 — Algorithm rollover dual-signature acceptance** — pin in [dnssec/rfc4035_algorithm_rollover_test.go](dnssec/rfc4035_algorithm_rollover_test.go) locks the validator's "at least one RRSIG suffices" iteration strategy across a true multi-algorithm rollover scenario. The test signs the same A RRset with two different algorithms (ED25519 and ECDSA-P256), wires both ZSKs into the root DNSKEY RRset, and walks the four-corner truth table: ED25519 expired / ECDSA fresh → Secure (rollover survival); ED25519 fresh / ECDSA expired → Secure (order-independence); both fresh → Secure (steady state); both expired → Bogus (negative control proving the iteration never silently downgrades to Insecure when every candidate fails). A regression that hard-coded a single algorithm path or short-circuited on first signature failure would turn every algorithm rollover into a resolver-wide SERVFAIL outage; this pin makes that regression impossible to land.

## [0.6.41] - 2026-05-28

### Hardened
- **RFC 4035 §3.1.3 + RFC 2181 §5.2 — Cache TTL decay uniform across RRset + RRSIG (Y89)** — every RR in an RRset MUST have the same TTL, AND a covering RRSIG must share that TTL with the covered RRset. The cache decays an entry uniformly via `WithDecayedTTL`: every record in `Records` and `Authority` is rewritten to the same `remaining` value. A regression that decayed Records but left Authority alone (or decayed by-type) would produce mixed-TTL pathology that downstream validating stubs treat as a protocol violation. Pin in [cache/rfc4035_ttl_uniformity_test.go](cache/rfc4035_ttl_uniformity_test.go) decays an entry containing A + RRSIG(A) + NSEC(Authority) to remaining=42 and verifies every TTL matches; also asserts the decayed copy is independent of the source (no aliasing back).
- **RFC 4035 §5.3.2 — `canonicalWildcardOwner` truth table (Y90)** — when an answer is synthesised from a wildcard, the signed owner is `*.<closest_encloser>`, NOT the queried name; the validator must rebuild the signed owner before computing canonical wire form, or every wildcard-served signed zone answer comes back Bogus. Eight-case pin in [dnssec/rfc4035_wildcard_owner_test.go](dnssec/rfc4035_wildcard_owner_test.go) covers: Labels=0 root-apex (no rebuild), Labels == rrName label count (exact owner), 4-label/Labels=2 (wildcard at example.com), 5-label/Labels=2 (deep wildcard), 3-label/Labels=1 (wildcard at TLD), trailing-dot tolerated, defensive `Labels > rrName label count` (no crash), defensive empty rrName.
- **RFC 4035 §5.3.1 — `rrsigClockSkew` constant within sensible bounds (Y91)** — pin in [dnssec/rfc4035_clock_skew_test.go](dnssec/rfc4035_clock_skew_test.go) asserts the clock-skew tolerance for RRSIG Inception/Expiration checks is between 1s and 5min. Too small → periodic DNSSEC outages at signature boundaries from normal clock drift; too large → an attacker replaying expired signatures gets a long window of validity, eroding the RFC 4034 inception/expiration freshness guarantee. Current value (60s) sits squarely in BIND/Knot/Unbound's recommended 5s–5min band.
- **RFC 9018 §4.2 + RFC 7873 §5.2.4 — Server cookie binds client IP (rebinding defense, Y92)** — the server cookie is computed as a hash of (clientCookie, clientIP, timestamp, secret); a cookie issued to client A MUST NOT validate when presented from client B's IP. Without this binding, a leaked cookie could be replayed by any source to bypass cookie-based source validation entirely (defeating the §5.2.5 anti-amplification posture). Three-case pin in [server/rfc9018_cookie_ip_binding_test.go](server/rfc9018_cookie_ip_binding_test.go): same IP validates, different IPv4 rejects, IPv6 vs IPv4 distinct hash space.
- **RFC 7873 §5.2.1 + RFC 9018 §4 — Cookie option length semantics (Y93)** — six-case pin in [dns/rfc7873_cookie_length_test.go](dns/rfc7873_cookie_length_test.go) locks `ParseCookieOption` return shape: `len < 8 → (nil, nil)`, `len == 8 → (8-byte client, nil)` (bootstrap), `len == 16 → 8+8 split` (RFC 7873 legacy), `len == 24 → 8+16 split` (RFC 9018 current). Every downstream cookie consumer gates on `len(clientCookie) == 8`; a parser regression that returned a partial client cookie for under-length inputs would slip past the gate with misaligned hash inputs — silently failing validation in a way that looks like the security guard fired.

## [0.6.40] - 2026-05-28

### Fixed
- **RFC 4035 §5.4 / RFC 6840 §4.4 — Aggressive NSEC3 cache accepted parent-side delegation NSEC3 as NODATA proof (real bug, Y84)** — symmetric mirror of the v0.6.39 NSEC fix. The `cache/nsec3_aggressive.go:lookupNSEC3` had the same hole: a parent-side delegation NSEC3 at a zone cut (bitmap `{NS, RRSIG, NSEC3}` — every type the CHILD serves absent because it lives on the child side) could synthesise NODATA for arbitrary child-zone record types (A, AAAA, MX, …). Fix adds the `typeBitmapHas(NS) && !typeBitmapHas(SOA) → skip` guard. Three-polarity pin in [cache/rfc8198_nsec3_delegation_test.go](cache/rfc8198_nsec3_delegation_test.go).

### Hardened
- **RFC 5155 §6 + RFC 8198 §6 + RFC 9276 §3 — Opt-out NSEC3 dropped on registration (Y85)** — `RegisterNSEC3Interval` already drops NSEC3s whose opt-out flag (LSB of Flags) is set, because such records make NO claim about unsigned names in their gap. Aggressive synthesis from opt-out would fabricate NXDOMAIN for names the zone never proved nonexistent — the canonical RFC 8198 §6 pitfall. Two-case pin in [cache/rfc5155_optout_test.go](cache/rfc5155_optout_test.go) drives both polarities: opt-out=1 dropped (no synth), opt-out=0 cached (synth fires) — a regression that flipped the conditional is caught either way.
- **RFC 4035 §3.1.3 + RFC 6891 §6.1.4 — Response OPT DO bit mirrors query (Y86)** — the response OPT MUST signal whether DNSSEC RRs are included in the answer. Since the resolver strips DNSSEC RRs for non-DO clients (Y51) and includes them for DO clients, the response DO bit effectively mirrors the query. Pin in [server/rfc4035_do_mirror_test.go](server/rfc4035_do_mirror_test.go) drives DO=0 and DO=1 cache-hit responses and asserts the response OPT carries the same DO flag — a hard-code regression (always 0 or always 1) is caught by the unfailing polarity that breaks.
- **RFC 4034 §6.2 item 3 — Canonical RDATA name lowercasing (Y87)** — for the RR types whose RDATA contains embedded domain names (CNAME, NS, PTR, DNAME, MX, SRV, SOA, RRSIG), the names MUST be lowercased before forming the canonical RRset wire for RRSIG verification. Without this normalisation, auth servers that emit uppercase in wire responses would turn every CNAME hop into a false Bogus. Five-case pin in [dnssec/rfc4034_canonical_rdata_test.go](dnssec/rfc4034_canonical_rdata_test.go) covers CNAME, NS, MX (preference preserved + name lowercased), RRSIG (18-byte fixed header preserved, signer lowercased, signature preserved, length unchanged), plus the negation that TypeA RDATA bytes (which happen to contain uppercase ASCII when interpreted as letters) are NOT mangled by the canonicalizer.
- **RFC 4035 §5.3.1 — RRSIG SignerName bailiwick (Y88)** — the signer must be an ancestor (or equal) to the qname being verified. Without this check, an attacker who controls ANY signed zone could inject an RRSIG into a victim-zone response and the validator would fetch the attacker's DNSKEYs and verify successfully against attacker-keys. Nine-case truth-table pin in [dnssec/rfc4035_signer_bailiwick_test.go](dnssec/rfc4035_signer_bailiwick_test.go) covers root signer (always accepted), signer == qname, strict/deep ancestor, TLD-as-signer, sibling rejected, descendant cannot sign ancestor, and the security-critical **partial-label** case (`mple.com` MUST NOT sign for `example.com` — the leading-dot label boundary in `HasSuffix("." + signer)` is exactly what blocks this attack vector).

## [0.6.39] - 2026-05-28

### Fixed
- **RFC 4035 §5.4 / RFC 6840 §4.4 — Aggressive NSEC cache accepted parent-side delegation NSECs as NODATA proof (real bug, Y82)** — the validator path in `dnssec/nsec.go` already refused delegation NSECs (NS bit set, SOA bit clear) when used to "prove" NODATA for the child zone's records, but the **cache-side** aggressive synth in `cache/nsec_aggressive.go:lookupNSEC` had no equivalent gate. A delegation NSEC at the zone cut between `example.com` and `child.example.com` has bitmap `{NS, RRSIG, NSEC}` — every type the CHILD actually serves (A, AAAA, MX, …) is absent from the bitmap. The aggressive cache would happily synthesise "AAAA NODATA at child.example.com" for any query, hiding the child zone's real records. Fix adds the `typeBitmapHas(NS) && !typeBitmapHas(SOA) → skip` guard. Pin in [cache/rfc8198_delegation_nsec_test.go](cache/rfc8198_delegation_nsec_test.go) drives all three polarities (delegation rejected, authoritative apex accepted, plain leaf accepted).

### Hardened
- **RFC 4035 §5.4 — NSEC wildcard expansion proof + delegation-NSEC NODATA rejection at validator (Y79)** — pin in [dnssec/rfc4035_wildcard_proof_test.go](dnssec/rfc4035_wildcard_proof_test.go) locks the two security-critical structures in `VerifyNSECDenial`: (a) NXDOMAIN proof MUST contain both a qname-cover NSEC AND a wildcard-cover NSEC — accepting a "naked NSEC" (qname-cover only) would let an attacker replay a single zone NSEC to forge NXDOMAIN for any name in the gap and hide real wildcard-matched records; (b) a delegation-point NSEC (NS bit set, SOA bit clear) MUST NOT be accepted as NODATA proof — it belongs to the parent zone and proves nothing about the child's data.
- **RFC 6672 §2.4 + RFC 6840 §5.10 — DNAME owner bailiwick truth table (Y80)** — five-case pin in [resolver/rfc6672_dname_bailiwick_test.go](resolver/rfc6672_dname_bailiwick_test.go) on `extractDNAMETarget`: (1) immediate child substitutes; (2) deep descendant substitutes; (3) owner == qname returns "" (RFC 6672 §3.2 — DNAME doesn't redirect itself); (4) sibling owner with no suffix relationship rejected (out-of-bailiwick injection guard); (5) partial-label match like `ample.com` for qname `example.com` rejected — the `"."+owner` prefix in the suffix check is what enforces label boundary, and a regression that dropped it would let `ample` redirect every `*example` name.
- **RFC 4035 §5.3.2 / §5.3.3 — RRSIG OrigTTL in canonical wire form (Y81)** — pin in [dnssec/rfc4035_rrsig_origttl_test.go](dnssec/rfc4035_rrsig_origttl_test.go) drives `canonicalRRSetWire` with `rr.TTL=10` (cache-decayed) and `rrsig.OrigTTL=3600` (auth-signed) and verifies the canonical wire form encodes 3600 — not the decayed value. A regression that grabbed `rr.TTL` instead of `rrsig.OrigTTL` would Bogus every cached signed RRset within seconds of insertion as cache decay outran signature input stability.
- **RFC 7873 §5.4 — Cookie-disabled server gracefully ignores client cookies (Y83)** — pin in [server/rfc7873_cookies_disabled_test.go](server/rfc7873_cookies_disabled_test.go) sends a well-formed 24-byte cookie option to a handler with cookies DISABLED and asserts: (a) no FORMERR for the "unrecognised" option, (b) no extended BADCOOKIE response — the server cannot demand validation it doesn't perform; cookie-aware stubs (BIND ≥ 9.10, Knot, systemd-resolved) would otherwise loop forever retrying.

## [0.6.38] - 2026-05-28

### Hardened
- **RFC 6605 §2 — DNSSEC algorithm/hash pairing truth table (Y73)** — pin in [dnssec/rfc6605_hash_pairing_test.go](dnssec/rfc6605_hash_pairing_test.go) locks the eight-case mapping. The history here matters: algorithm 14 (ECDSAP384) was once grouped with RSASHA512 under SHA-512, which made every zone signed with alg 14 (e.g. `fedoraproject.org`) come back Bogus despite intact cryptography. The fix gave alg 14 its own SHA-384 case; this pin makes the regression-to-grouping impossible to land silently. Covers RSASHA1/256/512, ECDSAP256/P384, ED25519 (no external hash, returns 0), plus reserved/unsupported alg numbers returning error.
- **RFC 6840 §5.4 + RFC 4034 §3.1.6 — findMatchingDNSKEY requires algo+keytag match + RFC 5011 §2 revoked-key skip (Y74)** — four-case pin in [dnssec/rfc6840_dnskey_match_test.go](dnssec/rfc6840_dnskey_match_test.go) covers: (a) matching tag+algorithm returns key; (b) right tag + wrong algorithm rejected (algorithm-substitution attack surface — the tag is only 16 bits so birthday-paradox collisions happen at ~2^8 keys); (c) right algorithm + wrong tag rejected; (d) RFC 5011 §2 REVOKE-bit-set DNSKEY skipped even with matching tag+algorithm (an attacker who stole an old key could otherwise keep using it past revocation).
- **RFC 4034 App B.1 — DNSKEY KeyTag fixture pin (Y75)** — the pre-existing key-tag test computed its expected value with the same algorithm as the code under test (a tautology). Pin in [dns/rfc4034_keytag_fixture_test.go](dns/rfc4034_keytag_fixture_test.go) uses three independently hand-computed fixtures: (1) all-zero header → tag=0; (2) `KSK alg=8 PublicKey=[01,02,03,04]` → tag=2063; (3) overflow case `[FF×8]` forcing the `ac += ac>>16 & 0xFFFF` fold-back → tag=1033. A bit-twiddle regression (off-by-one in even/odd split, missing fold-back, wrong final mask) is caught immediately. Companion test pins KeyTag stability across struct-built ↔ ParseDNSKEY-built representations.
- **RFC 6840 §5.2 — Unsupported-algorithm validator truth table (Y76)** — fifteen-case exhaustive pin in [dnssec/rfc6840_unsupported_alg_test.go](dnssec/rfc6840_unsupported_alg_test.go) on `isUnsupportedRRSIGAlg`. Supported set: RSASHA1, RSASHA256, RSASHA512, ECDSAP256, ECDSAP384, ED25519. Unsupported: Reserved(0), RSAMD5(1), DSA(3), DSA-NSEC3-SHA1(6), RSASHA1-NSEC3(7), GOST(12), ED448(16), PRIVATEDNS(253), PRIVATEOID(254). RFC 6840 §5.2 mandates treating unsupported-algo signatures "as if not signed" (→ Insecure, not Bogus); a regression that flipped a supported alg to unsupported would silently demote valid signed zones to Insecure (silent security loss).
- **RFC 5155 §8.2 + IANA NSEC3 Parameters — NSEC3 hash algorithm support (Y77)** — six-case pin in [dnssec/rfc5155_nsec3_hash_alg_test.go](dnssec/rfc5155_nsec3_hash_alg_test.go). Only algorithm 1 (SHA-1) is defined; 0 is permanently Reserved; 2..255 are unassigned. Accepting an unknown hash algorithm would either crash inside an unimplemented routine or — worse — return a meaningless hash that an attacker could synthesise NSEC3 records to match. Pins alg=1 accepted, alg=0/2/3/100/255 rejected with `errUnsupportedHashAlg` so a future IANA allocation lands on the correct guard rail.
- **RFC 4034 §2.1.2 — SEP bit is advisory, not validation-gating (Y78)** — pin in [dnssec/rfc4034_sep_advisory_test.go](dnssec/rfc4034_sep_advisory_test.go) drives `findMatchingDNSKEY` with both a KSK (flag=257, SEP=1) and a ZSK (flag=256, SEP=0) and asserts BOTH are independently findable by their respective key_tag+algorithm. A well-intentioned hardening that "only KSKs can validate" would silently break every zone following the recommended KSK/ZSK split — KSKs typically sign only the DNSKEY RRset, ZSKs sign the bulk of zone data (A, MX, NS, etc.). Rejecting ZSK signatures would force every signed zone Bogus despite correct crypto. The pin distinguishes the SEP bit (advisory, §2.1.2) from the Zone Key bit (gating, §2.1.1 — Y53 already covers this).

## [0.6.37] - 2026-05-28

### Hardened
- **RFC 7686 §2 + RFC 6761 + RFC 8375 — Special-use names handler integration (Y68)** — the unit-level matcher in `resolver/specialuse.go` was already covered; this pin asserts the INTEGRATION through the full request pipeline so a refactor that hooked the short-circuit too late in the chain (after a real iterative attempt had left the wire) is caught immediately. Seven-name pin in [server/rfc7686_onion_handler_test.go](server/rfc7686_onion_handler_test.go) covers `.onion` (Tor de-anonymisation hazard), `.invalid`, `.test`, `.example` TLD, `.local`, `home.arpa`. Negation pin verifies public names with `onion`/`test`/`local` as substring (e.g. `myonion.example.com`, `protest.example.com`) are NOT swept up — matchers must be SUFFIX-based, not SUBSTRING-based.
- **RFC 8767 §3.3 — Stale-max-age ceiling (Y69)** — without an enforced ceiling on how far past expiry the cache will serve stale, a single entry inserted with a short TTL and never re-fetched (long-tail name, accessed once and then again months later) would still be served forever — and worse, if the auth changed the record meanwhile, our resolver would keep returning the OLD answer indefinitely. Three-case pin in [cache/rfc8767_stale_max_age_test.go](cache/rfc8767_stale_max_age_test.go): in-window served, past-window rejected, `staleMaxAge=0` means "disabled" (operator opt-out, served unbounded). The middle case is the critical regression target — a refactor flipping `>` to `>=` would change behaviour at the 1-second boundary and slip past most timing tolerances.
- **RFC 3597 §3 — Unknown RR type opaque roundtrip (Y70)** — "An implementation of the DNS protocol MUST handle all RR types that it does not implement at least by treating the RDATA as a generic opaque block." Pin in [dns/rfc3597_unknown_rr_test.go](dns/rfc3597_unknown_rr_test.go) drives `TypeSPF=99` (IANA-assigned, no special-case parser) through TWO full pack→unpack cycles and asserts the 13-byte RDATA (with a first byte of `0x07` — deliberately resembling a label-length prefix to bait a buggy "interpret as name" fallback) survives bit-identical, with `Type`/`Class`/`TTL`/`Name`/`RDLength` all preserved. Without this invariant, the resolver could not safely cache RR types it does not natively understand and the forward-compatibility promise breaks.
- **RFC 7873 §5.2 + §5.4 — Cookie state-machine permissiveness (Y71)** — the handler MUST be permissive about the SHAPE of the cookie option in two valid protocol states: (a) **bootstrap query** with only an 8-byte client cookie and no server cookie, and (b) **non-16-byte server cookie** lengths within the RFC 9018 §4 [8, 32]-byte range that aren't our current spec. A regression that tightened either gate to FORMERR would silently break interop with millions of cookie-aware stubs (Knot < 5.3, BIND pre-9.18) AND prevent every cookie-aware client from EVER exchanging a first cookie with us. Pin in [server/rfc7873_cookie_bootstrap_test.go](server/rfc7873_cookie_bootstrap_test.go).
- **RFC 6303 §3 + RFC 1918 / RFC 4193 — Private reverse zones handler integration (Y72)** — leaking `192.168.x.x` / `10.x.x.x` reverse PTR queries to the public DNS root is a privacy/topology disclosure (the QUERY PATTERN tells external observers about internal network layout) AND unnecessary root load. Eight-case integration pin in [server/rfc6303_private_reverse_handler_test.go](server/rfc6303_private_reverse_handler_test.go) covers all three RFC 1918 ranges, loopback, IPv4 link-local, TEST-NET-1, IPv6 ULA (`fd00::/8`), and IPv6 link-local (`fe80::/10`) — each asserts the FULL handler pipeline returns NXDOMAIN without reaching upstream. Negation pin (public `8.8.8.8` reverse) proves the matcher doesn't broaden to all `in-addr.arpa` names (which would blind monitoring/logging tools to all reverse-DNS data).

## [0.6.36] - 2026-05-28

### Hardened
- **RFC 8482 §4.5 — Minimal ANY HINFO format pin (Y62)** — the synthetic response to an ANY query must be exactly `HINFO CPU="RFC8482" OS=""` with TTL=0. A regression that lost the "RFC8482" literal would strip the self-documenting hint and make the synth indistinguishable from a real HINFO record served from the zone, costing operators hours of debugging time when example.com appears to be running an obscure CPU. Six-invariant pin in [server/rfc8482_minimal_any_test.go](server/rfc8482_minimal_any_test.go) (RCODE / answer count / Type=HINFO / Class=IN / TTL=0 / RDATA bytes) + negation pin that TypeA queries are NOT intercepted.
- **RFC 1035 §4.1.2 — QDCOUNT ≠ 1 returns FORMERR (Y63)** — the standard only ever defined the behaviour of single-question messages; multi-question queries are a classic AXFR-look-alike that some authoritatives historically crashed on, and QDCOUNT==0 surfaces in malformed stateful probes. Two-case pin in [server/rfc1035_qdcount_test.go](server/rfc1035_qdcount_test.go) (QDCOUNT=0 raw header / QDCOUNT=2 packed) drives the handler and asserts FORMERR with QR=1.
- **RFC 1035 §4.1.1 / RFC 6895 §2.2 — Opcode ≠ QUERY returns NOTIMP (Y65)** — a recursive resolver implements only OPCODE QUERY (0); UPDATE / NOTIFY / IQUERY / STATUS have completely different message semantics. A regression that let UPDATE through the recursion pipeline could treat the update section's RRs as answers — a CVE-class "DNS UPDATE injection via misclassified opcode". Four-opcode pin in [server/rfc1035_opcode_test.go](server/rfc1035_opcode_test.go) (IQUERY / STATUS / NOTIFY / UPDATE) confirms NOTIMP for each.
- **RFC 4034 §6.1 — Canonical DNS name ordering (Y66)** — the foundation of every NSEC denial proof, every RRset canonical-form RRSIG, and the RFC 8198 aggressive-NSEC interval walker. A regression in the comparator silently breaks DNSSEC validation across the entire signed-name space: either accepts forged NXDOMAIN proofs (gap inversion) or rejects valid ones (no-gap-found). Six-case truth-table pin in [dnssec/rfc4034_canonical_order_test.go](dnssec/rfc4034_canonical_order_test.go) exercises identity, cross-TLD ordering, shorter-suffix-first, RFC 4343 case-folding, second-label tiebreak, and the ASCII digit-vs-letter byte ordering — plus an antisymmetry pin on every case (`compare(a,b) = -compare(b,a)`).

### Security
- **RFC 7873 §5.2.3 — BADCOOKIE response MUST echo a fresh server-cookie (Y64)** — after a routine server-secret rotation, the client's stored cookie hashes against the OLD secret and fails forever, with no in-band path to learn a new one — unless the BADCOOKIE response itself carries a freshly issued cookie under the new secret. Without this echo, every active client population is permanently locked out by the rotation event. Pin in [server/rfc7873_badcookie_echo_test.go](server/rfc7873_badcookie_echo_test.go) sends a deliberately-mismatched cookie, asserts the response is extended-RCODE BADCOOKIE (23) AND that it carries an OPT Cookie option whose first 8 bytes are the client's cookie and whose next 16 bytes are a fresh server cookie different from the rejected one.
- **RFC 9018 §4.3 + RFC 7873 §5.2.5 — Cookie-secret rotation: 1-secret grace + bounded expiry (Y67)** — the handler keeps exactly ONE previous secret in a grace window so a rotation doesn't simultaneously invalidate every active client's cookie. The pin enforces two security invariants in [server/rfc9018_cookie_rotation_test.go](server/rfc9018_cookie_rotation_test.go): (a) a cookie under secret A still validates after rotation A→B (grace path), but no longer validates after A→B→C — only ONE previous secret is retained, not a chain (an unbounded chain would mean any historical-secret leak compromises all-time forward); (b) even the immediately-previous secret stops accepting cookies past the 1-hour `§4.3` max-age, enforced by a `nowFunc`-fast-forwarded test that asserts rejection at now+2h.

## [0.6.35] - 2026-05-28

### Hardened
- **RFC 9276 §3.2 — NSEC3 iteration cap applies to every record (Y59)** — the iteration ceiling (`MaxNSEC3Iterations = 100`, aligned with BIND 9.18+ / Unbound 1.16+) must reject the whole proof when ANY record in the denial bundle exceeds it, not just `records[0]`. An attacker mixing one over-cap NSEC3 with low-iter siblings could otherwise force the validator into a CPU-amplified hash walk per NXDOMAIN proof — the exact "Hash Calculations" DoS RFC 9276 §2.1 is written to prevent. Three-position pin in [dnssec/rfc9276_nsec3_iter_test.go](dnssec/rfc9276_nsec3_iter_test.go) (offending record at first/middle/last) plus a boundary pin proving `iterations == MaxNSEC3Iterations` is still processed (the inequality is `>`, not `>=`).
- **RFC 9520 §4 — Failure cache only stores SERVFAIL, never positive RCODEs (Y60)** — the resolution-failure short-circuit is reserved for SERVFAILs that could not be classified further (no auth answered, all NS REFUSED, network dropped). A regression that loosened the `result.RCODE == RCodeServFail` gate would start caching every legitimate NXDOMAIN here for the §4 short TTL, racing against the answer cache's RFC 2308 negative TTL and breaking the "fix auth → resolver reflects within seconds" expectation operators have. Three-case pin in [resolver/rfc9520_failure_cache_gate_test.go](resolver/rfc9520_failure_cache_gate_test.go) drives NOERROR / NXDOMAIN / SERVFAIL through a mock and asserts only the third populates failureCache. A second test pins the RFC 7871 §7.1 interaction: an ECS-bearing SERVFAIL is NOT cached (failures are not subnet-portable — an auth that REFUSED 192.0.2.0/24 may happily answer 198.51.100.0/24).
- **RFC 9156 — QNAME minimisation invariants (Y61)** — five-case truth-table pin in [resolver/rfc9156_qmin_test.go](resolver/rfc9156_qmin_test.go) on `minimizeQName`: root qname (`""`) never rewritten (keeps the root DNSKEY walk intact, §3); TypeDS never minimised (DS lives at the parent, §4.1 — minimising lands the resolver at the child auth which has no DS for itself, breaking the chain-of-trust walker); at-root query collapses to TLD-only with TypeNS (§3 one-extra-label-per-iteration leak floor for root servers); single-label-remaining inside the current zone asks the FULL qtype (the final leaf query is not rewritten to NS, which would render it unanswerable); intermediate hops peel one label and use NS as the probe. Each broken invariant is a silent failure mode — DS regression breaks every signed zone's validation, root-NS leak destroys §3 privacy gains, leaf-NS rewrite turns every A/AAAA lookup into an unanswerable NS query.

## [0.6.34] - 2026-05-28

### Fixed
- **RFC 8767 §3 + RFC 8914 §4.19 — stale NXDOMAIN was unreachable via GetStale (real cache bug)** — `Cache.Get()` correctly probed the NXDOMAIN sentinel (`qtype=0` — "covers all types") as a second-chance lookup when the typed key missed, but `Cache.GetStale()` only checked the typed key. Net effect: an expired NXDOMAIN cached entry was structurally invisible to the serve-stale path. On upstream failure for a name the resolver had previously denied, the handler would fall through to SERVFAIL with EDE 23 (Network Error) instead of serving the stale denial with EDE 19 (Stale NXDOMAIN Answer). The Y57 pin caught this — `GetStale()` now mirrors the `Get()` fallback ([cache/cache.go](cache/cache.go)). Behavioral change for the better: clients that hit the serve-stale window during an upstream outage now receive a useful denial instead of a generic failure.

### Hardened
- **RFC 8914 §4.3 / §4.19 — serve-stale picks EDE 3 vs EDE 19 by cached RCODE (Y57)** — RFC 8914 defines EDE 3 "Stale Answer" for positive serve-stale and a separate EDE 19 "Stale NXDOMAIN Answer" specifically for stale denial-of-existence. A refactor that flattened the code path to always emit EDE 3 would leak a stale NXDOMAIN as a positive-stale signal, defeating the §4.19 use case (clients deciding whether to retry against another resolver weight a stale denial differently from a stale positive). Two-case pin in [server/rfc8914_stale_ede_test.go](server/rfc8914_stale_ede_test.go) drives the handler through both the positive and NXDOMAIN cached-RCODE branches via a broken resolver, plus a non-EDNS counterpart that asserts §3 gating still suppresses OPT/EDE for legacy stubs.
- **RFC 8914 §4.3 / §4.19 negative pin — fresh cache hits never carry stale EDE (Y58)** — guards against the refactor that hoists EDE attachment too high (into a shared cache-response builder) and starts spraying EDE 3/19 on every normal cache hit. Two pins in [server/rfc8914_no_stale_ede_fresh_test.go](server/rfc8914_no_stale_ede_fresh_test.go): a healthy positive entry in its TTL window emits no EDE 3, and a fresh cached NXDOMAIN emits no EDE 19. A client that sees EDE 19 on a non-stale denial would (correctly under §4.19 semantics) doubt the answer and retry — turning a working negative cache into an upstream-load amplifier.

### UI
- **QueriesPage — DNSSEC "Insecure" badge** — the resolver already emits `dnssec_status="insecure"` for unsigned zones (no DS chain — the legitimate baseline for most of the internet), but the queries table only rendered the green secure / red bogus icons. Added a muted-slate unfilled shield for the insecure state with a tooltip that distinguishes it from a failure ("normal for unsigned domains; not a failure"). Operators reading the queries page can now see at a glance which traffic is signed-and-validated, signed-but-broken, and unsigned.

## [0.6.33] - 2026-05-28

### Hardened
- **RFC 6891 §6.2.5 — UDP buffer-size advertisement truth-table (Y54)** — `advertisedUDPBufferSize` clamps unset / sub-512 / over-65535 / negative operator values back to 1232. An eight-case pin in [server/rfc6891_udp_buffer_size_test.go](server/rfc6891_udp_buffer_size_test.go) covers (unset, 256, 512 floor, 1232 default, 4096 BIND-default, 65535 ceiling, 70000 overflow, -1 typo) so a refactor that swapped the inequality direction (or changed `< minSize` to `<= minSize`) can't silently regress a single cell. Misconfigured int → too-small OPT means fragmentation under any non-trivial answer; misconfigured int → overflow uint16 means a bogus OPT advertisement on the wire.
- **RFC 1034 §3.1 / RFC 4343 — Cache lookups are case-insensitive (Y55)** — DNS names compare case-insensitively. Three-case pin in [cache/rfc1034_case_insensitive_test.go](cache/rfc1034_case_insensitive_test.go) covers `Store(lower)→Get(MIXED)`, `Store(MIXED)→Get(lower)`, and the structural invariant "both case-folded forms map to ONE entry, not two." A regression here would silently double-store entries on every 0x20-randomised query (Y48) and break the cache integration with the DNSSEC canonical-form rule (RFC 4034 §6.2).

### Security
- **RFC 5452 §7 + §9 — Query ID entropy (Y56)** — predictable IDs reduce the off-path forgery search space below the nominal 16 bits. Two statistical pins in [resolver/rfc5452_txid_entropy_test.go](resolver/rfc5452_txid_entropy_test.go) over 256 consecutive `randomTXID()` calls: (1) collision count ≤ 5 (vs ~0.5 expected for a fair 16-bit RNG, vs ~256 for a counter); (2) Hamming union of all 256 IDs covers ≥ 14 of 16 bit positions; (3) consecutive-pair ascending ratio ≤ 80% (vs ~50% random, ~99% counter). Catches the silent regression where someone swaps `crypto/rand` for an unseeded `math/rand` or for a uint16 counter — invisible in normal traffic, only an active probe would notice without these pins.

## [0.6.32] - 2026-05-27

### Security
- **RFC 4034 §2.1.1 + RFC 6840 §5.6 — DNSKEY Zone Key bit required for validation (Y53)** — a DNSKEY whose Zone Key flag (bit 7, value 0x0100) is clear holds some other kind of public key (e.g. host SIG(0) keys) and MUST NOT be used to verify RRSIGs over RRsets. Without this gate, an attacker with a SIG(0) key whose tag happens to match a DS record could appear to validate the zone. New `DNSKEYRecord.IsZoneKey()` helper ([dns/rdata.go](dns/rdata.go)) + `VerifyRRSIG` gate ([dnssec/verify.go](dnssec/verify.go)) — the bit is checked BEFORE algorithm dispatch so the rejection survives any algorithm switch. Pin tests [dnssec/rfc4034_zone_key_test.go](dnssec/rfc4034_zone_key_test.go) cover three cases: SEP-only key rejected, ZSK accepted past the gate (crypto fails on bogus material — proves gate is permissive enough), and a six-flag truth table on the helper.
- **RFC 8914 §3 — EDE only when client carries EDNS (Y52)** — Extended DNS Errors only make sense to clients that speak EDNS; sending an OPT-bearing EDE response to a non-EDNS legacy stub both wastes bytes and risks tripping strict RFC 1035-only stubs that count "unknown additional" as malformed. The `queryHasEDNS` byte-level gate already covered the ACL/rate-limit refuse paths; pin test [server/rfc8914_ede_edns_gating_test.go](server/rfc8914_ede_edns_gating_test.go) drives the same ACL-denied query twice (with and without OPT) and asserts: non-EDNS response has ARCount=0 with no EDE; EDNS response carries an OPT bearing EDE 18 (Prohibited, §4.18).

### Documentation
- **README.md RFC compliance table rewritten** — the previous 14-entry table was stale (last touched before the Y34 audit started). Replaced with a 9-section matrix that mirrors the AboutPage compliance panel: Core Protocol, DNSSEC, Aggressive NSEC/NSEC3, EDNS / Cookies / Padding, Transport Security, Special-Use Names, and Error Signalling / Caching / Policy. Every "Pinned" row points at a `*/rfcNNNN_*_test.go` file under the new audit naming convention. Features section updated to surface the v0.6.26-v0.6.28 UI work (Resolver Observability panel, CD/EDE diagnostic badges, RFC Compliance Matrix on AboutPage).

## [0.6.31] - 2026-05-27

### Security
- **RFC 1034 §3.7 — AA bit MUST be clear on resolver responses (Y50)** — a recursive resolver is by definition NOT authoritative for any name, even when serving cached data that originated from an AA=1 upstream. Monitoring tools and stub resolvers treat AA=1 as "fresh, direct from origin"; a cache hit that ships AA=1 silently misleads them into trusting stale data as live. Two pin sets in [server/rfc1034_aa_bit_test.go](server/rfc1034_aa_bit_test.go): five-case matrix on `buildCacheResponse` (every DNSSECStatus × CD combination) and three-case matrix on `buildResponse` (NOERROR/NXDOMAIN/SERVFAIL) — AA MUST be 0 in every case.
- **RFC 4035 §3.2.1 — DNSSEC RR stripping for non-DO clients (Y51)** — `stripDNSSECRRs` has unit tests but the integration was not pinned. A refactor that moved the strip call out of `buildResponse` / `buildCacheResponse` would silently ship RRSIG/DNSKEY/NSEC/NSEC3 records to a legacy stub — both a DDoS amplification surface (multi-KB DNSSEC blobs to clients that asked for a 30-byte A answer) AND a confusion source for strict stubs that reject unknown RR types. Three-case pin in [server/rfc4035_strip_dnssec_integration_test.go](server/rfc4035_strip_dnssec_integration_test.go): (1) cache path strips DNSSEC for non-DO; (2) live path strips DNSSEC for non-DO; (3) explicit `qtype=DNSKEY` query keeps its DNSKEY even without DO (§3.2.1 exception so DNS-audit tooling still works).

## [0.6.30] - 2026-05-27

### Security
- **RFC 6891 §6.1.3 — Extended RCODE pack/unpack round-trip (Y46)** — the 12-bit Extended RCODE is split across the DNS header's low-4-bit RCODE nibble and the OPT pseudo-record's TTL byte 0. A refactor that "simplified" the error builder to write the full 12-bit value into the header nibble alone would silently truncate BADCOOKIE (23) to RCODE 7 (NXRRSET) — and clients would never see the cookie-rotation signal. Two new pin tests in [server/rfc6891_extrcode_test.go](server/rfc6891_extrcode_test.go) round-trip both BADCOOKIE and BADVERS through `dns.Unpack` + `dns.ParseOPT` and recompose `(ExtRCODE<<4)|header.RCODE()` to confirm the original 12-bit value. Also pins that the BADVERS response carries OPT Version=0 (our highest supported), per §6.1.3 — a future bump must not accidentally still advertise 0.
- **RFC 5452 §6 — DNS 0x20 case randomization behavioural pin (Y48)** — `Caps0x20Enabled` only adds defence value if the randomization actually reaches the wire. Behavioural pin [resolver/rfc5452_0x20_test.go](resolver/rfc5452_0x20_test.go) captures the outbound QNAME at a mock UDP socket and verifies: `Caps0x20Enabled=true → mixed-case bytes on wire` (with a 24-letter QNAME the chance of an all-lowercase RNG result is ~6×10⁻⁸ — flake-proof); `Caps0x20Enabled=false → lowercase preserved`. Both modes pin that letter identity is preserved case-insensitively — a regression that mangled the QNAME would surface here.

### Hardened
- **RFC 2308 §5 — Negative cache TTL = MIN(SOA RR TTL, SOA.Minimum) (Y47)** — taking the MAX would extend negative caching beyond zone-owner intent; using only RR TTL or only Minimum would ignore the other input. Truth-table pin [cache/rfc2308_negative_ttl_test.go](cache/rfc2308_negative_ttl_test.go) covers three cases (Minimum smaller, RR TTL smaller, equal) plus the no-SOA fallback path (which must NOT collapse to 0 or grow unboundedly — silent disabling of negative caching for misbehaving upstreams is the regression to catch).

## [0.6.29] - 2026-05-27

### Security
- **RFC 4035 §4.7 — DO bit on outbound queries (Y43)** — a validating resolver MUST set the DNSSEC OK bit in the OPT pseudo-record of every upstream query so the authoritative server includes RRSIG records. A refactor that loses this would silently degrade every answer to Insecure (validator gets no signatures to verify). New behavioural pin [resolver/rfc4035_do_bit_test.go](resolver/rfc4035_do_bit_test.go) captures the actual outbound query at a mock UDP socket and asserts the OPT TTL high-word DO bit follows the `DNSSECEnabled` config: `true → DO=1`, `false → DO=0`.
- **RFC 4035 §3.2.2 + RFC 6840 §5.7 — AD bit gating (Y45)** — the AD bit on responses to clients MUST only be set when the data was validated AND the client did not opt out with CD=1. Five-case truth table pinned in [server/rfc4035_ad_bit_test.go](server/rfc4035_ad_bit_test.go): `secure+CD=0→AD=1`, `secure+CD=1→AD=0`, `insecure/bogus/unset+CD=0→AD=0`. A regression here is a silent downgrade — stub resolvers trust AD to decide whether to forward the answer to apps; an unvalidated AD=1 is the resolver lying to its downstream.

### Hardened
- **RFC 9210 §3.7 + RFC 7766 §6.2 — TCP idle timeout + pipeline cap defaults (Y44)** — a TCP server with no idle timeout or unbounded pipeline is a trivial DoS surface. Four-case pin [server/rfc9210_tcp_idle_test.go](server/rfc9210_tcp_idle_test.go) enforces the operational invariants: default idle timeout `> 0 and ≤ 30s`; default pipeline max `> 0 and ≤ 10000`; both option helpers (`WithIdleTimeout` / `WithPipelineMax`) apply positive overrides AND refuse non-positive values (so a misconfigured `0` cannot clobber the default to "disabled").

## [0.6.28] - 2026-05-27

### Added
- **AboutPage RFC Compliance Matrix (Y42)** — a curated, filterable list of the standards Labyrinth implements, grouped by capability so an SRE / security reader can scan the resolver's compliance posture without opening the CHANGELOG. Categories: Core Protocol, DNSSEC Validation, Aggressive NSEC/NSEC3, EDNS / Cookies / Padding, Transport Security, Special-Use Names, Extended Errors, Caching, Blocking & Policy. Each card surfaces the RFC number (linking to the IETF datatracker), the section (when behaviour is pinned to a specific section, e.g. RFC 6840 §5.9), title, one-line summary of what we do, and the version that shipped it. A debounced search input filters across all fields and a category chip row narrows by capability. Data lives in [web/ui/src/data/rfcCompliance.ts](web/ui/src/data/rfcCompliance.ts) with a vitest integrity pin ([web/ui/src/data/rfcCompliance.test.ts](web/ui/src/data/rfcCompliance.test.ts)) that catches: empty fields, unknown category labels, malformed `since` versions, duplicate entries — so a typo in the matrix can't ship as a false compliance claim.

## [0.6.27] - 2026-05-27

### Added
- **DiagnosticsPage CD bit + RFC 8914 EDE badges (Y41)** — the trace UI now surfaces what the upstream actually sent back, not just the rcode and answer count. Each `upstream` event renders inline pill badges for the DNSSEC AD flag, the CD bit (RFC 6840 §5.9), and any Extended DNS Error codes the upstream attached. New backend helper [resolver/trace_ede.go](resolver/trace_ede.go) walks the response OPT pseudo-record and pulls every EDE option into a JSON-friendly descriptor (`{code, name, text}`), where `name` is the human-readable label from RFC 8914 §4 (Filtered, Prohibited, Stale Answer, DNSSEC Bogus, …). Unknown codes fall through to `EDE<n>` so future IANA assignments still render. The same details now flow through both forward and iterative paths ([resolver/trace.go](resolver/trace.go)) and render via a new `<TraceFlagBadges>` component on [web/ui/src/pages/DiagnosticsPage.tsx](web/ui/src/pages/DiagnosticsPage.tsx) — tooltips on hover explain what each bit means so an operator doesn't need to keep the RFC open in a tab. Pin test [resolver/trace_ede_test.go](resolver/trace_ede_test.go) covers the OPT/EDE parser (two-EDE response, no-OPT response, nil-message safety) and the code → name map for the five most common values.

## [0.6.26] - 2026-05-27

### Added
- **Dashboard "Resolver Observability" panel (Y40)** — the eight Y34/Y35/Y36 counters added in v0.6.24 lived only on `/metrics` (Prometheus scrape format). With v0.6.26 they are now first-class fields on `/api/stats` ([metrics/metrics.go](metrics/metrics.go), [web/api_stats.go](web/api_stats.go)) and surfaced on the dashboard as a six-card panel ([web/ui/src/pages/DashboardPage.tsx](web/ui/src/pages/DashboardPage.tsx)):
  - Failure cache hit/miss + hit-ratio bar (RFC 9520)
  - Server-cookie cache hit/miss + hit-ratio bar (RFC 7873 §5.3)
  - BADCOOKIE outbound retries with operator hint ("should trend to zero once cookie cache warms") (RFC 7873 §5.4)
  - NSEC aggressive synth NXDOMAIN / NODATA split (RFC 8198 §5.2 vs §5.4)
  - NSEC3 aggressive synth NXDOMAIN / NODATA split (RFC 8198 §5.2 vs §5.4)
  - Stale-while-refresh trigger counter (RFC 8767 §3.1)

  The TypeScript shape was extended with optional fields so the dashboard still renders against older servers that haven't surfaced these counters yet ([web/ui/src/api/types.ts](web/ui/src/api/types.ts)). Pin test [web/api_stats_v0_6_24_observability_test.go](web/api_stats_v0_6_24_observability_test.go) increments each counter and asserts the JSON output carries the matching key with the right value — catches both "added the field on one side but not the other" regressions.

## [0.6.25] - 2026-05-27

### Added
- **RFC 6840 §5.9 CD bit propagation (Y38)** — when a downstream stub or forwarder asks us to skip DNSSEC validation by setting CD=1 on its query, we now carry that intent through to forward-mode upstream queries instead of silently letting the upstream's own validator overrule the request. New `ResolveWithECSAndCD` entry point on the resolver, plumbed through `queryForwardECSCD` → `sendForwardQueryECSCD` → `sendQueryWithRDECSCD` so the CD bit reaches the wire ([resolver/forward.go](resolver/forward.go), [resolver/resolver.go](resolver/resolver.go)). Server wires the incoming header's CD bit via `msg.Header.CD()` ([server/handler.go](server/handler.go)). The original `ResolveWithECS` is preserved as a thin `cd=false` wrapper so every existing call site keeps its pre-Y38 behaviour. Pin test [resolver/rfc6840_cd_bit_test.go](resolver/rfc6840_cd_bit_test.go).

### Security
- **RFC 4509 §2.4 / RFC 8624 §3.3 — DS digest type 0 unconditionally rejected (Y37)** — IANA reserves digest type 0 as unusable for DNSKEY authentication. `isWeakDSDigest` now rejects it even when the operator opts into `allowSHA1=true` — the SHA-1 escape hatch is for *deprecated-but-functional*, not for *reserved* ([dns/dnssec_algorithms.go](dns/dnssec_algorithms.go), [dnssec/validator.go](dnssec/validator.go)). Pin test [dnssec/rfc4509_ds_digest_zero_test.go](dnssec/rfc4509_ds_digest_zero_test.go).
- **RFC 8624 §3.1 MUST-NOT algorithms gated by name (Y39)** — added IANA-numbered constants for the four "MUST NOT validate" algorithms (RSAMD5=1, DSA=3, DSA-NSEC3-SHA1=6, RSASHA1-NSEC3-SHA1=7) ([dns/dnssec_algorithms.go](dns/dnssec_algorithms.go)) so the reject path in `VerifyRRSIG`'s algorithm switch is pinned to the registry values, not to magic numbers. A renumber would silently break the gate (we'd reject the wrong number and accept the broken one). Pin test [dnssec/rfc8624_must_not_algorithms_test.go](dnssec/rfc8624_must_not_algorithms_test.go) drives `VerifyRRSIG` with each algorithm and asserts unsupported-algorithm rejection plus IANA constant values.

## [0.6.24] - 2026-05-27

### Added
- **Observability for the v0.6.18 → v0.6.23 feature set** — eight new Prometheus counters expose what was previously a blind spot: how often the new caches actually save work, and where the resolver is paying the bills.
  - `labyrinth_failure_cache_{hits,misses}_total` — RFC 9520 failure-cache (Y26) hit/miss ratio. High hit ratio = retry storms being absorbed; high miss ratio = each failure is its own.
  - `labyrinth_server_cookie_cache_{hits,misses}_total` — RFC 7873 §5.3 server-cookie cache (Y25). High hit ratio = we're paying the BADCOOKIE round-trip once per server; a low ratio with cookie-enforcing peers means the cache is being evicted faster than it warms up.
  - `labyrinth_nsec_aggressive_synth_total{kind="nxdomain|nodata"}` and `labyrinth_nsec3_aggressive_synth_total{kind=...}` — RFC 8198 §5.2 / §5.4 aggressive-use synthesis counters split by index (NSEC vs NSEC3) and kind (NXDOMAIN vs NODATA, the §5.2-vs-§5.4 distinction from Y16/Y27/Y32/Y33).
  - `labyrinth_outbound_badcookie_retries_total` — RFC 7873 §5.4 retry rate (Y24). Should trend to zero once the server-cookie cache is warm; sustained non-zero rate means churn.
  - `labyrinth_stale_while_refresh_total` — RFC 8767 §3.1 (Y29) background refresh trigger count. Zero with high stale-serve traffic means the prefetch hook is mis-wired.

  Wired into existing call sites in [cache/nsec_aggressive.go](cache/nsec_aggressive.go), [cache/nsec3_aggressive.go](cache/nsec3_aggressive.go), [cache/cache.go](cache/cache.go), [resolver/resolver.go](resolver/resolver.go), and [resolver/upstream.go](resolver/upstream.go) so the increment happens at the same instant the feature triggers — no separate accounting layer to drift. Pin tests [metrics/v0_6_24_observability_test.go](metrics/v0_6_24_observability_test.go) cover each counter's Inc method AND its surfacing on the /metrics endpoint (the second guard catches the "added the counter but forgot the writer" regression).

## [0.6.23] - 2026-05-27

### Added
- **RFC 8914 EDE on REFUSED responses** (§4.17 Filtered, §4.18 Prohibited) — the three refuse paths (global ACL deny, per-zone ACL deny, rate-limit deny) now attach an Extended DNS Error to the REFUSED response when the client carried EDNS, so a misconfigured client can tell "you cannot recurse here" (EDE 18, ACL) from "you tripped the rate limiter" (EDE 17, RRL) instead of treating REFUSED as one opaque verdict. A small byte-level helper [server/handler.go](server/handler.go) `queryHasEDNS` gates the emission per RFC 8914 §3 — non-EDNS clients still get a clean REFUSED with no surprise OPT in additional. Pin tests [server/rfc8914_refused_ede_test.go](server/rfc8914_refused_ede_test.go) cover the ARCount detection and the too-short-query defensive guard.
- **RFC 8198 §5.4 NSEC NODATA aggressive use** — extends the v0.6.18 NSEC aggressive-use index from "NXDOMAIN via interval coverage" to also synthesise NODATA when a cached NSEC's owner name EXACTLY matches qname and the type bitmap excludes qtype. Without this path the cache could prove "qname does not exist" but had to re-fetch upstream to prove "qname exists but not for type X" — even though the cached NSEC's bitmap is itself authenticated proof of the absence. New `LookupNSECCoversTyped` companion to the existing `LookupNSECCovers` (untyped wrapper kept for callers that only want NXDOMAIN), shared `buildNSECSynthEntry` helper for the two synthesis paths, and `typeBitmap` field on each cached interval. Server now uses the typed lookup. Pin tests [cache/rfc8198_nodata_aggressive_test.go](cache/rfc8198_nodata_aggressive_test.go) cover owner-match-with-type-absent, owner-match-with-type-present (synth must NOT fire), the NXDOMAIN regression guard, and the qtype=0 untyped path.
- **RFC 8198 §5.4 NSEC3 NODATA aggressive use** — parallel to the NSEC NODATA path but for NSEC3-signed zones. When `hash(qname)` under the cached NSEC3PARAM equals a cached owner hash AND qtype is absent from that NSEC3's type bitmap, the resolver synthesises NODATA locally. Same opt-out filter and RFC 9276 §3.2 iteration ceiling that gate the existing NSEC3 NXDOMAIN path apply. New `LookupNSEC3CoversTyped`, shared `buildNSEC3SynthEntry`, `typeBitmap` field on `nsec3Interval`. Pin tests [cache/rfc8198_nsec3_nodata_test.go](cache/rfc8198_nsec3_nodata_test.go) cover owner-hash-match-with-type-absent, type-present-skips, and the qtype=0 untyped wrapper.

## [0.6.22] - 2026-05-27

### Added
- **RFC 6303 locally-served reverse zones** — reverse-DNS queries for RFC 1918 private space (10/8, 172.16-31/12, 192.168/16), RFC 3927 link-local (169.254/16), RFC 5737 TEST-NET-1/2/3, RFC 1122 "current network" and loopback, RFC 4193 IPv6 ULA (fc00::/7 → d.f.ip6.arpa), and RFC 4291 IPv6 link-local (fe80::/10 → 8/9/a/b.e.f.ip6.arpa) are now short-circuited to NXDOMAIN inside the resolver instead of leaking to the public root. Stops the resolver from being a private-network reverse-traffic source on the root servers (RFC 6303 §2 motivation: "the public DNS sees an enormous amount of noise [...] revealing each origin's private network structure"). Operators who want a specific reverse zone to traverse upstream can configure it explicitly as a forward zone — the forward table is consulted before the short-circuit, so explicit operator intent wins. Implementation: [resolver/rfc6303_locally_served.go](resolver/rfc6303_locally_served.go), wired into `ResolveWithECS` after the RFC 6761 special-use check. Pin tests [resolver/rfc6303_locally_served_test.go](resolver/rfc6303_locally_served_test.go) cover RFC 1918 reverse, IPv6 ULA/link-local reverse, public-reverse non-interference, and the partial-suffix label-boundary guard.
- **RFC 8767 §3.1 stale-while-refresh** — when the cache serves a stale entry (existing serve-stale-on-upstream-failure path), it now also kicks off an async refresh via the existing prefetch hook so the next client query gets fresh data instead of more stale. Without this trigger, a long-tail name whose upstream was briefly broken would be stuck on the same stale answer for the whole stale window even after upstream recovered. Wired in `cache.GetStale`. Pin tests [cache/rfc8767_stale_while_refresh_test.go](cache/rfc8767_stale_while_refresh_test.go) cover the async-refresh fire-and-forget on stale serve and the prefetch-disabled no-op path.
- **RFC 8914 §4.13 EDE Cached Error on failure-cache replay** — a SERVFAIL replayed from the RFC 9520 resolution-failure cache now carries EDE info code 13 ("Cached Error") in addition to the original failure reason's EDE code (e.g. 22 No Reachable Authority). Operators debugging intermittent failures can finally tell a cache replay from a live identical failure without correlating to query timing. New `FromFailureCache` field on `ResolveResult` set when the early-return path fires; server's response builder attaches EDE 13 when the flag is set. Pin tests [resolver/rfc9520_ede_cached_test.go](resolver/rfc9520_ede_cached_test.go) cover the flag propagation through the failure-cache hit path and the false-by-default invariant for fresh resolutions.

## [0.6.21] - 2026-05-27

### Added
- **Per-IP server-cookie cache** (RFC 7873 §5.3) — the resolver now remembers the most-recent server cookie observed for each upstream auth and pre-emptively includes it in the next query to that auth, so the BADCOOKIE round-trip introduced in v0.6.20 is paid at most once per server rather than once per query. Cookie store lives in [resolver/server_cookie_cache.go](resolver/server_cookie_cache.go); bounded LRU-eviction at 1024 entries with the RFC 9018 §4.3 one-hour validity window as TTL, so a server-secret rotation upstream invalidates our cache automatically. Wired into `queryUpstreamOnceECS` both on the BADCOOKIE retry path and on every successful response that carried a cookie. Pin tests [resolver/rfc7873_server_cookie_cache_test.go](resolver/rfc7873_server_cookie_cache_test.go) cover the round-trip, defensive-copy contract, oldest-evicted-when-full, TTL eviction on lookup, capacity=0 disable, and nil-receiver safety.
- **Resolution-failure caching** (RFC 9520) — when a recursive resolution returns SERVFAIL with no answer (the broken-delegation case the operator's `153.133.185.147.in-addr.arpa` query exercised), the failure is recorded with the RFC §4 maximum five-second TTL so a downstream client retry storm against the same broken auth chain is absorbed by the resolver instead of re-traversing the failing delegation each time. DNSSEC-bogus outcomes are intentionally excluded (those have their own SERVFAIL caching with the bogus marker); ECS-bearing queries also bypass the cache because failure portability across subnets is not safe (an auth that REFUSED our subnet may happily answer another). New `failureCache` type in [resolver/failure_cache.go](resolver/failure_cache.go); bounded LRU at 4096 entries. Wired in `ResolveWithECS`. Pin tests [resolver/rfc9520_failure_cache_test.go](resolver/rfc9520_failure_cache_test.go) cover Put-then-Get replay, TTL expiry, key-independence across types/names, oldest-evicted-when-full, capacity=0 disable, and nil-receiver safety.
- **Aggressive use of NSEC3-validated cache** (RFC 8198 §5.3) — extends the v0.6.18 NSEC aggressive-use index to NSEC3-signed zones, which is most of the modern signed Internet (.com, .net, the bulk of ccTLDs). The new `nsec3Index` in [cache/nsec3_aggressive.go](cache/nsec3_aggressive.go) stores each interval's owner hash, next hash, and hashing parameters (algorithm + iterations + salt) so a later query can be hashed with the same scheme and tested for coverage. RFC 5155 §6 opt-out NSEC3s are filtered out at registration time because their denial guarantees do not extend to aggressive synthesis (they do not prove unsigned names in the gap are nonexistent). RFC 9276 §3.2 iteration ceiling (100) is honoured. Wired into the resolver alongside NSEC registration in [resolver/resolver.go](resolver/resolver.go) and into the server cache-miss lookup in [server/handler.go](server/handler.go). Pin tests [cache/rfc8198_nsec3_aggressive_test.go](cache/rfc8198_nsec3_aggressive_test.go) cover the strict-between coverage check, zone-wrap edge, hashing-gate safety rails (algorithm and iterations), owner-hash extraction (including malformed-owner rejection), and the opt-out filter.

## [0.6.20] - 2026-05-27

### Added
- **EDNS(0) PADDING on DoT and DoH responses** (RFC 7830 §3 + RFC 8467 §4.1) — when an encrypted-transport client (DoT or DoH) carries a PADDING option in its query, the response is now padded with zero bytes to the next 468-byte boundary so a passive observer on the wire cannot fingerprint queries from response length alone. Small NXDOMAIN, medium A answer, and large DNSSEC-signed AAAA used to sit in distinct length buckets; with padding they all sit in the same 468/936/1404… bucket. Padding is intentionally NOT applied to plain TCP (RFC 8467 §6 forbids it — zero privacy benefit on a wire the observer already reads in full, pure bandwidth waste). New `EDNSOptionCodePadding` (code 12), `PaddingBlockSize` constant, `BuildPaddingOption`, `HasPaddingOption`, and `PadRawResponse` helpers in [dns/edns.go](dns/edns.go); wired through [server/tcp_policies.go](server/tcp_policies.go) for DoT and inline in [web/api_doh.go](web/api_doh.go) for DoH. Pin tests [dns/rfc7830_padding_test.go](dns/rfc7830_padding_test.go) cover happy path, already-aligned, invalid-wire pass-through, and zero-block disable.
- **edns-tcp-keepalive on TCP and DoT responses** (RFC 7828 §3.1) — when a TCP/DoT client carries the KEEPALIVE option in its query, the server response advertises the connection's idle timeout (in 100ms units) so the client can intelligently hold the connection open across multiple queries instead of paying the three-way-handshake / TLS handshake cost per query. RFC 7828 §3.4 limits each response to a single keepalive option, so the helper is idempotent — if a downstream path already added the option we leave it alone. New `EDNSOptionCodeTCPKeepalive` (code 11), `BuildTCPKeepaliveOption`, `HasTCPKeepaliveOption`, and `AddTCPKeepaliveToRawResponse` in [dns/edns.go](dns/edns.go), wired into [server/tcp.go](server/tcp.go) and [server/dot.go](server/dot.go). DoH is intentionally excluded (HTTP/2 manages its own connection state). Pin tests [dns/rfc7828_keepalive_test.go](dns/rfc7828_keepalive_test.go) cover the append, idempotency, and client-signal detection paths.
- **BADCOOKIE retry on outbound queries** (RFC 7873 §5.4) — when an upstream auth replies with extended RCODE 23 (BADCOOKIE) and includes its freshly-minted server cookie in the OPT COOKIE option, the resolver now extracts that server cookie and re-issues the query once with `client_cookie || server_cookie` so the auth recognises us as the same client across the round-trip. Without this retry the resolver would never get past auths that enforce cookies — they would reply BADCOOKIE forever. The retry is one-shot: a second BADCOOKIE is surfaced as the answer (the auth is misbehaving). New `extendedRCODE` helper composes the 12-bit RCODE per RFC 6891 §6.1.3 (header low-4 bits | OPT TTL high byte); a resolver looking only at `Header.RCODE()` sees BADCOOKIE as plain "7" and misses the retry trigger. New `extractServerCookie` pulls bytes 8..end out of the response's COOKIE option. `sendQuery` now accepts an optional server cookie that is appended after the client cookie on retry. Pin tests [resolver/rfc7873_badcookie_retry_test.go](resolver/rfc7873_badcookie_retry_test.go) cover the rcode composition (both extended and plain paths plus nil-msg guard), server cookie extraction, and the missing-server-cookie no-retry path.

## [0.6.19] - 2026-05-27

### Added
- **SVCB / HTTPS / CAA record types recognised in the type registry** (RFC 9460 §2.1 / §9, RFC 8659) — `TypeSVCB` (64), `TypeHTTPS` (65), and `TypeCAA` (257) are now first-class entries in [dns/types.go](dns/types.go) `TypeToString`. The wire parser already treated unknown RDATA opaquely per RFC 3597, so traffic flowed correctly before — the bug was that logs and the queries UI showed `TYPE65` / `TYPE257` for HTTPS and CAA records, hiding the rising tide of HTTP/3, ECH, and cert-issuance traffic. Pin test [dns/rfc9460_svcb_test.go](dns/rfc9460_svcb_test.go).
- **Server cookie secret rotation with grace window** (RFC 7873 §5.2.5: "Cookies created with old secrets remain valid until they expire") — new `MainHandler.RotateCookieSecret` method moves the current secret aside, generates a fresh one, and keeps the previous secret usable for one hour (matching the RFC 9018 §4.3 cookie validity window) so a routine rotation does not invalidate every active client's cookie at once. `validateServerCookie` now tries current then previous, eliminating the BADCOOKIE round-trip spike that would otherwise follow rotation. Operators can wire this into an admin/config-reload action; the default behaviour (never rotate) is unchanged. New `cookieMu` mutex protects concurrent secret access. Pin tests [server/rfc7873_cookie_rotation_test.go](server/rfc7873_cookie_rotation_test.go) cover the grace path, the post-grace eviction, and the disabled-cookies refusal.
- **Outbound DNS cookie + response integrity check** (RFC 7873 §5.4) — every EDNS-bearing outbound query now carries a stable 8-byte random Client Cookie generated once at resolver startup. Auths that implement RFC 7873 echo the cookie in their reply's COOKIE option; the resolver's new `validateResponseCookie` in [resolver/upstream.go](resolver/upstream.go) rejects any response whose echoed first 8 bytes do not match, because a mismatch is positive evidence of off-path forgery (the spoofer cannot guess the random 64-bit cookie value). On top of the TXID (16 bits), source-port (~15 bits), and 0x20 caps (variable, typically ~10 bits) layers the resolver already enforces, this multiplies the brute-force window for blind off-path spoofing by ~10¹⁹. Auths that do not include a cookie are accepted unchanged — full back-compat per §5.4 ("the resolver MUST NOT discard responses that do not include a COOKIE option"). The full server-cookie state machine (per-IP cache + BADCOOKIE retry) is a follow-up; the client-cookie-only path already provides the bulk of the off-path hardening. Pin tests [resolver/rfc7873_outbound_cookie_test.go](resolver/rfc7873_outbound_cookie_test.go) cover match, mismatch, no-cookie, disabled-resolver-cookie, and malformed-cookie paths.

## [0.6.18] - 2026-05-27

### Added
- **RFC 8198 aggressive use of DNSSEC-validated cache** — when a Secure NXDOMAIN response arrives, the NSEC records in its authority section are themselves authenticated proof that every name strictly between an NSEC's owner and next-domain fields does not exist. The resolver now registers those intervals in a per-zone index ([cache/nsec_aggressive.go](cache/nsec_aggressive.go)) so a subsequent miss for any OTHER name covered by the same gap is answered from cache without going upstream. The synthesised response carries the original SOA + NSEC + RRSIGs so downstream validators can confirm AD. For popular signed zones (`.com`, `.org`, the ccTLDs) routinely hit by random-subdomain garbage traffic, the same gap interval covers many unrelated nonexistent queries, dropping auth-server load by an order of magnitude in practice. Bounded per-zone interval count and TTL-expiry prune keep memory finite. Pin tests [cache/rfc8198_nsec_aggressive_test.go](cache/rfc8198_nsec_aggressive_test.go) cover gap synthesis, existing-name negative, cross-zone refusal, and expiry-driven invalidation.
- **`cache.stale_max_age` setting bounding how far past expiry a stale entry may be served** (RFC 8767 §3.3) — the spec says "responses no longer than 1-3 days old be considered for stale serve." The pre-fix `GetStale` returned any entry that was simply expired, regardless of how long ago — a long-tail name accessed once and then six months later would still be served stale. New `staleMaxAge` field in [cache/cache.go](cache/cache.go) caps the elapsed-since-expiry interval. Default is 86400 seconds (1 day, conservative end of the RFC range); operators who explicitly want unbounded behaviour can set 0 to disable the cap. Pin tests in [cache/rfc8198_nsec_aggressive_test.go](cache/rfc8198_nsec_aggressive_test.go) cover both the reject-too-old and accept-within-cap paths plus the zero-disables behaviour.

## [0.6.17] - 2026-05-27

### Fixed
- **Diagnostic trace gave up after the first NS failure even though more NS records were available** — the trace path in [resolver/trace.go](resolver/trace.go) `traceIterative` worked on a flat `[]string` of IPs derived once from the delegation; when that list exhausted on REFUSED/ServFail (the typical broken-reverse-zone shape: one glue'd NS rejects, three NS hostnames remain unresolved) the loop printed "no reachable nameserver" without ever resolving the other 3 hostnames. The production resolver path (`selectAndResolveNS` in `resolveIterativeFromInner`) already did this correctly — so the trace UI was lying about what production actually did, making operators believe the resolver itself was broken when in fact it was upstream. The trace path now keeps a `pendingNSHostnames` list of un-tried NS hostnames from the most recent delegation and drains it (A then AAAA recursive resolution) before declaring exhaustion. RFC 1034 §4.3.2.

### Added
- **EDE info code 22 (No Reachable Authority) on the all-NS-refused SERVFAIL path** (RFC 8914 §4.22) — when every authoritative NS in the final delegation refused or was unreachable (the broken-reverse-zone shape on `in-addr.arpa` /24s whose published NS never had real auth set up), the SERVFAIL response now carries EDE 22 with a human-readable hint. Clients and operators can then distinguish "our resolver is broken" (retry) from "the upstream delegation is broken" (retry is hopeless, the fix is at the parent zone). New `ResolveResult.FailureReason` field in [resolver/resolver.go](resolver/resolver.go) tags the cause at every exhaustion site; the server maps it in [server/handler.go](server/handler.go) to the granular EDE code with descriptive text. Pin test [resolver/no_reachable_authority_test.go](resolver/no_reachable_authority_test.go).
- **Diagnostic UI auto-rewrites bare IP literals to in-addr.arpa / ip6.arpa when type=PTR** — typing `46.20.5.236` and selecting `PTR` previously sent the literal string to the resolver, which iterated from the root for the leftmost label (`236`) and bottomed out at NXDOMAIN, confusing operators into thinking the resolver was broken. The form now rewrites IPv4 to the dotted-reversed `…in-addr.arpa` form (RFC 1035 §3.5) and IPv6 to the nibble-reversed `…ip6.arpa` form (RFC 3596 §2.5) before sending. Non-IP inputs pass through unchanged so legitimate PTR queries on already-formed arpa names keep working. New helper [web/ui/src/pages/reverseDns.ts](web/ui/src/pages/reverseDns.ts); pin test [web/ui/src/pages/reverseDns.test.ts](web/ui/src/pages/reverseDns.test.ts) covers IPv4, IPv6 canonical/shorthand, edge cases, and malformed-input rejection.

## [0.6.16] - 2026-05-27

### Fixed
- **Weaker DS digest types were considered alongside stronger ones for the same key** (RFC 4509 §3 / RFC 6840 §5.2 violation) — the spec is explicit: "If the DS RRset of a delegation contains multiple records with different digest types, a signed DNSKEY RRset is validated if it is validated by at least one of the records that uses the algorithm with the highest value among the supported ones." A pre-fix validator running with `dnssec.allow_sha1 = true` (operator policy for legacy zones) would accept a SHA-1 DS match even when a SHA-256 DS for the same key was also published — a SHA-1 collision against the same key tag + algorithm could chain to a key the operator would never have accepted under SHA-256. The fix adds `strongestDSDigestForKey` in [dnssec/validator.go](dnssec/validator.go) and wires it into both `verifyDNSKEYWithDS` and `verifyAgainstTrustAnchors`; DS digest types are now selected per (key tag, algorithm) and only the strongest supported one is honoured. Pin tests [dnssec/rfc4509_strongest_ds_test.go](dnssec/rfc4509_strongest_ds_test.go).
- **OPT pseudo-RR with non-root owner was silently accepted** (RFC 6891 §6.1.2: "NAME — domain name — MUST be 0 (root domain)") — a buggy or hostile client could smuggle arbitrary names through the EDNS OPT, potentially confusing log pipelines, ACL paths keyed on RR name, or downstream EDNS option parsers that assume owner == root. The Handle gate in [server/handler.go](server/handler.go) now FORMERRs any OPT whose owner is not the root, alongside the pre-existing multi-OPT FORMERR (RFC 6891 §6.1.1). Pin test [server/rfc6891_opt_owner_test.go](server/rfc6891_opt_owner_test.go).
- **Responses with multiple CNAME RRs at a single owner were silently accepted** (RFC 2181 §10.1 violation) — "There may be only one such [CNAME] record per domain name." The pre-fix classifier set `hasCNAME = true` without counting, and `extractCNAMETarget` returned the first match. A malicious or misconfigured authoritative could attach a forged second CNAME to a legitimate response, redirecting the chain to attacker-controlled infrastructure. The classifier in [resolver/classify.go](resolver/classify.go) now counts CNAMEs at qname and returns `responseServFail` when more than one is present, forcing the iterative loop to try a sibling nameserver. Pin test [resolver/rfc2181_cname_test.go](resolver/rfc2181_cname_test.go).

## [0.6.15] - 2026-05-26

### Fixed
- **RRSIG.Labels was not bounded against the owner-name label count** (RFC 4034 §3.1.3) — the spec is explicit: "The value of the Labels field MUST be less than or equal to the number of labels in the RRSIG owner name." A larger Labels value is structurally malformed — no legitimate signer can produce one, because Labels records how many labels the original signed owner actually had (root and wildcard label excluded). The previous code in [dnssec/verify.go](dnssec/verify.go) silently let it through and `canonicalWildcardOwner` returned the owner verbatim, widening the attack surface on the wildcard-reconstruction path. The fix rejects the RRSIG up front with `errMalformedLabels`; the validator's outer loop treats it as one signature failure and tries the next RRSIG (so the rollover-safe fallback is preserved). Pin tests [dnssec/rfc4034_labels_test.go](dnssec/rfc4034_labels_test.go).

### Added
- **Granular RFC 8914 EDE info codes on DNSSEC failures** — every Bogus answer used to collapse into the generic EDE 6 (DNSSEC Bogus), making it impossible to tell "the auth's signature expired" (operational failure at the signer) from "we saw a cryptographic forgery on the wire" (security event). The validator now classifies the failure cause through a new `FailureReason` type ([dnssec/failure_reason.go](dnssec/failure_reason.go)) and a `ValidateResponseWithReason` entrypoint; the resolver propagates the cause as `ResolveResult.DNSSECReason`; the server in [server/dnssec_ede.go](server/dnssec_ede.go) maps it to the correct EDE code:
  - RRSIG `Expiration < now` → EDE 7 (Signature Expired, RFC 8914 §4.7)
  - RRSIG `Inception > now` → EDE 8 (Signature Not Yet Valid, RFC 8914 §4.8)
  - DNSKEY rrset fetch failed or no key with matching tag/algorithm → EDE 9 (DNSKEY Missing)
  - All RRSIGs used a refused/unsupported algorithm → EDE 1 (Unsupported DNSKEY Algorithm)
  - Other Bogus (crypto verify, out-of-bailiwick signer, trust-chain bogus) → EDE 6 (generic)

  The hot path stays allocation-free — `ValidateResponseWithReason` doesn't allocate the per-RRSIG step slice. Pin tests [dnssec/rfc_ede_reason_test.go](dnssec/rfc_ede_reason_test.go).
- **CNAME synthesis from DNAME when upstream omits the companion CNAME** (RFC 6672 §5.3) — the spec says: "If the resolver does not find a CNAME associated with the DNAME, it MUST synthesize one." Many stub resolvers and applications only know how to follow CNAME chains; without the synthesised CNAME the DNAME redirection is invisible to them and the lookup appears to fail. The auth is supposed to include the synth-CNAME per RFC 6672 §3.2, but historical and non-conformant servers omit it — the iterative resolver is the last line of defence. The DNAME branch in [resolver/resolver.go](resolver/resolver.go) now detects the missing companion and synthesises a CNAME at qname pointing to the DNAME-substituted target, inheriting the DNAME's TTL (RFC 6672 §5.3.3). The synthesised CNAME is intentionally unsigned — RFC 6672 §3.2 forbids signing it because the DNAME RRSIG already authenticates the substitution rule. New helper `dns.EncodeNameToBytes` ([dns/name.go](dns/name.go)) produces the uncompressed wire-format RData for the synthesised record. Pin test [resolver/rfc6672_dname_synth_test.go](resolver/rfc6672_dname_synth_test.go).

## [0.6.14] - 2026-05-26

### Fixed
- **RRset TTLs were stored with their original mixed values, violating RFC 2181 §5.2** — when an authoritative published an rrset with non-uniform TTLs (e.g. three A records at 300/600/60), the cache preserved each record's TTL verbatim. RFC 2181 §5.2 is explicit: "If any of the records in the set have different TTLs, then a receiver must … treat them as if they all had the same TTL — the lowest of those TTLs." A hostile or buggy auth could otherwise mix one short-TTL record with several long-TTL ones; downstream serve-stale would key off the longest, pinning poisoned or outdated data in cache far past the rrset's intended life. The cache in [cache/cache.go](cache/cache.go) now runs `normalizeRRSetTTLs` over both answers and authority at store time, grouping by (name, type, class) and collapsing each group to its minimum. Pin test [cache/rfc2181_rrset_test.go](cache/rfc2181_rrset_test.go).
- **Compact denial of existence accepted NSEC at qname whose bitmap LISTED the qtype** (RFC 6840 §4.1 / "black lies" replay attack) — Cloudflare-style compact denial puts a legitimate NSEC at the very name being queried with a synthetic bitmap that excludes the qtype. The pre-fix loop in [dnssec/nsec.go](dnssec/nsec.go) `VerifyNSECDenial` only required `OwnerName == qname` and the absence of CNAME/DNAME/parent-side-NS, but did *not* check whether the bitmap itself omitted the qtype. An attacker who replays a real signed NSEC for an *existing* name (bitmap contains A/AAAA/MX) paired with a forged RCODE=NXDOMAIN would slip past the validator. The fix adds `nsecHasType(&n.NSECRecord, qtype) { continue }` — if the bitmap asserts the type exists, the denial claim is structurally a lie. Pin test [dnssec/compact_denial_test.go](dnssec/compact_denial_test.go).

### Added
- **RFC 6975 DAU/DHU/N3U algorithm signaling on outbound DNSSEC queries** — when DNSSEC validation is enabled, the resolver now advertises which signature algorithms (DAU, EDNS option code 5), DS digest types (DHU, code 6), and NSEC3 hash algorithms (N3U, code 7) it can actually validate, letting auth servers prefer signatures the client will not just discard. The advertised lists reflect the resolver's real capability surface — RSASHA256, RSASHA512, ECDSAP256, ECDSAP384, ED25519 (plus RSASHA1 only if `dnssec.allow_sha1`), DS digest types SHA-256 / SHA-384 (plus SHA-1 conditionally), and NSEC3 hash 1 (SHA-1, the only defined value). New helpers `BuildDAUOption` / `BuildDHUOption` / `BuildN3UOption` in [dns/edns.go](dns/edns.go); wired in [resolver/upstream.go](resolver/upstream.go) `sendQuery` alongside the existing EDNS0 OPT pseudo-RR. Pin test [dns/rfc6975_test.go](dns/rfc6975_test.go).

## [0.6.13] - 2026-05-26

### Changed
- **`resolver.caps_for_id` (DNS 0x20 case randomization) now defaults to `true`** (RFC 5452 §9.2 hardening) — for every ASCII letter in an outbound qname the resolver flips the case at random, and the auth server is required to mirror the exact case on the way back. An off-path spoofer had to guess the 16-bit TXID (65 536 possibilities); with 0x20 enabled on a typical 10-letter name they now also have to guess 10 random bits of case, multiplying the brute-force window by ~1024 at zero protocol cost. The infrastructure has shipped since 0.4 but was disabled by default; the audit flagged this and 0.6.13 flips the default on. Operators who interact with the (very rare) misbehaving authoritative that does not preserve case can still set `resolver.caps_for_id: false` in config. [config/defaults.go](config/defaults.go).

### Added
- **EDE info code 19 (STALE-NXDOMAIN-ANSWER) on serve-stale NXDOMAIN responses** (RFC 8914 §4.4 / RFC 8767 §6) — previously the serve-stale path emitted the generic "Stale Answer" code (3) for both positive and negative cached entries, so clients had no way to tell "expired denial of existence" from "expired positive answer". The selection in [server/handler.go](server/handler.go) now branches on `entry.RCODE`. Useful for both log triage and client-side retry policy (a stale NXDOMAIN typically should not be retried; a stale positive answer can be revalidated against the same upstream).
- **EDE info code 4 (FORGED ANSWER) when the private-IP filter strips records** (RFC 8914 §4.6) — when `security.private_address_filter` removes A/AAAA records (DNS-rebinding protection) the response was empty without any wire-level indication that the resolver had mutated the upstream answer. Clients could not distinguish "auth returned no records" from "resolver rebind-protected the answer". The new EDE in [server/handler.go](server/handler.go) `buildResponse` fires only when the filter actually removed something, so legitimate empty answers are not falsely tagged as forged.

### Fixed
- **Revoked DNSKEYs (RFC 5011 §3, bit 8 / mask `0x0080`) were accepted in chain validation** — `verifyAgainstTrustAnchors`, `verifyDNSKEYWithDS`, and `findMatchingDNSKEY` ([dnssec/validator.go](dnssec/validator.go)) all walked the DNSKEY RRset without checking the REVOKE flag. RFC 5011's whole point is to give an operator a way to disown a key (compromise, planned rollover) by re-publishing it with REVOKE set — the resolver MUST treat such keys as no longer authoritative. Without the check, a revoked-yet-DS-published key during the hold-down period would still validate signatures, defeating the rollover. New [`DNSKEYRecord.IsRevoked`](dns/rdata.go) decodes the flag; all three call sites now skip revoked keys, forcing the chain to rebuild from unrevoked siblings. Pin test [dnssec/rfc5011_revoke_test.go](dnssec/rfc5011_revoke_test.go).
- **CD=1 (Checking Disabled) queries had their Bogus verdicts masked behind SERVFAIL** (RFC 4035 §3.2.2 violation) — when the client explicitly asked for validation to be skipped (e.g. a debugging stub like `dig +cd`), the handler still converted Bogus to SERVFAIL, hiding the bogus data the client deliberately requested. The handler in [server/handler.go](server/handler.go) now passes Bogus data through unmodified when CD=1; the AD bit is already cleared under CD=1 by the response-builder, so clients still see the non-validated state without losing the data itself. The MITM/downgrade defenders (CD=0 — the overwhelming default) are unchanged.

## [0.6.12] - 2026-05-26

### Fixed
- **NSEC3 closest-encloser proof skipped (RFC 5155 §8.4–8.7 / RFC 6840 §4.8 violation)** — `VerifyClosestEncloser` in [dnssec/nsec3.go](dnssec/nsec3.go) was dead code (its `hashStr`/`ownerHash` locals were assigned then immediately discarded with `_ = …`) and the path actually used by the validator, `VerifyNSEC3DenialFull`, accepted *any* NSEC3 whose owner-hash interval covered H(qname) as proof of NXDOMAIN. A signed-but-unrelated NSEC3 lifted from elsewhere in the same zone could be replayed to forge NXDOMAIN for any name whose true closest-encloser the attacker chose to lie about — the proof-substitution attack RFC 5155 was written to prevent. New [`VerifyNSEC3Denial5155`](dnssec/nsec3.go) requires the full three-record proof:
  1. Closest-encloser MATCH — an NSEC3 whose owner-hash equals H(deepest existing ancestor)
  2. Next-closer COVER — an NSEC3 whose interval contains H(CE's immediate child label on the path to qname)
  3. Wildcard-at-CE COVER — an NSEC3 whose interval contains H(*.CE)

  Also pinned: RFC 9276 §3.2 iteration cap now applies to **every** NSEC3 record in the proof rather than only `records[0]` (a previous oversight let an attacker mix one low-iteration leader with high-iteration siblings to slip past the cap). RFC 5155 §6 opt-out: an opt-out next-closer-cover NSEC3 invalidates the NXDOMAIN proof — the next-closer name may exist as an unsigned delegation. The validator now hits the new function in [dnssec/validator.go](dnssec/validator.go) `validateDenialResponse`. Pin tests in [dnssec/rfc_audit_test.go](dnssec/rfc_audit_test.go) cover the negative (loose-proof rejection, opt-out invalidation, per-record iteration cap) and positive (proper three-NSEC3 proof, direct NODATA match) shapes. The pre-existing `TestValidateDenialResponse_SecureWithNSEC3DenialProof` was updated to expect Bogus where it used to expect Secure — locking in the regression rather than the bug.
- **Unauthenticated empty-DS downgrade (RFC 4035 §5.2 / RFC 5155 §10.4 violation)** — `fetchDS` in [dnssec/validator.go](dnssec/validator.go) returned an empty DS list on any NOERROR-no-DS response, and the chain walker accepted that as proof of Insecure delegation without verifying the parent's denial of DS. An off-path attacker who wins the TXID/0x20 race for a single forged packet could inject a NOERROR-empty DS reply and downgrade a previously-Secure child zone to Insecure for the cache lifetime — the classic resolver downgrade vector. The fix threads the parent zone's verified DNSKEY rrset through the chain walker (`parentKeys` in `validateTrustChain`), surfaces the DS response's authority section out of `fetchDS`, and calls a new [`verifyDSDenial`](dnssec/validator.go) helper that authenticates the denial before accepting Insecure. Three proof forms are recognised:
  - NSEC at the child's owner name whose bitmap omits DS (and includes NS)
  - NSEC3 at H(childZone) whose bitmap omits DS (new [`VerifyNSEC3DenialDSAbsent`](dnssec/nsec3.go))
  - Opt-out NSEC3 covering H(childZone) (the canonical TLD-served insecure-delegation shape — com/net/etc.)

  Each accepted proof must be signed by a key in `parentKeys`; an unsigned authority section is now Bogus, not Insecure. The legacy `TestValidateTrustChain_TLDNoDSInsecure` was updated to expect Bogus on unauthenticated empty-DS — what it used to test was the downgrade vector itself.

## [0.6.11] - 2026-05-26

### Fixed
- **FORMERR downgrade vector against DNSSEC validation (RFC 5452 §6.1 hardening)** — `queryUpstreamOnceECS` in [resolver/upstream.go](resolver/upstream.go) used to interpret a FORMERR on an EDNS-bearing query as "this server hates EDNS, retry without OPT" per the original RFC 6891 §7 recipe. DNS Flag Day 2020 made EDNS mandatory on the public DNS — an EDNS-hostile auth server is now extinct. What is still very real: an off-path attacker who wins the TXID/0x20/source-port race for a *single* forged packet can inject a FORMERR and trigger our silent downgrade to a non-EDNS query that drops DNSSEC OK, ECS, and the 1232-byte buffer ceiling — a one-packet DNSSEC-validation downgrade. The unconditional retry is removed; a FORMERR is now treated as a server failure ([resolver/classify.go](resolver/classify.go)) so the iterative loop moves to a sibling NS and no spoofed FORMERR strips the DO bit off the resolution.
- **Lame/forged answers accepted as authoritative (RFC 1034 §3.7 / RFC 2181 §6.1 violation)** — `classifyResponse` in [resolver/classify.go](resolver/classify.go) didn't check the AA bit before promoting an `ANCount > 0` response to `responseAnswer`. The resolver issues iterative queries (RD=0) at servers it believes are authoritative for the relevant zone; a response carrying answers but with AA=0 is either a lame server echoing its own cache or an off-path forgery race-winner, and either way must not be cached as authoritative. The check now skips such responses and lets the loop fall through to a sibling NS. Mock test fixtures grew an `ensureAAOnAuthoritativeReply` shim so existing tests can model realistic auth replies without each individually flipping `SetAA(true)`.
- **Off-bailiwick SOA forging negative caching (RFC 2308 §3 violation)** — `classifyResponse` accepted *any* SOA in the authority section as proof of NODATA, and `Cache.StoreNegative` cached the entry without verifying the SOA owner. A hostile or buggy authoritative could attach an SOA for an unrelated zone (with attacker-controlled minimum-TTL) to forge a negative response that pinned the queried name into NXDOMAIN/NODATA for the SOA-dictated lifetime — a long-lived denial-of-service via cache poisoning. Both layers now require the SOA owner to be the queried name itself or an ancestor of it: a new `soaCoversName` helper in [resolver/classify.go](resolver/classify.go) gates classification, and a defense-in-depth `authorityCoversName` check in [cache/cache.go](cache/cache.go) refuses the store even if a future caller bypasses the classifier.
- **Resolution-failure amplification against upstream auth servers (RFC 9520 §3 missing)** — when the resolver returned SERVFAIL (DNSSEC bogus, all NS unreachable, lame delegation, every upstream timing out) nothing was cached, so a client retrying every 100 ms re-ran the entire iterative chain on every QPS spike. RFC 9520 §3 mandates short-lived caching of resolution failures specifically to protect upstream auth servers from this stampede. New `Cache.StoreFailure` ([cache/cache.go](cache/cache.go)) stores a `NegServFail` entry with TTL clamped to `[1, MaxFailureTTL=30s]` and a default of 5 s; the handler writes one on both the resolver-returned-SERVFAIL path and the resolver-error path. Cached failure entries are still subject to RRL on the cache-hit path (new addition to [server/handler.go](server/handler.go)) so a flood of clients for the same broken name is rate-limited rather than amplifying out a stream of cached SERVFAILs.
- **DNS cookie validation never enforced (RFC 7873 §5.2 missing)** — `validateServerCookie` had existed since 0.4 but was unreachable code; the handler echoed cookies but never validated them. A client presenting a stale, IP-mismatched, or forged server cookie was silently accepted, completely defeating the cookie's role as proof-of-IP-ownership for bypassing rate-limit/RRL — exactly the attack vector cookies are meant to close. The handler ([server/handler.go](server/handler.go)) now validates the server cookie immediately after the EDNS-version check (early enough that a garbage-cookie flood cannot consume CPU on cache lookup or recursive resolution) and emits a BADCOOKIE response on failure. New `RCodeBadCookie = 23` extended-RCODE constant ([dns/types.go](dns/types.go)); new `buildBadCookieResponse` encodes the 12-bit RCODE per RFC 6604 §3 (low 4 bits `0x07` in the header, high 8 bits `0x01` in the OPT TTL byte 0) and MUST echo a freshly issued server cookie so the client can adopt it (RFC 7873 §5.2.3 — refusing would lock out legitimate clients forever after a server-secret rotation). Pin-test `TestHandle_BadCookie` in [server/rfc_audit_test.go](server/rfc_audit_test.go) locks the wire layout.

### Deferred to v0.6.12 (DNSSEC engine refactor)
- **NSEC3 closest-encloser proof skipped (RFC 5155 §8.4–8.7 / RFC 6840 §4.8)** — `VerifyClosestEncloser` is dead code in [dnssec/nsec3.go](dnssec/nsec3.go) (results are discarded), and `VerifyNSEC3DenialFull` accepts any covering NSEC3 over the qname hash without requiring the (closest-encloser, next-closer, wildcard-at-CE) triple. A forged single NSEC3 can fake NXDOMAIN. Requires propagating NSEC3 owner-hash labels through the parser. Tracked for the next release.
- **Unauthenticated empty-DS downgrade (RFC 4035 §5.2 / RFC 5155 §10.4)** — `fetchDS` in [dnssec/validator.go](dnssec/validator.go) returns an empty DS list on NOERROR with no DS records, which the chain walker accepts as proof of insecure delegation without verifying the parent's NSEC/NSEC3 denial of DS. An off-path attacker spoofing a NOERROR-empty DS reply downgrades a secure child to Insecure. Fix requires threading parent DNSKEYs into the DS fetch path so the denial can be validated; deferred to the same release.

## [0.6.10] - 2026-05-26

### Fixed
- **TTL with the most-significant bit set was honoured verbatim (RFC 2181 §8 violation)** — a hostile or buggy authoritative could ship a record with `TTL = 0xFFFFFFFF` (~136 years) and we would store it for the full duration, turning a single poisoned answer into a near-permanent cache entry. RFC 2181 §8 is explicit: "Values of the TTL field with the MSB set should be treated as if the entire TTL field was set to zero." New `sanitizeWireTTL` in [cache/cache.go](cache/cache.go) clamps any MSB-set value to 0 at the wire boundary, then the §8 don't-cache rule below drops the entry. Applied symmetrically to positive (`extractTTL`) and negative (`extractNegativeTTL`) paths.
- **TTL=0 records were silently promoted to `minTTL` and cached (RFC 2181 §8 violation)** — when an authoritative deliberately returned `TTL=0` (the standard signal for "use once, do not cache" — common in dynamic DNS, GSLB-tailored answers, transient failover entries), the cache's `extractTTL` floor of `c.minTTL` (typically 5 s) lifted it to a real cache hit. RFC 2181 §8: "Zero TTL values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached." `Cache.Store`, `Cache.StoreWithECSStatus`, and `Cache.StoreNegative` now short-circuit when the post-sanitize TTL is 0, returning without writing the entry. The `minTTL` knob still raises non-zero TTLs (its original purpose). Note: tests that previously relied on `Store(..., TTL:0, ...)` + `time.Sleep` to construct a stale entry now use `TTL:1`.
- **NS records that are CNAMEs were followed silently (RFC 2181 §10.3 violation)** — when a referral named an authoritative server whose A/AAAA lookup returned a CNAME chain rather than an address record at the NS owner name, we would follow the chain and query the resolved address. RFC 2181 §10.3 forbids this: "The domain name used as the value of a NS resource record … must not be an alias." A hostile auth could chain `ns1.victim.com.` → `attacker.com.` → arbitrary IP. New `nsHasCNAMERedirect` in [resolver/resolver.go](resolver/resolver.go) detects the case in both the A and AAAA arms of `selectAndResolveNS` and skips the NS, falling through to the next sibling in the NSSET.
- **Special-use names hit the iterative root path instead of being short-circuited (RFC 6761/7686/8375)** — queries for `.onion`, `.invalid`, `.test`, bare `.example` (TLD), `.local`, and `home.arpa` were dispatched up to the root servers, leaking the existence of Tor hidden-service users, internal lab/test/staging names, and mDNS local-link names to the public DNS. Each of these zones has a normative MUST or SHOULD on resolvers to answer locally:
  - RFC 7686 §2 — `.onion` MUST be answered with `NXDOMAIN`
  - RFC 6761 §6.4 — `.invalid` MUST be answered with `NXDOMAIN`
  - RFC 6761 §6.2 — `.test` SHOULD be answered with `NXDOMAIN`
  - RFC 6761 §6.5 — `.example` TLD itself returns `NXDOMAIN`; `example.com`/`net`/`org` keep their real delegations and are NOT short-circuited
  - RFC 6762 §3 — `.local` MUST be answered with `NXDOMAIN` for non-mDNS resolvers (operator can override with a local zone)
  - RFC 8375 §4 — `home.arpa` MUST NOT be forwarded outside the home network

  New [resolver/specialuse.go](resolver/specialuse.go) handles all six. Wired into `ResolveWithECS` ([resolver/resolver.go](resolver/resolver.go)) and `Trace` ([resolver/trace.go](resolver/trace.go)) *after* the local-zone lookup so operator-configured `.local` or `home.arpa` zones still take precedence.
- **EDNS queries with version > 0 were silently downgraded to no-OPT or treated as FORMERR (RFC 6891 §6.1.3 violation)** — RFC 6891 §6.1.3 mandates a specific BADVERS response: header `RCODE=0` (low 4 bits), OPT `ExtRCODE=1` (high 8 bits, composing the effective RCODE=16), and the OPT in the reply carrying the responder's highest supported version (0) so the client can downgrade. New `buildBadVersResponse` in [server/handler.go](server/handler.go) constructs the response exactly per spec; new pin-test `TestHandle_BadVers` in [server/edns_rfc_test.go](server/edns_rfc_test.go) locks the byte-level layout.
- **Queries with more than one OPT record were processed normally (RFC 6891 §6.1.1 violation)** — RFC 6891 §6.1.1: "If a query message with more than one OPT RR is received, a FORMERR (RCODE=1) MUST be returned." Handler now counts OPT records in `Additional` and short-circuits to `FORMERR` before EDNS processing. Pin-test `TestHandle_MultipleOPTs`.
- **DNS cookie validation accepted future-timestamped server cookies up to the full 1-hour validity window (RFC 9018 §4.3 violation)** — without an upper bound on future timestamps, an attacker probing the validation window had the same 1-hour tolerance in both directions, doubling the search space for forging a cookie against the truncated SipHash output. `validateServerCookie` in [server/handler.go](server/handler.go) now enforces a 5-minute future-skew ceiling: `timestamp > now && timestamp-now > 300 → reject`. Pin-test `TestCookie_FutureTimestampRejected`.

## [0.6.9] - 2026-05-26

### Changed
- **EDNS Client Subnet (RFC 7871) is now per-query end-to-end** — the resolver previously held a process-global `activeECS atomic.Pointer[dns.ECSOption]` and the `Resolver.SetActiveECS` setter that wrote into it. Under concurrent client load, the slot read by one goroutine's outbound query was racing with another goroutine's setter; one client's subnet could be stitched onto another client's upstream query. The race was acknowledged in the field doc comment but not fixed. Removed entirely. The plumbing now carries `clientECS *dns.ECSOption` as an explicit parameter through [`Resolver.ResolveWithECS`](resolver/resolver.go) → `resolveIterativeFromInner` → `queryUpstreamECS` → `sendQuery` (and the forward-zone twin `sendQueryWithRDECS`). The legacy `Resolver.Resolve(name, qtype, qclass)` is preserved as a no-ECS wrapper so the existing 50+ test sites and trace/DNSSEC chain-walks (which never carry client subnet) keep working unchanged.

### Added
- **ECS-aware cache** — cache lookups and stores now honour the authoritative SCOPE PREFIX-LENGTH returned by the upstream (RFC 7871 §7.3). When the upstream answers with `scope=0` the entry is global and shared across all clients (the existing pre-ECS behaviour). When the upstream answers with a non-zero scope, the entry is keyed under `truncate(client_subnet, scope) + "/" + scope` via the new [`Cache.StoreWithECSStatus`](cache/cache.go), and a missed global lookup is followed by a scoped lookup using the outbound option's `CacheKey()`. The new test `TestHandle_ECS_ScopedCacheIsolation` pins the property end-to-end: a /24-scoped CDN answer for clients in `1.2.3.0/24` is **not** served to a client in `8.8.8.0/24` — proved by the second client getting SERVFAIL against an unreachable upstream because the scoped entry was correctly invisible.
- **Passthrough ECS forwarding policy** — the handler reads the client's OPT for an ECS option ([`buildOutboundECS`](server/handler.go)) and, if `resolver.ecs_enabled` is set, forwards it to every authoritative query for the lifetime of the resolution. The source-prefix length is clamped to per-family operator ceilings (`resolver.ecs_max_prefix` for IPv4, default `/24`; new `resolver.ecs_max_prefix_v6`, default `/56` — both RFC 7871 §11.1 recommendations). A client-sent `SourcePrefixLen=0` is preserved as an explicit opt-out: the upstream sees `/0` and MUST NOT geo-tailor. ECS options whose source address lands in any reserved range (RFC 1918, CGNAT, loopback, link-local, TEST-NET, multicast) are stripped wholesale — those addresses are never globally meaningful to a CDN and would only fingerprint the operator's internal network (§7.1.2, §11.1). No synthesis: clients that send no ECS get no ECS forwarded, which is the privacy-conscious default.
- **ECS echo in responses** — when the client signalled ECS in its query, the response now carries an ECS option echoing the client's source prefix back with the authoritative scope (RFC 7871 §7.2.1), so the client knows whether and how the answer was geo-tailored. Implemented via [`appendECSToResponse`](server/handler.go) on both the cache-hit path ([`buildCacheResponseECS`](server/handler.go)) and the fresh-resolution path. Verified by `TestHandle_ECS_EchoesScopeInResponse`.
- **Hot-reload for ECS settings** — `resolver.ecs_enabled`, `resolver.ecs_max_prefix`, and `resolver.ecs_max_prefix_v6` are applied immediately by the existing `SetRuntimeApplier` hook in [`main_runtime_helpers.go`](main_runtime_helpers.go) without a process restart. The new [`MainHandler.SetECSPrefixes`](server/handler.go) takes both families at once; the older `SetECS(enabled, prefix)` is preserved as a convenience wrapper.

## [0.6.8] - 2026-05-20

### Changed
- **`security.private_address_filter` default is now `false`** — previously `true`, which silently dropped A/AAAA records pointing at RFC1918 / loopback / link-local / CGNAT / etc. from every response. That made internal/split-horizon zones (e.g. `internal.corp` resolving to `10.x.x.x`) appear unresolvable to clients: the resolver returned NOERROR with an empty answer section, indistinguishable from NODATA. Operators who serve only public names and want the DNS-rebinding defense should set `security.private_address_filter: true` explicitly. The diagnostic trace is not affected — it reports the upstream answer before the handler-side strip — so this change closes a long-standing "trace says answers=1, dig says nothing" discrepancy.

### Added
- **Live config reload for hot-applicable settings** — `PUT /api/config/raw` now invokes a runtime applier after validating and writing the new YAML, so changes to `security.private_address_filter` take effect immediately without a restart. The response carries a new `live_applied: true` field; `restart_required` stays `true` because most other settings (listen addresses, TLS material, web bind) still need a process restart. Wire-up: [`AdminServer.SetRuntimeApplier`](web/server.go) registered from [`main_runtime_helpers.go`](main_runtime_helpers.go), calls [`handler.SetPrivateFilter`](server/handler.go). Future hot-reloadable flags go in the same applier closure.
- **Autonomous self-update from the web UI** — the `POST /api/system/update/apply` endpoint and its dashboard button have existed since 0.4, but every install produced by [install.sh](install.sh) was structurally unable to use them: the binary was at `/usr/local/bin/labyrinth` (root-owned, parent dir not writable by the `labyrinth` service user) and the systemd unit had `ProtectSystem=strict` + `ReadOnlyPaths=/etc/labyrinth` (blocking both the binary swap and the live-config-reload above). Fixed by moving to a service-user-owned install layout:
  - Binary now lives at `/opt/labyrinth/bin/labyrinth`, owned by `labyrinth:labyrinth`. `/usr/local/bin/labyrinth` becomes a symlink so `which labyrinth` and existing shell scripts keep working.
  - [labyrinth.service](labyrinth.service) and the unit embedded in [install.sh](install.sh) now use `ExecStart=/opt/labyrinth/bin/labyrinth` and `ReadWritePaths=/etc/labyrinth /opt/labyrinth/bin`. The `ReadOnlyPaths=/etc/labyrinth` entry that blocked live reload is removed.
  - [update.sh](update.sh) now performs an idempotent migration: detects the legacy layout (real binary at `/usr/local/bin/labyrinth`, no `/opt/labyrinth/bin`, or unit missing `ReadWritePaths=/opt/labyrinth/bin`), moves the binary, drops a symlink at the legacy path (`.pre-migration.bak` kept), patches the unit (`*.bak` kept), and `daemon-reload`s. Safe to re-run.
  - After a single `sudo bash update.sh` on an existing 0.6.x install, all subsequent updates can be applied from the dashboard's "About / Updates" page with a single click — the daemon downloads the asset, verifies its SHA-256 against `checksums.txt`, atomically renames into place, and `syscall.Exec`s into the new binary (same PID, systemd doesn't even see a restart).

## [0.6.7] - 2026-05-20

### Fixed
- **DNSSEC algorithm 14 (ECDSA P-384) was hashed with SHA-512 instead of SHA-384** — every signed zone publishing with algorithm 14 (fedoraproject.org, redhat.com, ietf.org, isc.org, …) silently came back `Bogus` → `SERVFAIL`. `hashForAlgorithm` in [dnssec/verify.go](dnssec/verify.go) grouped `AlgECDSAP384` in the same `case` arm as `AlgRSASHA512`. RFC 6605 §2.1 mandates the pairing as P-384 with **SHA-384**; algorithm 14 now has its own arm, and `_ "crypto/sha512"` is explicitly imported so `SHA384` is registered. An incorrect legacy table test that locked in the bug (`{ECDSAP384, SHA512}`) was corrected, and two regression-locking tests added (`TestHashForAlgorithm_ECDSAP384UsesSHA384`, `TestHashForAlgorithm_RFC6605Pairings`). The matching ECDSAP384 fixtures in `coverage_test.go` were re-signed with SHA-384 — they previously passed only because both ends shared the same bug.
- **Wildcard-served answers always validated Bogus** — `canonicalRRSetWire` in [dnssec/verify.go](dnssec/verify.go) used `rr.Name` verbatim for the canonical owner. RFC 4035 §5.3.2 requires reconstructing the wildcard owner (`*.<closest_encloser>`) when `rr.Name` has more labels than the RRSIG's `Labels` field. New `canonicalWildcardOwner` does the reconstruction; regression test `TestCanonicalRRSetWire_WildcardExpansion` rejects the broken-before-fix encoding.
- **Embedded RDATA names not lowercased before signature verification** — RFC 4034 §6.2 item 3 requires every domain name embedded in the RDATA of CNAME, NS, PTR, DNAME, MX, SOA, SRV, RRSIG, and NSEC to be lowercased in the canonical form used by the signer. The previous code appended `rr.RData` verbatim, so any auth server returning mixed-case wire (or any 0x20-randomised return path) made signature verification fail. New `canonicalRData`/`lowercaseWireName` in [dnssec/verify.go](dnssec/verify.go) does the type-aware lowercasing — label-length octets, numeric fields, signatures, and bitmaps are left untouched. Four focused regression tests cover CNAME, MX (preference bytes preserved), RRSIG (fixed header + signature bytes preserved), and non-name-bearing types (A) (no transformation).
- **Diagnostic trace "another trace is already running" after Cancel** — the handler called `runTrace` synchronously inside its read loop, so it couldn't process the `cancel` message the UI sent before closing the socket; and when the WebSocket closed mid-trace, the handler returned without unlocking the global `traceMu`. A second fix was needed even after moving the trace to its own goroutine — the orphan goroutine could still be waiting up to 2 s on a slow upstream after the user clicked Stop, holding the global mutex; meanwhile the new WS arrived, called `TryLock`, and got "busy". [web/api_trace.go](web/api_trace.go) now drops the global trace lock entirely (each WebSocket runs under its own context; per-connection `writeMu` still serialises socket writes; auth + 60 s ctx timeouts cap abuse) and explicitly cancels any prior in-flight trace on the same socket before starting a new one. Cancel-then-Trace now feels instant.

### Added
- **DNS Lookup Diagnostics page** — new UI page at [/diagnostics](web/ui/src/pages/DiagnosticsPage.tsx) and backend WebSocket `/api/diagnostics/trace`. Type a domain + qtype, hit Trace, and watch the resolver walk through every pipeline stage in real time: local-zones → answer cache → forward/stub → iterative-step (each NS query) → classify → CNAME/DNAME chase → delegation → DNSSEC validation → fallback → finish. Pipeline cards show the worst status per stage; the stage that broke the chain gets a red ring; the log lists every event with expandable JSON details. Toggles for "bypass cache" and "skip DNSSEC" make it trivial to localise whether a SERVFAIL is upstream-related or validation-related. The diagnostic was the proximate cause of finding the algorithm-14 bug above — within three traces it went from "Bogus, no idea why" to "verify-failed alg=14 labels=3 — every algorithm-14 zone is broken".
- **`dnssec.ValidateResponseDetailed`** — a per-RRSIG step log surfaced alongside the verdict. Each attempted RRSIG yields a `ValidationStep` with stage (`skip-weak`, `skip-unsupported`, `no-rrset`, `expired`, `not-yet`, `out-of-bailiwick`, `no-dnskey`, `no-matching-key`, `verify-failed`, `verify-ok`, `trust-chain`), signer, key tag, algorithm, type covered, labels, and human-readable detail. Production `ValidateResponse` is unchanged in behaviour and allocates no steps; the diagnostic UI uses the detailed variant so an operator sees exactly which signature was tried, which key matched, and why it was accepted or rejected.
- **`resolver.Resolver.Trace`** — parallel iterative-resolution routine that emits a `TraceEvent` stream as it walks roots → leaves. Reuses the production primitives (queryUpstream, classifyResponse, the validator, bailiwick sanitiser, qmin) so trace output reflects real resolver behaviour. Supports `BypassCache` and `SkipDNSSEC` per-trace options.

## [0.6.6] - 2026-05-19

### Fixed
- **Flaky `TestSnapshotAggregated_WeightedLatency`** — test created buckets at `time.Now().Truncate(time.Minute).Add(-2s|-1s)`, both in the previous wall-clock minute, then called `SnapshotAggregated(time.Minute, time.Minute)`. When the test ran in the last ~2 seconds of a minute, `Snapshot`'s `cutoff = time.Now() - 1m` slipped past the older bucket and dropped it, leaving 5 queries instead of 15. Widened the window to `2*time.Minute` so the cutoff is unaffected by where in the minute the test runs. Aggregation still groups both source buckets into the same minute super-bucket, so the assertions are unchanged. Caught by the v0.6.5 release-workflow run.

### Released
- v0.6.5 binaries (the workflow failed on this flake before uploading artifacts; v0.6.6 is the first tag that actually publishes the WS-reconnect + popover fixes from v0.6.5 along with the deps bump in `888615c`).

## [0.6.5] - 2026-05-19

### Fixed
- **Dashboard stops streaming after tab idle / laptop wake** — the live-queries and time-series WebSocket hooks treated `readyState === OPEN` as proof of liveness, so a zombie socket (laptop sleep, NAT/proxy idle drop, network blip) blocked any reconnect attempt on visibility return. The page sat frozen until manual refresh. Both [useWebSocket.ts](web/ui/src/hooks/useWebSocket.ts) and [useTimeSeriesStream.ts](web/ui/src/hooks/useTimeSeriesStream.ts) now:
  - Always tear down the prior socket (null handlers, then `close()`) before opening a new one — never trust readyState.
  - Guard `onopen`/`onclose` with an identity check so orphaned sockets can't schedule reconnects against a live one.
  - Cancel pending reconnect timers when a new `connect()` runs.
  - Reset the exponential-backoff counter on visibility return so the user-visible reconnect is immediate, not delayed.
  - Listen for `window`'s `online` and `focus` events for additional recovery paths.
- **Time-series watchdog** — server pushes every 1s in live mode (10s in history); `useTimeSeriesStream` now force-reconnects if no message arrived for 30s while the tab is visible. Catches silent proxy/NAT timeouts that don't deliver a close frame.
- **Server-side WS keepalive** — [api_queries.go](web/api_queries.go) and [timeseries_ws.go](web/timeseries_ws.go) now send a `conn.Ping` every 30s. Surfaces dead peers quickly and prevents reverse-proxy idle timeouts from silently killing connections.
- **Queries page: domain hover popover unusable when paused** — the popover sat at `top-full mt-1`, leaving a 4px gap where the cursor would briefly enter dead space, fire `onMouseLeave` on the trigger, and unmount the popover before the mouse could reach it. [QueriesPage.tsx](web/ui/src/pages/QueriesPage.tsx) wraps the card in an outer `pt-1` bridge anchored at `top-full` (hover area is now contiguous) and adds a 150 ms close delay so cursor jitter doesn't trip the close.

## [0.6.4] - 2026-05-19

### Fixed
- **NSEC denial validation** — Cloudflare-hosted DNSSEC zones (and every other online-signer using compact denial of existence / "black lies") now resolve. Previously every negative answer from a Cloudflare-signed zone — NXDOMAIN or NODATA — turned into `Bogus` → `SERVFAIL` because `validateDenialResponse` only handled NSEC3 and silently rejected NSEC. New [dnssec/nsec.go](dnssec/nsec.go) implements three proof forms:
  - **NODATA** (RFC 4035 §5.4) — NSEC owner == qname, qtype & CNAME absent from bitmap, delegation NSEC (NS set without SOA) rejected.
  - **NXDOMAIN with closest-encloser proof** (RFC 4035 §5.4) — covering NSEC for qname + covering NSEC for `*.closest_encloser`; closest encloser derived as the longest ancestor of qname shared with either side of the covering NSEC.
  - **Compact denial of existence** (draft-ietf-dnsop-compact-denial-of-existence, deployed by Cloudflare et al.) — NXDOMAIN RCODE with NSEC at qname whose bitmap excludes CNAME/DNAME; treated as a valid denial proof.
- DNSSEC: `validateDenialResponse` collects NSEC records from the authority section, accepts `RRSIG(NSEC)` alongside `RRSIG(NSEC3)`/`RRSIG(SOA)` in the authenticity filter, and runs NSEC verification against the RRSIG-authenticated subset.
- Resolver: `QueryDNSSEC` for the root zone (`.`) no longer gets rewritten by qmin into an `NS` query, which had silently broken the chain-of-trust walker — the validator never saw the root DNSKEY RRset and every DNSSEC verdict downstream collapsed.
- Resolver: `DS` queries now bypass qmin. DS records live at the parent zone, not the child; qmin's "rewrite to NS, follow referral" step took the resolver one delegation deeper than the DS, the child returned NODATA, and the chain walker reported "insecure delegation" for every non-root zone. (RFC 9156 §3 / §4.1.)
- Resolver: qmin fallback now also triggers when the rewrite changed `qtype` (not just `qname`). Closes a defense-in-depth gap behind the two fixes above — if any future qmin step changes the qtype, an "answer" classified against the rewritten type would otherwise carry the wrong RRset back to the caller.
- Resolver: `responseNXDomain` and `responseNoData` branches now run the DNSSEC validator. Previously both returned immediately, so `validateDenialResponse` (and its new NSEC path) was dead code from the resolver's perspective and every signed negative answer was reported with empty `DNSSECStatus`.

### Tests
- `dnssec/nsec_test.go` — 14 unit tests covering NODATA owner-match, qtype-in-bitmap rejection, CNAME rejection, parent-delegation rejection, apex NSEC, compact denial NXDOMAIN, classic two-NSEC name-error proof, missing-covering-NSEC rejection, canonical name comparison (case folding, root-dot normalization, label-length ordering), open-interval coverage (incl. wrap-around), closest-encloser derivation.
- `dnssec_probe_integration_test.go` (`-tags=integration`) — end-to-end probe against real public DNSSEC zones: IANA baseline, Cloudflare A/AAAA positive, Cloudflare NODATA + NSEC, and two Cloudflare compact-denial NXDOMAIN cases. All six return `DNSSECStatus="secure"`.

## [0.6.3] - 2026-05-19

### Fixed
- **DNSSEC validation correctness pass** — fixes signed-zone resolution for downstream recursors (notably `systemd-resolved 127.0.0.53` with `DNSSEC=allow-downgrade`). Symptom was `SERVFAIL`/no-record on CNAME-chained signed names such as `acme-v02.api.letsencrypt.org`.
- Resolver: `QueryDNSSEC` now resolves iteratively instead of issuing a single root NS query; the validator was effectively inoperative for most names prior.
- Resolver: `extractCNAMERecords` now preserves the covering `RRSIG(CNAME)` — dropping it broke downstream validators chasing CNAME chains because the chain ended up partially signed.
- Resolver: DNAME branch preserves `RRSIG(DNAME)` identically.
- Resolver: CNAME/DNAME hops now validate each upstream response and combine the per-hop verdict (RFC 4035 §3.2.3 — AD only when every RRset on the chain is Authentic).
- Resolver: `queryForward` / `queryFallback` propagate the upstream AD bit when DNSSEC is enabled, so forwarded zones keep their security indication.
- Resolver: `cacheDelegation` preserves `RRSIG(NS)` so a later cache-served NS lookup remains independently verifiable.
- Resolver: stale-served cache entries (RFC 8767) drop their `DNSSECStatus` because RRSIGs may be expired.
- Resolver: `activeECS` becomes `atomic.Pointer[dns.ECSOption]` to remove a data race between config reload and concurrent upstream queries.
- DNSSEC: RRsets are filtered by owner before signature check (RFC 4034 §3); a multi-owner RRset can no longer be falsely validated.
- DNSSEC: every covering RRSIG is tried before declaring Bogus (RFC 4035 §5.3.3); an in-flight KSK rollover no longer breaks validation on the first bad signature.
- DNSSEC: unsupported algorithms (e.g. ED448) now classify as Insecure rather than Bogus, per RFC 6840 §5.2.
- DNSSEC: denial path tracks authenticated (owner, type) pairs and filters NSEC3 records to verified-only before running the closest-encloser proof — closes a forgery vector where unverified NSEC3 could be used.
- DNSSEC: DNSKEY/DS fetches gain a singleflight guard, removing thundering-herd on the same trust anchor.
- DNSSEC: negative DNSKEY cache TTL capped at 60s; SERVFAIL/REFUSED returns an error instead of caching emptiness for an hour.
- Server: `buildResponse` / `buildCacheResponse` set AD/CD per RFC 4035 §3.2.2.
- Server: DO=0 clients get DNSSEC RRs stripped from responses (RFC 4035 §3.2.1).
- Server: cache writes carry `DNSSECStatus` through `StoreWithStatus` so AD survives re-serving.
- Web UI: BlocklistPage now displays custom blocked/allowed domain rules.
- Web UI: `client.ts` adds missing `BlocklistDomainsResponse` import.

### Tests
- Unit tests for `extractCNAMERecords`, `extractRRsForOwnerWithRRSIG`, `verdictToStatus`, `combineDNSSECStatus`, `isDNSSECRRType`, `stripDNSSECRRs` — all six new helpers at 100% line coverage.

## [0.6.2] - 2026-05-04

### Security
- Comprehensive security audit remediation across 12 finding categories (C-1/2/3, H-1/2/3/4/5/6/7/8/9/10/11, L-2, M-6).
- Server: floor client EDNS UDPSize at RFC 6891 §6.2.5 minimum (1232 bytes).
- Server: apply UDP response cap to cache-hit and ANY query paths.
- Server: advertise 1232-byte EDNS0 buffer to downstream clients.
- DNSSEC: tighten NSEC3 iteration limit to 100 per RFC 9276 guidance.
- DNSSEC: reject weak SHA1 primitives by default.
- Resolver: advertise 1232-byte EDNS0 buffer to defang fragment injection attacks.
- Resolver: reject out-of-bailiwick glue in upstream responses.
- Web: rate-limit `/api/auth/login` by client IP.
- Web: harden DNSSEC denial path and reserved-IP filter.

### Added
- Fallback resolver per-query logging in UI and Prometheus metrics.
- `addEDEToResponse` refactored as `MainHandler` method for cleaner code organization.

### Changed
- Full security audit report documentation added (4-phase pipeline).

## [0.6.1] - 2026-04-10

### Added
- Web UI unit test infrastructure with Vitest + Testing Library (`npm run test`, `npm run test:coverage`).
- Initial Web UI test suites for auth context, API client behavior (token/header/cache), WebSocket query stream behavior, and utility formatters.

### Changed
- Web UI build chunking tuned via `manualChunks` for better cacheability and faster incremental loads (`react-vendor`, `router-vendor`, `charts-vendor`, `icons-vendor`).
- Web UI package versions bumped to `0.6.1` (`web/ui`, `website`).

### Fixed
- Queries page React purity issue: removed `Date.now()` call from render-path memoization by moving live-window time source into state + interval.
- Dead code cleanup in core packages (`dnssec`, `server`, `web`) and stale test helpers removed.
- Removed impossible TCP/DoT branch condition (`uint16 > 65535`) to eliminate unreachable control flow.

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
