# Hunt: Injection / Crypto / Secrets / Update Flow

## Summary
13 findings: 2 critical, 4 high, 3 medium, 3 low, 1 info.

| Sev | Count |
|-----|-------|
| Critical | 2 |
| High     | 4 |
| Medium   | 3 |
| Low      | 3 |
| Info     | 1 |

Most of the surface area (DNS protocol parsing, blocklist parsers, embedded UI,
JWT auth, daemon/PID handling) is implemented carefully:
- Custom YAML parser (no third-party deserialization gadget surface).
- `http.FileServer(http.FS(embed.FS))` for static assets — embed.FS rejects path
  traversal natively.
- JWT validation pins `alg=HS256` and uses `hmac.Equal`; bcrypt is used for
  passwords with `DefaultCost` (10) and a precomputed dummy hash absorbs
  username-enumeration timing.
- Login limiter throttles bcrypt brute-force.
- Default TLS minimum is 1.2 on the DoT and auto-TLS paths.
- Web admin server lives behind `requireAuth` for every sensitive endpoint
  except `/api/setup/*` (see C-1) and `/api/system/health|version|dns-guide`.
- DoH POST body is bounded by `io.LimitReader(r.Body, 65536)`.
- Blocklist downloads are bounded by `io.LimitReader(resp.Body, 50<<20)`.
- No raw `os/exec` of attacker-influenced data; the only `exec.Command` calls
  re-exec the running binary with `os.Args[1:]` (daemonize / Windows update
  helper) — values are not user-influenced at runtime.

The findings below cluster around (a) the unauthenticated setup endpoint,
(b) the self-update path (no signature/hash verification), and (c) HTTP
client hardening on outbound calls.

## Findings

### [CRITICAL] Unauthenticated setup endpoint can overwrite live config and seize admin (CWE-306, CWE-862)
**File**: `web/api_setup.go:39-98` and `web/server.go:389-390`
**Skill**: sc-rce / sc-broken-auth
**Description**:
`/api/setup/complete` is registered without `requireAuth`:
```go
mux.HandleFunc("/api/setup/complete", s.handleSetupComplete)
```
The handler gates only on the in-memory boolean `s.setupDone`, which starts
`false` on every process start and is **never auto-initialised from the
on-disk config**. Nothing in `NewAdminServer` (`web/server.go:69-112`) or its
callers sets `setupDone = true` when an existing `labyrinth.yaml` is present.

The handler then unconditionally calls `os.Create("labyrinth.yaml")` (relative
path, line 88 / 102) and writes attacker-supplied YAML — including
`auth.username` and a bcrypt hash of an attacker-supplied password.

```go
if s.setupDone { ... return }            // setupDone is always false at boot
...
cfgPath := "labyrinth.yaml"
if err := writeConfigYAML(cfgPath, req, passwordHash); err != nil { ... }
s.setupDone = true
```

**Reachability**: any unauthenticated client that can reach the admin HTTP
listener (default `127.0.0.1:8080`, but operators bind it externally) can
send a single POST to `/api/setup/complete`. After the daemon is restarted —
which the operator will eventually do, or which the attacker can trigger via
crafted SIGHUP/system events — the new credentials in the rewritten
`labyrinth.yaml` are loaded and the attacker has admin. The attacker can also
overwrite previously-configured `web.addr`, blocklist URLs, etc.

A second consequence: the attacker can keep calling `/api/setup/complete` at
any time the server is freshly restarted (race window where `setupDone=false`)
to clobber the file again.

**Recommendation**:
1. Initialise `setupDone` in `NewAdminServer` based on whether a usable config
   was loaded (e.g. `cfg.Web.Auth.Username != ""` or the file at
   `s.configPath` exists and parses).
2. In `handleSetupComplete`, additionally refuse if any auth is already
   configured or if a config file already exists at the path that will be
   written.
3. Bind the setup endpoint to loopback only until first-run is complete, or
   require a one-time bootstrap token printed to stdout / written to a
   root-owned file at install time.
4. Use the configured config path from `s.configFilePath()` rather than the
   hardcoded relative `labyrinth.yaml`.

---

### [CRITICAL] Self-update accepts unsigned, unverified binary (CWE-494, CWE-345)
**File**: `web/api_update.go:174-304`
**Skill**: sc-rce
**Description**:
`handleApplyUpdate` downloads a binary from `BrowserDownloadURL` returned by
the GitHub releases API, copies it onto disk, `chmod 0755`, renames it over
the current executable, and `syscall.Exec`s it (`web/update_unix.go:15`).
There is **no signature check, no checksum check, no TLS pinning, no minisign
/ cosign / GPG verification**:

```go
resp, err := updateHTTPGet(downloadURL)            // line 200
...
io.Copy(tmpFile, resp.Body)                        // line 237 — no size cap
...
updateChmod(tmpPath, 0755)                         // line 247
updateRename(tmpPath, exePath)                     // line 272
... updateRestartSelf()                            // line 300 → syscall.Exec
```

Trust model relies entirely on:
- The integrity of `api.github.com` (single point of failure).
- The integrity of the asset host that GitHub redirects to (default
  `objects.githubusercontent.com`).
- A correct system root-store (no MITM proxy).

There is also no maximum body size on `io.Copy`, so a hostile redirect target
can fill disk; and `http.Get` is used with the package-level default client
that has **no timeout**.

**Reachability**: any authenticated admin can trigger
`POST /api/system/update/apply`. If the admin's session is compromised
(stolen JWT, XSS in a future UI bug, or via the C-1 setup endpoint above),
the attacker gets RCE-as-the-daemon-user. If GitHub or its asset CDN is ever
serving a malicious blob for that release, every Labyrinth install with
`auto_update` enabled is silently compromised.

**Recommendation**:
1. Ship a minisign / cosign / Ed25519 release public key embedded in the
   binary. Require the asset to be accompanied by a detached signature
   (`labyrinth-…sig`); fetch it, verify it against the embedded key, and
   refuse the update on mismatch.
2. As a minimum interim mitigation, fetch a checksum file from the same
   release, re-fetch the binary from the asset URL, and verify the SHA256
   matches before `Rename`.
3. Set a `*http.Client` for `updateHTTPGet` with `Timeout: 60*time.Second`
   and a max bytes counter on the body (`http.MaxBytesReader`-style).
4. Refuse to apply updates when the running user is `root`/`SYSTEM` unless
   the operator has explicitly opted in; an unsigned-update RCE is much
   worse when running privileged.

---

### [HIGH] Outbound update fetch uses default HTTP client with no timeout (CWE-400)
**File**: `web/api_update.go:51`, `308`, `375`
**Skill**: sc-data-exposure / sc-dos
**Description**:
```go
updateHTTPGet = http.Get
```
`http.Get` resolves to `http.DefaultClient`, which has **no timeout**. A slow
or hung GitHub / mirror can pin a goroutine indefinitely, and during
`handleApplyUpdate` a slow `io.Copy` from the body can hold the request
goroutine and the temp file open indefinitely. There is no per-request
deadline.

**Reachability**: every authenticated admin update poll, plus the periodic
`StartUpdateChecker` goroutine.

**Recommendation**: replace `http.Get` with a `*http.Client{ Timeout:
60*time.Second }` (or per-call `context.WithTimeout` + `http.NewRequest`).
Also wrap the download body in a size-bounded reader.

---

### [HIGH] Blocklist HTTP client follows redirects to any scheme/host with no SSRF guard (CWE-918)
**File**: `blocklist/manager.go:108-110`, `283-307`, `309-324`
**Skill**: sc-ssrf
**Description**:
```go
httpClient: &http.Client{ Timeout: 30 * time.Second },
```
The client has the default redirect policy (up to 10 redirects, any host).
There is no scheme allow-list, no host allow-list, and no check that the
resolved address is not in RFC1918 / loopback / link-local. URLs come from
`config.Blocklist.Lists[].URL` (operator-controlled today — `api_blocklist.go`
exposes no runtime URL-add endpoint). The risk is two-fold:

1. A malicious or compromised blocklist publisher can redirect the URL to
   `http://127.0.0.1:8080/api/...` or to an internal AWS metadata IP
   (`169.254.169.254`). The body is then parsed by `ParseHostsFile` /
   `ParseDomainList` / `ParseABP` / `ParseRPZ` and the rule count plus the
   error string from the parser are surfaced via `/api/blocklist/lists` —
   an information-leak channel about internal services.
2. Operators copy-pasting a URL from a community list can be redirected
   without notice.

The 50 MB `io.LimitReader` cap is good but only covers post-redirect body
size, not the redirect target.

**Reachability**: every `RefreshAll()` call (startup, background timer, and
authenticated `POST /api/blocklist/refresh`). On startup the manager runs
unauthenticated by virtue of process boot.

**Recommendation**:
- Set `httpClient.CheckRedirect` to enforce: same scheme (https → https),
  reject any redirect target that resolves to RFC1918 / loopback /
  link-local / multicast (use `net.ParseIP` + `IsPrivate` / `IsLoopback`).
- Restrict allowed schemes to `https` (and `http` only if the operator
  explicitly opts in per-list).
- Optionally cap redirects at 3.

---

### [HIGH] PID file written without O_EXCL — symlink/TOCTOU on shared paths (CWE-367, CWE-59)
**File**: `daemon/pidfile.go:11-14`, used from `daemon/daemon_unix.go:26`
**Skill**: sc-race-condition / sc-path-traversal
**Description**:
```go
func WritePID(path string) error {
    pid := os.Getpid()
    return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0644)
}
```
`os.WriteFile` opens with `O_WRONLY|O_CREATE|O_TRUNC`, which **follows
symlinks**. If the daemon runs as root and the PID-file path lives on a
directory writable by an unprivileged user (e.g. `/tmp/labyrinth.pid`, or a
shared `/var/run` on systems where it's not a tmpfs root-only mount), an
unprivileged attacker can pre-create a symlink at the path pointing to
e.g. `/etc/cron.d/labyrinth` or `/root/.ssh/authorized_keys`. The first run
of the daemon then truncates and writes `<pid>\n` to that target with
mode 0644.

Compounding this, `StopDaemon` (`daemon/daemon_unix.go:57`) reads the file
back and sends `SIGTERM` to whatever PID it finds — an attacker who can
write the file can make `labyrinth stop` (run by root) kill arbitrary
processes.

**Reachability**: triggered automatically on every `Daemonize` call when
`cfg.Daemon.PIDFile` is set; the path is operator-supplied but the operator
typically copies a default from documentation.

**Recommendation**:
- Open the PID file with `os.OpenFile(path,
  os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0644)` so the
  symlink case fails closed.
- On Linux, prefer `flock(LOCK_EX|LOCK_NB)` for crash-safe mutual exclusion.
- In `StopDaemon`, sanity-check that the stored PID's `/proc/<pid>/exe`
  resolves to the running labyrinth binary before signalling.

---

### [HIGH] `?token=` query-parameter auth on WebSockets leaks JWT to logs/proxies (CWE-598)
**File**: `web/middleware.go:36-39`, `web/api_queries.go:43-50`,
`web/timeseries_ws.go:121-128`
**Skill**: sc-data-exposure
**Description**:
The auth middleware accepts a JWT either in `Authorization: Bearer …` or in
`?token=…`. Browsers cannot set custom WebSocket headers, so the WS handlers
(`/api/queries/stream`, `/api/stats/timeseries/ws`) effectively force the
JWT into the URL. Any access log, intermediate proxy, reverse proxy, or
APM that captures URLs will record the long-lived JWT (24-hour expiry,
`web/auth.go:61`).

The two WS endpoints also set `InsecureSkipVerify: true` on
`websocket.AcceptOptions`, disabling Origin checking. Because the auth is in
the URL (not a cookie), classic CSWSH is not possible — but this still
removes one layer of defence.

**Reachability**: every dashboard user; any deployment behind a TLS-terminating
proxy that logs request URIs.

**Recommendation**:
- Use a short-lived ticket: client calls a small REST endpoint to obtain a
  one-shot, single-use, ~30-second ticket bound to its IP, then connects to
  WS with `?ticket=…` instead of the full JWT.
- Alternatively, accept the JWT only via the `Sec-WebSocket-Protocol` header
  (a documented browser-API workaround) and reject `?token=` on WS endpoints.
- Restrict `InsecureSkipVerify` to a configured allow-list of Origins, or
  default to same-origin only.

---

### [MEDIUM] Update binary write replaces in place without preserving original mode/owner (CWE-732)
**File**: `web/api_update.go:224-282`
**Skill**: sc-data-exposure / sc-rce
**Description**:
`updateCreateTemp(filepath.Dir(exePath), "labyrinth-update-*")` creates the
temp file with Go's default `0600` permission. After `os.Chmod(tmpPath,
0755)` and `os.Rename(tmpPath, exePath)`, the new executable inherits the
*temp file's* owner (the running daemon user) and mode `0755`. If the
original binary was `root:root 0755` and the daemon runs unprivileged, the
rename will fail (good); but if the daemon runs as root and the install is
expected to be `root:wheel 0755`, group ownership / ACLs / xattrs / setcap
attributes are lost. Loss of `cap_net_bind_service=ep` would silently break
port-53 binding on next start.

**Reachability**: any successful `POST /api/system/update/apply` from an
authenticated admin.

**Recommendation**:
- `os.Stat` the original `exePath` before replace; on Unix `Chown` the temp
  file to the original `Uid:Gid` and `Chmod` to the original mode.
- Re-apply file capabilities (`xattr "security.capability"`) where present.
- Document that an external `setcap` may be required after an in-place
  update.

---

### [MEDIUM] JSON error responses interpolate raw `err.Error()` (CWE-116)
**File**: `web/api_tls.go:54`
**Skill**: sc-data-exposure
**Description**:
```go
http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
```
If `err.Error()` contains `"`, `\n`, or backslash characters (Go's autocert
errors can include URLs and certificate subjects under operator control via
ACME), the produced body is invalid JSON. This is a low-impact response-body
integrity bug — clients receive malformed JSON — and a possible CRLF/header
injection sink if a future caller writes the same string into a header.

**Reachability**: any authenticated `POST /api/system/tls/renew` that fails.

**Recommendation**: use `jsonResponse(w, http.StatusInternalServerError,
map[string]string{"error": err.Error()})` like the rest of the codebase.

---

### [MEDIUM] `writeFileAtomically` rename loses permission of original config (CWE-732)
**File**: `web/api_config.go:380-429`, `web/auth.go:325-365`
**Skill**: sc-data-exposure
**Description**:
`os.CreateTemp` creates the temp file with mode 0600. After `os.Rename`,
the config file ends up at 0600 regardless of its previous mode — which is
actually a security improvement *for the new password-hash bcrypt blob* but
will silently change the file mode an operator may have intentionally set
(0640 with a `labyrinth` group, etc.). `auth.go:363` re-asserts 0600
explicitly, which is fine, but the dashboard-layout and config-raw flows
both rely on the implicit 0600.

The `.bak` file at `path + ".bak"` (line 410-417) is left at the temp file's
0600 mode and is **never removed** on success; it persists with the previous
config (potentially containing the previous bcrypt hash) at a deterministic
path. Operators rotating the password thus leave the old bcrypt hash on
disk indefinitely under `labyrinth.yaml.bak`.

**Reachability**: every `PUT /api/config/raw`, `PUT /api/dashboard/layout`,
and `POST /api/auth/change-password`.

**Recommendation**:
- After successful rename, `os.Stat` the previous `.bak`, copy its mode/uid/gid
  onto the new file (or capture before rename).
- Remove `path + ".bak"` after a successful rename, or rotate it
  (`.bak.1`, `.bak.2`) and keep only N copies.
- Explicitly chmod the result to a known safe mode (0600 if it contains a
  hash, otherwise the previous mode).

---

### [LOW] HTTP cluster fanout has no per-peer authentication tying (CWE-345)
**File**: `web/api_cache.go:233-277`
**Skill**: sc-ssrf-adjacent
**Description**:
`fanoutCacheFlush` POSTs to `peer.APIBase + "/api/cache/flush"` with
`Authorization: Bearer <peer.APIToken>` and `X-Labyrinth-Cluster-Fanout: 1`.
The handler `handleCacheFlush` checks the header and skips re-fanout, but it
does **not** re-validate the bearer is from a peer (`requireAuth` accepts any
valid JWT issued by the local server). If two clusters share a JWT secret —
or a single attacker with a valid JWT to one node forges the fanout header —
they can flush cache on the peer.

**Reachability**: requires an attacker already holding a valid admin JWT on
at least one cluster member.

**Recommendation**: have `handleCacheFlush` (and other fanout-target
handlers) require a *separate* peer-to-peer shared secret carried in a
distinct header — not the local admin JWT. Or compare incoming bearer
against `cfg.Cluster.Peers[*].APIToken`.

---

### [LOW] `compareSemver` parses operator-supplied tag without validation (CWE-20)
**File**: `web/api_update.go:399-434`
**Skill**: sc-data-exposure
**Description**:
`parseSemverParts` runs `strconv.Atoi` on each segment of the GitHub
`tag_name`, defaulting silently to 0 on parse errors. A tag like
`v9.9.9-malicious` or `v0..0` will parse to `[9,9,9]` / `[0,0,0]` with no
error; if the GitHub repo owner is ever taken over and pushes a tag of
`v999.0.0`, every running deployment marks itself as out-of-date and the
auto-update path (with `auto_update: true`) becomes a one-call exploit
chain on top of C-2.

**Reachability**: any update check.

**Recommendation**: enforce a strict regex (`^v?\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?$`)
on `tag_name` before comparing. Reject tags whose major version jumps more
than one beyond the running version unless the user has explicitly opted in.

---

### [LOW] DoH `Cache-Control` allows zero `max-age` from upstream-shaped responses (CWE-345)
**File**: `web/api_doh.go:62-69`, `129-169`
**Skill**: sc-data-exposure
**Description**:
`dohMinTTL` walks the response wire format and returns the smallest answer
TTL, with no bounds; if a downstream cache (or a misbehaving client) sends
back a TTL of `0xFFFFFFFF`, the resulting `Cache-Control: max-age=4294967295`
is interpolated unsanitised into a header line. RFC compliance prefers a
ceiling. Header injection isn't possible because the `%d` formatter only
emits digits, but caching for ~136 years is a misconfiguration vector.

**Reachability**: any DoH client query whose authoritative answer carries a
hostile or malformed TTL.

**Recommendation**: clamp `maxAge` to e.g. `min(maxAge, 86400)`.

---

### [INFO] Zabbix agent listener is unauthenticated by protocol design
**File**: `web/api_zabbix.go:111-173`
**Skill**: sc-data-exposure
**Description**:
`StartZabbixAgent` opens a TCP listener with no authentication and replies
to any client with internal metrics (cache hits/misses, upstream queries,
goroutine count). This is the Zabbix passive-agent protocol — the upstream
Zabbix protocol has no auth either. Operators must restrict by network
ACL/firewall.

**Recommendation**: document that the listener address must be bound to
loopback (or restricted by firewall to the Zabbix server). Optionally add a
`zabbix.allow_from` IP allow-list inside the daemon.
