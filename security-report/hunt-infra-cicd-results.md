# Hunt: Infrastructure / CI-CD / Docker / Daemon

## Summary

17 findings: 2 critical, 4 high, 6 medium, 4 low, 1 info

Two issues stand out:

1. The self-update path (`web/api_update.go`) and the `install.sh` shell installer
   both pull a binary over HTTPS from GitHub Releases and execute it without
   verifying the published `checksums.txt` or any signature. The release
   workflow already produces `checksums.txt`; nothing on the client side
   consumes it.
2. The PID-file plumbing is happy to write `/var/run/labyrinth.pid` with
   mode 0644 (no `O_EXCL`, no symlink hardening) and to `kill(pid, SIGTERM)`
   on whatever process currently owns the integer it reads back. Combined
   with `/var/run` being world-readable and (depending on tmpfs setup)
   potentially writable to other service accounts, that is the normal
   pidfile TOCTOU pattern.

The Dockerfile is reasonable (USER applied, EXPOSE correct, multi-stage,
no secrets baked in, `.dockerignore` present). Main gaps are floating
base tags, no HEALTHCHECK, and no SBOM/signing in CI.

The systemd unit at the repo root (`labyrinth.service`) is fairly well
hardened — `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`,
`ProtectHome`, ambient `CAP_NET_BIND_SERVICE`. Missing: `CapabilityBoundingSet`,
`RestrictAddressFamilies`, `SystemCallFilter`, `MemoryDenyWriteExecute`,
`LockPersonality`, `RestrictNamespaces`, etc. The unit copy emitted by
`install.sh` also diverges from the in-repo unit (writable vs read-only
`/etc/labyrinth`).

GitHub Actions workflows pin official `actions/*` and `docker/*` actions
by major tag (`@v5`, `@v6`) rather than by commit SHA. `release.yml`
declares `contents: write, packages: write` at workflow scope, which
applies to the `test` and `build` jobs that don't need it.

## Findings

### [CRITICAL] Self-update downloads & executes binary without integrity check (CWE-494, CWE-345)

**File**: `web/api_update.go:200-282`
**Skill**: sc-iac
**Description**: `handleApplyUpdate` performs `updateHTTPGet(downloadURL)`,
copies the response body to a temp file in the install directory, `chmod
0755`s it, and renames it over the running executable. There is no
checksum comparison against the `checksums.txt` produced by
`release.yml:97`, no Sigstore/cosign verification, and no minisign /
ed25519 signature check. `findAssetURL` looks up the asset URL by name
from the GitHub API but trusts `BrowserDownloadURL` verbatim.
**Impact**: Anyone who can MITM the TLS connection (compromised CA,
hostile transparent proxy on the operator's network, GitHub release
asset host compromise, or — most realistically — a compromised
maintainer GitHub token replacing the asset) can ship arbitrary code
that the daemon happily installs and re-execs as the service user
(potentially with `CAP_NET_BIND_SERVICE` ambient). The web UI gating
(admin auth required) limits *who* can trigger it but does nothing
about what gets installed once triggered. `auto_update: true` is in
the default config (`install.sh:188`) so this can be triggered by the
checker loop too — review the loop more carefully if "auto-apply"
exists; here `StartUpdateChecker` only *checks*, it does not apply,
which is the saving grace, but the apply path is one admin click away.
**Recommendation**: Download `checksums.txt` from the same release,
verify the SHA-256 of the downloaded asset matches the expected line,
and refuse the rename if it doesn't. Better: sign releases with cosign
(keyless, via the existing `id-token: write` permission) and verify
the signature with the bundled cosign public key or via Rekor before
swapping the binary.

### [CRITICAL] install.sh pipes downloaded binary to disk with no checksum/signature verification (CWE-494, CWE-829)

**File**: `install.sh:98-110`
**Skill**: sc-ci-cd
**Description**: `curl -fsSL -o "$TMP_FILE" "$DOWNLOAD_URL"; chmod +x;
mv "$TMP_FILE" /usr/local/bin/labyrinth`. No GPG, no cosign, no SHA-256
comparison against the release's `checksums.txt`. The release notes
template in `release.yml:104-108` even invites users to pipe `install.sh`
straight into bash. Same problem in the published release body for the
auto-suggested `curl … | bash` install one-liner.
**Impact**: A single compromised release token replaces the published
asset and every fresh install in the wild executes attacker-supplied
code as root (the script enforces `EUID -ne 0` exit at line 62, so it's
always root). No detection mechanism — `set -euo pipefail` only catches
download failure, not tampering.
**Recommendation**: Have `install.sh` fetch `checksums.txt` and verify
`sha256sum -c` (or `shasum -a 256`) before `mv`. Long term, sign the
release with cosign keyless and have the script verify with `cosign
verify-blob --certificate-identity-regexp …` before install.

### [HIGH] PID-file write is symlink-followable and not exclusive (CWE-59, CWE-367)

**File**: `daemon/pidfile.go:11-14`
**Skill**: sc-iac
**Description**: `WritePID` calls `os.WriteFile(path, …, 0644)`, which
follows symlinks at the destination and does not use `O_EXCL`. Default
path is `/var/run/labyrinth.pid` (`config/defaults.go:84`,
`main.go:115`). `/var/run` is world-readable and historically world-
writable on some systems (mode 0777 with sticky on `/run`), and other
service users in the same namespace can race to drop a symlink at that
path before the daemon is started.
**Impact**: A local low-privileged user who can pre-create
`/var/run/labyrinth.pid` as a symlink to e.g. `/etc/passwd` will cause
the daemon (running with `CAP_NET_BIND_SERVICE` ambient under the
systemd unit, or as root in `daemon` mode) to overwrite that target
with `<pid>\n`. Even without symlink games, mode 0644 leaves the file
world-readable, which is fine for a PID, but combined with the
`StopDaemon` path below, an attacker who can write `/var/run/labyrinth.pid`
gets a free `kill()` primitive.
**Recommendation**: Open with `os.OpenFile(path, O_CREATE|O_WRONLY|O_EXCL|O_NOFOLLOW, 0640)`
(use `unix.O_NOFOLLOW` on Linux). Restrict the directory to
`/run/labyrinth/` (mode 0750, owned by `labyrinth`) and adjust the
systemd unit to use `RuntimeDirectory=labyrinth` so systemd creates and
tears it down.

### [HIGH] StopDaemon signals whatever PID it reads (CWE-367, CWE-672)

**File**: `daemon/daemon_unix.go:57-74`, `daemon/daemon_windows.go:50-67`
**Skill**: sc-iac
**Description**: `StopDaemon` reads the integer from the PID file and
calls `process.Signal(SIGTERM)` (or `process.Kill()` on Windows) without
verifying that the PID still belongs to a labyrinth process.
`labyrinth daemon stop` runs as the user invoking the CLI; if the CLI
is wired into ops automation that runs as root, it will signal any PID
on the system that an attacker can plant in the file.
**Impact**: PID reuse plus the symlink/no-exclusive issue above gives a
local attacker an arbitrary-process SIGTERM (or SIGKILL on Windows). It
also means a stale PID file from a crashed daemon (since cleanup only
happens on graceful SIGTERM in `main_runtime_helpers.go:242-244`) will
silently signal whatever now occupies that slot.
**Recommendation**: Before signalling, verify the process by reading
`/proc/<pid>/comm` (Linux) or matching the cmdline against the binary
name. Acquire an exclusive `flock(2)` / `fcntl(F_SETLK)` on the PID
file at start time and refuse to start if the lock is taken; require
the lock to be present before honouring `stop`.

### [HIGH] CI workflow grants `contents: write` and `packages: write` to every job (CWE-272)

**File**: `.github/workflows/release.yml:7-9`
**Skill**: sc-ci-cd
**Description**: `permissions:` is declared at the workflow scope, so
`test`, `build`, `release`, and `docker` all inherit `contents: write`
and `packages: write`. Only `release` actually needs `contents: write`
(to publish the GitHub Release) and only `docker` needs `packages:
write` (to push to GHCR).
**Impact**: A compromised dependency, a malicious `go test` (the test
job runs `go test ./...` over the full tree, which executes
arbitrary user code under the workflow's `GITHUB_TOKEN`), or any
script-injection vector in those jobs gets a token that can rewrite
release assets and push container images.
**Recommendation**: Move `permissions:` to job scope. Default the
workflow to `permissions: { contents: read }` and grant
`contents: write` only on the `release` job and `packages: write`
only on the `docker` job. The `test` and `build` jobs should not
even be able to read repo secrets they don't reference.

### [HIGH] Third-party / official actions pinned by tag, not by commit SHA (CWE-829)

**File**: `.github/workflows/release.yml` (entire file),
`.github/workflows/website.yml` (entire file)
**Skill**: sc-ci-cd
**Description**: `actions/checkout@v5`, `actions/setup-go@v6`,
`actions/setup-node@v5`, `softprops/action-gh-release@v2`,
`docker/login-action@v3`, `docker/metadata-action@v5`,
`docker/setup-buildx-action@v3`, `docker/build-push-action@v6`,
`actions/upload-artifact@v5`, `actions/download-artifact@v5`,
`actions/configure-pages@v5`, `actions/upload-pages-artifact@v4`,
`actions/deploy-pages@v5` are all referenced by mutable tag.
**Impact**: An attacker who compromises a tag (forced re-push) or a
maintainer account can substitute action code that exfiltrates the
release `GITHUB_TOKEN`, the GHCR write token, or signing material.
Per GitHub's own hardening guidance, third-party actions in
particular (`softprops/action-gh-release`) should be pinned by full
40-character commit SHA. Even GitHub-owned actions have had
incidents (`tj-actions/changed-files` style) and SHA pinning is
considered best practice for release workflows.
**Recommendation**: Pin every `uses:` to a 40-char SHA with a
trailing comment indicating the tag, e.g.
`uses: softprops/action-gh-release@<sha> # v2.0.6`. Use Dependabot
in `.github/dependabot.yml` with `package-ecosystem: github-actions`
to surface SHA bumps automatically.

### [HIGH] Release artifacts are not signed and ship no SBOM/provenance (CWE-345, CWE-1395)

**File**: `.github/workflows/release.yml:85-112`
**Skill**: sc-ci-cd
**Description**: `release` job uploads `labyrinth-*` and `checksums.txt`
to the GitHub Release. There is no cosign signing, no SLSA provenance
attestation (`actions/attest-build-provenance`), no SPDX/CycloneDX
SBOM. The Docker image build (`docker` job) similarly does not call
`actions/attest-build-provenance` or push a cosign signature, despite
already having `id-token: write` available at workflow scope.
**Impact**: Downstream consumers (install.sh, container pull, manual
download) have no way to detect tampering at the asset host. The
attack surface is the same as the install.sh and self-update findings;
this is the upstream half of the same problem.
**Recommendation**: Add `sigstore/cosign-installer` and either keyless
sign the binaries / digest of the image, or use
`actions/attest-build-provenance@v1` and
`actions/attest-sbom@v1`. Emit a CycloneDX SBOM via `anchore/sbom-action`
or `cyclonedx/gh-gomod-generate-sbom`.

### [MED] Dockerfile base images use floating tags, no digest pin (CWE-1357)

**File**: `Dockerfile:1, 14`
**Skill**: sc-docker
**Description**: `FROM golang:1.26-alpine AS build` and `FROM alpine:3.20`
are tag references, not digest references. The build is not
reproducible and a re-tagged upstream silently changes what ships.
**Impact**: A compromised or malicious upstream Alpine/Go image
propagates into every release rebuild, including supply-chain
incidents on Docker Hub. The fact that the workflow uses
`cache-from: type=gha` does not protect — a fresh runner without
cache fetches whatever the tag currently points at.
**Recommendation**: Pin to digests:
`FROM golang:1.26-alpine@sha256:<digest> AS build` and
`FROM alpine:3.20@sha256:<digest>`. Renovate / dependabot can update
these. Optionally use `gcr.io/distroless/static-debian12:nonroot` for
the runtime stage to drop the apk surface entirely.

### [MED] No HEALTHCHECK in Dockerfile (CWE-1295)

**File**: `Dockerfile:14-23`
**Skill**: sc-docker
**Description**: No `HEALTHCHECK` directive. Orchestrators that
respect the image-level healthcheck (Docker, Nomad, Podman) will
treat the container as healthy as long as the process is alive,
even if the resolver is wedged.
**Impact**: Wedged DNS service (e.g. cache poisoned to NXDOMAIN
storm, deadlock, exhausted FDs) is not surfaced to the platform,
delaying restart. Lower severity because Kubernetes ignores
HEALTHCHECK in favor of probes, but most other platforms honor it.
**Recommendation**: Add e.g.
`HEALTHCHECK --interval=30s --timeout=3s CMD ["labyrinth", "check", "--addr", "127.0.0.1:53"]`
or a small dig-equivalent; document the metrics endpoint as the
Kubernetes liveness/readiness probe.

### [MED] systemd unit missing modern hardening directives (CWE-250)

**File**: `labyrinth.service:1-26`
**Skill**: sc-iac
**Description**: Present: `User`, `Group`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`,
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`. Missing: `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`
(without this, ambient is the only cap set but the bounding set is
inherited from the system default), `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`,
`SystemCallFilter=@system-service ~@privileged ~@resources`,
`SystemCallArchitectures=native`, `MemoryDenyWriteExecute=true`,
`LockPersonality=true`, `RestrictRealtime=true`,
`RestrictNamespaces=true`, `RestrictSUIDSGID=true`,
`ProtectKernelTunables=true`, `ProtectKernelModules=true`,
`ProtectKernelLogs=true`, `ProtectControlGroups=true`,
`ProtectProc=invisible`, `ProcSubset=pid`,
`ProtectClock=true`, `ProtectHostname=true`, `RemoveIPC=true`,
`UMask=0027`, `RuntimeDirectory=labyrinth`,
`StateDirectory=labyrinth`, `LogsDirectory=labyrinth`.
**Impact**: A code-execution bug in the resolver runs with more
ambient kernel surface than necessary — full syscall table, ability
to load kernel modules (capabilities permitting), write+execute
mappings (JIT-ROP), all address families.
**Recommendation**: Add the directives above. `systemd-analyze
security labyrinth.service` should target ≤ 3.0 ("OK") and ideally
≤ 2.0.

### [MED] Installer-emitted unit diverges from in-repo unit (CWE-1188)

**File**: `install.sh:224-251` vs `labyrinth.service:21`
**Skill**: sc-iac
**Description**: The unit baked into `install.sh` uses
`ReadWritePaths=/etc/labyrinth`. The repo unit uses
`ReadOnlyPaths=/etc/labyrinth`. The web admin's
`writeFileAtomically` (`web/api_config.go:380`) writes to that
directory at runtime, so the read-only repo unit will break the
web "save config" flow if anyone deploys it directly. The
inconsistency means whichever copy the security review is done
against doesn't match what users actually run.
**Impact**: Either (a) an op uses the repo unit and discovers
`ReadOnlyPaths` blocks save (operational), or (b) reviewers
believe the directory is read-only when in production it is not.
The split also means changes drift over time.
**Recommendation**: Pick one. If the web UI needs to save config,
use `ReadWritePaths=/etc/labyrinth` everywhere and document the
trust model (admin auth is the only barrier between web user and
config edit). Consider removing `install.sh`'s embedded copy and
having it `cp` the repo unit instead — single source of truth.

### [MED] Stale PID file not removed on non-graceful exit (CWE-672)

**File**: `main_runtime_helpers.go:235-245`, `daemon/pidfile.go`
**Skill**: sc-iac
**Description**: `RemovePID` is only called inside the
`SIGINT/SIGTERM` branch of the signal loop. On panic, OOM kill,
SIGKILL, or `os.Exit` from another error path, the PID file
remains on disk. There is no startup cleanup that removes a stale
PID file when the recorded PID is not running.
**Impact**: Stale `/var/run/labyrinth.pid` combined with
`StopDaemon` (no liveness check beyond the signal-0 probe inside
`IsRunning`, but `StopDaemon` itself does not call `IsRunning`)
means `labyrinth daemon stop` after a crash will SIGTERM whatever
process now holds that PID. Also blocks a clean restart on
`daemon start` if startup were ever to honour an existing PID
file (currently it does not — second issue: nothing prevents
two daemons from racing).
**Recommendation**: Use `defer daemon.RemovePID(pidFile)` at the
top of the daemon's main path so every exit cleans up. On
`Daemonize`, before writing, read any existing PID file, call
`IsRunning`, and refuse to start (or remove the file) accordingly.

### [LOW] PID file mode 0644 (CWE-732)

**File**: `daemon/pidfile.go:13`
**Skill**: sc-iac
**Description**: `os.WriteFile(path, …, 0644)`. PID is not
secret, but world-write is what enables the planted-symlink and
PID-confusion attacks above; world-readable is harmless on its
own. Listing as separate finding for completeness.
**Impact**: Combined with the lack of `O_EXCL`/`O_NOFOLLOW`,
this is what makes the PID file abusable.
**Recommendation**: Use 0640 with the file owned by the service
user, dir 0750. Better: place inside `/run/labyrinth/` managed by
systemd `RuntimeDirectory=`.

### [LOW] SIGHUP advertised as "config reload" but only logs (CWE-440)

**File**: `signals_unix.go:31-36`, `labyrinth.service:12`
**Skill**: sc-iac
**Description**: `ExecReload=/bin/kill -SIGUSR1 $MAINPID` in the
unit; `SIGUSR1` triggers cache flush in `signals_unix.go:21-26`.
`SIGHUP` is wired up but does nothing except log "restart to apply
config changes". `systemctl reload labyrinth` therefore silently
flushes the cache rather than reloading config — operationally
surprising. Not a memory-safety issue, but it is a security-
relevant misuse: an admin who runs `systemctl reload` thinking
they applied a security policy change instead just nuked their
cache while the old policy keeps running.
**Impact**: Operator confusion. Stale security policy continues
to apply after what the operator believes was a reload.
**Recommendation**: Either implement real config reload on
`SIGHUP` (re-read file, apply non-disruptive settings) and point
`ExecReload` at SIGHUP, or remove `ExecReload` and document that
restart is required.

### [LOW] release workflow has no concurrency cancel (CWE-405)

**File**: `.github/workflows/release.yml`
**Skill**: sc-ci-cd
**Description**: No `concurrency:` block. Two rapid tag pushes
trigger two parallel release workflows, both of which try to
upload to the same GitHub Release tag and push the same image
tag. `softprops/action-gh-release` may overwrite or duplicate
asset uploads non-deterministically.
**Impact**: Race on which build's binary actually lands in the
release; potential for the older build to win and ship.
**Recommendation**: Add
```
concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false
```
(do not cancel — let the first one finish).

### [LOW] release notes recommend `curl … | bash` install (CWE-494)

**File**: `.github/workflows/release.yml:104-108`
**Skill**: sc-ci-cd
**Description**: The release body string templated into every
GitHub Release reads
`curl -sSL https://raw.githubusercontent.com/${{ github.repository }}/main/install.sh | bash`,
i.e. the latest `main` install script — not the script that
shipped with this tagged release. A future malicious commit to
`main`'s `install.sh` is therefore retroactively re-advertised by
every old release page.
**Impact**: Combined with the unsigned install.sh finding, gives
an attacker who lands a single commit on `main` immediate reach
into every existing release page. Severity is bounded by branch
protection.
**Recommendation**: Pin the URL to `${{ github.ref_name }}`
(the tag) instead of `main`, so each release advertises the
install script that was reviewed at that tag.

### [INFO] Dockerfile good practices already in place

**File**: `Dockerfile:1-23`, `.dockerignore:1-15`
**Skill**: sc-docker
**Description**: For completeness — the Dockerfile correctly:
multi-stage builds with `--platform=$BUILDPLATFORM`; uses `apk add
--no-cache`; `adduser -D -H labyrinth` and `USER labyrinth` before
`ENTRYPOINT`; uses `COPY` rather than `ADD`; does not embed
secrets; `EXPOSE 53/udp 53/tcp 9153/tcp` matches the listener
defaults; `.dockerignore` excludes `.git`, `.github`, `website/`,
`node_modules`, and tests/markdown noise. The container will fail
to bind `:53` as the non-root `labyrinth` user without
`--cap-add=NET_BIND_SERVICE` or `setcap cap_net_bind_service=+ep`
on the binary; this is a deliberate trade-off worth documenting in
the README so operators don't fall back to running as root.

