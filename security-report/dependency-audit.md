# Dependency Audit — LabyrinthDNS

## Go Modules (go.mod / go.sum)

| Module | Version | Direct? | Notes |
|--------|---------|---------|-------|
| github.com/quic-go/qpack | v0.6.0 | indirect | QPACK header compression for HTTP/3 / DoQ |
| github.com/quic-go/quic-go | v0.59.0 | indirect | QUIC; current at audit time. Has historical CVEs in older releases (e.g. CVE-2024-22189 ≤ v0.42.0). v0.59.0 is recent — no published advisory matching this version found in MITRE/Go vuln DB at audit. Verify via `govulncheck`. |
| golang.org/x/crypto | v0.49.0 | indirect | Recent. Past advisories: CVE-2025-22869 (ssh ≤ v0.34.0), CVE-2024-45337 (ssh ≤ v0.30.0). bcrypt unaffected; project uses bcrypt only. |
| golang.org/x/net | v0.51.0 | indirect | Recent. Past: CVE-2025-22871 (≤ v0.38.0, h2c smuggling), CVE-2025-22870 (proxy.matchHost ≤ v0.36.0). v0.51.0 above all. |
| golang.org/x/sys | v0.42.0 | indirect | No standing advisory at audit time. |
| golang.org/x/text | v0.35.0 | indirect | Past CVE-2024-45341 (≤ v0.21.0). v0.35.0 well above. |
| nhooyr.io/websocket | v1.8.17 | indirect | Library has been archived/relocated (now coder/websocket). v1.8.17 is the final tagged release. Recommend migration to coder/websocket for ongoing maintenance. No current published high-severity advisory at audit. |

### Action items (Go)
- Run `govulncheck ./...` against current toolchain for symbol-level confirmation; this static review can't observe call-graph reachability.
- Plan migration of `nhooyr.io/websocket` → `github.com/coder/websocket` (drop-in fork; original repo archived). [LOW priority — not a CVE, but supply-chain hygiene]
- Verify quic-go v0.59 against QUIC-LEVEL-DOS / amplification advisories tracked at https://github.com/quic-go/quic-go/security.

## NPM Dependencies — `web/ui/package.json`
Production deps:
- `react@^19.2.4`, `react-dom@^19.2.4` — current.
- `react-router-dom@^7.13.2` — current major.
- `recharts@^3.8.1` — current.
- `tailwind-merge@^3.5.0`, `clsx@^2.1.1` — utilities, low risk.
- `lucide-react@^1.7.0` — note: lucide-react latest is 0.x → *suspicious version* (likely a typo or alpha). Recommend pinning to a known release line; verify on registry. **POTENTIAL FINDING (LOW): unverified package version.**

DevDeps include `vite@^8.0.1`, `vitest@^3.2.4`, `typescript@~5.9.3`, `eslint@^9.39.4`. All current.

### Action items (npm — web/ui)
- Verify `lucide-react@^1.7.0` resolves to a real published version (current upstream is `0.5xx`); if a private fork or fabricated version, fix dependency drift before next `npm install` pulls something unexpected.
- Run `npm audit --omit=dev` and `npx better-npm-audit audit` to confirm.
- `package-lock.json` not inspected here; integrity hashes should be reviewed in lockfile.

## NPM Dependencies — `website/`
Marketing site, deployed to GitHub Pages. Risk surface limited to client-side static content. Per Glob, `website/node_modules/` is committed — this is unusual; verify `.gitignore` and PR hygiene to avoid leaking transient deps into release artifacts. **POTENTIAL FINDING (INFO): node_modules tracked in repo (size/supply-chain bloat).**

## Supply-Chain / Build
- Dockerfile pulls `golang:1.26-alpine` and `alpine:3.20` (digest **not pinned**) — reproducibility / supply-chain risk: an attacker who compromises the Alpine registry (or equivalent) could substitute a base. **FINDING (LOW): unpinned base images.**
- GitHub Actions reference `actions/checkout@v5`, `actions/setup-go@v6`, `actions/setup-node@v5`, `docker/build-push-action@v6`, `softprops/action-gh-release@v2`, etc. — all by major-version tag, not commit SHA. **FINDING (LOW): GH Actions pinned by tag only. CISA / OpenSSF recommend SHA-pinning third-party actions.**
- `release.yml` uses default `GITHUB_TOKEN` for ghcr.io login — scope is per-job, fine.
- `release.yml` runs `npm ci` in `web/ui` before `go build` → embedded UI provenance depends on lockfile integrity.

## Aggregate Risk
- No critical CVEs identified for currently pinned versions of Go modules at audit time.
- Verify questionable `lucide-react` version pin.
- Treat unpinned Docker base images and GH Action tag pins as low-priority supply-chain hygiene findings.
- Recommend automated `govulncheck` and `npm audit` in CI.
