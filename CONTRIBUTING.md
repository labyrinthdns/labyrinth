# Contributing to LabyrinthDNS

Thank you for considering contributing to LabyrinthDNS! This
document provides guidelines and processes for contributing.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Workflow](#development-workflow)
4. [Coding Standards](#coding-standards)
5. [Testing](#testing)
6. [Commit Messages](#commit-messages)
7. [Pull Request Process](#pull-request-process)
8. [Branch Protection and Release](#branch-protection-and-release)
9. [RFC Compliance](#rfc-compliance)

## Code of Conduct

This project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md).
By participating, you agree to maintain a harassment-free environment
for everyone.

## Getting Started

### Prerequisites

- Go 1.26+
- Node.js 22+
- npm

### Local Setup

```bash
# Clone the repository
git clone https://github.com/labyrinthdns/labyrinth.git
cd labyrinth

# Build the frontend (required for //go:embed)
cd web/ui && npm ci && npm run build && cd ../..

# Build the binary
go build -ldflags="-s -w" -o labyrinth .

# Quick smoke test
./labyrinth -version
./labyrinth check
```

### Running Tests

```bash
# Run all first-party packages with the race detector
# (the Makefile allowlist deliberately excludes frontend node_modules)
make test-race

# Run a specific package
go test ./resolver/... -count=1 -race

# Run a specific test
go test ./dnssec/... -run TestRFC4035AlgorithmRollover -v

# Benchmarks across first-party packages
make bench
```

## Development Workflow

### 1. Pick an issue

Start by browsing [open issues](https://github.com/labyrinthdns/labyrinth/issues)
or the [PLAN.md](PLAN.md) roadmap. Comment on the issue to let others
know you're working on it.

### 2. Create a branch

```bash
git checkout -b fix/description-of-fix
```

Branch naming:
- `fix/` — bug fixes
- `feat/` — new features
- `docs/` — documentation changes
- `refactor/` — code changes without behaviour change
- `chore/` — build/lint/dependency work

### 3. Make your changes

Follow the [coding standards](#coding-standards) below.

### 4. Test your changes

```bash
make test-race
make vet
cd web/ui && npm run lint && npm test
```

### 5. Commit and push

See [commit messages](#commit-messages) below.

### 6. Open a pull request

See [pull request process](#pull-request-process) below.

## Coding Standards

### General

- **Readability over cleverness.** DNS resolver correctness is hard enough;
  optimise for the next reader, not the compiler.
- **Comments explain *why*, not *what***. The code already says what it does.
  Comments should explain design decisions, RFC references, and edge cases.
- **RFC references in comments.** When implementing an RFC behaviour, add a
  comment linking the relevant section: `// RFC 4035 §3.2.2 — AD bit gating`.
- **No silent fallbacks.** If a platform-specific feature is unavailable,
  log a warning and degrade gracefully. Do not fail silently.
- **Defensive bounds.** Every config value read from YAML/environment that
  feeds into a `make()` or a loop condition must have a clamp or floor.
  See `config/config.go` `clampConfigBounds` for the pattern.

### Go

- Format with `gofumpt` (or `go fmt` as fallback).
- Run `make vet` before every commit; it uses the first-party package allowlist and never traverses frontend `node_modules`.
- Use `atomic.Bool` / `atomic.Int64` for cross-goroutine flags.
- Avoid `interface{}` — use `any`.
- Error wrapping: `fmt.Errorf("context: %w", err)`.
- Prefer `log/slog` for structured logging.
- Context propagation: pass `context.Context` as the first argument.
- Import ordering: stdlib → external → internal.

### Frontend (web/ui)

- TypeScript strict mode.
- React functional components with hooks.
- Tailwind CSS for styling.
- Vitest for tests.
- Eslint + `eslint-plugin-react-hooks`.

## Testing

- **Every RFC-pinned behaviour needs a test.** File naming: `rfcNNNN_*_test.go`.
- **Regression tests first.** When fixing a bug, write a test that reproduces
  the bug before applying the fix, then verify the fix passes.
- **Race detector.** Run `-race` on all tests. New tests must pass with
  `-count=1 -race`.
- **Avoid `time.Sleep` in tests.** Use mocked clocks or channel-driven
  coordination. See `dnssec/rfc5011_lifecycle_test.go` for a time-mocking
  pattern.
- **Table-driven tests** are preferred for multiple-input scenarios.
- **Coverage.** New code should be covered. Aim for ≥85% on core packages
  (`dns/`, `dnssec/`, `resolver/`, `cache/`, `server/`).

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`.

Scopes match package directories: `resolver`, `dnssec`, `server`, `cache`,
`web`, `config`, `dns`, `security`, `daemon`, `metrics`, `blocklist`.

Examples:
```
fix(dnssec): correct NSEC RRSIG canonicalisation (RFC 6840 §5.1)
feat(config): add max_queries_per_request config knob
docs(web): add API reference for /api/cache endpoints
```

## Pull Request Process

1. **Ensure tests pass** with `make test-race`.
2. **Run `make vet`** — no warnings.
3. **Update CHANGELOG.md** under the `[Unreleased]` section.
4. **Update PLAN.md** if your change affects a milestone item.
5. **Update `docs/rfc-compliance-matrix.md`** if your change adds or modifies
   RFC coverage.
6. **One PR per logical change.** Don't mix refactoring with features.
7. **PR title** follows the same Conventional Commits format as commit messages.
8. **Keep PRs small** (< 400 lines preferred). Large changes should be broken
   into stacked PRs.
9. **Request review** from a project maintainer.
10. **Address review feedback** with additional commits — squash before merge.

## Branch Protection and Release

`main` is protected. Changes reach `main` through a pull request whose
required status checks have passed. An approving review is no longer required
by the protection (see [Reviews](#reviews)).

### Required status checks

A pull request cannot be merged until all five of these report **success** on
its head commit:

| Check | Comes from | What it covers |
|---|---|---|
| `lint` | `ci.yml` → `lint` | `make lint` (golangci-lint) and `golangci-lint fmt --diff` |
| `typecheck` | `ci.yml` → `typecheck` | `web/ui`: `npm ci`, lint, `tsc -b`, vitest |
| `test` | `ci.yml` → `test` | `make test` and the scoped `-race` lane |
| `docker-build` | `ci.yml` → `docker-build` | image builds and smoke-runs |
| `build` | `website.yml` → `build` | `website/`: `npm ci`, lint, `tsc -b && vite build` |

The names are **check-run names, not workflow names**. `website.yml` is called
"Deploy Website" in its `name:` field, but it emits checks called `build` and
`deploy`; configuring "Deploy Website" as a required check would match nothing.

`deploy` is deliberately **not** required. It is gated on
`github.event_name == 'push'`, so on a pull request it reports `skipped`. A
check that reports `skipped` on every PR gates nothing, and requiring one that
never runs blocks every PR permanently. `build` is the part that validates
your change.

### Reviews

As of 2026-10-12 the protection no longer requires an approving review: pull
requests show no review requirement, and merges have landed without one. The
five status checks above are still required.

Asking for a review is still the expected practice for anything beyond a
trivial change. Approval is now a process rule rather than a merge gate, so
a reviewer's comments are only binding if the author waits for them.

### Known limitation: the "block direct pushes" half is not expressible here

GitHub's "Require a pull request before merging" rule is
`required_pull_request_reviews` in classic protection. Whether that rule was
removed or kept with zero required approvals is not visible without admin
access to the protection settings. What is visible is that the five checks
must pass on the commit that reaches `main`.

The rulesets-level alternative cannot be configured here either. This
repository cannot express `allow_direct_pushes: false`, the rulesets-level
switch that additionally refuses direct pushes to the branch:

- the classic branch protection endpoint on this repository has no
  `allow_direct_pushes` field at all — a PUT carrying it returns `200` and the
  field is silently absent from the following GET;
- the rulesets endpoint rejects the `pull_request` rule whenever parameters
  are present. `deletion`, `non_fast_forward` and a bare
  `{"type": "pull_request"}` are accepted; adding any parameter —
  `allow_direct_pushes` alone, `required_reviewers` alone, the documented
  four-field minimum, the full documented set, with and without the
  `X-GitHub-Api-Version` header — returns
  `422 Invalid property /rules/N: data matches no possible input`.

So: **do not rely on this document as evidence that direct pushes are
blocked.** The protection is enforced server-side and cannot be inspected
through the API; whether a given direct push is refused has to be established
by attempting one, which is not something to do casually on `main`. Until the
ruleset limitation is resolved, the pull-request requirement is a process rule,
not a configuration you can audit from here.

If you must land something immediately, use a pull request anyway: it runs
the required checks and records what was merged and why.

### Merging

Prefer the GitHub merge button or `gh pr merge`, which wait for the required
checks and record the merge on the PR. A local `git merge --ff-only` plus
`git push origin main` is what several `docs`/`chore` changes in this
repository's history used, because the PR was already fully green; it is
recorded here as a known workaround, not as the recommended path, and it
bypasses the PR record.

### Releases

Releases are cut by pushing a `v*` tag. `.github/workflows/release.yml` then
runs frontend lint/test/build, `make check-go-package-scope`, `make test`, and
only then builds and publishes binaries, the container image and the GitHub
Release. Keep the `go-version` in `go.mod`, `ci.yml` and `release.yml` in step
— a partial bump lets CI compile with a toolchain `go.mod` rejects.

## RFC Compliance

LabyrinthDNS values RFC compliance. When adding behaviour mandated by an RFC:

1. Reference the RFC and section in source comments.
2. Add a file named `rfcNNNN_descriptive_name_test.go` in the relevant package.
3. Update `docs/rfc-compliance-matrix.md`.
4. Run the full suite to confirm no regressions.

If your change intentionally diverges from an RFC recommendation (rare),
document both the divergence and the rationale in source comments.
