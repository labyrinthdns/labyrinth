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
8. [RFC Compliance](#rfc-compliance)

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
# Run all tests with race detector
go test ./... -count=1 -race -timeout 120s

# Run a specific package
go test ./resolver/... -count=1 -race

# Run a specific test
go test ./dnssec/... -run TestRFC4035AlgorithmRollover -v

# Benchmarks
go test ./... -bench=. -benchmem -run='^$'
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
go test ./... -count=1 -race -timeout 120s
go vet ./...
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
- Run `go vet ./...` before every commit.
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

1. **Ensure tests pass** with `go test ./... -count=1 -race -timeout 120s`.
2. **Run `go vet ./...`** — no warnings.
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

## RFC Compliance

LabyrinthDNS values RFC compliance. When adding behaviour mandated by an RFC:

1. Reference the RFC and section in source comments.
2. Add a file named `rfcNNNN_descriptive_name_test.go` in the relevant package.
3. Update `docs/rfc-compliance-matrix.md`.
4. Run the full suite to confirm no regressions.

If your change intentionally diverges from an RFC recommendation (rare),
document both the divergence and the rationale in source comments.
