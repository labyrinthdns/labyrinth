# LabyrinthDNS — Codebase Action Plan

**Date:** 2026-07-15  
**Basis:** Codebase audit report (`codebase-audit-report.md`)  
**Integration:** Cross-referenced against `PLAN.md` (v1.0.0 roadmap)

---

## How to Read This Document

Each finding from the audit is mapped to one of three categories:

1. **New work item** — not covered by the existing PLAN.md roadmap
2. **PLAN.md integration** — fits into an existing milestone gap
3. **Informational** — by-design or non-actionable

Priority: **P0** (blocking) > **P1** (before release) > **P2** (quality) > **P3** (nice-to-have)

---

## Action Items

---

### ~~P1-01 — Add CSP Headers to SPA Responses~~ ✅ Already implemented

**Source:** Audit finding M4 (retracted — false positive)  
**Priority:** ~~P1~~ → Done  
**Verification:** `web/middleware.go:179–192` — the `securityHeaders` middleware sets a full CSP on every response:

```
Content-Security-Policy: default-src 'self'; img-src 'self' data:;
script-src 'self'; style-src 'self' 'unsafe-inline';
connect-src 'self' ws: wss:; frame-ancestors 'none';
base-uri 'none'; form-action 'self'
```

The audit report has been corrected to reflect this.

---

### ~~P1-02 — Add Component Tests for Critical UI Pages~~ ✅ Done

**Source:** Audit finding M5 (M1 in the issue tracker)  
**Priority:** ~~P1~~ → Done  
**Effort:** Implemented (~3 hours)  
**Verification:**

| Page | Tests | Scenarios covered |
|------|-------|-------------------|
| `LoginPage` | 9 tests (165 lines) | Form render, error display, generic error, success + navigation, loading state, password toggle, error clearing, required validation, maxLength |
| `DashboardPage` | 7 tests (253 lines) | Render without crash, time-series chart, pie chart, top clients/domains tables, stats/profile API calls, version/update fetches |

The DashboardPage test uses hoisted mocks for 8 API endpoints, recharts components, and WebSocket hooks. All 16 tests pass in vitest.  
**Remaining:** ConfigPage, SetupWizard, SecurityPage, CachePage are still uncovered.

---

### ~~P1-03 — Migrate JWT from localStorage to HttpOnly Cookie~~ ✅ Done

**Source:** Audit finding M6 (M2 in the issue tracker)  
**Priority:** ~~P1~~ → Done  
**Effort:** Implemented (~2 hours)  

**Changes:**
- `web/auth.go`: login handler sets `labyrinth_token` HttpOnly cookie (Secure if TLS, SameSite=Strict, 24h Max-Age). New `handleLogout` revokes the JWT jti and clears the cookie with MaxAge=-1.
- `web/middleware.go`: `requireAuth` reads the cookie first, falls back to `Authorization: Bearer` header, then `?token=` query param.
- `web/server.go`: registered `POST /api/auth/logout` route.
- `web/ui/src/api/client.ts`: `request()` no longer sends Bearer header. Added `api.logout()`.
- `web/ui/src/App.tsx`: `ProtectedRoute` uses `useAuth()`. Auth check calls `api.me()` unconditionally (cookie is auto-sent). Logout calls `api.logout()`.
- `web/ui/src/api/client.test.ts`: updated Bearer header test.
- All 75 tests pass (Go backend + TS frontend).

---

### ~~P2-01 — Optimise RRL Eviction from O(n) to O(log n)~~ ✅ Done

**Source:** Audit finding M3  
**Priority:** ~~P2~~ → Done  
**Effort:** Implemented  
**Verification:** `security/ratelimit.go` now uses a `container/heap` min-heap alongside the map. `evictOldestLocked` runs in O(log n) instead of O(n). The heap is lazy-initialised and rebuilds from the map on first use (handles test setups that seed the map directly). The cleanup tick trims stale heap entries when they exceed 2x the map size. All 6 `TestRateLimiter*` tests pass, including `-race`.  
**Commit:** Not yet committed (working tree).

---

### P2-02 — Add Accessibility Audit Baseline

**Source:** Audit weakness #5 (Section 14)  
**Priority:** P2 (quality)  
**Affected files:** `web/ui/src/` (all pages)  
**PLAN.md fit:** UI-M7 (Operator UX polish)  
**Effort:** ~2–4 hours  

**Problem:** The UI has basic semantic HTML but no formal accessibility audit. WCAG 2.2 AA compliance is not verified, and there are no `aria-*` attributes, keyboard navigation tests, or screen-reader validation.

**Action:**
1. Install `@axe-core/react` in the dev dependencies for automated aXe scanning.
2. Add a `data-audit="a11y"` integration test that runs `vitest` + `jest-axe` on every page.
3. Audit and fix the top 10 violations:
   - Ensure all form inputs have associated `<label>` elements
   - Add `aria-label` to icon-only buttons (sidebar toggle, theme switch, logout)
   - Ensure focus indicators are visible on all interactive elements
   - Add `role="status"` to live-updating metric cards
   - Ensure colour contrast meets 4.5:1 on all text

**Acceptance criteria:**
- `npx axe http://localhost:9153/` returns 0 violations of category "critical" or "serious"
- Tab-navigation through the sidebar, dashboard, config page, and login page is complete and visible
- Screen reader can announce all metric values and chart data

---

### P2-03 — Docker Build Optimisation (Separate Node Stage)

**Source:** Audit finding L1  
**Priority:** P2 (quality)  
**Affected file:** `Dockerfile`  
**PLAN.md fit:** M8.5 (Release artifacts)  
**Effort:** ~1 hour  

**Problem:** The Dockerfile installs Node.js/npm inside the Go builder image, downloading npm packages on every build. This adds 60–90s to every build and mixes concerns.

**Action:**

```dockerfile
# Stage 1: Build React frontend
FROM node:22-alpine AS webui
WORKDIR /src/web/ui
COPY web/ui/package.json web/ui/package-lock.json ./
RUN npm ci --silent
COPY web/ui/ .
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.26-alpine AS build
COPY --from=webui /src/web/ui/dist /src/web/ui/dist
...
```

**Acceptance criteria:**
- `docker build` completes successfully
- The embedded SPA is served correctly
- Build time is not regressed (ideally improved by layer caching of `node_modules`)

---

### ~~P2-04 — Add Fuzz Harness for NSEC3 Hash and RPZ Matcher~~ ✅ Done

**Source:** PLAN.md M6.1  
**Priority:** ~~P2~~ → Done  
**Effort:** Implemented (~1 hour)  
**Files:** `dnssec/fuzz_nsec3_test.go` (56 lines), `blocklist/fuzz_matcher_test.go` (78 lines)  

**Fuzz targets:**

| Target | Corpus | Execs/6s | Result |
|--------|--------|----------|--------|
| `FuzzComputeNSEC3Hash` | 7 seeds (name, algorithm, iterations, salt) | 341K | ✅ 0 failures |
| `FuzzNSEC3HashToString` | 3 seeds (arbitrary hash bytes) | — | ✅ 0 failures |
| `FuzzRPZParser` | 7 seeds (RPZ zone content) | 146K | ✅ 0 failures, 170 interesting |
| `FuzzDomainMatcher` | 3 seeds (null-terminated domains) | 218K | ✅ 0 failures, 94 interesting |

PLAN.md M6.1 gap filled. All existing tests pass.

---

### P2-05 — Clarify Cluster Mode Implementation Status

**Source:** Audit weakness #7 (Section 14)  
**Priority:** P2 (quality)  
**Affected files:** `config/config.go`, `web/server.go`, `docs/architecture-deep-dive.md`  
**PLAN.md fit:** M8.3 (Final API freeze)  
**Effort:** ~1 hour  

**Problem:** The `labyrinth.yaml` config has a full `cluster:` section with peer definitions, sync modes, and fanout actions, but the audit could not determine how much of this is implemented vs aspirational. This ambiguity is a documentation gap, not a code bug.

**Action:**
1. Search the codebase for all references to `ClusterConfig` fields.
2. Audit which cluster features are wired vs config-only.
3. Document the implemented subset in `docs/architecture-deep-dive.md`.
4. Add `// TODO(v1.0): not yet implemented` comments on config fields where the handler code is absent.

**Acceptance criteria:**
- Each `ClusterConfig` field is annotated in the source as `// implemented` or `// planned`
- Architecture deep-dive has a "Cluster Mode" section describing the implemented subset
- No config-only trap: operators can tell at a glance what works

---

### ~~P2-06 — Property-Based Tests for DNS Wire Parsing~~ ✅ Done

**Source:** PLAN.md M6.2  
**Priority:** ~~P2~~ → Done  
**Effort:** Implemented (~2 hours)  
**File:** `dns/pbt_wire_test.go` (624 lines)  

5 properties covering:
1. Header bijection — `testing/quick` on all 6 uint16 fields (100 random values)
2. Name bijection — 1000 random valid domain names
3. All 14 RR types round-trip — A, AAAA, NS, CNAME, MX, SOA, TXT, SRV, PTR, DNAME, OPT, RRSIG, NSEC, plus multi-section and empty message
4. Compression pointer stability across 3 Pack/Unpack iterations
5. Buffer bounds — Pack correctly errors on undersized buffers

All 16 tests pass. Existing fuzz tests are unaffected.

---

### P3-01 — Document WebSocket Idle Disconnect Policy

**Source:** Audit finding L2  
**Priority:** P3 (nice-to-have)  
**Affected file:** `web/timeseries_ws.go`  
**Effort:** ~30 min  

**Action:** Add a constant and doc comment for WebSocket idle max-age along with the existing `MaxWebSocketMessageBytes`. The `coder/websocket` library's `CloseTimeout` should be set on the connection context.

---

### P3-02 — Set Up 72-Hour Soak Test Harness

**Source:** PLAN.md M8.2 (long-running soak — not implemented)  
**Priority:** P3 (nice-to-have)  
**PLAN.md fit:** M8.2 (Long-running soak — existing gap)  
**Effort:** ~3–4 hours  

**Action:** Create a `test/soak/` directory with a Go test that runs the resolver against a downstream test zone for 72 hours, tracking memory, goroutine count, and response latency at 1-minute intervals. Fail on: goroutine leak (>5% growth), memory leak (>10% RSS growth), latency spike (>5x baseline for >1% of queries).

---

## Summary by Priority

| Priority | Count | Items |
|----------|-------|-------|
| **P0** (blocking) | 0 | — |
| **P1** (before release) | 0 | — |
| **P2** (quality) | 2 | a11y audit, cluster doc |
| **P3** (nice-to-have) | 1 | soak harness |

---

## Mapping to PLAN.md Milestones

| Audit item | Maps to PLAN.md | Notes |
|-----------|----------------|-------|
| CSP headers | New (not in PLAN.md) | Add to M8 stabilization |
| UI component tests | UI-M7 / UI-M8 | Extends existing UI milestone scope |
| JWT cookie migration | UI-M7 / M8.3 | API freeze prerequisite |
| RRL O(n) fix | M5 (DoS/Security) | Hardening optimisation |
| a11y audit | UI-M7 (UX polish) | Standard UX requirement |
| Docker build | M8.5 (Release artifacts) | DevOps refinement |
| Fuzz harnesses | M6.1 (existing gap) | Completes incomplete item |
| Cluster docs | M8.3 (API freeze) | Documentation gap |
| Property tests | M6.2 (existing gap) | Completes incomplete item |
| Soak test | M8.2 (existing gap) | Completes incomplete item |

---

## Execution Order Recommendation

```
Phase 1 — Quick wins (1–2 days)
├── P1-01: CSP headers             (~30 min)
├── P2-05: Cluster mode docs       (~1 hour)
├── P3-01: WebSocket doc           (~30 min)
└── P2-03: Docker build fix        (~1 hour)

Phase 2 — Security hardening (2–3 days)
├── P1-03: JWT cookie migration    (~3–5 hours)
├── P2-01: RRL O(n) fix           (~2–3 hours)
└── P1-01: CSP headers (already in Phase 1)

Phase 3 — Test infrastructure (3–5 days)
├── P1-02: UI component tests      (~4–6 hours)
├── P2-04: Fuzz harnesses         (~2 hours)
└── P2-06: Property tests         (~3–4 hours)

Phase 4 — QA polish (2–3 days)
├── P2-02: a11y audit             (~2–4 hours)
└── P3-02: Soak harness           (~3–4 hours)
```

---

## Appendix: Measurement Criteria

| Area | Current state | Target state |
|------|--------------|--------------|
| CSP coverage | 0 endpoints | All SPA responses |
| UI test coverage | 21% (9/43 files) | ≥50% (≥22/43 files) |
| JWT storage | localStorage | HttpOnly cookie |
| RRL eviction complexity | O(n) | O(log n) |
| aXe violations | Unknown | 0 critical/serious |
| Docker build stages | 2 (mixed) | 3 (separated) |
| Fuzz targets | 3 | ≥5 |
| Property tests | 0 | ≥3 invariants |
| Cluster mode docs | None | Documented |
