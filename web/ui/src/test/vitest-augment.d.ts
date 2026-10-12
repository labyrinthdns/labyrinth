// Extend vitest's Assertion interface so that expect(el).toHaveNoViolations() type-checks.
//
// Up to vitest 4 this was declared on the global `jest.Matchers` namespace,
// which vitest merged into its own Assertion for jest compatibility. vitest 5
// dropped that merge (see Assertion in vitest/dist/chunks/task-utils.*.d.ts,
// now `interface Assertion<R, T>` inside `declare module "vitest"`), so the
// jest.Matchers augmentation silently stopped applying — every toHaveNoViolations()
// call in src/test/a11y.test.tsx failed `tsc -b` with TS2339.
//
// Declaration merging requires an identical type-parameter list, so this must
// mirror vitest 5's `<R, T>` order exactly. The matcher itself returns void:
// it is a terminal assertion, not a chaining link.
//
// Runtime counterpart: expect.extend(toHaveNoViolations) in ./setup.ts, wired
// through vitest.config.ts `setupFiles`.
import 'vitest'

declare module 'vitest' {
  // R and T are deliberately unused here. TypeScript declaration merging
  // requires an identifier-identical type-parameter list, so this interface
  // must spell vitest's own `Assertion<R, T>` exactly — dropping or renaming
  // the parameters silently breaks the merge and reinstates TS2339.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface Assertion<R, T> {
    toHaveNoViolations(): void
  }
}
