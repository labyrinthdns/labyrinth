// Extend vitest's Assertion interface so that expect(el).toHaveNoViolations() type-checks.
// vitest merges jest.Matchers into its own Assertion type for compatibility.
import 'vitest'

declare global {
  namespace jest {
    interface Matchers<R> {
      toHaveNoViolations(): R
    }
  }
}
