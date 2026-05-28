import { describe, it, expect } from 'vitest'
import { resolveMetricPath } from './complianceMetricResolve'

describe('resolveMetricPath', () => {
  it('returns top-level number values', () => {
    expect(resolveMetricPath({ a: 5 }, 'a')).toBe(5)
  })

  it('walks one nested level', () => {
    expect(resolveMetricPath({ cookies: { badcookie_responses: 42 } }, 'cookies.badcookie_responses')).toBe(42)
  })

  it('walks two nested levels', () => {
    expect(resolveMetricPath({ a: { b: { c: 7 } } }, 'a.b.c')).toBe(7)
  })

  it('returns undefined for a missing top-level segment', () => {
    expect(resolveMetricPath({ a: 5 }, 'b')).toBeUndefined()
  })

  it('returns undefined for a missing nested segment', () => {
    expect(resolveMetricPath({ a: { b: 1 } }, 'a.c')).toBeUndefined()
  })

  it('returns undefined when the path resolves to a non-number', () => {
    expect(resolveMetricPath({ a: 'string' }, 'a')).toBeUndefined()
    expect(resolveMetricPath({ a: { b: true } }, 'a.b')).toBeUndefined()
    expect(resolveMetricPath({ a: { b: null } }, 'a.b')).toBeUndefined()
  })

  it('returns undefined for null / undefined root', () => {
    expect(resolveMetricPath(null, 'a')).toBeUndefined()
    expect(resolveMetricPath(undefined, 'a')).toBeUndefined()
  })

  it('handles numeric-looking keys (the EDE counts map case)', () => {
    // /api/security carries ede_counts as Record<string, number> with
    // decimal-string keys like "6", "17". The path "ede_counts.6"
    // must resolve through that string key.
    expect(resolveMetricPath({ ede_counts: { '6': 12 } }, 'ede_counts.6')).toBe(12)
  })
})
