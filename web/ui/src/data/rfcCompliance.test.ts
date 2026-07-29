import { describe, it, expect } from 'vitest'
import { COMPLIANCE_ENTRIES, CATEGORY_LABELS } from './rfcCompliance'

// The compliance matrix is hand-curated and rendered as user-facing
// claims on the AboutPage — a typo here ships as a false claim. These
// tests pin the data-integrity invariants the renderer relies on.
describe('rfcCompliance data integrity', () => {
  it('has at least one entry', () => {
    expect(COMPLIANCE_ENTRIES.length).toBeGreaterThan(0)
  })

  it('every entry has a non-empty rfc, title, and summary', () => {
    for (const e of COMPLIANCE_ENTRIES) {
      expect(e.rfc, `rfc field empty in ${JSON.stringify(e)}`).toMatch(/^RFC\s+\d+/)
      expect(e.title.length, `title empty for ${e.rfc}`).toBeGreaterThan(0)
      expect(e.summary.length, `summary empty for ${e.rfc}`).toBeGreaterThan(0)
    }
  })

  it('every entry maps to a known category label', () => {
    for (const e of COMPLIANCE_ENTRIES) {
      expect(CATEGORY_LABELS[e.category], `unknown category for ${e.rfc}: ${e.category}`).toBeDefined()
    }
  })

  it('"since" version field, when present, is a vN.N.N tag', () => {
    for (const e of COMPLIANCE_ENTRIES) {
      if (e.since) {
        expect(e.since, `bad since version for ${e.rfc}`).toMatch(/^v\d+\.\d+\.\d+$/)
      }
    }
  })

  it('does not list the same (rfc, section, title) triple twice', () => {
    // Section is optional in the matrix (e.g. "RFC 8198 §5.2" vs "§5.4" are
    // legitimately two separate entries). Pin uniqueness over the full triple
    // — duplicate by accident here would render a doubled card in the UI.
    const seen = new Set<string>()
    for (const e of COMPLIANCE_ENTRIES) {
      const key = `${e.rfc}|${e.section ?? ''}|${e.title}`
      expect(seen.has(key), `duplicate compliance entry: ${key}`).toBe(false)
      seen.add(key)
    }
  })
})
