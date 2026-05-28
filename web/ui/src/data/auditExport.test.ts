import { describe, it, expect } from 'vitest'
import { buildAuditCSV, buildAuditJSON, csvField } from './auditExport'
import { AUDIT_TIMELINE, type AuditRelease } from './auditTimeline'

// UI-M5.4 — pins the CSV and JSON export shapes that downstream
// compliance tooling will consume. A regression here would silently
// ship malformed CSV / JSON for auditors and break Excel-style
// importers that rely on RFC 4180 quoting + CRLF line endings.

describe('csvField — RFC 4180 §2.6 escaping', () => {
  it('passes simple ASCII fields verbatim', () => {
    expect(csvField('hello')).toBe('hello')
    expect(csvField('v0.7.11')).toBe('v0.7.11')
  })

  it('quotes fields containing a comma', () => {
    expect(csvField('a, b')).toBe('"a, b"')
  })

  it('quotes and doubles embedded quotes', () => {
    // RFC 4180 §2.7: "If double-quotes are used to enclose fields,
    // then a double-quote appearing inside a field must be escaped
    // by preceding it with another double quote."
    expect(csvField('say "hi"')).toBe('"say ""hi"""')
  })

  it('quotes fields containing CR or LF', () => {
    expect(csvField('line1\nline2')).toBe('"line1\nline2"')
    expect(csvField('line1\rline2')).toBe('"line1\rline2"')
  })
})

describe('buildAuditCSV — flattened RFC 4180 export', () => {
  it('emits a header row first', () => {
    const csv = buildAuditCSV()
    const firstLine = csv.split('\r\n')[0]
    expect(firstLine).toBe('version,date,theme,rfc,kind,summary')
  })

  it('emits one row per (release × entry) pair', () => {
    const csv = buildAuditCSV()
    // Trailing CRLF means split gives one empty tail element; drop it.
    const lines = csv.split('\r\n').filter((l) => l.length > 0)
    let expectedRows = 1 // header
    for (const rel of AUDIT_TIMELINE) {
      expectedRows += rel.entries.length
    }
    expect(lines.length).toBe(expectedRows)
  })

  it('escapes a summary containing a comma', () => {
    // Synthetic fixture with an embedded comma in the summary —
    // we don't depend on a real entry having one (the real timeline
    // is allowed to evolve without breaking the pin).
    const fixture: AuditRelease[] = [
      {
        version: 'v9.9.9',
        date: '2026-05-28',
        theme: 'test theme',
        entries: [{ rfc: 'RFC 0', kind: 'added', summary: 'has, comma' }],
      },
    ]
    const csv = buildAuditCSV(fixture)
    const dataRow = csv.split('\r\n')[1]
    expect(dataRow).toBe('v9.9.9,2026-05-28,test theme,RFC 0,added,"has, comma"')
  })

  it('uses CRLF line endings per RFC 4180 §2.1', () => {
    const csv = buildAuditCSV()
    // The first line break must be CRLF, not just LF.
    const firstBreak = csv.indexOf('\n')
    expect(csv[firstBreak - 1]).toBe('\r')
  })

  it('terminates with a trailing CRLF', () => {
    const csv = buildAuditCSV()
    expect(csv.endsWith('\r\n')).toBe(true)
  })
})

describe('buildAuditJSON — structured export', () => {
  it('emits valid JSON', () => {
    const json = buildAuditJSON()
    expect(() => JSON.parse(json)).not.toThrow()
  })

  it('stamps a generated_at timestamp in ISO-8601 form', () => {
    const fixedNow = new Date('2026-05-28T12:34:56.789Z')
    const json = buildAuditJSON(AUDIT_TIMELINE, fixedNow)
    const parsed = JSON.parse(json)
    expect(parsed.generated_at).toBe('2026-05-28T12:34:56.789Z')
  })

  it('carries the timeline under a releases key with the AuditRelease shape', () => {
    const json = buildAuditJSON()
    const parsed = JSON.parse(json)
    expect(Array.isArray(parsed.releases)).toBe(true)
    expect(parsed.releases.length).toBe(AUDIT_TIMELINE.length)
    const first = parsed.releases[0]
    expect(typeof first.version).toBe('string')
    expect(typeof first.date).toBe('string')
    expect(typeof first.theme).toBe('string')
    expect(Array.isArray(first.entries)).toBe(true)
  })
})
