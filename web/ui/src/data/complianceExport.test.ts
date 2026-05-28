import { describe, it, expect } from 'vitest'
import { buildComplianceCSV, buildComplianceJSON, csvField } from './complianceExport'
import { COMPLIANCE_ENTRIES, CATEGORY_LABELS, type ComplianceEntry } from './rfcCompliance'

// UI-M5.1 / UI-M5.4 — pins the compliance-matrix export shape that
// downstream auditors and compliance-tooling will consume. The CSV
// path tightens the RFC 4180 quoting rules so a Excel-style importer
// doesn't fold rows together; the JSON path stamps a generation
// timestamp and includes the category label dictionary so a consumer
// doesn't have to know the internal taxonomy.

describe('csvField — RFC 4180 §2.6', () => {
  it('escapes a field containing a comma', () => {
    expect(csvField('a,b')).toBe('"a,b"')
  })

  it('doubles embedded quotes', () => {
    expect(csvField('say "yes"')).toBe('"say ""yes"""')
  })

  it('passes simple fields verbatim', () => {
    expect(csvField('RFC 1035')).toBe('RFC 1035')
  })
})

describe('buildComplianceCSV', () => {
  it('emits the documented header row', () => {
    const csv = buildComplianceCSV()
    expect(csv.split('\r\n')[0]).toBe('rfc,section,title,category,category_label,since,summary')
  })

  it('emits one row per entry plus the header', () => {
    const csv = buildComplianceCSV()
    const rows = csv.split('\r\n').filter((l) => l.length > 0)
    expect(rows.length).toBe(COMPLIANCE_ENTRIES.length + 1)
  })

  it('quotes a summary containing commas', () => {
    const fixture: ComplianceEntry[] = [
      { rfc: 'RFC 0', title: 'Test', summary: 'has, comma', category: 'core' },
    ]
    const csv = buildComplianceCSV(fixture)
    const dataRow = csv.split('\r\n')[1]
    // category=core → label "Core Protocol"
    expect(dataRow).toBe('RFC 0,,Test,core,Core Protocol,,"has, comma"')
  })

  it('renders an empty cell when section / since is undefined', () => {
    const fixture: ComplianceEntry[] = [
      { rfc: 'RFC 9999', title: 'No section', summary: 'No since either', category: 'core' },
    ]
    const csv = buildComplianceCSV(fixture)
    const dataRow = csv.split('\r\n')[1]
    expect(dataRow).toBe('RFC 9999,,No section,core,Core Protocol,,No since either')
  })

  it('uses CRLF line endings + trailing CRLF', () => {
    const csv = buildComplianceCSV()
    const firstNL = csv.indexOf('\n')
    expect(csv[firstNL - 1]).toBe('\r')
    expect(csv.endsWith('\r\n')).toBe(true)
  })
})

describe('buildComplianceJSON', () => {
  it('emits valid JSON', () => {
    expect(() => JSON.parse(buildComplianceJSON())).not.toThrow()
  })

  it('carries entries, category_labels, and generated_at', () => {
    const fixedNow = new Date('2026-05-28T00:00:00.000Z')
    const parsed = JSON.parse(buildComplianceJSON(COMPLIANCE_ENTRIES, fixedNow))
    expect(parsed.generated_at).toBe('2026-05-28T00:00:00.000Z')
    expect(parsed.category_labels).toEqual(CATEGORY_LABELS)
    expect(Array.isArray(parsed.entries)).toBe(true)
    expect(parsed.entries.length).toBe(COMPLIANCE_ENTRIES.length)
  })
})
