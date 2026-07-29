// complianceExport — UI-M5.1/M5.4. Compliance matrix CSV/JSON
// builders. Kept separate from the page component so the helpers
// stay headless-testable. Same RFC 4180 §2.6 + §2.1 shape as
// auditExport so downstream tooling sees a uniform export contract.

import { COMPLIANCE_ENTRIES, CATEGORY_LABELS, type ComplianceEntry } from './rfcCompliance'

export function csvField(s: string): string {
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return '"' + s.replace(/"/g, '""') + '"'
  }
  return s
}

// buildComplianceCSV emits one row per RFC entry. The `since` column
// reads as the empty string when the entry has no `since` (a core
// entry shipped pre-v0.1) — distinguishing those is more important
// than a synthetic placeholder.
export function buildComplianceCSV(entries: readonly ComplianceEntry[] = COMPLIANCE_ENTRIES): string {
  const header = ['rfc', 'section', 'title', 'category', 'category_label', 'since', 'summary']
  const rows: string[][] = [header]
  for (const e of entries) {
    rows.push([
      e.rfc,
      e.section ?? '',
      e.title,
      e.category,
      CATEGORY_LABELS[e.category] ?? e.category,
      e.since ?? '',
      e.summary,
    ])
  }
  return rows.map((r) => r.map(csvField).join(',')).join('\r\n') + '\r\n'
}

export function buildComplianceJSON(
  entries: readonly ComplianceEntry[] = COMPLIANCE_ENTRIES,
  now: Date = new Date(),
): string {
  return JSON.stringify(
    {
      generated_at: now.toISOString(),
      category_labels: CATEGORY_LABELS,
      entries,
    },
    null,
    2,
  )
}
