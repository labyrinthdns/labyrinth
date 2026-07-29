// auditExport — UI-M5.4 from PLAN.md. Pure-data helpers that turn the
// AUDIT_TIMELINE array into CSV (RFC 4180) and structured JSON for
// download. Kept separate from AuditPage.tsx so the helpers are
// testable in isolation without booting a React renderer or mocking
// document.createElement.

import { AUDIT_TIMELINE, type AuditRelease } from './auditTimeline'

// csvField applies RFC 4180 §2.6 escaping: a field containing comma,
// quote, CR, or LF is wrapped in double quotes; embedded quotes are
// doubled. We don't pull in a CSV library for ~50 rows.
export function csvField(s: string): string {
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return '"' + s.replace(/"/g, '""') + '"'
  }
  return s
}

// buildAuditCSV flattens the timeline into one-row-per-entry CSV.
// CRLF line endings per RFC 4180 §2.1 so Excel-style consumers don't
// fold rows together.
export function buildAuditCSV(timeline: readonly AuditRelease[] = AUDIT_TIMELINE): string {
  const header = ['version', 'date', 'theme', 'rfc', 'kind', 'summary']
  const rows: string[][] = [header]
  for (const rel of timeline) {
    for (const e of rel.entries) {
      rows.push([rel.version, rel.date, rel.theme, e.rfc, e.kind, e.summary])
    }
  }
  return rows.map((r) => r.map(csvField).join(',')).join('\r\n') + '\r\n'
}

// buildAuditJSON returns the timeline as pretty-printed JSON, stamped
// with a generation timestamp. The releases array preserves the
// internal AuditTimeline shape so downstream tooling can rely on it.
export function buildAuditJSON(
  timeline: readonly AuditRelease[] = AUDIT_TIMELINE,
  now: Date = new Date(),
): string {
  return JSON.stringify({ generated_at: now.toISOString(), releases: timeline }, null, 2)
}
