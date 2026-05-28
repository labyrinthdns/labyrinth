import { useMemo, useState } from 'react'
import { History, ShieldCheck, ShieldAlert, Wrench, Plus, Download, FileJson, FileText } from 'lucide-react'
import { AUDIT_TIMELINE, type AuditEntry } from '@/data/auditTimeline'
import { buildAuditCSV, buildAuditJSON } from '@/data/auditExport'

function triggerDownload(content: string, filename: string, mime: string): void {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// Audit timeline — chronological view of the RFC pin work that
// landed in each release. Renders newest-first from the hand-curated
// data array. The operator answering "what got safer this month?"
// scrolls top-down; the auditor answering "when was RFC 7646 added?"
// uses the per-entry RFC reference column with the in-page filter.

function KindBadge({ kind }: { kind: AuditEntry['kind'] }) {
  switch (kind) {
    case 'added':
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-sky-500/10 text-sky-700 dark:text-sky-400 border border-sky-500/30 uppercase tracking-wider">
          <Plus className="h-2.5 w-2.5" />
          added
        </span>
      )
    case 'harden':
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30 uppercase tracking-wider">
          <ShieldCheck className="h-2.5 w-2.5" />
          harden
        </span>
      )
    case 'fixed':
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/30 uppercase tracking-wider">
          <Wrench className="h-2.5 w-2.5" />
          fixed
        </span>
      )
  }
}

export default function AuditPage() {
  const [filter, setFilter] = useState('')

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return AUDIT_TIMELINE
    return AUDIT_TIMELINE
      .map((rel) => ({
        ...rel,
        entries: rel.entries.filter(
          (e) =>
            e.rfc.toLowerCase().includes(q) ||
            e.summary.toLowerCase().includes(q) ||
            e.kind.toLowerCase().includes(q),
        ),
      }))
      .filter((rel) => rel.entries.length > 0 || rel.version.toLowerCase().includes(q) || rel.theme.toLowerCase().includes(q))
  }, [filter])

  const totals = useMemo(() => {
    const t = { added: 0, harden: 0, fixed: 0 }
    for (const rel of AUDIT_TIMELINE) {
      for (const e of rel.entries) {
        t[e.kind]++
      }
    }
    return t
  }, [])

  return (
    <div className="px-4 sm:px-6 lg:px-8 py-6 max-w-5xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-white flex items-center gap-2">
          <History className="h-6 w-6 text-amber-500" />
          Audit Timeline
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Per-release record of the RFC pin work and behaviour locks. Sourced from CHANGELOG; the changelog itself is canonical.
        </p>
        <div className="mt-3 flex items-center gap-4 text-sm">
          <span className="inline-flex items-center gap-1 text-sky-700 dark:text-sky-400">
            <Plus className="h-3.5 w-3.5" />
            <strong>{totals.added}</strong> added
          </span>
          <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400">
            <ShieldCheck className="h-3.5 w-3.5" />
            <strong>{totals.harden}</strong> harden
          </span>
          <span className="inline-flex items-center gap-1 text-amber-700 dark:text-amber-400">
            <Wrench className="h-3.5 w-3.5" />
            <strong>{totals.fixed}</strong> fixed (real bug)
          </span>
        </div>
      </div>

      <div className="mb-4 flex flex-col sm:flex-row gap-2">
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by RFC, summary, or kind (added / harden / fixed)…"
          className="flex-1 px-3 py-2 text-sm border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 rounded-md focus:outline-none focus:ring-1 focus:ring-amber-500"
        />
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const today = new Date().toISOString().slice(0, 10)
              triggerDownload(buildAuditCSV(), `labyrinth-audit-${today}.csv`, 'text/csv;charset=utf-8')
            }}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800"
            title="Download all audit entries as RFC 4180 CSV — feed to a spreadsheet or compliance tracker"
          >
            <FileText className="h-3.5 w-3.5" />
            <span>Export CSV</span>
            <Download className="h-3 w-3 opacity-60" />
          </button>
          <button
            type="button"
            onClick={() => {
              const today = new Date().toISOString().slice(0, 10)
              triggerDownload(buildAuditJSON(), `labyrinth-audit-${today}.json`, 'application/json')
            }}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800"
            title="Download structured JSON — same shape as the internal data model"
          >
            <FileJson className="h-3.5 w-3.5" />
            <span>Export JSON</span>
            <Download className="h-3 w-3 opacity-60" />
          </button>
        </div>
      </div>

      <div className="space-y-4">
        {filtered.map((rel) => (
          <article key={rel.version} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
            <header className="px-4 py-3 flex items-center justify-between border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50">
              <div className="flex items-baseline gap-3">
                <span className="font-mono text-base font-semibold text-amber-600 dark:text-amber-500">{rel.version}</span>
                <span className="text-sm text-slate-700 dark:text-slate-300">{rel.theme}</span>
              </div>
              <span className="text-xs font-mono text-slate-500 dark:text-slate-400">{rel.date}</span>
            </header>
            <ul className="divide-y divide-slate-200 dark:divide-slate-800">
              {rel.entries.map((e, idx) => (
                <li key={idx} className="px-4 py-2.5 flex items-start gap-3">
                  <KindBadge kind={e.kind} />
                  <div className="flex-1 min-w-0">
                    <div className="font-mono text-xs text-slate-600 dark:text-slate-400">{e.rfc}</div>
                    <div className="mt-0.5 text-sm text-slate-900 dark:text-slate-100">{e.summary}</div>
                  </div>
                </li>
              ))}
            </ul>
          </article>
        ))}
        {filtered.length === 0 && (
          <div className="text-center py-12 text-sm text-slate-500 dark:text-slate-400">
            No entries match the filter.
            <button onClick={() => setFilter('')} className="ml-2 text-amber-600 dark:text-amber-500 hover:underline">
              Clear
            </button>
          </div>
        )}
      </div>

      <p className="mt-6 text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1">
        <ShieldAlert className="h-3 w-3" />
        Older releases (pre-v0.6.42) carry the Y34-Y93 audit pins; see the full CHANGELOG for that history.
      </p>
    </div>
  )
}
