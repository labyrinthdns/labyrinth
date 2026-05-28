import { useMemo, useState } from 'react'
import { BookOpen, ExternalLink, Search, Download, FileJson, FileText, ArrowUpDown } from 'lucide-react'
import { COMPLIANCE_ENTRIES, CATEGORY_LABELS, type ComplianceCategory } from '@/data/rfcCompliance'
import { buildComplianceCSV, buildComplianceJSON } from '@/data/complianceExport'

// UI-M5.1 — RFC compliance matrix as its own page. Where AboutPage's
// matrix is a passing reference for someone reading the About blurb,
// `/compliance` is the auditor's destination: full filter, category
// pivot, sort by RFC number / since-version / category, and CSV/JSON
// export so the result can leave the browser.

function rfcDatatrackerURL(rfc: string): string {
  const m = rfc.match(/RFC\s+(\d+)/)
  if (!m) return ''
  return `https://datatracker.ietf.org/doc/html/rfc${m[1]}`
}

const CATEGORY_TINT: Record<ComplianceCategory, string> = {
  core: 'border-slate-400/40 bg-slate-500/10 text-slate-700 dark:text-slate-300',
  dnssec: 'border-emerald-400/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  'nsec-aggressive': 'border-teal-400/40 bg-teal-500/10 text-teal-700 dark:text-teal-300',
  edns: 'border-sky-400/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  'transport-security': 'border-indigo-400/40 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
  'special-use': 'border-violet-400/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  'error-signalling': 'border-amber-400/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  caching: 'border-cyan-400/40 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300',
  blocking: 'border-rose-400/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
}

type SortKey = 'rfc' | 'since' | 'category'

// rfcNumeric extracts the numeric RFC number for sort ordering.
// "RFC 1034" → 1034. Sub-RFCs (with section) tie-break alphabetically.
function rfcNumeric(rfc: string): number {
  const m = rfc.match(/RFC\s+(\d+)/)
  return m ? parseInt(m[1], 10) : 0
}

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

export default function CompliancePage() {
  const [query, setQuery] = useState('')
  const [activeCategory, setActiveCategory] = useState<ComplianceCategory | 'all'>('all')
  const [sort, setSort] = useState<SortKey>('rfc')

  const categoriesPresent = useMemo(() => {
    const set = new Set<ComplianceCategory>()
    for (const e of COMPLIANCE_ENTRIES) set.add(e.category)
    return Array.from(set)
  }, [])

  const categoryCounts = useMemo(() => {
    const counts: Partial<Record<ComplianceCategory, number>> = {}
    for (const e of COMPLIANCE_ENTRIES) counts[e.category] = (counts[e.category] ?? 0) + 1
    return counts
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const base = COMPLIANCE_ENTRIES.filter((e) => {
      if (activeCategory !== 'all' && e.category !== activeCategory) return false
      if (!q) return true
      const hay = `${e.rfc} ${e.section ?? ''} ${e.title} ${e.summary} ${e.since ?? ''}`.toLowerCase()
      return hay.includes(q)
    })
    const sorted = [...base]
    switch (sort) {
      case 'rfc':
        sorted.sort((a, b) => {
          const d = rfcNumeric(a.rfc) - rfcNumeric(b.rfc)
          if (d !== 0) return d
          return (a.section ?? '').localeCompare(b.section ?? '')
        })
        break
      case 'since':
        // Entries without `since` are core (pre-v0.1) — sort them last
        // so the operator sees the recently-added RFCs first.
        sorted.sort((a, b) => {
          const av = a.since ?? ''
          const bv = b.since ?? ''
          if (av === '' && bv === '') return 0
          if (av === '') return 1
          if (bv === '') return -1
          return bv.localeCompare(av) // newest first
        })
        break
      case 'category':
        sorted.sort((a, b) => {
          const d = a.category.localeCompare(b.category)
          if (d !== 0) return d
          return rfcNumeric(a.rfc) - rfcNumeric(b.rfc)
        })
        break
    }
    return sorted
  }, [query, activeCategory, sort])

  return (
    <div className="px-4 sm:px-6 lg:px-8 py-6 max-w-7xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-white flex items-center gap-2">
          <BookOpen className="h-6 w-6 text-amber-500" />
          RFC Compliance Matrix
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Standards Labyrinth implements, grouped by capability. The full list lives in <code className="font-mono text-xs">web/ui/src/data/rfcCompliance.ts</code> and is the single source of truth for the matrix shown on About and exported here. {COMPLIANCE_ENTRIES.length} entries total.
        </p>
      </div>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 mb-4 space-y-3">
        <div className="flex flex-col lg:flex-row gap-2">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by RFC number, section, title, summary, or since version…"
              className="w-full h-9 pl-9 pr-3 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400"
            />
          </div>

          <div className="flex items-center gap-2">
            <label className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300">
              <ArrowUpDown className="h-3.5 w-3.5 opacity-60" />
              <select
                value={sort}
                onChange={(e) => setSort(e.target.value as SortKey)}
                className="bg-transparent outline-none text-xs"
              >
                <option value="rfc">RFC number</option>
                <option value="since">Since version (newest first)</option>
                <option value="category">Category</option>
              </select>
            </label>
            <button
              type="button"
              onClick={() => {
                const today = new Date().toISOString().slice(0, 10)
                triggerDownload(buildComplianceCSV(), `labyrinth-compliance-${today}.csv`, 'text/csv;charset=utf-8')
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              title="Download the full matrix as RFC 4180 CSV"
            >
              <FileText className="h-3.5 w-3.5" />
              CSV
              <Download className="h-3 w-3 opacity-60" />
            </button>
            <button
              type="button"
              onClick={() => {
                const today = new Date().toISOString().slice(0, 10)
                triggerDownload(buildComplianceJSON(), `labyrinth-compliance-${today}.json`, 'application/json')
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              title="Download the matrix as structured JSON (includes category labels)"
            >
              <FileJson className="h-3.5 w-3.5" />
              JSON
              <Download className="h-3 w-3 opacity-60" />
            </button>
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setActiveCategory('all')}
            className={`px-2.5 py-1 rounded-full text-[11px] border transition ${
              activeCategory === 'all'
                ? 'border-slate-700 dark:border-slate-300 bg-slate-700 dark:bg-slate-300 text-white dark:text-slate-900'
                : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700'
            }`}
          >
            All ({COMPLIANCE_ENTRIES.length})
          </button>
          {categoriesPresent.map((cat) => (
            <button
              type="button"
              key={cat}
              onClick={() => setActiveCategory(cat)}
              className={`px-2.5 py-1 rounded-full text-[11px] border transition ${
                activeCategory === cat
                  ? 'border-slate-700 dark:border-slate-300 bg-slate-700 dark:bg-slate-300 text-white dark:text-slate-900'
                  : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700'
              }`}
            >
              {CATEGORY_LABELS[cat]} ({categoryCounts[cat]})
            </button>
          ))}
        </div>

        <div className="text-xs text-slate-500 dark:text-slate-400">
          {filtered.length} / {COMPLIANCE_ENTRIES.length} shown
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="text-center py-12 text-sm text-slate-500 dark:text-slate-400">
          No entries match the current filter.
          <button onClick={() => { setQuery(''); setActiveCategory('all') }} className="ml-2 text-amber-600 dark:text-amber-500 hover:underline">
            Clear
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {filtered.map((e) => {
            const tint = CATEGORY_TINT[e.category]
            const url = rfcDatatrackerURL(e.rfc)
            return (
              <div
                key={`${e.rfc}-${e.section ?? ''}-${e.title}`}
                className="rounded-md border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-3 space-y-1.5"
              >
                <div className="flex items-baseline justify-between gap-2 flex-wrap">
                  <a
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-amber-700 dark:text-amber-300 hover:underline"
                  >
                    {e.rfc}{e.section ? ` ${e.section}` : ''}
                    <ExternalLink size={10} />
                  </a>
                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-mono uppercase border ${tint}`}>
                    {CATEGORY_LABELS[e.category]}
                  </span>
                </div>
                <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 leading-snug">
                  {e.title}
                </div>
                <div className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                  {e.summary}
                </div>
                {e.since && (
                  <div className="text-[10px] text-slate-500 dark:text-slate-500 font-mono pt-1">
                    since {e.since}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
