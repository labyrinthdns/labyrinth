import { useCallback, useEffect, useMemo, useState } from 'react'
import { Download, FileJson, FileSpreadsheet, Loader2, RefreshCw, Copy, Check, FileText } from 'lucide-react'
import { api } from '@/api/client'
import type { TopEntry } from '@/api/types'
import { copyTextToClipboard } from '@/lib/utils'

type Snapshot = {
  at: string
  window: string
  topLimit: number
  stats: Record<string, unknown>
  profile: Record<string, unknown>
  topClients: TopEntry[]
  topClientsTotal: number
  topDomains: TopEntry[]
  topDomainsTotal: number
  timeseries: Record<string, unknown>[]
}

const SNAPSHOT_WINDOWS = ['5m', '15m', '1h'] as const
const TOP_LIMIT_OPTIONS = [50, 100, 250, 500, 1000] as const
type SnapshotWindow = (typeof SNAPSHOT_WINDOWS)[number]

function downloadFile(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export default function ReportsPage() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [windowSize, setWindowSize] = useState<SnapshotWindow>('1h')
  const [topLimit, setTopLimit] = useState<number>(250)
  const [topClientFilter, setTopClientFilter] = useState('')
  const [topDomainFilter, setTopDomainFilter] = useState('')
  const [loading, setLoading] = useState(false)
  const [copyDone, setCopyDone] = useState(false)
  const [error, setError] = useState('')

  const refreshSnapshot = useCallback(async () => {
    setLoading(true)
    setError('')
    setCopyDone(false)
    try {
      const [statsRes, profileRes, clientsRes, domainsRes, tsRes] = await Promise.all([
        api.stats(),
        api.systemProfile(),
        api.topClients(topLimit, 0),
        api.topDomains(topLimit, 0),
        api.timeseries(windowSize),
      ])

      setSnapshot({
        at: new Date().toISOString(),
        window: windowSize,
        topLimit,
        stats: statsRes as Record<string, unknown>,
        profile: profileRes as unknown as Record<string, unknown>,
        topClients: (clientsRes as { entries?: TopEntry[] }).entries || [],
        topClientsTotal: Number((clientsRes as { total?: number }).total || 0),
        topDomains: (domainsRes as { entries?: TopEntry[] }).entries || [],
        topDomainsTotal: Number((domainsRes as { total?: number }).total || 0),
        timeseries: (tsRes as { buckets?: Record<string, unknown>[] }).buckets || [],
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to collect snapshot')
    } finally {
      setLoading(false)
    }
  }, [windowSize, topLimit])

  useEffect(() => {
    void refreshSnapshot()
  }, [refreshSnapshot])

  const summary = useMemo(() => {
    if (!snapshot) return null
    const totalQueriesByType = Object.values((snapshot.stats.queries_by_type || {}) as Record<string, number>)
      .reduce((sum, v) => sum + Number(v || 0), 0)
    const timeseries = snapshot.timeseries || []
    const totalWindowErrors = timeseries.reduce((sum, row) => sum + Number((row.errors as number) || 0), 0)
    const peakQueries = timeseries.reduce((max, row) => Math.max(max, Number((row.queries as number) || 0)), 0)
    const peakErrors = timeseries.reduce((max, row) => Math.max(max, Number((row.errors as number) || 0)), 0)
    const incidentPoints = timeseries.filter((row) => Number((row.errors as number) || 0) > 0).length
    return {
      totalQueries: totalQueriesByType,
      topClientCount: snapshot.topClientsTotal || snapshot.topClients.length,
      topDomainCount: snapshot.topDomainsTotal || snapshot.topDomains.length,
      tsPoints: snapshot.timeseries.length,
      totalWindowErrors,
      peakQueries,
      peakErrors,
      incidentPoints,
    }
  }, [snapshot])

  const topClientsFiltered = useMemo(() => {
    const list = snapshot?.topClients || []
    const needle = topClientFilter.trim().toLowerCase()
    if (!needle) return list
    return list.filter((item) => item.key.toLowerCase().includes(needle))
  }, [snapshot, topClientFilter])

  const topDomainsFiltered = useMemo(() => {
    const list = snapshot?.topDomains || []
    const needle = topDomainFilter.trim().toLowerCase()
    if (!needle) return list
    return list.filter((item) => item.key.toLowerCase().includes(needle))
  }, [snapshot, topDomainFilter])

  const exportJSON = useCallback(() => {
    if (!snapshot) return
    const pretty = JSON.stringify(snapshot, null, 2)
    const stamp = snapshot.at.replace(/[:.]/g, '-').replace('T', '_').replace('Z', '')
    downloadFile(`labyrinth-report-${snapshot.window}-${stamp}.json`, pretty, 'application/json')
  }, [snapshot])

  const copyJSON = useCallback(async () => {
    if (!snapshot) return
    const copied = await copyTextToClipboard(JSON.stringify(snapshot, null, 2))
    if (copied) {
      setError('')
      setCopyDone(true)
      setTimeout(() => setCopyDone(false), 1200)
    } else {
      setError('Clipboard access is blocked in this browser. Copy manually from the exported output.')
    }
  }, [snapshot])

  const exportCSV = useCallback(() => {
    if (!snapshot) return

    const lines: string[] = []
    lines.push('section,key,value')

    Object.entries(snapshot.stats).forEach(([key, value]) => {
      if (typeof value !== 'object') {
        lines.push(`stats,${key},${String(value).replace(/,/g, ';')}`)
      }
    })

    lines.push('')
    lines.push('top_clients,rank,client,queries')
    snapshot.topClients.forEach((row, idx) => {
      const key = String(row.key || '')
      const count = String(row.count || 0)
      lines.push(`top_clients,${idx + 1},${key.replace(/,/g, ';')},${count}`)
    })

    lines.push('')
    lines.push('top_domains,rank,domain,queries')
    snapshot.topDomains.forEach((row, idx) => {
      const key = String(row.key || '')
      const count = String(row.count || 0)
      lines.push(`top_domains,${idx + 1},${key.replace(/,/g, ';')},${count}`)
    })

    lines.push('')
    lines.push('timeseries,time,queries,errors,avg_latency_ms')
    snapshot.timeseries.forEach((row) => {
      const ts = String((row.timestamp as string) || (row.ts as string) || '')
      const queries = String((row.queries as number) || 0)
      const errors = String((row.errors as number) || 0)
      const avgLatency = String((row.avg_latency_ms as number) || 0)
      lines.push(`timeseries,${ts},${queries},${errors},${avgLatency}`)
    })

    const stamp = snapshot.at.replace(/[:.]/g, '-').replace('T', '_').replace('Z', '')
    downloadFile(`labyrinth-report-${snapshot.window}-${stamp}.csv`, lines.join('\n'), 'text/csv;charset=utf-8')
  }, [snapshot])

  const exportMarkdown = useCallback(() => {
    if (!snapshot) return

    const lines: string[] = []
    lines.push('# Labyrinth Snapshot Report')
    lines.push('')
    lines.push(`- Generated: ${new Date(snapshot.at).toLocaleString()}`)
    lines.push(`- Window: ${snapshot.window}`)
    lines.push(`- Total queries: ${summary?.totalQueries || 0}`)
    lines.push(`- Window errors: ${summary?.totalWindowErrors || 0}`)
    lines.push(`- Peak queries per bucket: ${summary?.peakQueries || 0}`)
    lines.push(`- Peak errors per bucket: ${summary?.peakErrors || 0}`)
    lines.push('')

    lines.push('## Top Clients')
    lines.push('')
    const clients = snapshot.topClients.slice(0, 10)
    if (clients.length === 0) {
      lines.push('_No data_')
    } else {
      clients.forEach((row, idx) => {
        lines.push(`${idx + 1}. ${row.key} - ${row.count}`)
      })
    }
    lines.push('')

    lines.push('## Top Domains')
    lines.push('')
    const domains = snapshot.topDomains.slice(0, 10)
    if (domains.length === 0) {
      lines.push('_No data_')
    } else {
      domains.forEach((row, idx) => {
        lines.push(`${idx + 1}. ${row.key} - ${row.count}`)
      })
    }

    const stamp = snapshot.at.replace(/[:.]/g, '-').replace('T', '_').replace('Z', '')
    downloadFile(`labyrinth-report-${snapshot.window}-${stamp}.md`, lines.join('\n'), 'text/markdown;charset=utf-8')
  }, [snapshot, summary])

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Reports</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">Generate quick operational snapshots and export them as JSON, CSV, or Markdown.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="px-2.5 py-1 rounded-lg border border-slate-300 dark:border-slate-600 text-xs text-slate-600 dark:text-slate-300 bg-white dark:bg-slate-800">
            Generated {snapshot ? new Date(snapshot.at).toLocaleTimeString() : '-'}
          </span>
          <span className="px-2.5 py-1 rounded-lg border border-slate-300 dark:border-slate-600 text-xs text-slate-600 dark:text-slate-300 bg-white dark:bg-slate-800">
            Clients {snapshot?.topClients.length || 0}/{summary?.topClientCount || 0} / Domains {snapshot?.topDomains.length || 0}/{summary?.topDomainCount || 0}
          </span>
          <div className="inline-flex items-center gap-1 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 px-2.5 py-1">
            <span className="text-xs text-slate-500 dark:text-slate-400">Top limit</span>
            <select
              value={topLimit}
              onChange={(e) => setTopLimit(Number(e.target.value))}
              className="bg-transparent text-xs text-slate-700 dark:text-slate-200 outline-none"
            >
              {TOP_LIMIT_OPTIONS.map((value) => (
                <option key={value} value={value} className="text-slate-900">
                  {value}
                </option>
              ))}
            </select>
          </div>
          <div className="inline-flex rounded-lg border border-slate-300 dark:border-slate-600 overflow-hidden">
            {SNAPSHOT_WINDOWS.map((w) => (
              <button
                key={w}
                onClick={() => setWindowSize(w)}
                className={`px-2.5 py-1.5 text-xs font-medium ${windowSize === w ? 'bg-amber-600 text-white' : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300'}`}
              >
                {w}
              </button>
            ))}
          </div>
          <button
            onClick={() => void refreshSnapshot()}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-60"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
            Refresh Snapshot
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 space-y-4">
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Snapshot Status</h2>

        {snapshot ? (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 text-sm">
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">Generated At</p>
                <p className="mt-1 font-semibold text-slate-900 dark:text-slate-100">{new Date(snapshot.at).toLocaleString()}</p>
              </div>
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">Window</p>
                <p className="mt-1 font-semibold text-slate-900 dark:text-slate-100">{snapshot.window}</p>
              </div>
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">Total Queries</p>
                <p className="mt-1 font-semibold text-slate-900 dark:text-slate-100">{summary?.totalQueries || 0}</p>
              </div>
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">Time Series Points</p>
                <p className="mt-1 font-semibold text-slate-900 dark:text-slate-100">{summary?.tsPoints || 0}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 text-sm">
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">Window Errors</p>
                <p className="mt-1 font-semibold text-red-600 dark:text-red-400">{summary?.totalWindowErrors || 0}</p>
              </div>
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">Peak Queries / Bucket</p>
                <p className="mt-1 font-semibold text-slate-900 dark:text-slate-100">{summary?.peakQueries || 0}</p>
              </div>
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">Peak Errors / Bucket</p>
                <p className="mt-1 font-semibold text-slate-900 dark:text-slate-100">{summary?.peakErrors || 0}</p>
              </div>
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">Incident Buckets</p>
                <p className="mt-1 font-semibold text-amber-600 dark:text-amber-400">{summary?.incidentPoints || 0}</p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={exportJSON}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-sm font-medium"
              >
                <FileJson size={14} />
                Export JSON
              </button>
              <button
                onClick={copyJSON}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700"
              >
                {copyDone ? <Check size={14} /> : <Copy size={14} />}
                {copyDone ? 'Copied' : 'Copy JSON'}
              </button>
              <button
                onClick={exportCSV}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700"
              >
                <FileSpreadsheet size={14} />
                Export CSV
              </button>
              <button
                onClick={exportMarkdown}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700"
              >
                <FileText size={14} />
                Export Markdown
              </button>
              <span className="inline-flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 ml-1">
                <Download size={12} />
                Includes stats, top {snapshot.topLimit} clients/domains and {snapshot.window} time series
              </span>
            </div>

            <div className="text-xs text-slate-500 dark:text-slate-400">
              Top lists loaded: {snapshot.topClients.length} clients / {snapshot.topDomains.length} domains (total distinct: {summary?.topClientCount || 0} / {summary?.topDomainCount || 0})
            </div>
          </>
        ) : (
          <div className="text-sm text-slate-500 dark:text-slate-400">
            No snapshot yet. Click <span className="font-medium">Refresh Snapshot</span> to generate one.
          </div>
        )}
      </div>

      {snapshot && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
            <div className="flex items-center justify-between gap-2 mb-3">
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Top Clients (loaded {snapshot.topClients.length})</h2>
              <input
                value={topClientFilter}
                onChange={(e) => setTopClientFilter(e.target.value)}
                placeholder="Filter client..."
                className="h-8 w-40 rounded-md border border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-slate-900/40 px-2 text-xs text-slate-700 dark:text-slate-200"
              />
            </div>
            {topClientsFiltered.length > 0 ? (
              <div className="max-h-[460px] overflow-auto rounded-md border border-slate-200 dark:border-slate-700">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-slate-100 dark:bg-slate-900 z-10">
                    <tr className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      <th className="text-left px-2 py-2 w-8">#</th>
                      <th className="text-left px-2 py-2">Client</th>
                      <th className="text-right px-2 py-2 w-20">Queries</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {topClientsFiltered.map((row, idx) => (
                      <tr key={`${row.key}-${idx}`}>
                        <td className="px-2 py-1.5 text-xs text-slate-500">{idx + 1}</td>
                        <td className="px-2 py-1.5 text-xs font-mono text-slate-700 dark:text-slate-200 break-all">{row.key}</td>
                        <td className="px-2 py-1.5 text-right text-xs font-semibold text-slate-900 dark:text-slate-100">{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-sm text-slate-500 dark:text-slate-400">No client data in current snapshot.</div>
            )}
          </div>

          <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
            <div className="flex items-center justify-between gap-2 mb-3">
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Top Domains (loaded {snapshot.topDomains.length})</h2>
              <input
                value={topDomainFilter}
                onChange={(e) => setTopDomainFilter(e.target.value)}
                placeholder="Filter domain..."
                className="h-8 w-40 rounded-md border border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-slate-900/40 px-2 text-xs text-slate-700 dark:text-slate-200"
              />
            </div>
            {topDomainsFiltered.length > 0 ? (
              <div className="max-h-[460px] overflow-auto rounded-md border border-slate-200 dark:border-slate-700">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-slate-100 dark:bg-slate-900 z-10">
                    <tr className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      <th className="text-left px-2 py-2 w-8">#</th>
                      <th className="text-left px-2 py-2">Domain</th>
                      <th className="text-right px-2 py-2 w-20">Queries</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {topDomainsFiltered.map((row, idx) => (
                      <tr key={`${row.key}-${idx}`}>
                        <td className="px-2 py-1.5 text-xs text-slate-500">{idx + 1}</td>
                        <td className="px-2 py-1.5 text-xs text-slate-700 dark:text-slate-200 break-all">{row.key}</td>
                        <td className="px-2 py-1.5 text-right text-xs font-semibold text-slate-900 dark:text-slate-100">{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-sm text-slate-500 dark:text-slate-400">No domain data in current snapshot.</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
