import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Pause, Play, Trash2, Wifi, WifiOff, Shield, Search, Download, Copy, Check, Database, Loader2 } from 'lucide-react'
import { useQueryStream } from '@/hooks/useWebSocket'
import { api } from '@/api/client'
import { copyTextToClipboard, formatDuration, formatNumber } from '@/lib/utils'
import type { QueryEntry } from '@/api/types'

const QUERY_ROW_HEIGHT = 44
const QUERY_FLUSH_MS = 200

const RCODE_STYLES: Record<string, string> = {
  NOERROR: 'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400',
  NXDOMAIN: 'bg-yellow-100 dark:bg-yellow-900/40 text-yellow-700 dark:text-yellow-400',
  SERVFAIL: 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-400',
  REFUSED: 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-400',
}

function RcodeBadge({ rcode }: { rcode: string }) {
  const style = RCODE_STYLES[rcode] || 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${style}`}>
      {rcode}
    </span>
  )
}

function CachedBadge({ cached }: { cached: boolean }) {
  if (!cached) return <span className="text-xs text-slate-400">--</span>
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400">
      Cached
    </span>
  )
}

type CacheResult = {
  status: 'idle' | 'loading' | 'found' | 'miss' | 'error'
  records?: { type: string; rdata: string; ttl: number }[]
}

function DomainCell({ domain, qtype, paused }: { domain: string; qtype: string; paused: boolean }) {
  const [showPopover, setShowPopover] = useState(false)
  const [copied, setCopied] = useState(false)
  const [cache, setCache] = useState<CacheResult>({ status: 'idle' })
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const cancelClose = useCallback(() => {
    if (closeTimerRef.current) {
      clearTimeout(closeTimerRef.current)
      closeTimerRef.current = undefined
    }
  }, [])

  const openPopover = useCallback(() => {
    cancelClose()
    setShowPopover(true)
  }, [cancelClose])

  // Delay closing so the cursor can travel from the trigger to the popover
  // without the popover unmounting in the gap between them.
  const scheduleClose = useCallback(() => {
    cancelClose()
    closeTimerRef.current = setTimeout(() => {
      setShowPopover(false)
      setCopied(false)
    }, 150)
  }, [cancelClose])

  const handleCopy = useCallback(async () => {
    const ok = await copyTextToClipboard(domain)
    if (ok) {
      setCopied(true)
      clearTimeout(copyTimerRef.current)
      copyTimerRef.current = setTimeout(() => setCopied(false), 1200)
    }
  }, [domain])

  const handleCacheLookup = useCallback(async () => {
    setCache({ status: 'loading' })
    try {
      const res = await api.cacheLookup(domain, qtype) as { records?: { type: string; rdata: string; ttl: number }[] }
      if (res?.records && res.records.length > 0) {
        setCache({ status: 'found', records: res.records })
      } else {
        setCache({ status: 'miss' })
      }
    } catch {
      setCache({ status: 'miss' })
    }
  }, [domain, qtype])

  useEffect(() => {
    return () => {
      clearTimeout(copyTimerRef.current)
      clearTimeout(closeTimerRef.current)
    }
  }, [])

  if (!paused) {
    return <span className="truncate block max-w-xs">{domain}</span>
  }

  return (
    <div
      className="relative group"
      onMouseEnter={() => { openPopover(); setCache({ status: 'idle' }) }}
      onMouseLeave={scheduleClose}
    >
      <span className="truncate block max-w-xs cursor-default">{domain}</span>
      {showPopover && (
        // Outer wrapper anchors at top-full with NO gap and provides a 4px
        // transparent padding-top bridge so the cursor doesn't fall through
        // dead space between the trigger and the visible card.
        <div
          className="absolute left-0 top-full z-50 pt-1"
          onMouseEnter={openPopover}
          onMouseLeave={scheduleClose}
        >
          <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg p-2 min-w-[180px]">
            <div className="flex items-center gap-1 mb-1">
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
              >
                {copied ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
              <button
                onClick={handleCacheLookup}
                disabled={cache.status === 'loading'}
                className="flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
              >
                {cache.status === 'loading' ? <Loader2 size={12} className="animate-spin" /> : <Database size={12} />}
                Cache Query
              </button>
            </div>
            {cache.status === 'found' && cache.records && (
              <div className="border-t border-slate-200 dark:border-slate-700 pt-1.5 mt-1 space-y-0.5">
                {cache.records.slice(0, 5).map((r, i) => (
                  <div key={i} className="text-[11px] font-mono text-slate-600 dark:text-slate-300 flex items-center gap-2">
                    <span className="text-slate-400 w-8 shrink-0">{r.type}</span>
                    <span className="truncate">{r.rdata}</span>
                    <span className="text-slate-400 ml-auto shrink-0">{r.ttl}s</span>
                  </div>
                ))}
                {cache.records.length > 5 && (
                  <p className="text-[10px] text-slate-400">+{cache.records.length - 5} more</p>
                )}
              </div>
            )}
            {cache.status === 'miss' && (
              <p className="border-t border-slate-200 dark:border-slate-700 pt-1.5 mt-1 text-[11px] text-slate-400">Not in cache</p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function QueryRow({ q, paused }: { q: QueryEntry; paused: boolean }) {
  return (
    <div
      className="grid grid-cols-[72px_88px_140px_minmax(140px,1.4fr)_64px_120px_72px_72px] gap-0 items-center px-4 text-sm border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30"
      style={{ height: QUERY_ROW_HEIGHT }}
    >
      <div className="text-xs font-mono text-slate-400 dark:text-slate-500 whitespace-nowrap truncate">
        {q.global_num ?? q.id}
      </div>
      <div className="text-xs font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">
        {new Date(q.ts).toLocaleTimeString()}
      </div>
      <div className="text-xs font-mono text-slate-600 dark:text-slate-300 whitespace-nowrap truncate">
        {q.client}
        {q.client_num != null && (
          <span className="ml-1.5 text-xs text-slate-400">#{q.client_num}</span>
        )}
      </div>
      <div className="text-slate-900 dark:text-slate-100 font-medium min-w-0">
        <DomainCell domain={q.qname} qtype={q.qtype} paused={paused} />
      </div>
      <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
        {q.qtype}
      </div>
      <div className="flex items-center gap-1.5 min-w-0">
        {q.blocked ? (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-400">
            <Shield size={10} />
            Blocked
          </span>
        ) : (
          <RcodeBadge rcode={q.rcode} />
        )}
        {q.dnssec_status === 'secure' && (
          <span title="DNSSEC Secure — signed zone, signature validated">
            <Shield size={12} className="text-green-500 dark:text-green-400" />
          </span>
        )}
        {q.dnssec_status === 'insecure' && (
          <span title="DNSSEC Insecure — unsigned zone (no DS chain). Normal for unsigned domains; not a failure.">
            <Shield size={12} className="text-slate-400 dark:text-slate-500" strokeWidth={1.5} />
          </span>
        )}
        {q.dnssec_status === 'bogus' && (
          <span title="DNSSEC Bogus — validator rejected signatures (forgery, expired, broken chain)">
            <Shield size={12} className="text-red-500 dark:text-red-400" />
          </span>
        )}
      </div>
      <div>
        <CachedBadge cached={q.cached} />
      </div>
      <div className="text-right text-xs font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">
        {formatDuration(q.duration_ms)}
      </div>
    </div>
  )
}

export default function QueriesPage() {
  const { queries, connected, paused, setPaused, clear } = useQueryStream(200, QUERY_FLUSH_MS)
  const [totalQueries, setTotalQueries] = useState(0)
  const [nowMs, setNowMs] = useState(() => Date.now())
  const [search, setSearch] = useState('')
  const [onlyBlocked, setOnlyBlocked] = useState(false)
  const [onlyErrors, setOnlyErrors] = useState(false)
  const [autoScroll, setAutoScroll] = useState(false)
  const tableRef = useRef<HTMLDivElement | null>(null)

  const liveWindowStats = useMemo(() => {
    const cutoff = nowMs - 10_000
    let count = 0
    let errors = 0
    for (const q of queries) {
      const ts = Date.parse(q.ts || '')
      if (!Number.isFinite(ts) || ts < cutoff) continue
      count++
      if (q.blocked || (q.rcode && q.rcode !== 'NOERROR')) errors++
    }
    return { queries10s: count, errors10s: errors }
  }, [queries, nowMs])

  const filteredQueries = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return queries.filter((q) => {
      if (onlyBlocked && !q.blocked) return false
      if (onlyErrors && q.rcode === 'NOERROR' && !q.blocked) return false
      if (!needle) return true
      return [
        q.client || '',
        q.qname || '',
        q.qtype || '',
        q.rcode || '',
        q.dnssec_status || '',
      ].some((v) => v.toLowerCase().includes(needle))
    })
  }, [queries, search, onlyBlocked, onlyErrors])

  useEffect(() => {
    const timer = setInterval(() => setNowMs(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])

  const rowVirtualizer = useVirtualizer({
    count: filteredQueries.length,
    getScrollElement: () => tableRef.current,
    estimateSize: () => QUERY_ROW_HEIGHT,
    overscan: 12,
  })

  useEffect(() => {
    if (!autoScroll) return
    const el = tableRef.current
    if (!el) return
    // Newest rows are rendered first, keep viewport at the top when enabled.
    el.scrollTop = 0
  }, [autoScroll, filteredQueries.length])

  useEffect(() => {
    let cancelled = false
    async function fetchTotals() {
      try {
        const data = await api.stats()
        if (cancelled) return
        const byType = (data?.queries_by_type || {}) as Record<string, number>
        const total = Object.values(byType).reduce((sum, v) => sum + (v || 0), 0)
        setTotalQueries(total)
      } catch {
        // keep last value
      }
    }
    void fetchTotals()
    const interval = setInterval(() => {
      void fetchTotals()
    }, 15000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  function exportCSV() {
    if (filteredQueries.length === 0) return
    const lines: string[] = []
    lines.push('id,time,client,domain,type,rcode,blocked,cached,dnssec_status,duration_ms')
    filteredQueries.forEach((q) => {
      const row = [
        q.global_num ?? q.id,
        new Date(q.ts).toISOString(),
        `"${(q.client || '').replace(/"/g, '""')}"`,
        `"${(q.qname || '').replace(/"/g, '""')}"`,
        q.qtype || '',
        q.rcode || '',
        q.blocked ? 'true' : 'false',
        q.cached ? 'true' : 'false',
        q.dnssec_status || '',
        q.duration_ms ?? 0,
      ]
      lines.push(row.join(','))
    })

    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `labyrinth-live-queries-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Live Queries
          </h1>
          <div className="flex items-center gap-1.5">
            {connected ? (
              <>
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" />
                </span>
                <span className="text-xs text-green-600 dark:text-green-400 font-medium">
                  Connected
                </span>
              </>
            ) : (
              <>
                <WifiOff size={14} className="text-red-500" />
                <span className="text-xs text-red-500 font-medium">
                  Disconnected
                </span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={12} className="absolute left-2 top-2.5 text-slate-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter query..."
              className="pl-7 pr-2 py-1.5 w-44 rounded-lg text-xs border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200"
            />
          </div>
          <button
            onClick={() => setOnlyBlocked((v) => !v)}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border ${onlyBlocked ? 'bg-red-100 dark:bg-red-900/30 border-red-300 dark:border-red-700 text-red-700 dark:text-red-300' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300'}`}
          >
            Blocked
          </button>
          <button
            onClick={() => setOnlyErrors((v) => !v)}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border ${onlyErrors ? 'bg-amber-100 dark:bg-amber-900/30 border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-300' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300'}`}
          >
            Errors
          </button>
          <button
            onClick={() => setAutoScroll((v) => !v)}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border ${autoScroll ? 'bg-sky-100 dark:bg-sky-900/30 border-sky-300 dark:border-sky-700 text-sky-700 dark:text-sky-300' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300'}`}
          >
            Auto-scroll
          </button>
          <button
            onClick={() => setPaused(!paused)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              paused
                ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 hover:bg-green-200 dark:hover:bg-green-900/50'
                : 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 hover:bg-amber-200 dark:hover:bg-amber-900/50'
            }`}
          >
            {paused ? <Play size={14} /> : <Pause size={14} />}
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            onClick={clear}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
          >
            <Trash2 size={14} />
            Clear
          </button>
          <button
            onClick={exportCSV}
            disabled={filteredQueries.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors disabled:opacity-50"
          >
            <Download size={14} />
            CSV
          </button>
          <div className="text-xs text-slate-400 ml-2">
            {filteredQueries.length}/{queries.length} entries
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Total Queries</p>
          <p className="mt-1 text-xl font-bold text-slate-900 dark:text-slate-100">{formatNumber(totalQueries)}</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Live Queries (10s)</p>
          <p className="mt-1 text-xl font-bold text-sky-600 dark:text-sky-400">{formatNumber(liveWindowStats.queries10s)}</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Live Errors (10s)</p>
          <p className="mt-1 text-xl font-bold text-rose-600 dark:text-rose-400">{formatNumber(liveWindowStats.errors10s)}</p>
        </div>
      </div>

      {/* Virtualized table */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
        <div className="grid grid-cols-[72px_88px_140px_minmax(140px,1.4fr)_64px_120px_72px_72px] gap-0 px-4 py-3 bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700 sticky top-0 z-10">
          {['#', 'Time', 'Client', 'Domain', 'Type', 'RCode', 'Cached', 'Duration'].map((label, i) => (
            <div
              key={label}
              className={`text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider ${i === 7 ? 'text-right' : 'text-left'}`}
            >
              {label}
            </div>
          ))}
        </div>
        <div ref={tableRef} className="overflow-x-auto max-h-[calc(100vh-220px)] overflow-y-auto">
          {filteredQueries.length === 0 ? (
            <div className="px-4 py-12 text-center text-slate-400 dark:text-slate-500">
              <div className="flex flex-col items-center gap-2">
                <Wifi size={24} className="text-slate-300 dark:text-slate-600" />
                <p>No matching queries...</p>
                <p className="text-xs">
                  Try clearing filters or wait for new events
                </p>
              </div>
            </div>
          ) : (
            <div
              className="relative w-full"
              style={{ height: `${rowVirtualizer.getTotalSize()}px` }}
            >
              {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                const q = filteredQueries[virtualRow.index]
                return (
                  <div
                    key={q.id}
                    className="absolute top-0 left-0 w-full"
                    style={{
                      height: `${virtualRow.size}px`,
                      transform: `translateY(${virtualRow.start}px)`,
                    }}
                  >
                    <QueryRow q={q} paused={paused} />
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
