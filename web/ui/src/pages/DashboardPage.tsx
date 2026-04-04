import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  AlertTriangle,
  ChevronDown,
  CheckCircle2,
  Cpu,
  HardDrive,
  MemoryStick,
  Network,
  RefreshCw,
  SlidersHorizontal,
  X,
} from 'lucide-react'
import {
  ComposedChart,
  Area,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'
import { api } from '@/api/client'
import type { StatsResponse, TimeSeriesBucket, TopEntry, SystemProfileResponse, CacheEntry, TopListResponse } from '@/api/types'
import { formatBytes, formatNumber, formatUptime, formatVersion } from '@/lib/utils'
import { useQueryStream } from '@/hooks/useWebSocket'

const QUERY_TYPE_COUNTERS = ['A', 'AAAA', 'MX', 'NS', 'PTR', 'SRV', 'CNAME', 'TXT'] as const
const TIME_WINDOWS = ['5m', '15m', '1h'] as const
type TimeWindow = (typeof TIME_WINDOWS)[number]
const REFRESH_INTERVALS = [
  { label: '5s', value: 5000 },
  { label: '15s', value: 15000 },
  { label: '30s', value: 30000 },
] as const
const CHART_SERIES_KEYS = ['queries', 'moving_avg', 'ema', 'qps', 'errors'] as const

type ChartSeriesKey = (typeof CHART_SERIES_KEYS)[number]

type VersionState = {
  current: string
  latest: string
  updateAvailable: boolean
  releaseUrl: string
}

const CHART_SERIES_LABELS: Record<ChartSeriesKey, string> = {
  queries: 'Queries',
  moving_avg: 'Moving Avg',
  ema: 'EMA',
  qps: 'QPS',
  errors: 'Errors',
}
const CHART_SERIES_STORAGE_KEY = 'labyrinth.dashboard.chart_series_visibility'
const TOP_PAGE_SIZE_OPTIONS = [25, 50, 100, 200] as const
const TOP_WINDOW_LIMIT = 2000

function movingAverage(values: number[], windowSize = 4): number[] {
  if (values.length === 0) return []
  const out: number[] = []
  for (let i = 0; i < values.length; i++) {
    const start = Math.max(0, i - windowSize + 1)
    const slice = values.slice(start, i + 1)
    out.push(slice.reduce((sum, x) => sum + x, 0) / slice.length)
  }
  return out
}

function ema(values: number[], alpha = 0.35): number[] {
  if (values.length === 0) return []
  const out: number[] = [values[0]]
  for (let i = 1; i < values.length; i++) {
    out.push(alpha * values[i] + (1 - alpha) * out[i - 1])
  }
  return out
}

function toTenSecondBucket(tsMs: number): number {
  return Math.floor(tsMs / 10_000) * 10_000
}

function defaultChartSeriesVisibility(): Record<ChartSeriesKey, boolean> {
  return {
    queries: true,
    moving_avg: true,
    ema: true,
    qps: true,
    errors: true,
  }
}

function normalizeChartSeriesVisibility(input: unknown): Record<ChartSeriesKey, boolean> {
  const defaults = defaultChartSeriesVisibility()
  if (!input || typeof input !== 'object') return defaults
  const raw = input as Record<string, unknown>
  const next = { ...defaults }
  CHART_SERIES_KEYS.forEach((key) => {
    if (typeof raw[key] === 'boolean') next[key] = raw[key] as boolean
  })
  return next
}

function MeterRow({
  icon: Icon,
  label,
  value,
  percent,
  barClass,
}: {
  icon: typeof Cpu
  label: string
  value: string
  percent: number
  barClass: string
}) {
  const clamped = Math.max(0, Math.min(100, percent))
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-[11px]">
        <span className="inline-flex items-center gap-1 text-slate-500 dark:text-slate-400">
          <Icon size={12} />
          {label}
        </span>
        <span className="font-semibold text-slate-900 dark:text-slate-100">{value}</span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
        <div className={`h-full rounded-full ${barClass}`} style={{ width: `${clamped}%` }} />
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [profile, setProfile] = useState<SystemProfileResponse | null>(null)
  const [timeseries, setTimeseries] = useState<TimeSeriesBucket[]>([])
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('15m')
  const [topClients, setTopClients] = useState<TopEntry[]>([])
  const [topDomains, setTopDomains] = useState<TopEntry[]>([])
  const [statsSnapshotAtMs, setStatsSnapshotAtMs] = useState(0)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [refreshMs, setRefreshMs] = useState(15000)
  const [showControls, setShowControls] = useState(false)
  const [showMatrixExtras, setShowMatrixExtras] = useState(false)
  const [errorThresholdPct, setErrorThresholdPct] = useState(5)
  const [latencyThresholdMs, setLatencyThresholdMs] = useState(250)
  const [clientFilter, setClientFilter] = useState('')
  const [domainFilter, setDomainFilter] = useState('')
  const [clientSortDesc, setClientSortDesc] = useState(true)
  const [domainSortDesc, setDomainSortDesc] = useState(true)
  const [clientPage, setClientPage] = useState(0)
  const [domainPage, setDomainPage] = useState(0)
  const [clientPageSize, setClientPageSize] = useState<number>(50)
  const [domainPageSize, setDomainPageSize] = useState<number>(50)
  const [clientTotal, setClientTotal] = useState(0)
  const [domainTotal, setDomainTotal] = useState(0)
  const [clientLoading, setClientLoading] = useState(false)
  const [domainLoading, setDomainLoading] = useState(false)
  const [lookupDomain, setLookupDomain] = useState<string | null>(null)
  const [lookupLoading, setLookupLoading] = useState(false)
  const [lookupError, setLookupError] = useState('')
  const [lookupResults, setLookupResults] = useState<CacheEntry[]>([])
  const [chartSeriesVisibility, setChartSeriesVisibility] = useState<Record<ChartSeriesKey, boolean>>(defaultChartSeriesVisibility())
  const [versionState, setVersionState] = useState<VersionState>({
    current: 'unknown',
    latest: 'unknown',
    updateAvailable: false,
    releaseUrl: '',
  })
  const [error, setError] = useState('')

  const { queries: streamQueries, connected: streamConnected } = useQueryStream(300)
  const clientOffset = clientPage * clientPageSize
  const domainOffset = domainPage * domainPageSize

  const fetchData = useCallback(async () => {
    setClientLoading(true)
    setDomainLoading(true)
    try {
      const [statsRes, clientsRes, domainsRes, profileRes] = await Promise.allSettled([
        api.stats(),
        api.topClients(clientPageSize, clientOffset),
        api.topDomains(domainPageSize, domainOffset),
        api.systemProfile(),
      ])

      if (statsRes.status === 'fulfilled') {
        setStats(statsRes.value as unknown as StatsResponse)
        setStatsSnapshotAtMs(Date.now())
      }
      if (clientsRes.status === 'fulfilled') {
        const data = clientsRes.value as TopListResponse
        setTopClients(data?.entries || [])
        setClientTotal(Math.min(TOP_WINDOW_LIMIT, data?.total || 0))
      }
      if (domainsRes.status === 'fulfilled') {
        const data = domainsRes.value as TopListResponse
        setTopDomains(data?.entries || [])
        setDomainTotal(Math.min(TOP_WINDOW_LIMIT, data?.total || 0))
      }
      if (profileRes.status === 'fulfilled') {
        setProfile(profileRes.value as unknown as SystemProfileResponse)
      }

      setUpdatedAt(new Date())
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch stats')
    } finally {
      setClientLoading(false)
      setDomainLoading(false)
    }
  }, [clientPageSize, clientOffset, domainPageSize, domainOffset])

  useEffect(() => {
    void fetchData()
  }, [fetchData])

  useEffect(() => {
    if (!autoRefresh) return
    const interval = setInterval(() => {
      if (document.hidden) return
      void fetchData()
    }, refreshMs)
    return () => clearInterval(interval)
  }, [autoRefresh, refreshMs, fetchData])

  useEffect(() => {
    let cancelled = false
    void Promise.allSettled([api.version(), api.checkUpdate(false)]).then(([versionRes, updateRes]) => {
      if (cancelled) return
      const current = versionRes.status === 'fulfilled' ? versionRes.value.version || 'unknown' : 'unknown'
      if (updateRes.status === 'fulfilled') {
        const u = updateRes.value
        setVersionState({
          current,
          latest: u.latest_version || current,
          updateAvailable: Boolean(u.update_available),
          releaseUrl: u.release_url || '',
        })
        return
      }
      setVersionState({
        current,
        latest: current,
        updateAvailable: false,
        releaseUrl: '',
      })
    })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    void api.config()
      .then((cfg) => {
        if (cancelled) return
        const web = (cfg?.web && typeof cfg.web === 'object') ? (cfg.web as Record<string, unknown>) : {}
        const errThreshold = Number(web.alert_error_threshold_pct)
        const latencyThreshold = Number(web.alert_latency_threshold_ms)
        if (Number.isFinite(errThreshold) && errThreshold > 0) setErrorThresholdPct(errThreshold)
        if (Number.isFinite(latencyThreshold) && latencyThreshold > 0) setLatencyThresholdMs(latencyThreshold)
      })
      .catch(() => {
        // keep defaults
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    const fetchTimeseries = async () => {
      try {
        const tsData = await api.timeseries(timeWindow) as { buckets?: TimeSeriesBucket[] }
        if (cancelled) return
        setTimeseries(tsData?.buckets || [])
      } catch {
        // keep last timeseries on transient errors
      }
    }

    void fetchTimeseries()
    const interval = setInterval(() => {
      if (!autoRefresh || document.hidden) return
      void fetchTimeseries()
    }, 1000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [timeWindow, autoRefresh])

  useEffect(() => {
    try {
      const raw = localStorage.getItem(CHART_SERIES_STORAGE_KEY)
      if (!raw) return
      setChartSeriesVisibility(normalizeChartSeriesVisibility(JSON.parse(raw)))
    } catch {
      // keep defaults
    }
  }, [])

  useEffect(() => {
    try {
      localStorage.setItem(CHART_SERIES_STORAGE_KEY, JSON.stringify(chartSeriesVisibility))
    } catch {
      // ignore storage failures
    }
  }, [chartSeriesVisibility])
  const liveWindowStats = useMemo(() => {
    const cutoff = Date.now() - 10_000
    let count = 0
    let errors = 0
    for (const q of streamQueries) {
      const ts = Date.parse(q.ts || '')
      if (!Number.isFinite(ts) || ts < cutoff) continue
      count++
      if (q.blocked || (q.rcode && q.rcode !== 'NOERROR')) errors++
    }
    return {
      queries10s: count,
      qps10s: count / 10,
      errors10s: errors,
    }
  }, [streamQueries])

  const streamDelta = useMemo(() => {
    const queryTypeDelta: Record<string, number> = {}
    const rcodeDelta: Record<string, number> = {}
    let hits = 0
    let misses = 0
    let blocked = 0
    for (const q of streamQueries) {
      const ts = Date.parse(q.ts || '')
      if (!Number.isFinite(ts) || ts <= statsSnapshotAtMs) continue
      const qt = (q.qtype || '').toUpperCase()
      if (qt) queryTypeDelta[qt] = (queryTypeDelta[qt] || 0) + 1
      const rc = (q.rcode || '').toUpperCase() || 'UNKNOWN'
      rcodeDelta[rc] = (rcodeDelta[rc] || 0) + 1
      if (q.cached) hits++
      else misses++
      if (q.blocked) blocked++
    }
    return { queryTypeDelta, rcodeDelta, hits, misses, blocked }
  }, [streamQueries, statsSnapshotAtMs])

  const statsView = useMemo<StatsResponse | null>(() => {
    if (!stats) return null
    const nextQueriesByType: Record<string, number> = { ...stats.queries_by_type }
    for (const [k, v] of Object.entries(streamDelta.queryTypeDelta)) {
      nextQueriesByType[k] = (nextQueriesByType[k] || 0) + v
    }
    const nextRcodes: Record<string, number> = { ...stats.responses_by_rcode }
    for (const [k, v] of Object.entries(streamDelta.rcodeDelta)) {
      nextRcodes[k] = (nextRcodes[k] || 0) + v
    }

    const cacheHits = (stats.cache_hits || 0) + streamDelta.hits
    const cacheMisses = (stats.cache_misses || 0) + streamDelta.misses
    const totalForHit = cacheHits + cacheMisses

    return {
      ...stats,
      queries_by_type: nextQueriesByType,
      responses_by_rcode: nextRcodes,
      cache_hits: cacheHits,
      cache_misses: cacheMisses,
      cache_hit_ratio: totalForHit > 0 ? cacheHits / totalForHit : 0,
      blocked_queries: (stats.blocked_queries || 0) + streamDelta.blocked,
    }
  }, [stats, streamDelta])

  const totalQueries = statsView?.queries_by_type
    ? Object.values(statsView.queries_by_type).reduce((a, b) => a + b, 0)
    : 0

  const chartDataRaw = useMemo(() => {
    return (timeseries || [])
      .map((b) => {
        const ts = b.timestamp || b.ts || ''
        const tsMs = Date.parse(ts)
        const bucketMs = Number.isFinite(tsMs) ? toTenSecondBucket(tsMs) : 0
        const queryCount = b.queries || 0
        return {
          ts,
          bucketMs,
          time: ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
          queries: queryCount,
          cacheHits: b.cache_hits || 0,
          cacheMisses: b.cache_misses || 0,
          errors: b.errors || 0,
          avgLatencyMs: b.avg_latency_ms || 0,
          qps: Number((queryCount / 10).toFixed(2)),
        }
      })
      .filter((row) => row.ts)
      .sort((a, b) => a.bucketMs - b.bucketMs)
  }, [timeseries])
  const trendWindow = timeWindow === '5m' ? 4 : timeWindow === '15m' ? 6 : 8
  const queryTrend = movingAverage(chartDataRaw.map((x) => x.queries), trendWindow)
  const queryEMA = ema(chartDataRaw.map((x) => x.queries), 0.35)
  const chartData = chartDataRaw.map((x, i) => ({
    ...x,
    queriesTrend: Number((queryTrend[i] || 0).toFixed(2)),
    queriesEMA: Number((queryEMA[i] || 0).toFixed(2)),
  }))

  const windowQueries = chartData.reduce((sum, row) => sum + row.queries, 0)
  const windowErrors = chartData.reduce((sum, row) => sum + row.errors, 0)
  const weightedLatency = chartData.reduce((sum, row) => sum + row.avgLatencyMs * row.queries, 0)
  const windowErrorRate = windowQueries > 0 ? (windowErrors / windowQueries) * 100 : 0
  const windowAvgLatency = windowQueries > 0 ? weightedLatency / windowQueries : 0
  const noErrorCount = statsView?.responses_by_rcode?.NOERROR || 0
  const nxdomainCount = statsView?.responses_by_rcode?.NXDOMAIN || 0
  const servfailCount = statsView?.responses_by_rcode?.SERVFAIL || 0
  const totalRcodes = Object.values(statsView?.responses_by_rcode || {}).reduce((a, b) => a + b, 0)
  const noErrorRatio = totalRcodes > 0 ? (noErrorCount / totalRcodes) * 100 : 0
  const uptimeText = statsView ? formatUptime(statsView.uptime_seconds) : '0m'
  const hasChartActivity = chartData.some((row) => row.queries > 0 || row.errors > 0 || row.qps > 0)

  const statusReasons = useMemo(() => {
    const reasons: string[] = []
    if (!statsView?.resolver_ready) reasons.push('Resolver is not ready')
    if (windowErrorRate >= errorThresholdPct) reasons.push(`Error rate high: ${windowErrorRate.toFixed(2)}% (>= ${errorThresholdPct.toFixed(2)}%)`)
    if (windowAvgLatency >= latencyThresholdMs) reasons.push(`Latency high: ${windowAvgLatency.toFixed(1)}ms (>= ${latencyThresholdMs}ms)`)
    if ((statsView?.upstream_errors || 0) > 0) reasons.push(`Upstream errors: ${formatNumber(statsView?.upstream_errors || 0)}`)
    if ((statsView?.rate_limited || 0) > 0) reasons.push(`Rate limited: ${formatNumber(statsView?.rate_limited || 0)}`)
    return reasons
  }, [statsView, windowErrorRate, windowAvgLatency, errorThresholdPct, latencyThresholdMs])

  const statusLevel = useMemo<'normal' | 'warning' | 'critical'>(() => {
    if (!statsView?.resolver_ready) return 'critical'
    if (windowErrorRate >= errorThresholdPct * 2 || windowAvgLatency >= latencyThresholdMs * 2) return 'critical'
    if (statusReasons.length > 0) return 'warning'
    return 'normal'
  }, [statsView, windowErrorRate, windowAvgLatency, errorThresholdPct, latencyThresholdMs, statusReasons])

  const qpsLive = liveWindowStats.qps10s
  const queryTypeCounts = QUERY_TYPE_COUNTERS.map((type) => ({
    type,
    count: statsView?.queries_by_type?.[type] || 0,
  }))
  const maxQueryTypeCount = Math.max(1, ...queryTypeCounts.map((item) => item.count))
  const dnssecSecure = statsView?.dnssec_secure || 0
  const dnssecInsecure = statsView?.dnssec_insecure || 0
  const dnssecBogus = statsView?.dnssec_bogus || 0
  const dnssecTotal = dnssecSecure + dnssecInsecure + dnssecBogus
  const dnssecSecureRatio = dnssecTotal > 0 ? (dnssecSecure / dnssecTotal) * 100 : 0
  const dnssecBogusRatio = dnssecTotal > 0 ? (dnssecBogus / dnssecTotal) * 100 : 0
  const responseSlices = useMemo(() => {
    const src = statsView?.responses_by_rcode || {}
    const preferred = ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED']
    const pairs = preferred
      .map((key) => ({ name: key, value: src[key] || 0 }))
      .filter((item) => item.value > 0)
    if (pairs.length > 0) return pairs
    return [{ name: 'NOERROR', value: 1 }]
  }, [statsView])

  const filteredClients = useMemo(() => {
    const key = clientFilter.trim().toLowerCase()
    const filtered = topClients.filter((entry) => !key || entry.key.toLowerCase().includes(key))
    return [...filtered].sort((a, b) => (clientSortDesc ? b.count - a.count : a.count - b.count))
  }, [topClients, clientFilter, clientSortDesc])

  const filteredDomains = useMemo(() => {
    const key = domainFilter.trim().toLowerCase()
    const filtered = topDomains.filter((entry) => !key || entry.key.toLowerCase().includes(key))
    return [...filtered].sort((a, b) => (domainSortDesc ? b.count - a.count : a.count - b.count))
  }, [topDomains, domainFilter, domainSortDesc])

  useEffect(() => {
    const maxPage = Math.max(0, Math.ceil(Math.max(0, clientTotal) / clientPageSize) - 1)
    if (clientPage > maxPage) setClientPage(maxPage)
  }, [clientTotal, clientPageSize, clientPage])

  useEffect(() => {
    const maxPage = Math.max(0, Math.ceil(Math.max(0, domainTotal) / domainPageSize) - 1)
    if (domainPage > maxPage) setDomainPage(maxPage)
  }, [domainTotal, domainPageSize, domainPage])

  const runCacheLookupForDomain = useCallback(async (domain: string) => {
    const qname = domain.endsWith('.') ? domain : `${domain}.`
    setLookupDomain(qname)
    setLookupLoading(true)
    setLookupError('')
    setLookupResults([])
    try {
      const res = await api.cacheLookup(qname, 'ALL')
      if (res && (res as Record<string, unknown>).entries) {
        const allRes = res as unknown as { entries: CacheEntry[] }
        setLookupResults(allRes.entries || [])
      } else {
        setLookupResults([res as unknown as CacheEntry])
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Lookup failed'
      if (msg.includes('404') || msg.toLowerCase().includes('not found')) {
        setLookupError(`"${qname}" is not in cache yet. Try running a query first, then check again.`)
      } else {
        setLookupError(msg)
      }
    } finally {
      setLookupLoading(false)
    }
  }, [])

  const toggleChartSeries = useCallback((key: ChartSeriesKey) => {
    setChartSeriesVisibility((prev) => {
      const activeCount = CHART_SERIES_KEYS.reduce((sum, k) => sum + (prev[k] ? 1 : 0), 0)
      if (prev[key] && activeCount <= 1) return prev
      return { ...prev, [key]: !prev[key] }
    })
  }, [])

  const primaryListenIP = profile?.network?.dns_listen_addresses?.[0] || profile?.network?.ip_addresses?.[0] || 'N/A'
  const upInterfaces = (profile?.network?.interfaces || []).filter((i) => i.flags?.includes('up')).length
  const loadAvgText = profile?.runtime?.os === 'windows'
    ? 'N/A on Windows'
    : `${(profile?.cpu?.load_avg_1m || 0).toFixed(2)} / ${(profile?.cpu?.load_avg_5m || 0).toFixed(2)} / ${(profile?.cpu?.load_avg_15m || 0).toFixed(2)}`
  const processMemText = formatBytes(profile?.memory?.process_alloc_bytes || 0)
  const freeMemText = formatBytes(profile?.memory?.system_free_bytes || 0)
  const diskUsedText = `${(profile?.disk?.used_pct || 0).toFixed(1)}%`
  const diskFreeText = formatBytes(profile?.disk?.free_bytes || 0)
  const rxTotalText = formatBytes(profile?.network?.io?.rx_bytes_total || 0)
  const txTotalText = formatBytes(profile?.network?.io?.tx_bytes_total || 0)
  const cpuLoadPct = profile?.runtime?.os === 'windows'
    ? 0
    : Math.max(0, Math.min(100, ((profile?.cpu?.load_avg_1m || 0) / Math.max(1, profile?.runtime?.cpu_cores || 1)) * 100))
  const memUsedPct = (() => {
    const total = profile?.memory?.system_total_bytes || 0
    const free = profile?.memory?.system_free_bytes || 0
    if (total <= 0) return 0
    return Math.max(0, Math.min(100, ((total - free) / total) * 100))
  })()
  const diskUsedPct = Math.max(0, Math.min(100, profile?.disk?.used_pct || 0))
  const networkRxPct = (() => {
    const rx = profile?.network?.io?.rx_bytes_total || 0
    const tx = profile?.network?.io?.tx_bytes_total || 0
    const total = rx + tx
    if (total <= 0) return 0
    return (rx / total) * 100
  })()

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Dashboard</h1>
            <button
              onClick={() => setShowControls((v) => !v)}
              className="inline-flex items-center gap-1 px-2.5 h-7 rounded-md text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
              title="Toggle dashboard controls"
            >
              <SlidersHorizontal size={12} />
              {showControls ? 'Hide Controls' : 'Controls'}
            </button>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Live resolver and system telemetry</p>
        </div>
        {versionState.updateAvailable ? (
          <a
            href={versionState.releaseUrl || '/about'}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-amber-500/40 bg-amber-500/10 text-amber-300 text-xs hover:bg-amber-500/20"
          >
            <span>Version {formatVersion(versionState.current)}</span>
            <span className="opacity-60">|</span>
            <AlertTriangle size={12} />
            <span>Update required</span>
          </a>
        ) : (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 text-xs">
            <span>Version {formatVersion(versionState.current)}</span>
            <CheckCircle2 size={12} />
          </span>
        )}
      </div>

      {showControls && (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-2">
          <button
            onClick={() => void fetchData()}
            className="inline-flex items-center gap-1.5 px-2.5 h-8 rounded-md text-xs font-semibold text-slate-900 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700"
          >
            <RefreshCw size={12} /> Refresh
          </button>
          <div className="inline-flex items-center gap-1 rounded-md px-2 h-8 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs text-slate-700 dark:text-slate-300">
            <span>Auto</span>
            <select
              value={refreshMs}
              onChange={(e) => setRefreshMs(Number(e.target.value))}
              className="bg-transparent outline-none"
            >
              {REFRESH_INTERVALS.map((item) => (
                <option key={item.value} value={item.value} className="text-slate-900">
                  {item.label}
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className={`inline-flex items-center gap-1.5 px-2.5 h-8 rounded-md text-xs font-semibold border ${
              autoRefresh
                ? 'bg-amber-500/10 text-amber-300 border-amber-500/30 hover:bg-amber-500/20'
                : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/20'
            }`}
          >
            {autoRefresh ? 'Pause Auto' : 'Resume Auto'}
          </button>
          <span className="px-2.5 h-8 inline-flex items-center rounded-md text-xs bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300">
            Updated {updatedAt ? updatedAt.toLocaleTimeString() : '-'}
          </span>
          <span className={`px-2.5 h-8 inline-flex items-center rounded-md text-xs border ${streamConnected ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30' : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700'}`}>
            WS: {streamConnected ? 'Live' : 'Offline'}
          </span>
        </div>
      )}

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200">DNS Resolver Matrix</h2>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowMatrixExtras((v) => !v)}
              className="inline-flex items-center gap-1 px-2.5 h-7 rounded-md text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700"
            >
              {showMatrixExtras ? 'Hide More' : 'Show More'}
              <ChevronDown size={12} className={`transition-transform ${showMatrixExtras ? 'rotate-180' : ''}`} />
            </button>
            {statusLevel !== 'normal' && (
              <a
                href="/operations"
                className="inline-flex items-center gap-1 text-xs font-semibold text-amber-300 hover:text-amber-200"
              >
                <AlertTriangle size={12} />
                Open Operations
              </a>
            )}
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className={`rounded-md border px-3 py-2 ${
            statusLevel === 'critical'
              ? 'border-rose-500/40 bg-rose-500/10'
              : statusLevel === 'warning'
                ? 'border-amber-500/40 bg-amber-500/10'
                : 'border-emerald-500/40 bg-emerald-500/10'
          }`}>
            <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Status</div>
            <div className={`mt-1 text-lg font-bold ${
              statusLevel === 'critical' ? 'text-rose-300' : statusLevel === 'warning' ? 'text-amber-300' : 'text-emerald-300'
            }`}>
              {statusLevel === 'critical' ? 'CRITICAL' : statusLevel === 'warning' ? 'WARNING' : 'NORMAL'}
            </div>
            <div className="mt-1 text-[10px] text-slate-500 dark:text-slate-400 line-clamp-1">
              {statusLevel === 'normal' ? 'No immediate operational alerts' : statusReasons[0]}
            </div>
          </div>
          <div className="rounded-md border border-cyan-500/30 bg-cyan-500/10 px-3 py-2">
            <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Queries/sec</div>
            <div className="mt-1 text-lg font-bold text-cyan-300">{qpsLive.toFixed(2)}</div>
            <div className="mt-1 text-[10px] text-slate-500 dark:text-slate-400">Live 10s window</div>
          </div>
          <div className={`rounded-md border px-3 py-2 ${windowErrorRate >= errorThresholdPct ? 'border-rose-500/40 bg-rose-500/10' : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60'}`}>
            <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Error Rate</div>
            <div className={`mt-1 text-lg font-bold ${windowErrorRate >= errorThresholdPct ? 'text-rose-300' : 'text-slate-900 dark:text-slate-100'}`}>{windowErrorRate.toFixed(2)}%</div>
            <div className="mt-1 text-[10px] text-slate-500 dark:text-slate-400">{formatNumber(windowErrors)} errors</div>
          </div>
          <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2">
            <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Cache Hit Ratio</div>
            <div className="mt-1 text-lg font-bold text-emerald-300">{((statsView?.cache_hit_ratio || 0) * 100).toFixed(1)}%</div>
            <div className="mt-1 text-[10px] text-slate-500 dark:text-slate-400">{formatNumber(statsView?.cache_hits || 0)} hits / {formatNumber(statsView?.cache_misses || 0)} misses</div>
          </div>
        </div>
        {showMatrixExtras && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
            <div className={`rounded-md border px-3 py-2 ${(statsView?.blocked_queries || 0) > 0 ? 'border-amber-500/40 bg-amber-500/10' : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60'}`}>
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Blocked</div>
              <div className={`mt-1 text-lg font-bold ${(statsView?.blocked_queries || 0) > 0 ? 'text-amber-300' : 'text-slate-900 dark:text-slate-100'}`}>{formatNumber(statsView?.blocked_queries || 0)}</div>
              <div className="mt-1 text-[10px] text-slate-500 dark:text-slate-400">Blocked queries total</div>
            </div>
            <div className={`rounded-md border px-3 py-2 ${(statsView?.upstream_errors || 0) > 0 ? 'border-rose-500/40 bg-rose-500/10' : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60'}`}>
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Upstream Errors</div>
              <div className={`mt-1 text-lg font-bold ${(statsView?.upstream_errors || 0) > 0 ? 'text-rose-300' : 'text-slate-900 dark:text-slate-100'}`}>{formatNumber(statsView?.upstream_errors || 0)}</div>
              <div className="mt-1 text-[10px] text-slate-500 dark:text-slate-400">Resolver upstream failures</div>
            </div>
            <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Total Queries</div>
              <div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(totalQueries)}</div>
              <div className="mt-1 text-[10px] text-slate-500 dark:text-slate-400">All-time counter</div>
            </div>
            <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Uptime</div>
              <div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{uptimeText}</div>
              <div className="mt-1 text-[10px] text-slate-500 dark:text-slate-400">Resolver process uptime</div>
            </div>
          </div>
        )}
      </div>

      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-4">
        <div className="flex items-center justify-between gap-2 mb-3">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200">Query Type Counters</h2>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">Compact view</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
          {queryTypeCounts.map((item) => (
            <div key={item.type} className="rounded-md border border-slate-200 dark:border-slate-700 px-2.5 py-2 bg-slate-50/80 dark:bg-slate-800/60">
              <div className="flex items-center justify-between gap-2">
                <div className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold">{item.type}</div>
                <div className="text-sm font-bold text-slate-900 dark:text-slate-100 font-mono">{formatNumber(item.count)}</div>
              </div>
              <div className="mt-1.5 h-1 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
                  style={{ width: `${Math.max(4, Math.min(100, (item.count / maxQueryTypeCount) * 100))}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-stretch">
        <div className="lg:col-span-2">
          <div className="relative overflow-hidden rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6 h-full lg:h-[560px] flex flex-col">
            <div className="pointer-events-none absolute -top-24 -left-24 h-64 w-64 rounded-full bg-cyan-500/10 blur-3xl" />
            <div className="pointer-events-none absolute -bottom-28 right-0 h-64 w-64 rounded-full bg-amber-500/10 blur-3xl" />

            <div className="relative flex flex-wrap items-start justify-between gap-3 mb-4">
              <div>
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-1">Traffic Stability & QPS Over Time</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Primary DNS signal: query volume, trend, QPS and failures in one frame</p>
              </div>
              <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 p-1">
                {TIME_WINDOWS.map((w) => (
                  <button
                    key={w}
                    onClick={() => setTimeWindow(w)}
                    className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-colors ${
                      timeWindow === w
                        ? 'bg-amber-500 text-slate-950'
                        : 'text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                    }`}
                  >
                    {w}
                  </button>
                ))}
              </div>
            </div>

            <div className="relative flex flex-wrap items-center gap-1.5 mb-3">
              {CHART_SERIES_KEYS.map((key) => {
                const visible = chartSeriesVisibility[key]
                return (
                  <button
                    key={key}
                    onClick={() => toggleChartSeries(key)}
                    className={`px-2 py-1 rounded-md text-[11px] border ${
                      visible
                        ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-300 dark:border-slate-600'
                    }`}
                  >
                    {visible ? 'Hide' : 'Show'} {CHART_SERIES_LABELS[key]}
                  </button>
                )
              })}
            </div>

            <div className="relative flex-1 min-h-[320px]">
              {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={chartData} margin={{ top: 10, right: 12, left: 4, bottom: 6 }}>
                    <defs>
                      <linearGradient id="queriesAreaGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.45} />
                        <stop offset="95%" stopColor="#22d3ee" stopOpacity={0.06} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.18} />
                    <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#94a3b8' }} minTickGap={20} />
                    <YAxis yAxisId="q" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#94a3b8' }} width={40} />
                    {chartSeriesVisibility.qps && (
                      <YAxis yAxisId="qps" orientation="right" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#94a3b8' }} width={42} />
                    )}
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        border: '1px solid #1e293b',
                        borderRadius: '10px',
                        color: '#e2e8f0',
                        fontSize: '12px',
                      }}
                    />
                    {chartSeriesVisibility.queries && (
                      <Area yAxisId="q" type="monotone" dataKey="queries" fill="url(#queriesAreaGrad)" stroke="#22d3ee" strokeWidth={1.8} name="Queries" />
                    )}
                    {chartSeriesVisibility.moving_avg && (
                      <Line yAxisId="q" type="linear" dataKey="queriesTrend" stroke="#f59e0b" strokeWidth={2.3} dot={false} name="Moving Avg" />
                    )}
                    {chartSeriesVisibility.ema && (
                      <Line yAxisId="q" type="linear" dataKey="queriesEMA" stroke="#60a5fa" strokeWidth={2} dot={false} strokeDasharray="4 4" name="EMA" />
                    )}
                    {chartSeriesVisibility.errors && (
                      <Line yAxisId="q" type="linear" dataKey="errors" stroke="#ef4444" strokeWidth={1.8} dot={false} name="Errors" />
                    )}
                    {chartSeriesVisibility.qps && (
                      <Line yAxisId="qps" type="linear" dataKey="qps" stroke="#14b8a6" strokeWidth={2} dot={false} name="QPS" />
                    )}
                  </ComposedChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-sm text-slate-500 dark:text-slate-400">No data yet</div>
              )}
              {!hasChartActivity && (
                <div className="absolute bottom-2 left-2 rounded-md border border-slate-300/60 dark:border-slate-600/60 bg-slate-50/90 dark:bg-slate-800/80 px-2.5 py-1 text-[11px] text-slate-600 dark:text-slate-300">
                  Waiting for live traffic...
                </div>
              )}
            </div>
          </div>

        </div>

        <div className="flex flex-col gap-4 lg:h-[560px]">
          <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6 flex-1">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4">Resolver Snapshot</h2>
            <div className="space-y-2.5 text-sm">
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">Live Queries (10s)</span><span className="font-semibold text-cyan-300">{formatNumber(liveWindowStats.queries10s)}</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">Live Errors (10s)</span><span className="font-semibold text-rose-300">{formatNumber(liveWindowStats.errors10s)}</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">Peak QPS (1m)</span><span className="font-semibold text-slate-900 dark:text-slate-100">{(profile?.traffic.last_minute_qps_peak || 0).toFixed(2)}</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">Window Latency</span><span className="font-semibold text-slate-900 dark:text-slate-100">{windowAvgLatency.toFixed(1)} ms</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">NOERROR Ratio</span><span className="font-semibold text-emerald-300">{noErrorRatio.toFixed(1)}%</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">NXDOMAIN + SERVFAIL</span><span className="font-semibold text-rose-300">{formatNumber(nxdomainCount + servfailCount)}</span></div>
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-5 flex-1">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-3">Security Snapshot</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
              <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2">
                <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">DNSSEC Secure</div>
                <div className="mt-1 text-lg font-bold text-emerald-400">{formatNumber(dnssecSecure)}</div>
              </div>
              <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2">
                <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">DNSSEC Insecure / Bogus</div>
                <div className="mt-1 text-lg font-bold text-amber-300">{formatNumber(dnssecInsecure)} / <span className="text-rose-300">{formatNumber(dnssecBogus)}</span></div>
              </div>
            </div>
            <div className="space-y-2">
              <div>
                <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 mb-1"><span>Secure Ratio</span><span className="font-semibold text-emerald-300">{dnssecSecureRatio.toFixed(1)}%</span></div>
                <div className="h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden"><div className="h-full rounded-full bg-emerald-500" style={{ width: `${Math.max(0, Math.min(100, dnssecSecureRatio))}%` }} /></div>
              </div>
              <div>
                <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 mb-1"><span>Bogus Ratio</span><span className="font-semibold text-rose-300">{dnssecBogusRatio.toFixed(1)}%</span></div>
                <div className="h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden"><div className="h-full rounded-full bg-rose-500" style={{ width: `${Math.max(0, Math.min(100, dnssecBogusRatio))}%` }} /></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4">System Glance</h2>
          <div className="space-y-3 mb-4">
            <MeterRow
              icon={Cpu}
              label="CPU"
              value={profile?.runtime?.os === 'windows' ? `load ${loadAvgText}` : `${cpuLoadPct.toFixed(1)}%`}
              percent={cpuLoadPct}
              barClass="bg-gradient-to-r from-sky-500 via-blue-500 to-indigo-500 shadow-[0_0_12px_rgba(59,130,246,0.35)]"
            />
            <MeterRow
              icon={MemoryStick}
              label="RAM"
              value={`proc ${processMemText} | free ${freeMemText}`}
              percent={memUsedPct}
              barClass="bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 shadow-[0_0_12px_rgba(16,185,129,0.35)]"
            />
            <MeterRow
              icon={HardDrive}
              label="Disk"
              value={`used ${diskUsedText} | free ${diskFreeText}`}
              percent={diskUsedPct}
              barClass="bg-gradient-to-r from-amber-500 via-orange-500 to-red-500 shadow-[0_0_12px_rgba(245,158,11,0.35)]"
            />
            <MeterRow
              icon={Network}
              label="Network"
              value={`up ${upInterfaces} | RX ${rxTotalText} / TX ${txTotalText}`}
              percent={networkRxPct}
              barClass="bg-gradient-to-r from-cyan-500 via-violet-500 to-fuchsia-500 shadow-[0_0_12px_rgba(34,211,238,0.35)]"
            />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Listen IP</div>
              <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100 break-all">{primaryListenIP}</div>
            </div>
            <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">CPU Cores</div>
              <div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(profile?.runtime?.cpu_cores || 0)}</div>
            </div>
            <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Goroutines</div>
              <div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(profile?.runtime?.goroutines || 0)}</div>
            </div>
            <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Go Runtime</div>
              <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">{profile?.runtime?.go_version || 'unknown'}</div>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4">Response Codes</h2>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={responseSlices} dataKey="value" nameKey="name" innerRadius={56} outerRadius={82} paddingAngle={2}>
                  {responseSlices.map((entry) => {
                    const color = entry.name === 'NOERROR'
                      ? '#22c55e'
                      : entry.name === 'NXDOMAIN'
                        ? '#f59e0b'
                        : entry.name === 'SERVFAIL'
                          ? '#ef4444'
                          : '#60a5fa'
                    return <Cell key={entry.name} fill={color} />
                  })}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #1e293b',
                    borderRadius: '10px',
                    color: '#e2e8f0',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 grid grid-cols-2 gap-2 text-[11px]">
            {responseSlices.map((entry) => (
              <div key={entry.name} className="rounded border border-slate-200 dark:border-slate-700 px-2 py-1.5 text-slate-600 dark:text-slate-300">
                <span className="font-semibold">{entry.name}</span>: {formatNumber(entry.value)}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200">
              Top Clients <span className="text-xs text-slate-500 dark:text-slate-400">({clientOffset + filteredClients.length}/{clientTotal || 0})</span>
            </h2>
            <div className="flex items-center gap-2">
              <input
                value={clientFilter}
                onChange={(e) => setClientFilter(e.target.value)}
                placeholder="Filter client..."
                className="h-8 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-2 text-xs text-slate-900 dark:text-slate-200 placeholder:text-slate-500"
              />
              <button onClick={() => setClientSortDesc((v) => !v)} className="h-8 px-2.5 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-xs text-slate-700 dark:text-slate-300">
                Sort {clientSortDesc ? 'High-Low' : 'Low-High'}
              </button>
            </div>
          </div>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span>Viewing top window up to {TOP_WINDOW_LIMIT}</span>
            <div className="flex items-center gap-2">
              <span>Rows</span>
              <select
                value={clientPageSize}
                onChange={(e) => {
                  setClientPageSize(Number(e.target.value))
                  setClientPage(0)
                }}
                className="h-7 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-2 text-xs text-slate-700 dark:text-slate-300"
              >
                {TOP_PAGE_SIZE_OPTIONS.map((size) => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </select>
            </div>
          </div>
          {clientLoading ? (
            <div className="flex items-center justify-center h-20 text-sm text-slate-500">Loading clients...</div>
          ) : filteredClients.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  <th className="text-left pb-2 w-8">#</th>
                  <th className="text-left pb-2">Client</th>
                  <th className="text-right pb-2">Queries</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredClients.map((entry, i) => (
                  <tr key={entry.key}>
                    <td className="py-1.5 text-xs text-slate-500">{clientOffset + i + 1}</td>
                    <td className="py-1.5 font-mono text-xs text-slate-900 dark:text-slate-200">{entry.key}</td>
                    <td className="py-1.5 text-right text-xs font-medium text-slate-900 dark:text-slate-100">{formatNumber(entry.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="flex items-center justify-center h-20 text-sm text-slate-500">No matching clients</div>
          )}
          <div className="mt-4 flex items-center justify-between">
            <button
              onClick={() => setClientPage((p) => Math.max(0, p - 1))}
              disabled={clientPage <= 0}
              className="h-8 px-3 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-xs text-slate-700 dark:text-slate-300 disabled:opacity-40"
            >
              Previous
            </button>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Page {clientPage + 1} / {Math.max(1, Math.ceil(Math.max(0, clientTotal) / clientPageSize))}
            </span>
            <button
              onClick={() => setClientPage((p) => p + 1)}
              disabled={clientOffset + clientPageSize >= clientTotal}
              className="h-8 px-3 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-xs text-slate-700 dark:text-slate-300 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200">
              Top Domains <span className="text-xs text-slate-500 dark:text-slate-400">({domainOffset + filteredDomains.length}/{domainTotal || 0})</span>
            </h2>
            <div className="flex items-center gap-2">
              <input
                value={domainFilter}
                onChange={(e) => setDomainFilter(e.target.value)}
                placeholder="Filter domain..."
                className="h-8 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-2 text-xs text-slate-900 dark:text-slate-200 placeholder:text-slate-500"
              />
              <button onClick={() => setDomainSortDesc((v) => !v)} className="h-8 px-2.5 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-xs text-slate-700 dark:text-slate-300">
                Sort {domainSortDesc ? 'High-Low' : 'Low-High'}
              </button>
            </div>
          </div>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span>Click a domain to run cache query</span>
            <div className="flex items-center gap-2">
              <span>Rows</span>
              <select
                value={domainPageSize}
                onChange={(e) => {
                  setDomainPageSize(Number(e.target.value))
                  setDomainPage(0)
                }}
                className="h-7 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-2 text-xs text-slate-700 dark:text-slate-300"
              >
                {TOP_PAGE_SIZE_OPTIONS.map((size) => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </select>
            </div>
          </div>
          {domainLoading ? (
            <div className="flex items-center justify-center h-20 text-sm text-slate-500">Loading domains...</div>
          ) : filteredDomains.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  <th className="text-left pb-2 w-8">#</th>
                  <th className="text-left pb-2">Domain</th>
                  <th className="text-right pb-2">Action</th>
                  <th className="text-right pb-2">Queries</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredDomains.map((entry, i) => (
                  <tr
                    key={entry.key}
                    className="group hover:bg-slate-50 dark:hover:bg-slate-800/40 cursor-pointer"
                    onClick={() => void runCacheLookupForDomain(entry.key)}
                  >
                    <td className="py-1.5 text-xs text-slate-500">{domainOffset + i + 1}</td>
                    <td className="py-1.5 text-xs text-slate-900 dark:text-slate-200 max-w-xs truncate" title={entry.key}>{entry.key}</td>
                    <td className="py-1.5 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation()
                          void runCacheLookupForDomain(entry.key)
                        }}
                        className="opacity-0 group-hover:opacity-100 transition-opacity h-7 px-2 rounded-md border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 text-[11px]"
                      >
                        Cache Query
                      </button>
                    </td>
                    <td className="py-1.5 text-right text-xs font-medium text-slate-900 dark:text-slate-100">{formatNumber(entry.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="flex items-center justify-center h-20 text-sm text-slate-500">No matching domains</div>
          )}
          <div className="mt-4 flex items-center justify-between">
            <button
              onClick={() => setDomainPage((p) => Math.max(0, p - 1))}
              disabled={domainPage <= 0}
              className="h-8 px-3 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-xs text-slate-700 dark:text-slate-300 disabled:opacity-40"
            >
              Previous
            </button>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Page {domainPage + 1} / {Math.max(1, Math.ceil(Math.max(0, domainTotal) / domainPageSize))}
            </span>
            <button
              onClick={() => setDomainPage((p) => p + 1)}
              disabled={domainOffset + domainPageSize >= domainTotal}
              className="h-8 px-3 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-xs text-slate-700 dark:text-slate-300 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {lookupDomain && (
        <div className="fixed inset-0 z-50 p-3 sm:p-6 md:p-10">
          <button
            aria-label="Close cache lookup modal"
            className="absolute inset-0 bg-slate-950/75 backdrop-blur-[2px]"
            onClick={() => {
              setLookupDomain(null)
              setLookupResults([])
              setLookupError('')
            }}
          />
          <div className="relative mx-auto max-w-4xl rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-5 shadow-2xl">
            <div className="flex items-center justify-between gap-2 mb-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200">Domain Cache Query</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-1">{lookupDomain}</p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setLookupDomain(null)
                  setLookupResults([])
                  setLookupError('')
                }}
                className="inline-flex items-center gap-1 px-2.5 h-8 rounded-md text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700"
              >
                <X size={12} />
                Close
              </button>
            </div>
            {lookupLoading ? (
              <div className="h-24 flex items-center justify-center text-sm text-slate-500 dark:text-slate-400">Querying cache...</div>
            ) : lookupError ? (
              <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 text-rose-300 text-sm px-3 py-2">{lookupError}</div>
            ) : lookupResults.length > 0 ? (
              <div className="space-y-3 max-h-[65vh] overflow-auto pr-1">
                {lookupResults.map((entry, idx) => (
                  <div key={`${entry.type}-${idx}`} className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 p-3">
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">{entry.type}</div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400">TTL {entry.ttl}s {entry.negative ? '• Negative' : ''}</div>
                    </div>
                    {entry.records?.length ? (
                      <div className="overflow-x-auto rounded border border-slate-200 dark:border-slate-700">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800">
                              <th className="text-left px-2 py-1.5">Type</th>
                              <th className="text-left px-2 py-1.5">TTL</th>
                              <th className="text-left px-2 py-1.5">Data</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                            {entry.records.map((rec, recIdx) => (
                              <tr key={`${rec.type}-${recIdx}`}>
                                <td className="px-2 py-1.5 text-slate-700 dark:text-slate-200">{rec.type}</td>
                                <td className="px-2 py-1.5 text-slate-500 dark:text-slate-400">{rec.ttl}s</td>
                                <td className="px-2 py-1.5 font-mono text-[11px] text-slate-700 dark:text-slate-200 break-all">{rec.rdata}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="text-xs text-slate-500 dark:text-slate-400">No record payload returned.</div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-24 flex items-center justify-center text-sm text-slate-500 dark:text-slate-400">No cache entries found.</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
