import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Cpu,
  Globe,
  HardDrive,
  MemoryStick,
  Network,
  RefreshCw,
  Shield,
  Zap,
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
import type { StatsResponse, TimeSeriesBucket, TopEntry, SystemProfileResponse } from '@/api/types'
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
type TelemetryPoint = {
  ts: string
  bucketMs: number
  time: string
  queries: number
  cacheHits: number
  cacheMisses: number
  errors: number
  avgLatencyMs: number
  qps: number
}

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

function SummaryCard({
  icon: Icon,
  label,
  value,
  sub,
  tone = 'default',
  href,
}: {
  icon: typeof Globe
  label: string
  value: string
  sub?: string
  tone?: 'default' | 'good' | 'warn' | 'danger' | 'info'
  href?: string
}) {
  const toneClasses = {
    default: 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100',
    good: 'border-emerald-300/60 dark:border-emerald-500/40 bg-emerald-50/70 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300',
    warn: 'border-amber-300/60 dark:border-amber-500/40 bg-amber-50/70 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300',
    danger: 'border-rose-300/70 dark:border-rose-500/40 bg-rose-50/80 dark:bg-rose-900/25 text-rose-700 dark:text-rose-300',
    info: 'border-cyan-300/60 dark:border-cyan-500/40 bg-cyan-50/70 dark:bg-cyan-900/20 text-cyan-700 dark:text-cyan-300',
  }[tone]

  const content = (
    <div className={`rounded-md border px-2.5 py-2 ${toneClasses}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[10px] uppercase tracking-wider opacity-75">{label}</p>
          <p className="text-sm font-semibold mt-0.5 leading-none">{value}</p>
          {sub && <p className="text-[10px] mt-1 opacity-75 line-clamp-1">{sub}</p>}
        </div>
        <Icon size={13} className="opacity-70 mt-0.5" />
      </div>
    </div>
  )

  if (href) {
    return (
      <a href={href} className="block hover:opacity-95 transition-opacity">
        {content}
      </a>
    )
  }

  return content
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
  const [clientFilter, setClientFilter] = useState('')
  const [domainFilter, setDomainFilter] = useState('')
  const [clientSortDesc, setClientSortDesc] = useState(true)
  const [domainSortDesc, setDomainSortDesc] = useState(true)
  const [chartSeriesVisibility, setChartSeriesVisibility] = useState<Record<ChartSeriesKey, boolean>>(defaultChartSeriesVisibility())
  const [versionState, setVersionState] = useState<VersionState>({
    current: 'unknown',
    latest: 'unknown',
    updateAvailable: false,
    releaseUrl: '',
  })
  const [error, setError] = useState('')

  const { queries: streamQueries, connected: streamConnected } = useQueryStream(300)

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, tsRes, clientsRes, domainsRes, profileRes] = await Promise.allSettled([
        api.stats(),
        api.timeseries(timeWindow),
        api.topClients(20),
        api.topDomains(20),
        api.systemProfile(),
      ])

      if (statsRes.status === 'fulfilled') {
        setStats(statsRes.value as unknown as StatsResponse)
        setStatsSnapshotAtMs(Date.now())
      }
      if (tsRes.status === 'fulfilled') {
        const tsData = tsRes.value as unknown as { buckets: TimeSeriesBucket[] }
        setTimeseries(tsData?.buckets || [])
      }
      if (clientsRes.status === 'fulfilled') {
        const data = clientsRes.value as unknown as { entries?: TopEntry[] }
        setTopClients(data?.entries || [])
      }
      if (domainsRes.status === 'fulfilled') {
        const data = domainsRes.value as unknown as { entries?: TopEntry[] }
        setTopDomains(data?.entries || [])
      }
      if (profileRes.status === 'fulfilled') {
        setProfile(profileRes.value as unknown as SystemProfileResponse)
      }

      setUpdatedAt(new Date())
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch stats')
    }
  }, [timeWindow])

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

  const liveChartPoint = useMemo<TelemetryPoint>(() => {
    const nowMs = Date.now()
    const bucketStartMs = toTenSecondBucket(nowMs)
    const bucketEndMs = bucketStartMs + 10_000
    let queries = 0
    let cacheHits = 0
    let cacheMisses = 0
    let errors = 0
    let totalLatencyMs = 0

    for (const q of streamQueries) {
      const tsMs = Date.parse(q.ts || '')
      if (!Number.isFinite(tsMs) || tsMs < bucketStartMs || tsMs >= bucketEndMs) continue
      queries++
      if (q.cached) cacheHits++
      else cacheMisses++
      if (q.blocked || (q.rcode && q.rcode !== 'NOERROR')) errors++
      totalLatencyMs += q.duration_ms || 0
    }

    const ts = new Date(bucketStartMs).toISOString()
    return {
      ts,
      bucketMs: bucketStartMs,
      time: new Date(bucketStartMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      queries,
      cacheHits,
      cacheMisses,
      errors,
      avgLatencyMs: queries > 0 ? totalLatencyMs / queries : 0,
      qps: Number((queries / 10).toFixed(2)),
    }
  }, [streamQueries])

  const chartDataRaw = useMemo(() => {
    const base: TelemetryPoint[] = (timeseries || [])
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

    const idx = base.findIndex((row) => row.bucketMs === liveChartPoint.bucketMs)
    if (idx >= 0) base[idx] = liveChartPoint
    else if (base.length === 0 || liveChartPoint.bucketMs >= base[base.length - 1].bucketMs) base.push(liveChartPoint)

    return base.sort((a, b) => a.bucketMs - b.bucketMs)
  }, [timeseries, liveChartPoint])
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
  const upstreamDnsRatio = (() => {
    const dns = profile?.traffic?.dns_queries_total || 0
    const upstream = profile?.traffic?.upstream_queries_total || 0
    if (dns <= 0) return 0
    return (upstream / dns) * 100
  })()

  const statusReasons = useMemo(() => {
    const reasons: string[] = []
    if (!statsView?.resolver_ready) reasons.push('Resolver is not ready')
    if ((statsView?.upstream_errors || 0) > 0) reasons.push(`Upstream errors: ${formatNumber(statsView?.upstream_errors || 0)}`)
    if (windowErrorRate >= 2) reasons.push(`Error rate high: ${windowErrorRate.toFixed(2)}%`)
    if ((statsView?.rate_limited || 0) > 0) reasons.push(`Rate limited: ${formatNumber(statsView?.rate_limited || 0)}`)
    return reasons
  }, [statsView, windowErrorRate])

  const isCritical = statusReasons.length > 0
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
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Dashboard</h1>
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
            <span className="opacity-60">|</span>
            <CheckCircle2 size={12} />
            <span>Up to date</span>
          </span>
        )}
      </div>

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

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      <div className="sticky top-2 z-20 rounded-xl border border-slate-200/80 dark:border-slate-700/80 bg-white/90 dark:bg-slate-900/90 backdrop-blur p-2.5 shadow-sm">
        <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-2.5">
          <SummaryCard
            icon={Shield}
            label="Status"
            value={isCritical ? 'ALARM' : 'NORMAL'}
            sub={isCritical ? 'Open Operations for active alert details' : 'No immediate operational alerts'}
            tone={isCritical ? 'danger' : 'good'}
            href={isCritical ? '/operations' : undefined}
          />
          <SummaryCard icon={Activity} label="Queries/sec" value={qpsLive.toFixed(2)} sub="Live 10s window" tone="info" />
          <SummaryCard icon={AlertTriangle} label="Error Rate" value={`${windowErrorRate.toFixed(2)}%`} sub={`${formatNumber(windowErrors)} errors`} tone={windowErrorRate >= 2 ? 'danger' : 'default'} />
          <SummaryCard icon={Zap} label="Cache Hit Ratio" value={`${((statsView?.cache_hit_ratio || 0) * 100).toFixed(1)}%`} sub={`${formatNumber(statsView?.cache_hits || 0)} hits / ${formatNumber(statsView?.cache_misses || 0)} misses`} tone="good" />
          <SummaryCard icon={Ban} label="Blocked" value={formatNumber(statsView?.blocked_queries || 0)} sub="Blocked queries total" tone={(statsView?.blocked_queries || 0) > 0 ? 'warn' : 'default'} />
          <SummaryCard icon={Globe} label="Upstream Errors" value={formatNumber(statsView?.upstream_errors || 0)} sub="Resolver upstream failures" tone={(statsView?.upstream_errors || 0) > 0 ? 'danger' : 'default'} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-start">
        <div className="lg:col-span-2 space-y-4">
          <div className="relative overflow-hidden rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
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

            <div className="relative h-80">
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

          <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
            <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-3">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Total Queries</div>
              <div className="mt-1 text-xl font-bold text-slate-900 dark:text-slate-100">{formatNumber(totalQueries)}</div>
            </div>
            <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-3">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Uptime</div>
              <div className="mt-1 text-xl font-bold text-slate-900 dark:text-slate-100">{uptimeText}</div>
            </div>
            <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-3">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">NOERROR Ratio</div>
              <div className="mt-1 text-xl font-bold text-emerald-400">{noErrorRatio.toFixed(1)}%</div>
            </div>
            <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-3">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Window Latency</div>
              <div className="mt-1 text-xl font-bold text-slate-900 dark:text-slate-100">{windowAvgLatency.toFixed(1)} ms</div>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4">Resolver Snapshot</h2>
            <div className="space-y-2.5 text-sm">
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">Live Queries (10s)</span><span className="font-semibold text-cyan-300">{formatNumber(liveWindowStats.queries10s)}</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">Live Errors (10s)</span><span className="font-semibold text-rose-300">{formatNumber(liveWindowStats.errors10s)}</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">Peak QPS (1m)</span><span className="font-semibold text-slate-900 dark:text-slate-100">{(profile?.traffic.last_minute_qps_peak || 0).toFixed(2)}</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">Window Queries ({timeWindow})</span><span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(windowQueries)}</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">Errors (1m)</span><span className="font-semibold text-rose-300">{formatNumber(profile?.traffic.last_minute_error_total || 0)}</span></div>
              <div className="flex items-center justify-between"><span className="text-slate-500 dark:text-slate-400">NXDOMAIN + SERVFAIL</span><span className="font-semibold text-rose-300">{formatNumber(nxdomainCount + servfailCount)}</span></div>
            </div>
            <div className="mt-4 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Latest Reason</div>
              <div className="mt-1 text-xs font-semibold text-slate-900 dark:text-slate-100 break-words">{isCritical ? statusReasons[0] : 'All clear'}</div>
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-5">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-3">System Glance</h2>
            <div className="space-y-3">
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
              <div className="text-[11px] text-slate-500 dark:text-slate-400">Listen IP: <span className="font-semibold text-slate-900 dark:text-slate-100">{primaryListenIP}</span></div>
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4">DNS Resolver Matrix</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">DNS Queries</div><div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(profile?.traffic.dns_queries_total || 0)}</div></div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Upstream Queries</div><div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(statsView?.upstream_queries || 0)}</div></div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Upstream / DNS</div><div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{upstreamDnsRatio.toFixed(1)}%</div></div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Duration Samples</div><div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(statsView?.query_duration_count || 0)}</div></div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Cache Entries</div><div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(statsView?.cache_entries || 0)}</div></div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Cache Evictions</div><div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(statsView?.cache_evictions || 0)}</div></div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Cache Pos / Neg</div><div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(statsView?.cache_positive || 0)} / {formatNumber(statsView?.cache_negative || 0)}</div></div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Rate Limited</div><div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100">{formatNumber(statsView?.rate_limited || 0)}</div></div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4">Security Snapshot</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
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

      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4">Query Type Counters</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
          {queryTypeCounts.map((item) => (
            <div key={item.type} className="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2 bg-slate-50 dark:bg-slate-800/70">
              <div className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold">{item.type}</div>
              <div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100 font-mono">{formatNumber(item.count)}</div>
              <div className="mt-1 h-1 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
                  style={{ width: `${Math.max(4, Math.min(100, (item.count / maxQueryTypeCount) * 100))}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200">
              Top Clients <span className="text-xs text-slate-500 dark:text-slate-400">({filteredClients.length}/{topClients.length})</span>
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
          {filteredClients.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  <th className="text-left pb-2 w-8">#</th>
                  <th className="text-left pb-2">Client</th>
                  <th className="text-right pb-2">Queries</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredClients.slice(0, 10).map((entry, i) => (
                  <tr key={entry.key}>
                    <td className="py-1.5 text-xs text-slate-500">{i + 1}</td>
                    <td className="py-1.5 font-mono text-xs text-slate-900 dark:text-slate-200">{entry.key}</td>
                    <td className="py-1.5 text-right text-xs font-medium text-slate-900 dark:text-slate-100">{formatNumber(entry.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="flex items-center justify-center h-20 text-sm text-slate-500">No matching clients</div>
          )}
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200">
              Top Domains <span className="text-xs text-slate-500 dark:text-slate-400">({filteredDomains.length}/{topDomains.length})</span>
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
          {filteredDomains.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  <th className="text-left pb-2 w-8">#</th>
                  <th className="text-left pb-2">Domain</th>
                  <th className="text-right pb-2">Queries</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredDomains.slice(0, 10).map((entry, i) => (
                  <tr key={entry.key}>
                    <td className="py-1.5 text-xs text-slate-500">{i + 1}</td>
                    <td className="py-1.5 text-xs text-slate-900 dark:text-slate-200 max-w-xs truncate" title={entry.key}>{entry.key}</td>
                    <td className="py-1.5 text-right text-xs font-medium text-slate-900 dark:text-slate-100">{formatNumber(entry.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="flex items-center justify-center h-20 text-sm text-slate-500">No matching domains</div>
          )}
        </div>
      </div>
    </div>
  )
}
