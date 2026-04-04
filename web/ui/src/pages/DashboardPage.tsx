import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import {
  Globe,
  Zap,
  Database,
  Clock,
  AlertTriangle,
  Users,
  Shield,
  Server,
  Cpu,
  HardDrive,
  Network,
  Activity,
  MemoryStick,
  RefreshCw,
  Pause,
  Play,
  GripVertical,
  EyeOff,
  Eye,
  LayoutGrid,
} from 'lucide-react'
import {
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  CartesianGrid,
} from 'recharts'
import { api } from '@/api/client'
import type { StatsResponse, TimeSeriesBucket, TopEntry, SystemProfileResponse } from '@/api/types'
import { formatNumber, formatUptime, formatBytes, formatVersion } from '@/lib/utils'
import { useQueryStream } from '@/hooks/useWebSocket'

const QUERY_TYPE_COUNTERS = ['A', 'AAAA', 'MX', 'NS', 'PTR', 'SRV', 'CNAME', 'TXT'] as const
const TIME_WINDOWS = ['5m', '15m', '1h'] as const
type TimeWindow = (typeof TIME_WINDOWS)[number]
type ThroughputPoint = { time: string; rxBps: number; txBps: number }
const REFRESH_INTERVALS = [
  { label: '5s', value: 5000 },
  { label: '15s', value: 15000 },
  { label: '30s', value: 30000 },
] as const
const CHART_SERIES_KEYS = ['queries', 'moving_avg', 'ema', 'qps', 'errors'] as const
type ChartSeriesKey = (typeof CHART_SERIES_KEYS)[number]
const CHART_SERIES_LABELS: Record<ChartSeriesKey, string> = {
  queries: 'Queries',
  moving_avg: 'Moving Avg',
  ema: 'EMA',
  qps: 'QPS',
  errors: 'Errors',
}
const CHART_SERIES_STORAGE_KEY = 'labyrinth.dashboard.chart_series_visibility'
const DASHBOARD_SECTION_IDS = ['query_types', 'network_security', 'top_lists'] as const
type DashboardSectionID = (typeof DASHBOARD_SECTION_IDS)[number]
const DEFAULT_SECTION_ORDER: DashboardSectionID[] = ['query_types', 'network_security', 'top_lists']
const SECTION_LABELS: Record<DashboardSectionID, string> = {
  query_types: 'Query Type Counters',
  network_security: 'Network & Security',
  top_lists: 'Top Clients & Domains',
}

const RCODE_COLORS: Record<string, string> = {
  NOERROR: '#22c55e',
  NXDOMAIN: '#eab308',
  SERVFAIL: '#ef4444',
  REFUSED: '#f97316',
  FORMERR: '#a855f7',
}

function movingAverage(values: number[], windowSize = 4): number[] {
  if (values.length === 0) return []
  const out: number[] = []
  for (let i = 0; i < values.length; i++) {
    const start = Math.max(0, i - windowSize + 1)
    const slice = values.slice(start, i + 1)
    const avg = slice.reduce((sum, x) => sum + x, 0) / slice.length
    out.push(avg)
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

function normalizeSectionOrder(input: string[] | undefined): DashboardSectionID[] {
  const known = new Set(DASHBOARD_SECTION_IDS)
  const unique: DashboardSectionID[] = []
  for (const raw of input || []) {
    const id = raw as DashboardSectionID
    if (!known.has(id) || unique.includes(id)) continue
    unique.push(id)
  }
  for (const id of DEFAULT_SECTION_ORDER) {
    if (!unique.includes(id)) unique.push(id)
  }
  return unique
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
  if (!input || typeof input !== 'object') {
    return defaults
  }
  const raw = input as Record<string, unknown>
  const next = { ...defaults }
  CHART_SERIES_KEYS.forEach((key) => {
    if (typeof raw[key] === 'boolean') {
      next[key] = raw[key] as boolean
    }
  })
  return next
}

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  iconColor,
}: {
  icon: typeof Globe
  label: string
  value: string
  sub?: string
  iconColor: string
}) {
  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
          <p className="text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1">
            {value}
          </p>
          {sub && (
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{sub}</p>
          )}
        </div>
        <div className={`flex items-center justify-center w-12 h-12 rounded-lg ${iconColor}`}>
          <Icon size={24} />
        </div>
      </div>
    </div>
  )
}

function UsageBar({
  label,
  value,
  percent,
  colorClass,
}: {
  label: string
  value: string
  percent: number
  colorClass: string
}) {
  const clamped = Math.max(0, Math.min(percent, 100))
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-500 dark:text-slate-400">{label}</span>
        <span className="font-semibold text-slate-900 dark:text-slate-100">{value}</span>
      </div>
      <div className="h-2 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${colorClass}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [profile, setProfile] = useState<SystemProfileResponse | null>(null)
  const [cpuUsagePct, setCPUUsagePct] = useState(0)
  const [timeseries, setTimeseries] = useState<TimeSeriesBucket[]>([])
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('15m')
  const [topClients, setTopClients] = useState<TopEntry[]>([])
  const [topDomains, setTopDomains] = useState<TopEntry[]>([])
  const [statsSnapshotAtMs, setStatsSnapshotAtMs] = useState(0)
  const [networkHistory, setNetworkHistory] = useState<ThroughputPoint[]>([])
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [refreshMs, setRefreshMs] = useState(15000)
  const [clientFilter, setClientFilter] = useState('')
  const [domainFilter, setDomainFilter] = useState('')
  const [clientSortDesc, setClientSortDesc] = useState(true)
  const [domainSortDesc, setDomainSortDesc] = useState(true)
  const [sectionOrder, setSectionOrder] = useState<DashboardSectionID[]>(DEFAULT_SECTION_ORDER)
  const [hiddenSections, setHiddenSections] = useState<DashboardSectionID[]>([])
  const [draggingSection, setDraggingSection] = useState<DashboardSectionID | null>(null)
  const [layoutPanelOpen, setLayoutPanelOpen] = useState(false)
  const [layoutStatus, setLayoutStatus] = useState('')
  const [chartSeriesVisibility, setChartSeriesVisibility] = useState<Record<ChartSeriesKey, boolean>>(defaultChartSeriesVisibility())
  const [error, setError] = useState('')

  const cpuSampleRef = useRef<{ sec: number; atMs: number } | null>(null)
  const netSampleRef = useRef<{ rx: number; tx: number; atMs: number } | null>(null)
  const layoutHydratedRef = useRef(false)
  const {
    queries: streamQueries,
    connected: streamConnected,
    paused: streamPaused,
    setPaused: setStreamPaused,
  } = useQueryStream(400)
  const recentQueries = useMemo(() => streamQueries.slice(0, 10), [streamQueries])

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
        const p = profileRes.value as unknown as SystemProfileResponse
        setProfile(p)

        const nowMs = Date.now()
        const secTotal = p?.cpu?.process_cpu_seconds_total || 0
        const prev = cpuSampleRef.current
        if (prev && secTotal >= prev.sec) {
          const dSec = secTotal - prev.sec
          const dWall = (nowMs - prev.atMs) / 1000
          if (dWall > 0) {
            const pct = (dSec / dWall) * 100
            setCPUUsagePct(Math.max(0, Math.min(100, pct)))
          }
        }
        cpuSampleRef.current = { sec: secTotal, atMs: nowMs }

        const rxTotal = p.network?.io?.rx_bytes_total || 0
        const txTotal = p.network?.io?.tx_bytes_total || 0
        const prevNet = netSampleRef.current
        if (prevNet && rxTotal >= prevNet.rx && txTotal >= prevNet.tx) {
          const dWall = (nowMs - prevNet.atMs) / 1000
          if (dWall > 0) {
            const rxBps = (rxTotal - prevNet.rx) / dWall
            const txBps = (txTotal - prevNet.tx) / dWall
            setNetworkHistory((prevSeries) => [
              ...prevSeries.slice(-23),
              {
                time: new Date(nowMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
                rxBps,
                txBps,
              },
            ])
          }
        }
        netSampleRef.current = { rx: rxTotal, tx: txTotal, atMs: nowMs }
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

  const liveWindowStats = useMemo(() => {
    const cutoff = Date.now() - 10_000
    let count = 0
    let errors = 0
    for (const q of streamQueries) {
      const ts = Date.parse(q.ts || '')
      if (!Number.isFinite(ts) || ts < cutoff) continue
      count++
      if (q.blocked || (q.rcode && q.rcode !== 'NOERROR')) {
        errors++
      }
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
    let total = 0
    for (const q of streamQueries) {
      const ts = Date.parse(q.ts || '')
      if (!Number.isFinite(ts) || ts <= statsSnapshotAtMs) continue
      total++
      const qt = (q.qtype || '').toUpperCase()
      if (qt) queryTypeDelta[qt] = (queryTypeDelta[qt] || 0) + 1
      const rc = (q.rcode || '').toUpperCase() || 'UNKNOWN'
      rcodeDelta[rc] = (rcodeDelta[rc] || 0) + 1
      if (q.cached) hits++
      else misses++
      if (q.blocked) blocked++
    }
    return { queryTypeDelta, rcodeDelta, hits, misses, blocked, total }
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
    const cacheHitRatio = totalForHit > 0 ? cacheHits / totalForHit : 0

    return {
      ...stats,
      queries_by_type: nextQueriesByType,
      responses_by_rcode: nextRcodes,
      cache_hits: cacheHits,
      cache_misses: cacheMisses,
      cache_hit_ratio: cacheHitRatio,
      blocked_queries: (stats.blocked_queries || 0) + streamDelta.blocked,
    }
  }, [stats, streamDelta])

  const totalQueries = statsView?.queries_by_type
    ? Object.values(statsView.queries_by_type).reduce((a, b) => a + b, 0)
    : 0

  const rcodeData = statsView?.responses_by_rcode
    ? Object.entries(statsView.responses_by_rcode)
        .filter(([, count]) => count > 0)
        .map(([name, value]) => ({ name, value }))
    : []

  const chartDataRaw = (timeseries || [])
    .map((b) => {
      const ts = b.timestamp || b.ts || ''
      const queryCount = b.queries || 0
      const cacheHits = b.cache_hits || 0
      const cacheMisses = b.cache_misses || 0
      return {
        ts,
        time: ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
        queries: queryCount,
        cacheHits,
        cacheMisses,
        errors: b.errors || 0,
        avgLatencyMs: b.avg_latency_ms || 0,
        qps: Number((queryCount / 10).toFixed(2)),
        hitRate: queryCount > 0 ? (cacheHits / queryCount) * 100 : 0,
      }
    })
    .sort((a, b) => a.ts.localeCompare(b.ts))

  const trendWindow = timeWindow === '5m' ? 4 : timeWindow === '15m' ? 6 : 8
  const queryTrend = movingAverage(chartDataRaw.map((x) => x.queries), trendWindow)
  const queryEMA = ema(chartDataRaw.map((x) => x.queries), 0.35)
  const chartData = chartDataRaw.map((x, i) => ({
    ...x,
    queriesTrend: Number(queryTrend[i].toFixed(2)),
    queriesEMA: Number(queryEMA[i].toFixed(2)),
  }))

  const queryTypeCounts = QUERY_TYPE_COUNTERS.map((type) => ({
    type,
    count: statsView?.queries_by_type?.[type] || 0,
  }))

  const memTotal = profile?.memory?.system_total_bytes || 0
  const memUsed = profile?.memory?.process_alloc_bytes || 0
  const memPct = memTotal > 0 ? (memUsed / memTotal) * 100 : 0
  const memValue = memTotal > 0
    ? `${formatBytes(memUsed)} (process)`
    : `${formatBytes(memUsed)} (process)`
  const diskPct = profile?.disk?.used_pct || 0
  const cpuHostSharePct = profile?.runtime.cpu_cores ? cpuUsagePct / Math.max(1, profile.runtime.cpu_cores) : 0
  const windowQueries = chartData.reduce((sum, row) => sum + row.queries, 0)
  const windowErrors = chartData.reduce((sum, row) => sum + row.errors, 0)
  const windowHits = chartData.reduce((sum, row) => sum + row.cacheHits, 0)
  const weightedLatency = chartData.reduce((sum, row) => sum + row.avgLatencyMs * row.queries, 0)
  const windowErrorRate = windowQueries > 0 ? (windowErrors / windowQueries) * 100 : 0
  const windowHitRate = windowQueries > 0 ? (windowHits / windowQueries) * 100 : 0
  const windowAvgLatency = windowQueries > 0 ? (weightedLatency / windowQueries) : 0
  const listenIPs = profile?.network.dns_listen_addresses?.length
    ? profile.network.dns_listen_addresses
    : (profile?.network.ip_addresses || [])
  const upInterfaces = (profile?.network.interfaces || []).filter((iface) => iface.flags?.includes('up')).length
  const securityTotalDNSSEC = (statsView?.dnssec_secure || 0) + (statsView?.dnssec_insecure || 0) + (statsView?.dnssec_bogus || 0)
  const dnssecSecureRatio = securityTotalDNSSEC > 0 ? ((statsView?.dnssec_secure || 0) / securityTotalDNSSEC) * 100 : 0
  const dnssecBogusRatio = securityTotalDNSSEC > 0 ? ((statsView?.dnssec_bogus || 0) / securityTotalDNSSEC) * 100 : 0
  const securityNeedsAttention = Boolean((statsView?.upstream_errors || 0) > 0 || (statsView?.rate_limited || 0) > 0 || (statsView?.dnssec_bogus || 0) > 0)
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
    let cancelled = false
    void api.dashboardLayout()
      .then((res) => {
        if (cancelled) return
        setSectionOrder(normalizeSectionOrder(res.panel_order))
        const hidden = normalizeSectionOrder(res.hidden_panels || []).filter((id) => (res.hidden_panels || []).includes(id))
        setHiddenSections(hidden)
      })
      .catch(() => {
        if (!cancelled) {
          setSectionOrder(DEFAULT_SECTION_ORDER)
          setHiddenSections([])
        }
      })
      .finally(() => {
        if (!cancelled) {
          layoutHydratedRef.current = true
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (!layoutHydratedRef.current) return
    const timer = window.setTimeout(() => {
      void api.saveDashboardLayout({
        panel_order: sectionOrder,
        hidden_panels: hiddenSections,
      }).then(() => {
        setLayoutStatus('Layout saved to YAML')
        window.setTimeout(() => setLayoutStatus(''), 1800)
      }).catch(() => {
        setLayoutStatus('Layout save failed')
        window.setTimeout(() => setLayoutStatus(''), 2200)
      })
    }, 350)
    return () => window.clearTimeout(timer)
  }, [sectionOrder, hiddenSections])

  useEffect(() => {
    try {
      const raw = localStorage.getItem(CHART_SERIES_STORAGE_KEY)
      if (!raw) return
      const parsed = JSON.parse(raw) as unknown
      setChartSeriesVisibility(normalizeChartSeriesVisibility(parsed))
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

  const moveSection = useCallback((source: DashboardSectionID, target: DashboardSectionID) => {
    setSectionOrder((prev) => {
      if (source === target) return prev
      const next = [...prev]
      const from = next.indexOf(source)
      const to = next.indexOf(target)
      if (from < 0 || to < 0) return prev
      next.splice(from, 1)
      next.splice(to, 0, source)
      return next
    })
  }, [])

  const hideSection = useCallback((id: DashboardSectionID) => {
    setHiddenSections((prev) => (prev.includes(id) ? prev : [...prev, id]))
  }, [])

  const showSection = useCallback((id: DashboardSectionID) => {
    setHiddenSections((prev) => prev.filter((v) => v !== id))
  }, [])

  const toggleChartSeries = useCallback((key: ChartSeriesKey) => {
    setChartSeriesVisibility((prev) => {
      const activeCount = CHART_SERIES_KEYS.reduce((sum, k) => sum + (prev[k] ? 1 : 0), 0)
      if (prev[key] && activeCount <= 1) return prev
      return { ...prev, [key]: !prev[key] }
    })
  }, [])

  const visibleSections = sectionOrder.filter((id) => !hiddenSections.includes(id))

  const renderSection = useCallback((id: DashboardSectionID) => {
    if (id === 'query_types') {
      return (
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4">
            Query Type Counters
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
            {queryTypeCounts.map((item) => (
              <div
                key={item.type}
                className="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2 bg-slate-50 dark:bg-slate-800/70"
              >
                <div className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold">
                  {item.type}
                </div>
                <div className="mt-1 text-lg font-bold text-slate-900 dark:text-slate-100 font-mono">
                  {formatNumber(item.count)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )
    }

    if (id === 'network_security') {
      return (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="xl:col-span-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
              <div>
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200">Network Interfaces</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">{upInterfaces} up / {profile?.network.interfaces?.length || 0} total interfaces</p>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {listenIPs.slice(0, 4).map((ip) => (
                  <span key={ip} className="px-2 py-0.5 rounded-full text-[10px] bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300">{ip}</span>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    <th className="text-left pb-2">Name</th>
                    <th className="text-center pb-2">State</th>
                    <th className="text-right pb-2">MTU</th>
                    <th className="text-right pb-2">Addrs</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  {(profile?.network.interfaces || []).slice(0, 8).map((iface) => {
                    const up = Boolean(iface.flags?.includes('up'))
                    return (
                      <tr key={iface.name}>
                        <td className="py-2 text-slate-900 dark:text-slate-200">{iface.name}</td>
                        <td className="py-2 text-center">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${up ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700'}`}>
                            {up ? 'UP' : 'DOWN'}
                          </span>
                        </td>
                        <td className="py-2 text-right text-slate-700 dark:text-slate-300">{formatNumber(iface.mtu)}</td>
                        <td className="py-2 text-right text-slate-700 dark:text-slate-300">{formatNumber(iface.addrs?.length || 0)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4 inline-flex items-center gap-2">
              <Shield size={15} className="text-amber-400" /> Security Snapshot
            </h2>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">Status</span><span className={`font-semibold ${securityNeedsAttention ? 'text-amber-300' : 'text-emerald-300'}`}>{securityNeedsAttention ? 'Needs Attention' : 'Healthy'}</span></div>
              <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">Blocked Queries</span><span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(statsView?.blocked_queries || 0)}</span></div>
              <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">Rate Limited</span><span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(statsView?.rate_limited || 0)}</span></div>
              <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">Upstream Errors</span><span className="font-semibold text-rose-300">{formatNumber(statsView?.upstream_errors || 0)}</span></div>
              <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">DNSSEC Secure</span><span className="font-semibold text-emerald-300">{formatNumber(statsView?.dnssec_secure || 0)}</span></div>
              <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">DNSSEC Insecure</span><span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(statsView?.dnssec_insecure || 0)}</span></div>
              <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">DNSSEC Bogus</span><span className="font-semibold text-rose-300">{formatNumber(statsView?.dnssec_bogus || 0)}</span></div>
              <div className="pt-2">
                <div className="flex justify-between text-xs text-slate-500 dark:text-slate-400 mb-1"><span>DNSSEC Secure Ratio</span><span>{dnssecSecureRatio.toFixed(1)}%</span></div>
                <div className="h-2 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden"><div className="h-full bg-emerald-500" style={{ width: `${Math.max(0, Math.min(100, dnssecSecureRatio))}%` }} /></div>
              </div>
              <div>
                <div className="flex justify-between text-xs text-slate-500 dark:text-slate-400 mb-1"><span>DNSSEC Bogus Ratio</span><span>{dnssecBogusRatio.toFixed(1)}%</span></div>
                <div className="h-2 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden"><div className="h-full bg-rose-500" style={{ width: `${Math.max(0, Math.min(100, dnssecBogusRatio))}%` }} /></div>
              </div>
            </div>
          </div>
        </div>
      )
    }

    return (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 flex items-center gap-2">
              <Users size={16} className="text-amber-400" />
              Top Clients
              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400">{filteredClients.length}/{topClients.length}</span>
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
            <div className="flex items-center justify-center h-20 text-sm text-slate-500">
              No matching clients
            </div>
          )}
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 flex items-center gap-2">
              <Globe size={16} className="text-amber-400" />
              Top Domains
              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400">{filteredDomains.length}/{topDomains.length}</span>
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
            <div className="flex items-center justify-center h-20 text-sm text-slate-500">
              No matching domains
            </div>
          )}
        </div>
      </div>
    )
  }, [
    queryTypeCounts,
    upInterfaces,
    profile,
    listenIPs,
    securityNeedsAttention,
    statsView,
    dnssecSecureRatio,
    dnssecBogusRatio,
    filteredClients,
    topClients.length,
    clientFilter,
    clientSortDesc,
    filteredDomains,
    topDomains.length,
    domainFilter,
    domainSortDesc,
  ])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Dashboard</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Live resolver and system telemetry</p>
      </div>

      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => void fetchData()}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold text-slate-900 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700"
          >
            <RefreshCw size={12} /> Refresh
          </button>

          <div className="inline-flex items-center gap-1 rounded-md px-2 py-1 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs text-slate-700 dark:text-slate-300">
            <span>Auto</span>
            <select
              value={refreshMs}
              onChange={(e) => setRefreshMs(Number(e.target.value))}
              className="bg-transparent outline-none"
            >
              {REFRESH_INTERVALS.map((item) => (
                <option key={item.value} value={item.value} className="text-slate-900">{item.label}</option>
              ))}
            </select>
          </div>

          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold text-slate-900 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700"
          >
            {autoRefresh ? <Pause size={12} /> : <Play size={12} />}
            {autoRefresh ? 'Pause Auto' : 'Resume Auto'}
          </button>

          <button
            onClick={() => setLayoutPanelOpen((v) => !v)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold text-slate-900 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700"
          >
            <LayoutGrid size={12} />
            {layoutPanelOpen ? 'Close Layout' : 'Customize Layout'}
          </button>

          <span className="px-2.5 py-1 rounded-md text-xs bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300">
            Updated {updatedAt ? updatedAt.toLocaleTimeString() : '-'}
          </span>
          {layoutStatus && (
            <span className="px-2.5 py-1 rounded-md text-xs bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
              {layoutStatus}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className={`px-2.5 py-1 rounded-md text-xs border ${statsView?.resolver_ready ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30' : 'bg-amber-500/10 text-amber-300 border-amber-500/30'}`}>
            {statsView?.resolver_ready ? 'Resolver Ready' : 'Resolver Not Ready'}
          </span>
          <span className={`px-2.5 py-1 rounded-md text-xs border ${streamConnected ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30' : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700'}`}>
            WS: {streamConnected ? 'Live' : 'Offline'}
          </span>
          <span className="px-2.5 py-1 rounded-md text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
            Live QPS 10s: {liveWindowStats.qps10s.toFixed(2)}
          </span>
          <span className="px-2.5 py-1 rounded-md text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">Avg QPS 1m: {(profile?.traffic.last_minute_qps_avg || 0).toFixed(2)}</span>
          <span className="px-2.5 py-1 rounded-md text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">Errors 1m: {formatNumber(profile?.traffic.last_minute_error_total || 0)}</span>
          <span className="px-2.5 py-1 rounded-md text-xs bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">Cache Hit: {((statsView?.cache_hit_ratio || 0) * 100).toFixed(1)}%</span>
          <span className="px-2.5 py-1 rounded-md text-xs bg-amber-500/10 text-amber-300 border border-amber-500/30">Blocked: {formatNumber(statsView?.blocked_queries || 0)}</span>
          <span className="px-2.5 py-1 rounded-md text-xs bg-rose-500/10 text-rose-300 border border-rose-500/30">Upstream Errors: {formatNumber(statsView?.upstream_errors || 0)}</span>
        </div>

        {layoutPanelOpen && (
          <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-3">
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
              Drag sections below to reorder. Hide low-priority sections and restore anytime.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {sectionOrder.map((id) => {
                const hidden = hiddenSections.includes(id)
                return (
                  <button
                    key={id}
                    onClick={() => (hidden ? showSection(id) : hideSection(id))}
                    className={`px-2 py-1 rounded-md text-xs border ${
                      hidden
                        ? 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-600'
                        : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                    }`}
                  >
                    {hidden ? <Eye size={11} className="inline mr-1" /> : <EyeOff size={11} className="inline mr-1" />}
                    {hidden ? `Show ${SECTION_LABELS[id]}` : `Hide ${SECTION_LABELS[id]}`}
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {!layoutPanelOpen && hiddenSections.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            {hiddenSections.map((id) => (
              <button
                key={id}
                onClick={() => showSection(id)}
                className="px-2 py-1 rounded-md text-xs border bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-600"
              >
                Show {SECTION_LABELS[id]}
              </button>
            ))}
          </div>
        )}
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200">Live Query Pulse</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              WebSocket stream preview (last 10 queries). Full stream in Queries page.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setStreamPaused(!streamPaused)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold text-slate-900 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700"
            >
              {streamPaused ? <Play size={12} /> : <Pause size={12} />}
              {streamPaused ? 'Resume Stream' : 'Pause Stream'}
            </button>
            <a
              href="/queries"
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 hover:bg-cyan-500/20"
            >
              Continue in Queries
            </a>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
          <div className="rounded-md border border-slate-200 dark:border-slate-700 px-2.5 py-2 bg-slate-50 dark:bg-slate-800/70">
            <p className="text-[11px] uppercase text-slate-500 dark:text-slate-400">Total Queries</p>
            <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{formatNumber(totalQueries)}</p>
          </div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 px-2.5 py-2 bg-slate-50 dark:bg-slate-800/70">
            <p className="text-[11px] uppercase text-slate-500 dark:text-slate-400">Live Queries (10s)</p>
            <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{formatNumber(liveWindowStats.queries10s)}</p>
          </div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 px-2.5 py-2 bg-slate-50 dark:bg-slate-800/70">
            <p className="text-[11px] uppercase text-slate-500 dark:text-slate-400">Avg QPS (1m)</p>
            <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{(profile?.traffic.last_minute_qps_avg || 0).toFixed(2)}</p>
          </div>
          <div className="rounded-md border border-slate-200 dark:border-slate-700 px-2.5 py-2 bg-slate-50 dark:bg-slate-800/70">
            <p className="text-[11px] uppercase text-slate-500 dark:text-slate-400">Live Errors (10s)</p>
            <p className="text-sm font-semibold text-rose-300">{formatNumber(liveWindowStats.errors10s)}</p>
          </div>
        </div>
        <div className="overflow-x-auto rounded-md border border-slate-200 dark:border-slate-700">
          <table className="w-full text-xs">
            <thead className="bg-slate-100 dark:bg-slate-800">
              <tr className="text-slate-500 dark:text-slate-400">
                <th className="text-left px-2 py-2">Time</th>
                <th className="text-left px-2 py-2">Client</th>
                <th className="text-left px-2 py-2">Domain</th>
                <th className="text-left px-2 py-2">Type</th>
                <th className="text-left px-2 py-2">RCode</th>
                <th className="text-right px-2 py-2">ms</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
              {recentQueries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-3 py-4 text-center text-slate-500 dark:text-slate-400">
                    No recent queries yet
                  </td>
                </tr>
              ) : (
                recentQueries.map((q) => (
                  <tr key={q.id}>
                    <td className="px-2 py-1.5 text-slate-600 dark:text-slate-300 whitespace-nowrap">
                      {q.ts ? new Date(q.ts).toLocaleTimeString() : '-'}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-slate-600 dark:text-slate-300">{q.client}</td>
                    <td className="px-2 py-1.5 text-slate-900 dark:text-slate-100 max-w-xs truncate" title={q.qname}>{q.qname}</td>
                    <td className="px-2 py-1.5 font-mono text-slate-600 dark:text-slate-300">{q.qtype}</td>
                    <td className="px-2 py-1.5 text-slate-600 dark:text-slate-300">{q.rcode}</td>
                    <td className="px-2 py-1.5 text-right text-slate-600 dark:text-slate-300">{(q.duration_ms || 0).toFixed(1)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-1">
                Traffic Stability & QPS Over Time
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Raw queries + moving average + EMA + QPS line
              </p>
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
          <div className="flex flex-wrap items-center gap-1.5 mb-3">
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
          <div className="h-72">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={chartData} margin={{ top: 10, right: 12, left: 4, bottom: 6 }}>
                  <defs>
                    <linearGradient id="queriesBarGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.45} />
                      <stop offset="95%" stopColor="#22d3ee" stopOpacity={0.06} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.18} />
                  <XAxis
                    dataKey="time"
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11, fill: '#94a3b8' }}
                    minTickGap={20}
                  />
                  <YAxis
                    yAxisId="q"
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11, fill: '#94a3b8' }}
                    width={40}
                  />
                  {chartSeriesVisibility.qps && (
                    <YAxis
                      yAxisId="qps"
                      orientation="right"
                      axisLine={false}
                      tickLine={false}
                      tick={{ fontSize: 11, fill: '#94a3b8' }}
                      width={42}
                    />
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
                    <Area yAxisId="q" type="monotone" dataKey="queries" fill="url(#queriesBarGrad)" stroke="#22d3ee" strokeWidth={1.8} name="Queries" />
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
              <div className="flex items-center justify-center h-full text-sm text-slate-500 dark:text-slate-400">
                No data yet
              </div>
            )}
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-200 mb-4">
            Response Codes
          </h2>
          <div className="h-64">
            {rcodeData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={rcodeData}
                    cx="50%"
                    cy="45%"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {rcodeData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={RCODE_COLORS[entry.name] || '#64748b'}
                      />
                    ))}
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
                  <Legend
                    verticalAlign="bottom"
                    iconType="circle"
                    iconSize={8}
                    formatter={(value: string) => (
                      <span className="text-xs text-slate-500 dark:text-slate-400">
                        {value}
                      </span>
                    )}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-sm text-slate-500 dark:text-slate-400">
                No data yet
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Server profile card */}
      {profile && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-6 shadow-sm relative overflow-hidden">
          <div className="absolute -top-16 -right-16 w-56 h-56 rounded-full bg-gradient-to-br from-amber-400/15 to-orange-500/10 blur-2xl" />
          <div className="absolute -bottom-20 -left-10 w-52 h-52 rounded-full bg-gradient-to-br from-sky-400/15 to-emerald-500/10 blur-2xl" />

          <div className="relative grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 space-y-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-200 border border-slate-200 dark:border-slate-700">
                  <Server size={13} />
                  {profile.hostname || 'unknown-host'}
                </span>
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs bg-amber-500/10 text-amber-300 border border-amber-500/30">
                  <Activity size={12} />
                  {formatVersion(profile.runtime.version)}
                </span>
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                  {profile.runtime.os}/{profile.runtime.arch}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-800/70">
                  <p className="text-xs text-slate-500 dark:text-slate-400">Primary Listen IP</p>
                  <p className="font-mono text-sm text-slate-900 dark:text-slate-100 mt-1 break-all">
                    {listenIPs[0] || 'N/A'}
                  </p>
                </div>
                <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-800/70">
                  <p className="text-xs text-slate-500 dark:text-slate-400">Interfaces</p>
                  <p className="text-sm text-slate-900 dark:text-slate-100 mt-1">
                    {formatNumber(profile.network.interfaces?.length || 0)}
                  </p>
                </div>
                <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-800/70">
                  <p className="text-xs text-slate-500 dark:text-slate-400">Go Runtime</p>
                  <p className="font-mono text-sm text-slate-900 dark:text-slate-100 mt-1 truncate" title={profile.runtime.go_version}>
                    {profile.runtime.go_version}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                <UsageBar
                  label="CPU (process, 1 core=100%)"
                  value={`${cpuUsagePct.toFixed(1)}%`}
                  percent={cpuUsagePct}
                  colorClass="bg-gradient-to-r from-sky-500 to-indigo-500"
                />
                <UsageBar
                  label="CPU (host share)"
                  value={`${cpuHostSharePct.toFixed(1)}%`}
                  percent={cpuHostSharePct}
                  colorClass="bg-gradient-to-r from-slate-500 to-slate-300"
                />
                <UsageBar
                  label="RAM (process)"
                  value={memValue}
                  percent={memPct}
                  colorClass="bg-gradient-to-r from-emerald-500 to-teal-500"
                />
                <UsageBar
                  label="Disk Usage"
                  value={`${diskPct.toFixed(1)}%`}
                  percent={diskPct}
                  colorClass="bg-gradient-to-r from-amber-500 to-orange-500"
                />
              </div>

              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 bg-slate-50 dark:bg-slate-800/70">
                <div className="flex items-center justify-between mb-2">
                  <h2 className="text-xs uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">Network Throughput (host)</h2>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    RX packets: {formatNumber(profile.network.io.rx_packets_total)} | TX packets: {formatNumber(profile.network.io.tx_packets_total)}
                  </div>
                </div>
                <div className="h-36">
                  {networkHistory.length > 1 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <ComposedChart data={networkHistory} margin={{ top: 8, right: 6, left: 0, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.16} />
                        <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#94a3b8' }} minTickGap={24} />
                        <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#94a3b8' }} width={30} />
                        <Tooltip
                          formatter={(value, name) => [`${formatBytes(Number(value) || 0)}/s`, String(name)]}
                          contentStyle={{ backgroundColor: '#020617', border: '1px solid #1e293b', borderRadius: '8px' }}
                        />
                        <Line type="monotone" dataKey="rxBps" stroke="#22d3ee" strokeWidth={2} dot={false} name="RX" />
                        <Line type="monotone" dataKey="txBps" stroke="#8b5cf6" strokeWidth={2} dot={false} name="TX" />
                      </ComposedChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex h-full items-center justify-center text-xs text-slate-500">Waiting for throughput samples...</div>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                <StatCard
                  icon={Globe}
                  label="Total Queries"
                  value={formatNumber(totalQueries)}
                  iconColor="bg-blue-100 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400"
                />
                <StatCard
                  icon={Zap}
                  label="Cache Hit Ratio"
                  value={statsView ? `${((statsView.cache_hit_ratio || 0) * 100).toFixed(1)}%` : '0%'}
                  sub={statsView ? `${formatNumber(statsView.cache_hits || 0)} hits / ${formatNumber(statsView.cache_misses || 0)} misses` : undefined}
                  iconColor="bg-amber-100 dark:bg-amber-900/40 text-amber-600 dark:text-amber-400"
                />
                <StatCard
                  icon={Database}
                  label="Cache Entries"
                  value={statsView ? formatNumber(statsView.cache_entries || 0) : '0'}
                  sub={statsView ? `${formatNumber(statsView.cache_positive || 0)} positive / ${formatNumber(statsView.cache_negative || 0)} negative` : undefined}
                  iconColor="bg-emerald-100 dark:bg-emerald-900/40 text-emerald-600 dark:text-emerald-400"
                />
                <StatCard
                  icon={Clock}
                  label="Uptime"
                  value={statsView ? formatUptime(statsView.uptime_seconds) : '0m'}
                  iconColor="bg-purple-100 dark:bg-purple-900/40 text-purple-600 dark:text-purple-400"
                />
              </div>
            </div>

            <div className="space-y-3">
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 bg-slate-50 dark:bg-slate-800/70">
                <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400 mb-3">
                  Traffic Snapshot
                </h3>
                <div className="space-y-2.5 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1.5"><Network size={13} /> Avg QPS (1m)</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{profile.traffic.last_minute_qps_avg.toFixed(2)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1.5"><Zap size={13} /> Peak QPS (1m)</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{profile.traffic.last_minute_qps_peak.toFixed(2)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400">DNS Queries</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(profile.traffic.dns_queries_total)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400">Upstream Queries</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(profile.traffic.upstream_queries_total)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400">Errors (1m)</span>
                    <span className="font-semibold text-red-300">{formatNumber(profile.traffic.last_minute_error_total)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400">Error Rate (window)</span>
                    <span className="font-semibold text-red-300">{windowErrorRate.toFixed(2)}%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400">Hit Rate (window)</span>
                    <span className="font-semibold text-emerald-300">{windowHitRate.toFixed(1)}%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400">Avg Latency (window)</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{windowAvgLatency.toFixed(1)} ms</span>
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 bg-slate-50 dark:bg-slate-800/70">
                <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400 mb-3">
                  Runtime
                </h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1.5"><Cpu size={13} /> CPU Cores</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{profile.runtime.cpu_cores}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400">Load Avg (1/5/15)</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">
                      {profile.runtime.os === 'windows'
                        ? 'N/A on Windows'
                        : `${profile.cpu.load_avg_1m.toFixed(2)} / ${profile.cpu.load_avg_5m.toFixed(2)} / ${profile.cpu.load_avg_15m.toFixed(2)}`}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1.5"><MemoryStick size={13} /> Goroutines</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(profile.runtime.goroutines)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400">GOMAXPROCS</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(profile.runtime.go_maxprocs)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400">Process Memory</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{formatBytes(memUsed)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1.5"><HardDrive size={13} /> Disk Free</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{formatBytes(profile.disk.free_bytes)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400">GC Cycles</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(profile.memory.gc_cycles)}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-4">
        {visibleSections.map((id) => (
          <section
            key={id}
            draggable={layoutPanelOpen}
            onDragStart={() => layoutPanelOpen && setDraggingSection(id)}
            onDragEnd={() => setDraggingSection(null)}
            onDragOver={(e) => e.preventDefault()}
            onDrop={() => {
              if (draggingSection) moveSection(draggingSection, id)
              setDraggingSection(null)
            }}
            className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-2"
          >
            <div className="flex items-center justify-between px-2 py-1.5">
              <div className="inline-flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
                <GripVertical size={12} />
                {SECTION_LABELS[id]}
              </div>
              <button
                onClick={() => hideSection(id)}
                className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <EyeOff size={12} />
                Hide
              </button>
            </div>
            <div className="pt-1">
              {renderSection(id)}
            </div>
          </section>
        ))}
      </div>

      {statsView && statsView.rate_limited > 0 && (
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-orange-100 dark:bg-orange-900/40 text-orange-600 dark:text-orange-400">
              <AlertTriangle size={20} />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                Security
              </h2>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                <span className="font-mono font-bold text-orange-600 dark:text-orange-400">
                  {formatNumber(statsView.rate_limited)}
                </span>{' '}
                queries rate limited
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
