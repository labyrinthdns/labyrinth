import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Globe,
  Zap,
  Database,
  Clock,
  AlertTriangle,
  Users,
  Shield,
  Lock,
  Server,
  Cpu,
  HardDrive,
  Network,
  Activity,
  MemoryStick,
} from 'lucide-react'
import {
  ComposedChart,
  Area,
  Bar,
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

const QUERY_TYPE_COUNTERS = ['A', 'AAAA', 'MX', 'NS', 'PTR', 'SRV', 'CNAME', 'TXT'] as const
const TIME_WINDOWS = ['5m', '15m', '1h'] as const
type TimeWindow = (typeof TIME_WINDOWS)[number]

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
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">{sub}</p>
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
        <span className="font-semibold text-slate-700 dark:text-slate-200">{value}</span>
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
  const [error, setError] = useState('')

  const cpuSampleRef = useRef<{ sec: number; atMs: number } | null>(null)

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, tsRes, clientsRes, domainsRes, profileRes] = await Promise.allSettled([
        api.stats(),
        api.timeseries(timeWindow),
        api.topClients(10),
        api.topDomains(10),
        api.systemProfile(),
      ])

      if (statsRes.status === 'fulfilled') setStats(statsRes.value as unknown as StatsResponse)

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
          const cores = Math.max(1, p.runtime.cpu_cores || 1)
          if (dWall > 0) {
            const pct = (dSec / dWall / cores) * 100
            setCPUUsagePct(Math.max(0, Math.min(100, pct)))
          }
        }
        cpuSampleRef.current = { sec: secTotal, atMs: nowMs }
      }

      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch stats')
    }
  }, [timeWindow])

  useEffect(() => {
    const initialFetch = setTimeout(() => {
      void fetchData()
    }, 0)
    const interval = setInterval(() => {
      void fetchData()
    }, 5000)
    return () => {
      clearTimeout(initialFetch)
      clearInterval(interval)
    }
  }, [fetchData])

  const totalQueries = stats?.queries_by_type
    ? Object.values(stats.queries_by_type).reduce((a, b) => a + b, 0)
    : 0

  const rcodeData = stats?.responses_by_rcode
    ? Object.entries(stats.responses_by_rcode)
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
        hitRate: queryCount > 0 ? (cacheHits / queryCount) * 100 : 0,
      }
    })
    .sort((a, b) => a.ts.localeCompare(b.ts))

  const trendWindow = timeWindow === '5m' ? 4 : timeWindow === '15m' ? 6 : 8
  const queryTrend = movingAverage(chartDataRaw.map((x) => x.queries), trendWindow)
  const chartData = chartDataRaw.map((x, i) => ({
    ...x,
    queriesTrend: Number(queryTrend[i].toFixed(2)),
  }))

  const queryTypeCounts = QUERY_TYPE_COUNTERS.map((type) => ({
    type,
    count: stats?.queries_by_type?.[type] || 0,
  }))

  const memTotal = profile?.memory?.system_total_bytes || 0
  const memUsed = profile?.memory?.process_sys_bytes || 0
  const memPct = memTotal > 0 ? (memUsed / memTotal) * 100 : 0
  const memValue = memTotal > 0
    ? `${formatBytes(memUsed)} / ${formatBytes(memTotal)}`
    : `${formatBytes(memUsed)} (process)`
  const diskPct = profile?.disk?.used_pct || 0

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
        Dashboard
      </h1>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      {/* Server profile card */}
      {profile && (
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6 shadow-sm relative overflow-hidden">
          <div className="absolute -top-16 -right-16 w-56 h-56 rounded-full bg-gradient-to-br from-amber-400/15 to-orange-500/10 blur-2xl" />
          <div className="absolute -bottom-20 -left-10 w-52 h-52 rounded-full bg-gradient-to-br from-sky-400/15 to-emerald-500/10 blur-2xl" />

          <div className="relative grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 space-y-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200">
                  <Server size={13} />
                  {profile.hostname || 'unknown-host'}
                </span>
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">
                  <Activity size={12} />
                  {formatVersion(profile.runtime.version)}
                </span>
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                  {profile.runtime.os}/{profile.runtime.arch}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50/80 dark:bg-slate-900/40">
                  <p className="text-xs text-slate-500 dark:text-slate-400">Primary IP</p>
                  <p className="font-mono text-sm text-slate-900 dark:text-slate-100 mt-1 break-all">
                    {profile.network.ip_addresses?.[0] || 'N/A'}
                  </p>
                </div>
                <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50/80 dark:bg-slate-900/40">
                  <p className="text-xs text-slate-500 dark:text-slate-400">Interfaces</p>
                  <p className="text-sm text-slate-900 dark:text-slate-100 mt-1">
                    {formatNumber(profile.network.interfaces?.length || 0)}
                  </p>
                </div>
                <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50/80 dark:bg-slate-900/40">
                  <p className="text-xs text-slate-500 dark:text-slate-400">Go Runtime</p>
                  <p className="font-mono text-sm text-slate-900 dark:text-slate-100 mt-1 truncate" title={profile.runtime.go_version}>
                    {profile.runtime.go_version}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <UsageBar
                  label="CPU (process)"
                  value={`${cpuUsagePct.toFixed(1)}%`}
                  percent={cpuUsagePct}
                  colorClass="bg-gradient-to-r from-sky-500 to-indigo-500"
                />
                <UsageBar
                  label={memTotal > 0 ? 'RAM (process/system)' : 'RAM (process)'}
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
            </div>

            <div className="space-y-3">
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 bg-slate-50/80 dark:bg-slate-900/40">
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
                    <span className="font-semibold text-red-600 dark:text-red-400">{formatNumber(profile.traffic.last_minute_error_total)}</span>
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 bg-slate-50/80 dark:bg-slate-900/40">
                <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400 mb-3">
                  Runtime
                </h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1.5"><Cpu size={13} /> CPU Cores</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{profile.runtime.cpu_cores}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1.5"><MemoryStick size={13} /> Goroutines</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(profile.runtime.goroutines)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1.5"><HardDrive size={13} /> Disk Free</span>
                    <span className="font-semibold text-slate-900 dark:text-slate-100">{formatBytes(profile.disk.free_bytes)}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={Globe}
          label="Total Queries"
          value={formatNumber(totalQueries)}
          iconColor="bg-blue-100 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400"
        />
        <StatCard
          icon={Zap}
          label="Cache Hit Ratio"
          value={stats ? `${((stats.cache_hit_ratio || 0) * 100).toFixed(1)}%` : '0%'}
          sub={stats ? `${formatNumber(stats.cache_hits || 0)} hits / ${formatNumber(stats.cache_misses || 0)} misses` : undefined}
          iconColor="bg-amber-100 dark:bg-amber-900/40 text-amber-600 dark:text-amber-400"
        />
        <StatCard
          icon={Database}
          label="Cache Entries"
          value={stats ? formatNumber(stats.cache_entries || 0) : '0'}
          sub={stats ? `${formatNumber(stats.cache_positive || 0)} positive / ${formatNumber(stats.cache_negative || 0)} negative` : undefined}
          iconColor="bg-emerald-100 dark:bg-emerald-900/40 text-emerald-600 dark:text-emerald-400"
        />
        <StatCard
          icon={Clock}
          label="Uptime"
          value={stats ? formatUptime(stats.uptime_seconds) : '0m'}
          iconColor="bg-purple-100 dark:bg-purple-900/40 text-purple-600 dark:text-purple-400"
        />
        {stats && (stats.blocked_queries || 0) > 0 && (
          <StatCard
            icon={Shield}
            label="Blocked"
            value={formatNumber(stats.blocked_queries || 0)}
            iconColor="bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400"
          />
        )}
        {stats && ((stats.dnssec_secure || 0) > 0 || (stats.dnssec_bogus || 0) > 0) && (
          <StatCard
            icon={Lock}
            label="DNSSEC"
            value={formatNumber(stats.dnssec_secure || 0)}
            sub={`${formatNumber(stats.dnssec_secure || 0)} secure / ${formatNumber(stats.dnssec_bogus || 0)} bogus`}
            iconColor="bg-teal-100 dark:bg-teal-900/40 text-teal-600 dark:text-teal-400"
          />
        )}
      </div>

      {/* Query Type Counters */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4">
          Query Type Counters
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
          {queryTypeCounts.map((item) => (
            <div
              key={item.type}
              className="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2 bg-slate-50 dark:bg-slate-900/40"
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

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Traffic chart */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1">
                Queries Over Time
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Bar = instantaneous queries, line = smoothed trend ({trendWindow} buckets)
              </p>
            </div>
            <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/40 p-1">
              {TIME_WINDOWS.map((w) => (
                <button
                  key={w}
                  onClick={() => setTimeWindow(w)}
                  className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-colors ${
                    timeWindow === w
                      ? 'bg-amber-500 text-white'
                      : 'text-slate-500 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
                  }`}
                >
                  {w}
                </button>
              ))}
            </div>
          </div>
          <div className="h-72">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={chartData} margin={{ top: 10, right: 12, left: 4, bottom: 6 }}>
                  <defs>
                    <linearGradient id="queriesBarGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.85} />
                      <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.35} />
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
                  <YAxis
                    yAxisId="pct"
                    orientation="right"
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11, fill: '#94a3b8' }}
                    width={36}
                    domain={[0, 100]}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #1e293b',
                      borderRadius: '10px',
                      color: '#e2e8f0',
                      fontSize: '12px',
                    }}
                  />
                  <Bar yAxisId="q" dataKey="queries" fill="url(#queriesBarGrad)" name="Queries" radius={[4, 4, 0, 0]} />
                  <Line yAxisId="q" type="linear" dataKey="queriesTrend" stroke="#f59e0b" strokeWidth={2.5} dot={false} name="Trend" />
                  <Line yAxisId="q" type="linear" dataKey="errors" stroke="#ef4444" strokeWidth={1.8} dot={false} name="Errors" />
                  <Area yAxisId="pct" type="monotone" dataKey="hitRate" stroke="#22c55e" fill="#22c55e22" strokeWidth={1.8} name="Hit Rate" />
                </ComposedChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-sm text-slate-400">
                No data yet
              </div>
            )}
          </div>
        </div>

        {/* RCode Distribution */}
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4">
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
              <div className="flex items-center justify-center h-full text-sm text-slate-400">
                No data yet
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top Clients & Top Domains */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4 flex items-center gap-2">
            <Users size={16} className="text-amber-600 dark:text-amber-400" />
            Top Clients
          </h2>
          {topClients.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  <th className="text-left pb-2 w-8">#</th>
                  <th className="text-left pb-2">Client</th>
                  <th className="text-right pb-2">Queries</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                {topClients.map((entry, i) => (
                  <tr key={entry.key}>
                    <td className="py-1.5 text-xs text-slate-400">{i + 1}</td>
                    <td className="py-1.5 font-mono text-xs text-slate-700 dark:text-slate-300">{entry.key}</td>
                    <td className="py-1.5 text-right text-xs font-medium text-slate-900 dark:text-slate-100">{formatNumber(entry.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="flex items-center justify-center h-20 text-sm text-slate-400">
              No data yet
            </div>
          )}
        </div>

        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4 flex items-center gap-2">
            <Globe size={16} className="text-amber-600 dark:text-amber-400" />
            Top Domains
          </h2>
          {topDomains.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  <th className="text-left pb-2 w-8">#</th>
                  <th className="text-left pb-2">Domain</th>
                  <th className="text-right pb-2">Queries</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                {topDomains.map((entry, i) => (
                  <tr key={entry.key}>
                    <td className="py-1.5 text-xs text-slate-400">{i + 1}</td>
                    <td className="py-1.5 text-xs text-slate-700 dark:text-slate-300 max-w-xs truncate" title={entry.key}>{entry.key}</td>
                    <td className="py-1.5 text-right text-xs font-medium text-slate-900 dark:text-slate-100">{formatNumber(entry.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="flex items-center justify-center h-20 text-sm text-slate-400">
              No data yet
            </div>
          )}
        </div>
      </div>

      {stats && stats.rate_limited > 0 && (
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
                  {formatNumber(stats.rate_limited)}
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
