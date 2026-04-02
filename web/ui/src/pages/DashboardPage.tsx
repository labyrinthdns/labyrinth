import { useState, useEffect, useCallback } from 'react'
import { Globe, Zap, Database, Clock, AlertTriangle, Users } from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts'
import { api } from '@/api/client'
import type { StatsResponse, TimeSeriesBucket, TopEntry } from '@/api/types'
import { formatNumber, formatUptime } from '@/lib/utils'

const RCODE_COLORS: Record<string, string> = {
  NOERROR: '#22c55e',
  NXDOMAIN: '#eab308',
  SERVFAIL: '#ef4444',
  REFUSED: '#f97316',
  FORMERR: '#a855f7',
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

export default function DashboardPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [timeseries, setTimeseries] = useState<TimeSeriesBucket[]>([])
  const [topClients, setTopClients] = useState<TopEntry[]>([])
  const [topDomains, setTopDomains] = useState<TopEntry[]>([])
  const [error, setError] = useState('')

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, tsRes, clientsRes, domainsRes] = await Promise.all([
        api.stats() as Promise<unknown>,
        api.timeseries('5m') as Promise<unknown>,
        api.topClients(10),
        api.topDomains(10),
      ])
      setStats(statsRes as StatsResponse)
      const tsData = tsRes as { buckets: TimeSeriesBucket[] }
      setTimeseries(tsData.buckets || [])
      setTopClients(clientsRes.entries || [])
      setTopDomains(domainsRes.entries || [])
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch stats')
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [fetchData])

  // Compute total queries (guard against null/undefined)
  const totalQueries = stats?.queries_by_type
    ? Object.values(stats.queries_by_type).reduce((a, b) => a + b, 0)
    : 0

  // RCode data for pie chart
  const rcodeData = stats?.responses_by_rcode
    ? Object.entries(stats.responses_by_rcode)
        .filter(([, count]) => count > 0)
        .map(([name, value]) => ({ name, value }))
    : []

  // Format timeseries for chart
  const chartData = (timeseries || []).map((b) => ({
    time: b.ts ? new Date(b.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
    queries: b.queries || 0,
    cacheHits: b.cache_hits || 0,
    cacheMisses: b.cache_misses || 0,
  }))

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
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* QPS Area Chart */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4">
            Queries Over Time
          </h2>
          <div className="h-64">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="queriesGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#d97706" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#d97706" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="hitsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="time"
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11, fill: '#94a3b8' }}
                  />
                  <YAxis
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11, fill: '#94a3b8' }}
                    width={40}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'var(--color-slate-800, #1e293b)',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#e2e8f0',
                      fontSize: '12px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="queries"
                    stroke="#d97706"
                    strokeWidth={2}
                    fill="url(#queriesGrad)"
                    name="Queries"
                  />
                  <Area
                    type="monotone"
                    dataKey="cacheHits"
                    stroke="#22c55e"
                    strokeWidth={2}
                    fill="url(#hitsGrad)"
                    name="Cache Hits"
                  />
                </AreaChart>
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
                      backgroundColor: 'var(--color-slate-800, #1e293b)',
                      border: 'none',
                      borderRadius: '8px',
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
        {/* Top Clients */}
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

        {/* Top Domains */}
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

      {/* Security */}
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
