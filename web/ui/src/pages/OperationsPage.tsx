import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, Activity, ShieldAlert, Server, Flame, Clock3, Pause, Play } from 'lucide-react'
import { ResponsiveContainer, ComposedChart, Bar, Line, CartesianGrid, XAxis, YAxis, Tooltip } from 'recharts'
import { api } from '@/api/client'
import type { StatsResponse, TimeSeriesBucket, SystemProfileResponse } from '@/api/types'
import { formatNumber } from '@/lib/utils'

type HealthResponse = {
  status?: string
  resolver_ready?: boolean
}

const OPS_WINDOWS = ['5m', '15m', '1h'] as const
type OpsWindow = (typeof OPS_WINDOWS)[number]
const OPS_REFRESH_INTERVALS = [
  { label: '5s', value: 5000 },
  { label: '15s', value: 15000 },
  { label: '30s', value: 30000 },
] as const

export default function OperationsPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [profile, setProfile] = useState<SystemProfileResponse | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [buckets, setBuckets] = useState<TimeSeriesBucket[]>([])
  const [timeWindow, setTimeWindow] = useState<OpsWindow>('1h')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [refreshMs, setRefreshMs] = useState(15000)
  const [errorThresholdPct, setErrorThresholdPct] = useState(2)
  const [latencyThresholdMs, setLatencyThresholdMs] = useState(80)
  const [error, setError] = useState('')
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)
  const fetchingRef = useRef(false)
  const healthFetchedAtRef = useRef(0)

  const fetchData = useCallback(async (opts?: { forceHealth?: boolean }) => {
    if (fetchingRef.current) return
    fetchingRef.current = true
    try {
      const coreResults = await Promise.allSettled([
        api.stats(),
        api.systemProfile(),
        api.timeseries(timeWindow),
      ])
      const [statsRes, profileRes, tsRes] = coreResults

      const now = Date.now()
      const shouldFetchHealth = Boolean(
        opts?.forceHealth ||
          !health ||
          (now - healthFetchedAtRef.current) >= 60_000,
      )
      let healthRes: PromiseSettledResult<unknown> | null = null
      if (shouldFetchHealth) {
        healthRes = await Promise.resolve(api.health()).then(
          (value) => ({ status: 'fulfilled', value } as PromiseFulfilledResult<unknown>),
          (reason) => ({ status: 'rejected', reason } as PromiseRejectedResult),
        )
        healthFetchedAtRef.current = now
      }

      if (statsRes.status === 'fulfilled') setStats(statsRes.value as unknown as StatsResponse)
      if (profileRes.status === 'fulfilled') setProfile(profileRes.value as unknown as SystemProfileResponse)
      if (healthRes?.status === 'fulfilled') setHealth(healthRes.value as unknown as HealthResponse)
      if (tsRes.status === 'fulfilled') {
        const data = tsRes.value as unknown as { buckets?: TimeSeriesBucket[] }
        setBuckets(data.buckets || [])
      }

      setUpdatedAt(new Date())
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load operations data')
    } finally {
      fetchingRef.current = false
    }
  }, [timeWindow, health])

  useEffect(() => {
    void fetchData()
    if (!autoRefresh) {
      return
    }
    const interval = setInterval(() => {
      if (document.hidden) return
      void fetchData()
    }, refreshMs)
    return () => clearInterval(interval)
  }, [fetchData, autoRefresh, refreshMs])

  const chartData = useMemo(() => {
    return (buckets || [])
      .map((b) => {
        const ts = b.timestamp || b.ts || ''
        return {
          ts,
          time: ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
          queries: b.queries || 0,
          errors: b.errors || 0,
          avgLatencyMs: b.avg_latency_ms || 0,
        }
      })
      .sort((a, b) => a.ts.localeCompare(b.ts))
  }, [buckets])

  const totalWindowQueries = chartData.reduce((sum, i) => sum + i.queries, 0)
  const totalWindowErrors = chartData.reduce((sum, i) => sum + i.errors, 0)
  const weightedLatency = chartData.reduce((sum, i) => sum + (i.avgLatencyMs * i.queries), 0)
  const errorRate = totalWindowQueries > 0 ? (totalWindowErrors / totalWindowQueries) * 100 : 0
  const avgLatency = totalWindowQueries > 0 ? (weightedLatency / totalWindowQueries) : 0

  const severity = !stats?.resolver_ready || errorRate >= errorThresholdPct * 2 || avgLatency >= latencyThresholdMs * 2
    ? 'critical'
    : errorRate >= errorThresholdPct || avgLatency >= latencyThresholdMs
      ? 'warning'
      : 'healthy'

  const alerts = [
    !stats?.resolver_ready && 'Resolver is not ready',
    errorRate >= errorThresholdPct && `Error rate threshold breached (${errorRate.toFixed(2)}% >= ${errorThresholdPct.toFixed(2)}%)`,
    avgLatency >= latencyThresholdMs && `Latency threshold breached (${avgLatency.toFixed(1)}ms >= ${latencyThresholdMs.toFixed(0)}ms)`,
    (stats?.upstream_errors || 0) > 0 && `Upstream errors observed (${formatNumber(stats?.upstream_errors || 0)})`,
    (stats?.rate_limited || 0) > 0 && `Rate limiting active (${formatNumber(stats?.rate_limited || 0)} hits)`,
  ].filter(Boolean) as string[]

  const incidents = chartData
    .filter((x) => x.errors > 0 || x.avgLatencyMs >= latencyThresholdMs)
    .slice(-8)
    .reverse()

  const qps1m = profile?.traffic?.last_minute_qps_avg || 0
  const peakQps1m = profile?.traffic?.last_minute_qps_peak || 0

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Operations</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">Live service health, reliability and throughput signals.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="px-2.5 py-1 rounded-lg border border-slate-300 dark:border-slate-600 text-xs text-slate-600 dark:text-slate-300 bg-white dark:bg-slate-800">
            Updated {updatedAt ? updatedAt.toLocaleTimeString() : '-'}
          </span>
          <span className={`px-2.5 py-1 rounded-lg border text-xs ${
            severity === 'critical'
              ? 'border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300'
              : severity === 'warning'
                ? 'border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300'
                : 'border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300'
          }`}>
            {severity.toUpperCase()}
          </span>
          <div className="inline-flex items-center gap-1 rounded-lg border border-slate-300 dark:border-slate-600 px-2 py-1 text-xs bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300">
            <span>Auto</span>
            <select
              value={refreshMs}
              onChange={(e) => setRefreshMs(Number(e.target.value))}
              className="bg-transparent outline-none"
            >
              {OPS_REFRESH_INTERVALS.map((item) => (
                <option key={item.value} value={item.value} className="text-slate-900">
                  {item.label}
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            {autoRefresh ? <Pause size={13} /> : <Play size={13} />}
            {autoRefresh ? 'Pause' : 'Resume'}
          </button>
          <div className="inline-flex rounded-lg border border-slate-300 dark:border-slate-600 overflow-hidden">
            {OPS_WINDOWS.map((w) => (
              <button
                key={w}
                onClick={() => setTimeWindow(w)}
                className={`px-2.5 py-1.5 text-xs font-medium ${timeWindow === w ? 'bg-amber-600 text-white' : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300'}`}
              >
                {w}
              </button>
            ))}
          </div>
          <button
            onClick={() => void fetchData({ forceHealth: true })}
            className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-4">
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">Resolver</p>
          <p className={`mt-1 text-xl font-bold ${stats?.resolver_ready ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
            {stats?.resolver_ready ? 'Ready' : 'Not Ready'}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Health: {health?.status || 'unknown'}</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">Error Rate ({timeWindow})</p>
          <p className="mt-1 text-xl font-bold text-red-600 dark:text-red-400">{errorRate.toFixed(2)}%</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{formatNumber(totalWindowErrors)} errors / {formatNumber(totalWindowQueries)} queries</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">QPS (1m avg / peak)</p>
          <p className="mt-1 text-xl font-bold text-sky-600 dark:text-sky-400">{qps1m.toFixed(2)} / {peakQps1m.toFixed(2)}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Current traffic pressure</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">Avg Latency ({timeWindow})</p>
          <p className="mt-1 text-xl font-bold text-amber-600 dark:text-amber-400">{avgLatency.toFixed(1)} ms</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Weighted by query volume</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">Severity</p>
          <p className={`mt-1 text-xl font-bold ${severity === 'critical' ? 'text-red-600 dark:text-red-400' : severity === 'warning' ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
            {severity.toUpperCase()}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Based on current thresholds</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">Security Pressure</p>
          <p className="mt-1 text-xl font-bold text-slate-900 dark:text-slate-100">
            {formatNumber(stats?.blocked_queries || 0)} / {formatNumber(stats?.rate_limited || 0)}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Blocked / Rate limited</p>
        </div>
      </div>

      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <div className="inline-flex items-center gap-2">
            <Flame size={14} className="text-red-500" />
            <span className="text-slate-500 dark:text-slate-400">Error threshold</span>
            <input
              type="number"
              min={0.1}
              step={0.1}
              value={errorThresholdPct}
              onChange={(e) => setErrorThresholdPct(Number(e.target.value || 0))}
              className="w-20 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-2 py-1 text-sm"
            />
            <span className="text-slate-500 dark:text-slate-400">%</span>
          </div>
          <div className="inline-flex items-center gap-2">
            <Clock3 size={14} className="text-amber-500" />
            <span className="text-slate-500 dark:text-slate-400">Latency threshold</span>
            <input
              type="number"
              min={1}
              step={1}
              value={latencyThresholdMs}
              onChange={(e) => setLatencyThresholdMs(Number(e.target.value || 0))}
              className="w-20 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-2 py-1 text-sm"
            />
            <span className="text-slate-500 dark:text-slate-400">ms</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Reliability Trend ({timeWindow})</h2>
          <div className="h-72">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={chartData} margin={{ top: 8, right: 12, left: 4, bottom: 4 }}>
                  <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.15} />
                  <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#94a3b8' }} minTickGap={20} />
                  <YAxis yAxisId="q" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#94a3b8' }} width={44} />
                  <YAxis yAxisId="e" orientation="right" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#94a3b8' }} width={36} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #1e293b',
                      borderRadius: '10px',
                      color: '#e2e8f0',
                      fontSize: '12px',
                    }}
                  />
                  <Bar yAxisId="q" dataKey="queries" fill="#0ea5e955" stroke="#0ea5e9" name="Queries" radius={[4, 4, 0, 0]} />
                  <Line yAxisId="e" type="monotone" dataKey="errors" stroke="#ef4444" strokeWidth={2} dot={false} name="Errors" />
                </ComposedChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-sm text-slate-400">No time series data</div>
            )}
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Quick Alerts</h2>
            {alerts.length > 0 ? (
              <div className="space-y-2.5">
                {alerts.map((a) => (
                  <div key={a} className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-900/20 px-3 py-2 text-sm text-red-700 dark:text-red-300 flex items-start gap-2">
                    <ShieldAlert size={15} className="mt-0.5" />
                    <span>{a}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-900/20 px-3 py-2 text-sm text-emerald-700 dark:text-emerald-300 flex items-center gap-2">
                <CheckCircle2 size={15} />
                No immediate operational alerts.
              </div>
            )}
          </div>

          <div>
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">Recent Incidents</h2>
            {incidents.length > 0 ? (
              <div className="space-y-2">
                {incidents.map((i) => (
                  <div key={`${i.ts}-${i.errors}-${i.avgLatencyMs}`} className="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2 text-xs bg-slate-50 dark:bg-slate-900/40">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 dark:text-slate-400">{new Date(i.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                      <span className="text-slate-700 dark:text-slate-200 font-semibold">{i.queries} q</span>
                    </div>
                    <div className="mt-1 flex items-center justify-between">
                      <span className="text-red-600 dark:text-red-400">errors: {i.errors}</span>
                      <span className="text-amber-600 dark:text-amber-400">latency: {i.avgLatencyMs.toFixed(1)}ms</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-sm text-slate-500 dark:text-slate-400">No incidents in this window.</div>
            )}
          </div>

          <div className="pt-2 border-t border-slate-200 dark:border-slate-700 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1"><Server size={13} /> Upstream Queries</span>
              <span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(stats?.upstream_queries || 0)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1"><AlertTriangle size={13} /> Upstream Errors</span>
              <span className="font-semibold text-red-600 dark:text-red-400">{formatNumber(stats?.upstream_errors || 0)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1"><Activity size={13} /> Rate Limited</span>
              <span className="font-semibold text-slate-900 dark:text-slate-100">{formatNumber(stats?.rate_limited || 0)}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
