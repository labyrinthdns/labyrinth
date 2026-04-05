import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, Activity, ShieldAlert, Server, Flame, Clock3 } from 'lucide-react'
import { ResponsiveContainer, ComposedChart, Bar, Line, CartesianGrid, XAxis, YAxis, Tooltip } from 'recharts'
import { api } from '@/api/client'
import type { StatsResponse, SystemProfileResponse } from '@/api/types'
import { formatNumber } from '@/lib/utils'
import { useTimeSeriesStream } from '@/hooks/useTimeSeriesStream'

type HealthResponse = {
  status?: string
  resolver_ready?: boolean
}

export default function OperationsPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [profile, setProfile] = useState<SystemProfileResponse | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [errorThresholdPct, setErrorThresholdPct] = useState(5)
  const [latencyThresholdMs, setLatencyThresholdMs] = useState(250)
  const [error, setError] = useState('')
  const fetchingRef = useRef(false)
  const healthRef = useRef(health)
  const healthFetchedAtRef = useRef(0)
  healthRef.current = health

  // Chart data via WebSocket: 1h window, 1m intervals = 60 data points, server pushes every 10s
  const { buckets: tsBuckets, connected: tsConnected } = useTimeSeriesStream({
    mode: 'history',
    window: '1h',
    interval: '1m',
  })

  // Fetch stats + profile via HTTP (health every 60s)
  const fetchData = useCallback(async (opts?: { forceHealth?: boolean }) => {
    if (fetchingRef.current) return
    fetchingRef.current = true
    try {
      const coreResults = await Promise.allSettled([
        api.stats(),
        api.systemProfile(),
      ])
      const [statsRes, profileRes] = coreResults

      const now = Date.now()
      const shouldFetchHealth = Boolean(
        opts?.forceHealth ||
          !healthRef.current ||
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
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load operations data')
    } finally {
      fetchingRef.current = false
    }
  }, [])

  // Auto-refresh stats every 15s
  useEffect(() => {
    void fetchData({ forceHealth: true })
    const interval = setInterval(() => {
      if (document.hidden) return
      void fetchData()
    }, 15000)
    return () => clearInterval(interval)
  }, [fetchData])

  // Load config thresholds
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
      .catch(() => {})
    return () => { cancelled = true }
  }, [])

  // Chart data from WS buckets
  const chartData = useMemo(() => {
    return (tsBuckets || [])
      .map((b) => {
        const ts = b.timestamp || b.ts || ''
        return {
          ts,
          time: ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
          queries: b.queries || 0,
          errors: b.errors || 0,
          avgLatencyMs: b.avg_latency_ms || 0,
          cacheHits: b.cache_hits || 0,
          cacheMisses: b.cache_misses || 0,
          cacheHitRatio: b.cache_hit_ratio || 0,
        }
      })
      .sort((a, b) => a.ts.localeCompare(b.ts))
  }, [tsBuckets])

  // Aggregated window stats
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

  // Enhanced alerts with detailed root cause analysis
  const alerts = useMemo(() => {
    const result: { level: 'critical' | 'warning' | 'info'; title: string; detail: string }[] = []

    if (!stats?.resolver_ready) {
      result.push({
        level: 'critical',
        title: 'Resolver Offline',
        detail: `DNS resolver is not accepting queries. Health status: ${health?.status || 'unknown'}. Check upstream connectivity and server configuration.`,
      })
    }

    if (errorRate >= errorThresholdPct) {
      const rcodes = stats?.responses_by_rcode || {}
      const errorRcodes = Object.entries(rcodes)
        .filter(([code]) => code !== 'NOERROR' && code !== 'NXDOMAIN')
        .sort(([, a], [, b]) => b - a)
      const topErrors = errorRcodes.slice(0, 3).map(([code, count]) => `${code}: ${formatNumber(count)}`).join(', ')

      result.push({
        level: errorRate >= errorThresholdPct * 2 ? 'critical' : 'warning',
        title: `Error Rate ${errorRate.toFixed(2)}%`,
        detail: `Threshold: ${errorThresholdPct}%. ${formatNumber(totalWindowErrors)} errors across ${formatNumber(totalWindowQueries)} queries in the last hour.${topErrors ? ` Response codes: ${topErrors}.` : ''} Investigate upstream DNS providers and network path.`,
      })
    }

    if (avgLatency >= latencyThresholdMs) {
      const peakBucket = chartData.length > 0
        ? chartData.reduce((peak, b) => b.avgLatencyMs > peak.avgLatencyMs ? b : peak)
        : null
      result.push({
        level: avgLatency >= latencyThresholdMs * 2 ? 'critical' : 'warning',
        title: `Latency ${avgLatency.toFixed(1)}ms`,
        detail: `Threshold: ${latencyThresholdMs}ms. Weighted average over the last hour.${peakBucket ? ` Peak: ${peakBucket.avgLatencyMs.toFixed(1)}ms at ${peakBucket.time}.` : ''} Possible causes: upstream DNS slowness, network congestion, or cache misses under high load.`,
      })
    }

    if ((stats?.upstream_errors || 0) > 0) {
      const pct = stats?.upstream_queries
        ? ((stats.upstream_errors / stats.upstream_queries) * 100).toFixed(2)
        : '?'
      result.push({
        level: 'warning',
        title: `${formatNumber(stats?.upstream_errors || 0)} Upstream Errors`,
        detail: `${pct}% upstream failure rate (${formatNumber(stats?.upstream_queries || 0)} total). DNS provider may be degraded or network path to upstream is unstable.`,
      })
    }

    if ((stats?.rate_limited || 0) > 0) {
      result.push({
        level: 'info',
        title: 'Rate Limiting Active',
        detail: `${formatNumber(stats?.rate_limited || 0)} queries throttled. Protects resolver capacity but may affect legitimate clients if thresholds are too aggressive.`,
      })
    }

    if ((stats?.fallback_queries || 0) > 0) {
      const fbQ = stats?.fallback_queries || 0
      const fbR = stats?.fallback_recoveries || 0
      const recoveryPct = fbQ > 0 ? ((fbR / fbQ) * 100).toFixed(1) : '0'
      result.push({
        level: fbR < fbQ ? 'warning' : 'info',
        title: `Fallback Resolver Active`,
        detail: `${formatNumber(fbQ)} fallback attempts, ${formatNumber(fbR)} recovered (${recoveryPct}%). Primary resolution is failing — check upstream DNS connectivity. ${fbR === fbQ ? 'All queries recovered via fallback.' : `${formatNumber(fbQ - fbR)} queries failed even with fallback.`}`,
      })
    }

    return result
  }, [stats, health, errorRate, errorThresholdPct, avgLatency, latencyThresholdMs, totalWindowErrors, totalWindowQueries, chartData])

  // Enhanced incidents with root cause analysis
  const incidents = useMemo(() => {
    return chartData
      .filter((x) => x.errors > 0 || x.avgLatencyMs >= latencyThresholdMs)
      .slice(-8)
      .reverse()
      .map((i) => {
        const causes: string[] = []
        const bucketErrorRate = i.queries > 0 ? (i.errors / i.queries) * 100 : 0

        if (i.errors > 0) {
          causes.push(`${i.errors} errors (${bucketErrorRate.toFixed(1)}% error rate)`)
        }
        if (i.avgLatencyMs >= latencyThresholdMs) {
          const ratio = (i.avgLatencyMs / latencyThresholdMs).toFixed(1)
          causes.push(`${i.avgLatencyMs.toFixed(1)}ms avg latency (${ratio}x threshold)`)
        }
        if (i.cacheHitRatio < 0.5 && i.queries > 0) {
          causes.push(`Low cache efficiency: ${(i.cacheHitRatio * 100).toFixed(0)}% hit ratio`)
        }

        return { ...i, causes, bucketErrorRate }
      })
  }, [chartData, latencyThresholdMs])

  const qps1m = profile?.traffic?.last_minute_qps_avg || 0
  const peakQps1m = profile?.traffic?.last_minute_qps_peak || 0

  return (
    <div className="space-y-6">
      {/* Clean title */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Operations</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">Service health, reliability and throughput — last hour.</p>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      {/* Top metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-4">
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">Resolver</p>
          <p className={`mt-1 text-xl font-bold ${stats?.resolver_ready ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
            {stats?.resolver_ready ? 'Ready' : 'Not Ready'}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Health: {health?.status || 'unknown'}</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">Error Rate (1h)</p>
          <p className="mt-1 text-xl font-bold text-red-600 dark:text-red-400">{errorRate.toFixed(2)}%</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{formatNumber(totalWindowErrors)} errors / {formatNumber(totalWindowQueries)} queries</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">QPS (1m avg / peak)</p>
          <p className="mt-1 text-xl font-bold text-sky-600 dark:text-sky-400">{qps1m.toFixed(2)} / {peakQps1m.toFixed(2)}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Current traffic pressure</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">Avg Latency (1h)</p>
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

      {/* Chart + Alerts/Incidents */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Chart card with threshold controls in header */}
        <div className="xl:col-span-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Reliability Trend</h2>
              <span className="text-xs text-slate-400 dark:text-slate-500">Last 1 hour · 1 min intervals</span>
              <span className={`inline-block w-1.5 h-1.5 rounded-full ${tsConnected ? 'bg-emerald-500' : 'bg-slate-400'}`} title={tsConnected ? 'Connected' : 'Disconnected'} />
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="inline-flex items-center gap-1.5">
                <Flame size={12} className="text-red-500" />
                <span className="text-slate-500 dark:text-slate-400">Error</span>
                <input
                  type="number"
                  min={0.1}
                  step={0.1}
                  value={errorThresholdPct}
                  onChange={(e) => setErrorThresholdPct(Number(e.target.value || 0))}
                  className="w-16 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-1.5 py-0.5 text-xs"
                />
                <span className="text-slate-400">%</span>
              </div>
              <div className="inline-flex items-center gap-1.5">
                <Clock3 size={12} className="text-amber-500" />
                <span className="text-slate-500 dark:text-slate-400">Latency</span>
                <input
                  type="number"
                  min={1}
                  step={1}
                  value={latencyThresholdMs}
                  onChange={(e) => setLatencyThresholdMs(Number(e.target.value || 0))}
                  className="w-16 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-1.5 py-0.5 text-xs"
                />
                <span className="text-slate-400">ms</span>
              </div>
            </div>
          </div>
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
              <div className="flex items-center justify-center h-full text-sm text-slate-400">
                {tsConnected ? 'Waiting for data...' : 'Connecting...'}
              </div>
            )}
          </div>
        </div>

        {/* Alerts + Incidents sidebar */}
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Alerts</h2>
            {alerts.length > 0 ? (
              <div className="space-y-2.5">
                {alerts.map((a) => (
                  <div
                    key={a.title}
                    className={`rounded-lg border px-3 py-2.5 text-sm ${
                      a.level === 'critical'
                        ? 'border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-900/20'
                        : a.level === 'warning'
                          ? 'border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-900/20'
                          : 'border-sky-200 dark:border-sky-900/60 bg-sky-50 dark:bg-sky-900/20'
                    }`}
                  >
                    <div className={`flex items-start gap-2 font-medium ${
                      a.level === 'critical'
                        ? 'text-red-700 dark:text-red-300'
                        : a.level === 'warning'
                          ? 'text-amber-700 dark:text-amber-300'
                          : 'text-sky-700 dark:text-sky-300'
                    }`}>
                      <ShieldAlert size={15} className="mt-0.5 shrink-0" />
                      <span>{a.title}</span>
                    </div>
                    <p className={`mt-1 text-xs leading-relaxed ${
                      a.level === 'critical'
                        ? 'text-red-600 dark:text-red-400'
                        : a.level === 'warning'
                          ? 'text-amber-600 dark:text-amber-400'
                          : 'text-sky-600 dark:text-sky-400'
                    }`}>{a.detail}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-900/20 px-3 py-2 text-sm text-emerald-700 dark:text-emerald-300 flex items-center gap-2">
                <CheckCircle2 size={15} />
                All systems operating normally.
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
                      <span className="text-slate-700 dark:text-slate-200 font-semibold">{formatNumber(i.queries)} queries</span>
                    </div>
                    <div className="mt-1.5 space-y-0.5">
                      {i.causes.map((cause) => (
                        <div key={cause} className="flex items-start gap-1.5">
                          <AlertTriangle size={10} className="mt-0.5 text-amber-500 shrink-0" />
                          <span className="text-slate-600 dark:text-slate-300">{cause}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-sm text-slate-500 dark:text-slate-400">No incidents in the last hour.</div>
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
            {((stats?.fallback_queries || 0) > 0) && (
              <div className="pt-1.5 mt-1.5 border-t border-slate-200 dark:border-slate-700 space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1"><ShieldAlert size={13} /> Fallback Queries</span>
                  <span className="font-semibold text-amber-600 dark:text-amber-400">{formatNumber(stats?.fallback_queries || 0)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1"><CheckCircle2 size={13} /> Fallback Recoveries</span>
                  <span className="font-semibold text-emerald-600 dark:text-emerald-400">{formatNumber(stats?.fallback_recoveries || 0)}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
