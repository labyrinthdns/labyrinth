import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Server,
  Clock3,
  Flame,
  Activity,
  Shield,
} from 'lucide-react'
import {
  ResponsiveContainer,
  ComposedChart,
  Bar,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
} from 'recharts'
import { api } from '@/api/client'
import type { StatsResponse, SystemProfileResponse, TLSStatusResponse } from '@/api/types'
import { formatNumber } from '@/lib/utils'
import { useTimeSeriesStream } from '@/hooks/useTimeSeriesStream'

type HealthResponse = {
  status?: string
  resolver_ready?: boolean
}

/* ── Window presets: every combo stays ≤ 30 data points ────────── */
const WINDOWS = [
  { label: '15m', window: '15m', interval: '1m', desc: '1-min buckets', points: 15 },
  { label: '1h', window: '1h', interval: '2m', desc: '2-min buckets', points: 30 },
  { label: '24h', window: '24h', interval: '1h', desc: '1-hour buckets', points: 24 },
] as const

export default function OperationsPage() {
  /* ── state ───────────────────────────────────────────────────── */
  const [winIdx, setWinIdx] = useState(1) // default 1h
  const preset = WINDOWS[winIdx]

  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [profile, setProfile] = useState<SystemProfileResponse | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [tlsStatus, setTlsStatus] = useState<TLSStatusResponse | null>(null)
  const [errorThresholdPct, setErrorThresholdPct] = useState(5)
  const [latencyThresholdMs, setLatencyThresholdMs] = useState(250)
  const [error, setError] = useState('')

  const fetchingRef = useRef(false)
  const healthRef = useRef(health)
  const healthFetchedAtRef = useRef(0)
  healthRef.current = health

  /* ── chart WS: pushes every 10 s, ≤ 30 points ───────────────── */
  const { buckets: tsBuckets, connected: tsConnected } = useTimeSeriesStream({
    mode: 'history',
    window: preset.window,
    interval: preset.interval,
  })

  /* ── HTTP polling: stats + profile every 15 s, health every 60 s */
  const fetchData = useCallback(async (opts?: { forceHealth?: boolean }) => {
    if (fetchingRef.current) return
    fetchingRef.current = true
    try {
      const [statsRes, profileRes] = await Promise.allSettled([
        api.stats(),
        api.systemProfile(),
      ])

      const now = Date.now()
      const shouldFetchHealth = Boolean(
        opts?.forceHealth ||
          !healthRef.current ||
          now - healthFetchedAtRef.current >= 60_000,
      )
      let healthRes: PromiseSettledResult<unknown> | null = null
      if (shouldFetchHealth) {
        healthRes = await Promise.resolve(api.health()).then(
          (value) => ({ status: 'fulfilled', value } as PromiseFulfilledResult<unknown>),
          (reason) => ({ status: 'rejected', reason } as PromiseRejectedResult),
        )
        healthFetchedAtRef.current = now
      }

      if (statsRes.status === 'fulfilled') setStats(statsRes.value)
      if (profileRes.status === 'fulfilled') setProfile(profileRes.value)
      if (healthRes?.status === 'fulfilled') setHealth(healthRes.value as HealthResponse)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load operations data')
    } finally {
      fetchingRef.current = false
    }
  }, [])

  useEffect(() => {
    void fetchData({ forceHealth: true })
    const t = setInterval(() => {
      if (!document.hidden) void fetchData()
    }, 15_000)
    return () => clearInterval(t)
  }, [fetchData])

  /* ── load threshold config once ──────────────────────────────── */
  useEffect(() => {
    let cancelled = false
    void api
      .config()
      .then((cfg) => {
        if (cancelled) return
        const web = cfg?.web && typeof cfg.web === 'object' ? (cfg.web as Record<string, unknown>) : {}
        const e = Number(web.alert_error_threshold_pct)
        const l = Number(web.alert_latency_threshold_ms)
        if (Number.isFinite(e) && e > 0) setErrorThresholdPct(e)
        if (Number.isFinite(l) && l > 0) setLatencyThresholdMs(l)
      })
      .catch(() => {})
    void api.tlsStatus().then((t) => { if (!cancelled) setTlsStatus(t) }).catch(() => {})
    return () => { cancelled = true }
  }, [])

  /* ── chart data (stable, max 30 points) ──────────────────────── */
  const chartData = useMemo(() => {
    return (tsBuckets || [])
      .map((b) => {
        const ts = b.timestamp || b.ts || ''
        const d = new Date(ts)
        return {
          ts,
          time: d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
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

  /* ── window aggregates ───────────────────────────────────────── */
  const totalQ = chartData.reduce((s, i) => s + i.queries, 0)
  const totalErr = chartData.reduce((s, i) => s + i.errors, 0)
  const wLatency = chartData.reduce((s, i) => s + i.avgLatencyMs * i.queries, 0)
  const errorRate = totalQ > 0 ? (totalErr / totalQ) * 100 : 0
  const avgLatency = totalQ > 0 ? wLatency / totalQ : 0

  const qps1m = profile?.traffic?.last_minute_qps_avg || 0
  const peakQps1m = profile?.traffic?.last_minute_qps_peak || 0

  const severity: 'critical' | 'warning' | 'healthy' =
    !stats?.resolver_ready || errorRate >= errorThresholdPct * 2 || avgLatency >= latencyThresholdMs * 2
      ? 'critical'
      : errorRate >= errorThresholdPct || avgLatency >= latencyThresholdMs
        ? 'warning'
        : 'healthy'

  /* ── alerts with root-cause detail ───────────────────────────── */
  const alerts = useMemo(() => {
    const out: { level: 'critical' | 'warning' | 'info'; title: string; detail: string }[] = []

    if (!stats?.resolver_ready) {
      out.push({
        level: 'critical',
        title: 'Resolver Offline',
        detail: `Health: ${health?.status || 'unknown'}. Check upstream connectivity and server configuration.`,
      })
    }

    if (errorRate >= errorThresholdPct) {
      const rcodes = stats?.responses_by_rcode || {}
      const top = Object.entries(rcodes)
        .filter(([c]) => c !== 'NOERROR' && c !== 'NXDOMAIN')
        .sort(([, a], [, b]) => b - a)
        .slice(0, 3)
        .map(([c, n]) => `${c}: ${formatNumber(n)}`)
        .join(', ')
      out.push({
        level: errorRate >= errorThresholdPct * 2 ? 'critical' : 'warning',
        title: `Error Rate ${errorRate.toFixed(2)}%`,
        detail: `Threshold ${errorThresholdPct}%. ${formatNumber(totalErr)} errors / ${formatNumber(totalQ)} queries.${top ? ` Top codes: ${top}.` : ''} Check upstream DNS.`,
      })
    }

    if (avgLatency >= latencyThresholdMs) {
      const peak = chartData.length > 0
        ? chartData.reduce((p, b) => (b.avgLatencyMs > p.avgLatencyMs ? b : p))
        : null
      out.push({
        level: avgLatency >= latencyThresholdMs * 2 ? 'critical' : 'warning',
        title: `Latency ${avgLatency.toFixed(1)} ms`,
        detail: `Threshold ${latencyThresholdMs} ms.${peak ? ` Peak ${peak.avgLatencyMs.toFixed(1)} ms at ${peak.time}.` : ''} Possible: upstream slowness, cache misses, congestion.`,
      })
    }

    if ((stats?.upstream_errors || 0) > 0) {
      const pct = stats?.upstream_queries
        ? ((stats.upstream_errors / stats.upstream_queries) * 100).toFixed(2)
        : '?'
      out.push({
        level: 'warning',
        title: `${formatNumber(stats?.upstream_errors || 0)} Upstream Errors`,
        detail: `${pct}% failure rate over ${formatNumber(stats?.upstream_queries || 0)} upstream queries.`,
      })
    }

    if ((stats?.rate_limited || 0) > 0) {
      out.push({
        level: 'info',
        title: 'Rate Limiting Active',
        detail: `${formatNumber(stats?.rate_limited || 0)} queries throttled.`,
      })
    }

    if ((stats?.fallback_queries || 0) > 0) {
      const fbQ = stats?.fallback_queries || 0
      const fbR = stats?.fallback_recoveries || 0
      const pct = fbQ > 0 ? ((fbR / fbQ) * 100).toFixed(1) : '0'
      out.push({
        level: fbR < fbQ ? 'warning' : 'info',
        title: 'Fallback Resolver Active',
        detail: `${formatNumber(fbQ)} attempts, ${formatNumber(fbR)} recovered (${pct}%).${fbR === fbQ ? ' All recovered.' : ` ${formatNumber(fbQ - fbR)} still failed.`}`,
      })
    }

    return out
  }, [stats, health, errorRate, errorThresholdPct, avgLatency, latencyThresholdMs, totalErr, totalQ, chartData])

  /* ── incidents: anomalous buckets ────────────────────────────── */
  const incidents = useMemo(() => {
    return chartData
      .filter((x) => x.errors > 0 || x.avgLatencyMs >= latencyThresholdMs)
      .slice(-6)
      .reverse()
      .map((i) => {
        const causes: string[] = []
        if (i.errors > 0) {
          const r = i.queries > 0 ? ((i.errors / i.queries) * 100).toFixed(1) : '0'
          causes.push(`${i.errors} errors (${r}%)`)
        }
        if (i.avgLatencyMs >= latencyThresholdMs) {
          causes.push(`${i.avgLatencyMs.toFixed(1)} ms latency (${(i.avgLatencyMs / latencyThresholdMs).toFixed(1)}x threshold)`)
        }
        if (i.cacheHitRatio < 0.5 && i.queries > 0) {
          causes.push(`Low cache: ${(i.cacheHitRatio * 100).toFixed(0)}% hit ratio`)
        }
        return { ...i, causes }
      })
  }, [chartData, latencyThresholdMs])

  /* ── max Y for error reference line ──────────────────────────── */
  const maxErrors = chartData.reduce((m, b) => Math.max(m, b.errors), 0)

  /* ── render ──────────────────────────────────────────────────── */
  const sevColor =
    severity === 'critical'
      ? 'text-red-600 dark:text-red-400'
      : severity === 'warning'
        ? 'text-amber-600 dark:text-amber-400'
        : 'text-emerald-600 dark:text-emerald-400'

  const sevDot =
    severity === 'critical'
      ? 'bg-red-500'
      : severity === 'warning'
        ? 'bg-amber-500'
        : 'bg-emerald-500'

  return (
    <div className="space-y-5">
      {/* ── Header ────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Operations</h1>
            <span className={`inline-flex items-center gap-1.5 text-xs font-semibold ${sevColor}`}>
              <span className={`w-2 h-2 rounded-full ${sevDot}`} />
              {severity.toUpperCase()}
            </span>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">
            Service health and reliability
          </p>
        </div>

        {/* Window selector */}
        <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 rounded-lg p-0.5">
          {WINDOWS.map((w, idx) => (
            <button
              key={w.label}
              onClick={() => setWinIdx(idx)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                idx === winIdx
                  ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-100 shadow-sm'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
              }`}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      {/* ── Key Metrics (4 cards) ─────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Status */}
        <div className={`rounded-lg border p-4 ${
          stats?.resolver_ready
            ? 'border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/50 dark:bg-emerald-900/10'
            : 'border-red-200 dark:border-red-900/60 bg-red-50/50 dark:bg-red-900/10'
        }`}>
          <p className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Resolver</p>
          <p className={`mt-1 text-xl font-bold ${stats?.resolver_ready ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
            {stats?.resolver_ready ? 'Healthy' : 'Down'}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{health?.status || 'checking...'}</p>
        </div>

        {/* Error Rate */}
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Error Rate</p>
          <p className={`mt-1 text-xl font-bold ${errorRate >= errorThresholdPct ? 'text-red-600 dark:text-red-400' : 'text-slate-900 dark:text-slate-100'}`}>
            {errorRate.toFixed(2)}%
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {formatNumber(totalErr)} / {formatNumber(totalQ)}
          </p>
        </div>

        {/* Latency */}
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Avg Latency</p>
          <p className={`mt-1 text-xl font-bold ${avgLatency >= latencyThresholdMs ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-slate-100'}`}>
            {avgLatency.toFixed(1)} ms
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">weighted by volume</p>
        </div>

        {/* QPS */}
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">QPS (1m)</p>
          <p className="mt-1 text-xl font-bold text-sky-600 dark:text-sky-400">
            {qps1m.toFixed(1)}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">peak {peakQps1m.toFixed(1)}</p>
        </div>
      </div>

      {/* ── Chart (full width) ────────────────────────────────── */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Reliability Trend</h2>
            <span className="text-xs text-slate-400 dark:text-slate-500">
              {preset.label} &middot; {preset.desc}
            </span>
            <span
              className={`w-1.5 h-1.5 rounded-full ${tsConnected ? 'bg-emerald-500' : 'bg-slate-400'}`}
              title={tsConnected ? 'WebSocket connected' : 'Disconnected'}
            />
          </div>
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <label className="inline-flex items-center gap-1.5">
              <Flame size={12} className="text-red-500" />
              <span className="text-slate-500 dark:text-slate-400">Error</span>
              <input
                type="number"
                min={0.1}
                step={0.1}
                value={errorThresholdPct}
                onChange={(e) => setErrorThresholdPct(Number(e.target.value) || 0)}
                className="w-14 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-1.5 py-0.5 text-xs text-center"
              />
              <span className="text-slate-400">%</span>
            </label>
            <label className="inline-flex items-center gap-1.5">
              <Clock3 size={12} className="text-amber-500" />
              <span className="text-slate-500 dark:text-slate-400">Latency</span>
              <input
                type="number"
                min={1}
                step={1}
                value={latencyThresholdMs}
                onChange={(e) => setLatencyThresholdMs(Number(e.target.value) || 0)}
                className="w-16 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-1.5 py-0.5 text-xs text-center"
              />
              <span className="text-slate-400">ms</span>
            </label>
          </div>
        </div>

        <div className="h-64">
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={chartData} margin={{ top: 8, right: 12, left: 0, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.12} />
                <XAxis
                  dataKey="time"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fontSize: 11, fill: '#94a3b8' }}
                  interval="preserveStartEnd"
                  minTickGap={36}
                />
                <YAxis
                  yAxisId="q"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fontSize: 11, fill: '#94a3b8' }}
                  width={46}
                  domain={[0, 'auto']}
                />
                <YAxis
                  yAxisId="e"
                  orientation="right"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fontSize: 11, fill: '#94a3b8' }}
                  width={32}
                  domain={[0, (max: number) => Math.max(max, 1)]}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #1e293b',
                    borderRadius: '10px',
                    color: '#e2e8f0',
                    fontSize: '12px',
                  }}
                  formatter={(value, name) => {
                    const n = Number(value)
                    if (name === 'Queries') return [formatNumber(n), name]
                    if (name === 'Errors') return [formatNumber(n), name]
                    return [n, name]
                  }}
                />
                <Bar
                  yAxisId="q"
                  dataKey="queries"
                  fill="#0ea5e940"
                  stroke="#0ea5e9"
                  strokeWidth={1}
                  name="Queries"
                  radius={[3, 3, 0, 0]}
                  isAnimationActive={false}
                />
                <Line
                  yAxisId="e"
                  type="monotone"
                  dataKey="errors"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                  name="Errors"
                  isAnimationActive={false}
                />
                {maxErrors > 0 && (
                  <ReferenceLine
                    yAxisId="e"
                    y={0}
                    stroke="transparent"
                    label=""
                  />
                )}
              </ComposedChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-sm text-slate-400">
              {tsConnected ? 'Waiting for data...' : 'Connecting...'}
            </div>
          )}
        </div>
      </div>

      {/* ── Bottom: Alerts + Incidents  |  Counters ───────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
        {/* Alerts & Incidents (wider) */}
        <div className="xl:col-span-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 space-y-5">
          {/* Alerts */}
          <div>
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Alerts</h2>
            {alerts.length > 0 ? (
              <div className="space-y-2">
                {alerts.map((a) => {
                  const styles =
                    a.level === 'critical'
                      ? 'border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300'
                      : a.level === 'warning'
                        ? 'border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300'
                        : 'border-sky-200 dark:border-sky-900/60 bg-sky-50 dark:bg-sky-900/20 text-sky-700 dark:text-sky-300'
                  const detailStyle =
                    a.level === 'critical'
                      ? 'text-red-600 dark:text-red-400'
                      : a.level === 'warning'
                        ? 'text-amber-600 dark:text-amber-400'
                        : 'text-sky-600 dark:text-sky-400'
                  return (
                    <div key={a.title} className={`rounded-lg border px-3 py-2.5 ${styles}`}>
                      <div className="flex items-start gap-2 text-sm font-medium">
                        <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                        <span>{a.title}</span>
                      </div>
                      <p className={`mt-1 text-xs leading-relaxed ${detailStyle}`}>{a.detail}</p>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="rounded-lg border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-900/20 px-3 py-2.5 text-sm text-emerald-700 dark:text-emerald-300 flex items-center gap-2">
                <CheckCircle2 size={14} />
                All systems operating normally.
              </div>
            )}
          </div>

          {/* Incidents */}
          <div>
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">Recent Incidents</h2>
            {incidents.length > 0 ? (
              <div className="space-y-2">
                {incidents.map((i) => (
                  <div
                    key={`${i.ts}-${i.errors}`}
                    className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/40 px-3 py-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 dark:text-slate-400 font-mono">
                        {new Date(i.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                      <span className="text-slate-700 dark:text-slate-200 font-semibold">
                        {formatNumber(i.queries)} queries
                      </span>
                    </div>
                    <div className="mt-1.5 space-y-0.5">
                      {i.causes.map((c) => (
                        <div key={c} className="flex items-start gap-1.5">
                          <AlertTriangle size={10} className="mt-0.5 text-amber-500 shrink-0" />
                          <span className="text-slate-600 dark:text-slate-300">{c}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-500 dark:text-slate-400">
                No incidents in the selected window.
              </p>
            )}
          </div>
        </div>

        {/* Operational Counters (narrower) */}
        <div className="xl:col-span-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Counters</h2>
          <div className="space-y-2.5 text-sm">
            <CounterRow icon={<Server size={13} />} label="Upstream Queries" value={formatNumber(stats?.upstream_queries || 0)} />
            <CounterRow icon={<AlertTriangle size={13} />} label="Upstream Errors" value={formatNumber(stats?.upstream_errors || 0)} color={stats?.upstream_errors ? 'text-red-600 dark:text-red-400' : undefined} />
            <CounterRow icon={<Shield size={13} />} label="Blocked Queries" value={formatNumber(stats?.blocked_queries || 0)} />
            <CounterRow icon={<Activity size={13} />} label="Rate Limited" value={formatNumber(stats?.rate_limited || 0)} />

            <div className="border-t border-slate-200 dark:border-slate-700 pt-2.5 mt-2.5 space-y-2.5">
              <CounterRow icon={<Shield size={13} />} label="DNSSEC Secure" value={formatNumber(stats?.dnssec_secure || 0)} color="text-emerald-600 dark:text-emerald-400" />
              <CounterRow icon={<Shield size={13} />} label="DNSSEC Insecure" value={formatNumber(stats?.dnssec_insecure || 0)} />
              <CounterRow icon={<Shield size={13} />} label="DNSSEC Bogus" value={formatNumber(stats?.dnssec_bogus || 0)} color={stats?.dnssec_bogus ? 'text-red-600 dark:text-red-400' : undefined} />
            </div>

            {(stats?.fallback_queries || 0) > 0 && (
              <div className="border-t border-slate-200 dark:border-slate-700 pt-2.5 mt-2.5 space-y-2.5">
                <CounterRow icon={<ShieldAlert size={13} />} label="Fallback Queries" value={formatNumber(stats?.fallback_queries || 0)} color="text-amber-600 dark:text-amber-400" />
                <CounterRow icon={<CheckCircle2 size={13} />} label="Fallback Recoveries" value={formatNumber(stats?.fallback_recoveries || 0)} color="text-emerald-600 dark:text-emerald-400" />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* TLS Certificate Status */}
      {tlsStatus?.enabled && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">TLS Certificate</h2>
            {tlsStatus.auto_tls && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400">
                Auto-TLS
              </span>
            )}
          </div>
          {tlsStatus.cert?.not_after ? (
            <div className="space-y-2.5 text-sm">
              <CounterRow icon={<Shield size={13} />} label="Domain" value={tlsStatus.cert.domain || tlsStatus.cert.subject || '—'} />
              <CounterRow icon={<Shield size={13} />} label="Issuer" value={tlsStatus.cert.issuer || '—'} />
              <CounterRow
                icon={<Clock3 size={13} />}
                label="Expires"
                value={new Date(tlsStatus.cert.not_after).toLocaleDateString()}
                color={
                  new Date(tlsStatus.cert.not_after).getTime() - Date.now() < 7 * 86400_000
                    ? 'text-red-600 dark:text-red-400'
                    : new Date(tlsStatus.cert.not_after).getTime() - Date.now() < 30 * 86400_000
                      ? 'text-amber-600 dark:text-amber-400'
                      : 'text-emerald-600 dark:text-emerald-400'
                }
              />
              {tlsStatus.cert.dns_names && tlsStatus.cert.dns_names.length > 0 && (
                <CounterRow icon={<Activity size={13} />} label="SANs" value={tlsStatus.cert.dns_names.join(', ')} />
              )}
              {tlsStatus.auto_tls && (
                <button
                  onClick={() => { api.tlsRenew().then(() => api.tlsStatus().then(setTlsStatus)).catch(() => {}) }}
                  className="mt-2 w-full text-xs py-1.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
                >
                  Force Renew
                </button>
              )}
            </div>
          ) : (
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {tlsStatus.auto_tls ? 'Certificate will be provisioned on first TLS handshake.' : 'No certificate information available.'}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

/* ── Small counter row component ──────────────────────────────── */
function CounterRow({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode
  label: string
  value: string
  color?: string
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-slate-500 dark:text-slate-400 inline-flex items-center gap-1.5">
        {icon}
        {label}
      </span>
      <span className={`font-semibold tabular-nums ${color || 'text-slate-900 dark:text-slate-100'}`}>
        {value}
      </span>
    </div>
  )
}
