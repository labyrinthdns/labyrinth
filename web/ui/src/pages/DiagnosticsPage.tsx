import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertCircle,
  Bug,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDashed,
  Loader2,
  Play,
  Square,
  XCircle,
} from 'lucide-react'
import { createDiagnosticsTraceSocket } from '@/api/client'
import type {
  TraceEvent,
  TraceResult,
  TraceServerMsg,
  TraceStatus,
} from '@/api/types'

// Stages, in pipeline order. Each stage card shows the most recent event for
// that stage as the "pipeline status"; full event log below shows every
// individual emit so you can see the timeline.
const PIPELINE_STAGES = [
  { id: 'start',          label: 'Start',         hint: 'Trace launched, options resolved' },
  { id: 'local-zones',    label: 'Local zones',   hint: 'Matched against zones served locally' },
  { id: 'cache',          label: 'Answer cache',  hint: 'Resolver answer cache lookup' },
  { id: 'forward-zones',  label: 'Forward/stub',  hint: 'Forwarding or stub-zone match' },
  { id: 'iterative-step', label: 'Iterative',     hint: 'Root-to-leaf iterative resolution' },
  { id: 'delegation',     label: 'Delegation',    hint: 'Referrals walked from parent to child' },
  { id: 'upstream',       label: 'Upstream',      hint: 'Each authoritative DNS query' },
  { id: 'classify',       label: 'Classify',      hint: 'Response interpretation per RFC 1034/9156' },
  { id: 'cname',          label: 'CNAME / DNAME', hint: 'Alias chase to a different name' },
  { id: 'dnssec',         label: 'DNSSEC',        hint: 'Trust chain & signature verification' },
  { id: 'fallback',       label: 'Fallback',      hint: 'Public-resolver fallback (if configured)' },
  { id: 'finish',         label: 'Finish',        hint: 'Resolver returned to caller' },
] as const

type StageId = (typeof PIPELINE_STAGES)[number]['id']

const QUERY_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV', 'DNSKEY', 'DS'] as const

function statusIcon(status: TraceStatus, size = 'h-4 w-4') {
  switch (status) {
    case 'ok':
      return <CheckCircle2 className={`${size} text-emerald-500`} />
    case 'warn':
      return <AlertCircle className={`${size} text-amber-500`} />
    case 'error':
      return <XCircle className={`${size} text-rose-500`} />
  }
  return <CircleDashed className={`${size} text-slate-400`} />
}

function statusRingClass(status: TraceStatus | 'pending') {
  switch (status) {
    case 'ok':
      return 'border-emerald-500/60 bg-emerald-500/5 dark:bg-emerald-500/10'
    case 'warn':
      return 'border-amber-500/60 bg-amber-500/5 dark:bg-amber-500/10'
    case 'error':
      return 'border-rose-500/60 bg-rose-500/5 dark:bg-rose-500/10'
    case 'info':
      return 'border-sky-500/40 bg-sky-500/5 dark:bg-sky-500/10'
  }
  return 'border-slate-200 dark:border-slate-800 bg-white/40 dark:bg-slate-900/40'
}

function formatDetails(d: unknown): string | null {
  if (!d || typeof d !== 'object') return null
  try {
    return JSON.stringify(d, null, 2)
  } catch {
    return null
  }
}

interface StageState {
  status: TraceStatus | 'pending'
  message?: string
  elapsedMs?: number
  count: number
}

export default function DiagnosticsPage() {
  const [name, setName] = useState('mirrormanager.fedoraproject.org')
  const [qtype, setQtype] = useState<(typeof QUERY_TYPES)[number]>('A')
  const [bypassCache, setBypassCache] = useState(true)
  const [skipDNSSEC, setSkipDNSSEC] = useState(false)
  const [running, setRunning] = useState(false)
  const [events, setEvents] = useState<TraceEvent[]>([])
  const [result, setResult] = useState<TraceResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [expandedDetails, setExpandedDetails] = useState<Record<number, boolean>>({})
  const wsRef = useRef<WebSocket | null>(null)
  const logEndRef = useRef<HTMLDivElement | null>(null)

  // Aggregate per-stage state for the pipeline cards.
  const stageState = useMemo(() => {
    const state: Record<StageId, StageState> = Object.fromEntries(
      PIPELINE_STAGES.map((s) => [s.id, { status: 'pending' as const, count: 0 }]),
    ) as Record<StageId, StageState>
    for (const ev of events) {
      const id = ev.stage as StageId
      if (!(id in state)) continue
      const prev = state[id]
      // Worst-status wins so the pipeline truthfully shows a failed stage even
      // if a later same-stage event was just informational. error > warn > ok > info.
      const rank: Record<TraceStatus | 'pending', number> = {
        pending: -1, info: 0, ok: 1, warn: 2, error: 3,
      }
      const next: StageState = {
        status: rank[ev.status] > rank[prev.status] ? ev.status : prev.status,
        message: ev.message,
        elapsedMs: ev.elapsed_ms,
        count: prev.count + 1,
      }
      state[id] = next
    }
    return state
  }, [events])

  const stuckAt = useMemo(() => {
    // The "stuck point": first error event, or last warn if no error. Used to
    // highlight where the pipeline died.
    const errEvt = events.find((e) => e.status === 'error')
    if (errEvt) return errEvt
    const warns = events.filter((e) => e.status === 'warn')
    return warns.length > 0 ? warns[warns.length - 1] : null
  }, [events])

  const cleanup = useCallback(() => {
    if (wsRef.current) {
      try { wsRef.current.close() } catch { /* noop */ }
      wsRef.current = null
    }
    setRunning(false)
  }, [])

  useEffect(() => () => cleanup(), [cleanup])

  // Autoscroll log to bottom on new events while running.
  useEffect(() => {
    if (running && logEndRef.current) {
      logEndRef.current.scrollIntoView({ block: 'end' })
    }
  }, [events, running])

  function startTrace(e: React.FormEvent) {
    e.preventDefault()
    if (running) return
    setEvents([])
    setResult(null)
    setError(null)
    setExpandedDetails({})

    const ws = createDiagnosticsTraceSocket()
    wsRef.current = ws
    setRunning(true)

    ws.onopen = () => {
      ws.send(JSON.stringify({
        action: 'start',
        name,
        type: qtype,
        bypass_cache: bypassCache,
        skip_dnssec: skipDNSSEC,
      }))
    }
    ws.onmessage = (m) => {
      let msg: TraceServerMsg
      try {
        msg = JSON.parse(m.data) as TraceServerMsg
      } catch {
        return
      }
      if (msg.kind === 'event') {
        setEvents((prev) => [...prev, msg.event])
      } else if (msg.kind === 'result') {
        setResult(msg.result)
        setRunning(false)
        try { ws.close() } catch { /* noop */ }
      } else if (msg.kind === 'error' || msg.kind === 'busy') {
        setError(msg.error)
        setRunning(false)
        try { ws.close() } catch { /* noop */ }
      }
    }
    ws.onerror = () => {
      setError('WebSocket connection error')
      setRunning(false)
    }
    ws.onclose = () => {
      setRunning(false)
    }
  }

  function cancelTrace() {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      try {
        wsRef.current.send(JSON.stringify({ action: 'cancel' }))
      } catch { /* noop */ }
    }
    cleanup()
  }

  return (
    <div className="p-4 md:p-6 space-y-6">
      <header className="flex items-center gap-3">
        <Bug className="h-6 w-6 text-amber-600" />
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">DNS Lookup Diagnostics</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Resolver'ın bir alan adını çözerken geçtiği her aşamayı canlı izleyin. Hangi adımda takıldığını ve
            ne dönen ne hatayla karşılaştığını görebilirsiniz.
          </p>
        </div>
      </header>

      {/* Form */}
      <form onSubmit={startTrace} className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-6 gap-3">
          <div className="md:col-span-3">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Domain</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="mirrormanager.fedoraproject.org"
              required
              disabled={running}
              className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm font-mono text-slate-900 dark:text-slate-100 focus:border-amber-500 focus:outline-none focus:ring-1 focus:ring-amber-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Type</label>
            <select
              value={qtype}
              onChange={(e) => setQtype(e.target.value as (typeof QUERY_TYPES)[number])}
              disabled={running}
              className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm text-slate-900 dark:text-slate-100 focus:border-amber-500 focus:outline-none focus:ring-1 focus:ring-amber-500"
            >
              {QUERY_TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div className="md:col-span-2 flex items-end gap-2">
            {!running ? (
              <button
                type="submit"
                className="inline-flex items-center justify-center gap-2 rounded-md bg-amber-600 px-4 py-2 text-sm font-medium text-white hover:bg-amber-700 disabled:opacity-50"
              >
                <Play className="h-4 w-4" /> Trace
              </button>
            ) : (
              <button
                type="button"
                onClick={cancelTrace}
                className="inline-flex items-center justify-center gap-2 rounded-md bg-rose-600 px-4 py-2 text-sm font-medium text-white hover:bg-rose-700"
              >
                <Square className="h-4 w-4" /> Cancel
              </button>
            )}
            {running && <Loader2 className="h-5 w-5 animate-spin text-amber-600" />}
          </div>
        </div>
        <div className="flex flex-wrap gap-4 text-sm">
          <label className="inline-flex items-center gap-2 text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={bypassCache}
              onChange={(e) => setBypassCache(e.target.checked)}
              disabled={running}
              className="rounded border-slate-300 text-amber-600 focus:ring-amber-500"
            />
            Cache'i bypass et (gerçek ağ trafiği gör)
          </label>
          <label className="inline-flex items-center gap-2 text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={skipDNSSEC}
              onChange={(e) => setSkipDNSSEC(e.target.checked)}
              disabled={running}
              className="rounded border-slate-300 text-amber-600 focus:ring-amber-500"
            />
            DNSSEC doğrulamayı atla (validator sebep mi diye anlamak için)
          </label>
        </div>
      </form>

      {error && (
        <div className="rounded-md border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950/30 p-3 text-sm text-rose-700 dark:text-rose-300 flex items-start gap-2">
          <AlertCircle className="h-5 w-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Pipeline cards */}
      <section>
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">Pipeline</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
          {PIPELINE_STAGES.map((stage) => {
            const s = stageState[stage.id]
            const isStuckHere = stuckAt && stuckAt.stage === stage.id
            return (
              <div
                key={stage.id}
                className={`rounded-lg border p-3 transition ${statusRingClass(s.status)} ${
                  isStuckHere ? 'ring-2 ring-rose-500/60 dark:ring-rose-400/60' : ''
                }`}
                title={stage.hint}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {statusIcon(s.status === 'pending' ? 'info' : s.status)}
                    <span className="text-xs font-medium text-slate-800 dark:text-slate-200">{stage.label}</span>
                  </div>
                  {s.count > 0 && (
                    <span className="text-[10px] text-slate-500 dark:text-slate-400">{s.count}</span>
                  )}
                </div>
                {s.message && (
                  <p className="mt-1 text-[11px] leading-tight text-slate-600 dark:text-slate-400 line-clamp-2 break-words">
                    {s.message}
                  </p>
                )}
                {typeof s.elapsedMs === 'number' && s.count > 0 && (
                  <p className="mt-1 text-[10px] text-slate-400 dark:text-slate-500">
                    @{s.elapsedMs}ms
                  </p>
                )}
              </div>
            )
          })}
        </div>
        {stuckAt && stuckAt.status === 'error' && (
          <p className="mt-2 text-xs text-rose-600 dark:text-rose-400">
            <strong>Takıldığı yer:</strong> {stuckAt.stage} — {stuckAt.message}
          </p>
        )}
      </section>

      {/* Result panel */}
      {result && (
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Result</h2>
            <span className="text-[11px] text-slate-500 dark:text-slate-400">{result.elapsed_ms}ms</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs mb-3">
            <div>
              <div className="text-slate-500 dark:text-slate-400">RCODE</div>
              <div className={`font-mono ${result.rcode === 'NOERROR' ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}>
                {result.rcode}
              </div>
            </div>
            <div>
              <div className="text-slate-500 dark:text-slate-400">DNSSEC</div>
              <div className="font-mono text-slate-800 dark:text-slate-200">{result.dnssec_status || 'n/a'}</div>
            </div>
            <div>
              <div className="text-slate-500 dark:text-slate-400">Answers</div>
              <div className="font-mono text-slate-800 dark:text-slate-200">{result.answers?.length ?? 0}</div>
            </div>
            <div>
              <div className="text-slate-500 dark:text-slate-400">Authority</div>
              <div className="font-mono text-slate-800 dark:text-slate-200">{result.authority?.length ?? 0}</div>
            </div>
          </div>
          {result.error && (
            <p className="text-xs text-rose-600 dark:text-rose-400 mb-2">Error: {result.error}</p>
          )}
          {result.answers && result.answers.length > 0 && (
            <div className="font-mono text-xs space-y-1 bg-slate-50 dark:bg-slate-950 rounded p-2 max-h-64 overflow-y-auto">
              {result.answers.map((rr, i) => (
                <div key={i} className="text-slate-800 dark:text-slate-200">
                  {rr.name}. {rr.ttl} IN {rr.type} {rr.data}
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Event log */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
        <header className="flex items-center justify-between p-3 border-b border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Log</h2>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">{events.length} event(s)</span>
        </header>
        <div className="max-h-[480px] overflow-y-auto">
          {events.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500 dark:text-slate-400">
              Trace başlatın — sonuçlar burada görünecek.
            </div>
          ) : (
            <ol className="divide-y divide-slate-100 dark:divide-slate-800">
              {events.map((ev) => {
                const details = formatDetails(ev.details)
                const expanded = expandedDetails[ev.seq] ?? false
                return (
                  <li key={ev.seq} className="px-3 py-2 text-xs flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-950/50">
                    <div className="mt-0.5">{statusIcon(ev.status)}</div>
                    <div className="font-mono text-slate-500 dark:text-slate-400 w-12 flex-shrink-0 text-right">
                      +{ev.elapsed_ms}ms
                    </div>
                    <div className="font-mono text-slate-700 dark:text-slate-300 w-24 flex-shrink-0 truncate">
                      {ev.stage}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-slate-800 dark:text-slate-200 break-words">{ev.message}</div>
                      {details && (
                        <>
                          <button
                            onClick={() => setExpandedDetails((prev) => ({ ...prev, [ev.seq]: !expanded }))}
                            className="mt-1 inline-flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-700 dark:text-slate-500 dark:hover:text-slate-300"
                          >
                            {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                            details
                          </button>
                          {expanded && (
                            <pre className="mt-1 bg-slate-50 dark:bg-slate-950 rounded p-2 text-[11px] overflow-x-auto text-slate-700 dark:text-slate-300">
                              {details}
                            </pre>
                          )}
                        </>
                      )}
                    </div>
                  </li>
                )
              })}
              <div ref={logEndRef} />
            </ol>
          )}
        </div>
      </section>
    </div>
  )
}
