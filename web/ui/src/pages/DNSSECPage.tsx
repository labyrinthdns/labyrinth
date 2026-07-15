import { useEffect, useState } from 'react'
import { ShieldCheck, ShieldOff, AlertTriangle, RefreshCw, Plus, Trash2, ChevronDown, ChevronRight, Search } from 'lucide-react'
import { api } from '@/api/client'
import type { DNSSECStatusResponse, DNSSECNTAEntry, TrustChainResponse } from '@/api/types'

// DNSSEC operator dashboard.
//
// Surfaces the M1 (DNSSEC completeness) state to operators:
//
//   - Validator on/off + SHA-1 acceptance toggle.
//   - Cumulative NTA-override counter (how many validations were
//     short-circuited by an active RFC 7646 NTA — useful to tell at a
//     glance "is my NTA actually catching queries"). A zero counter
//     against a configured NTA usually means the NTA scope is wrong.
//   - Per-NTA status row: zone, remaining validity window, reason,
//     active vs expired flag.
//
// The page polls /api/dnssec on a 10s timer. NTAs change on operator
// timescales (minutes-to-days), not query timescales, so a long
// polling interval is correct and keeps the page idle-cheap.

function formatRemaining(seconds: number): string {
  if (seconds <= 0) return 'expired'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m`
  return `${seconds}s`
}

function StatusBadge({ enabled }: { enabled: boolean }) {
  if (enabled) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30">
        <ShieldCheck className="h-3.5 w-3.5" />
        Validation enabled
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-500/10 text-slate-700 dark:text-slate-400 border border-slate-500/30">
      <ShieldOff className="h-3.5 w-3.5" />
      Validation disabled
    </span>
  )
}

function NTARow({ nta, onRemove }: { nta: DNSSECNTAEntry; onRemove: (zone: string) => void }) {
  const expired = nta.state === 'expired'
  return (
    <tr className={expired ? 'opacity-60' : ''}>
      <td className="px-4 py-2 font-mono text-sm text-slate-900 dark:text-slate-100">{nta.zone}</td>
      <td className="px-4 py-2 text-sm">
        {expired ? (
          <span className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400">
            <AlertTriangle className="h-3.5 w-3.5" />
            expired
          </span>
        ) : (
          <span className="text-emerald-700 dark:text-emerald-400">{formatRemaining(nta.expires_in_seconds)}</span>
        )}
      </td>
      <td className="px-4 py-2 text-xs text-slate-500 dark:text-slate-400 font-mono">{nta.expires_at}</td>
      <td className="px-4 py-2 text-sm text-slate-700 dark:text-slate-300">{nta.reason || <span className="text-slate-400">—</span>}</td>
      <td className="px-4 py-2 text-right">
        <button
          onClick={() => onRemove(nta.zone)}
          className="inline-flex items-center gap-1 px-2 py-1 text-xs text-rose-700 dark:text-rose-400 hover:bg-rose-500/10 rounded-md"
          title="Remove this NTA"
        >
          <Trash2 className="h-3.5 w-3.5" />
          Remove
        </button>
      </td>
    </tr>
  )
}

// ── Trust chain explorer ────────────────────────────────────────────

type ChainLevel = NonNullable<ReturnType<typeof api.trustChain> extends Promise<infer T> ? T : never>['levels'][number]

const ALGORITHM_LABELS: Record<number, string> = {
  5: 'RSA/SHA-1', 7: 'RSASHA1-NSEC3', 8: 'RSA/SHA-256',
  10: 'RSA/SHA-512', 13: 'ECDSA/P256', 14: 'ECDSA/P384',
  15: 'Ed25519', 16: 'Ed448',
}

const DIGEST_LABELS: Record<number, string> = {
  1: 'SHA-1', 2: 'SHA-256', 3: 'GOST R 34.11-94', 4: 'SHA-384',
}

const STATUS_CONFIG: Record<string, { bg: string; text: string; label: string }> = {
  secure:     { bg: 'bg-emerald-500/10', text: 'text-emerald-700 dark:text-emerald-400', label: 'Secure' },
  insecure:   { bg: 'bg-slate-500/10', text: 'text-slate-600 dark:text-slate-400', label: 'Insecure' },
  bogus:      { bg: 'bg-rose-500/10', text: 'text-rose-700 dark:text-rose-400', label: 'Bogus' },
  unreachable: { bg: 'bg-amber-500/10', text: 'text-amber-700 dark:text-amber-400', label: 'Unreachable' },
  unknown:    { bg: 'bg-slate-500/10', text: 'text-slate-600 dark:text-slate-400', label: 'Unknown' },
}

function algLabel(a: number): string {
  return ALGORITHM_LABELS[a] || `Alg ${a}`
}

function TrustChainPanel() {
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [chain, setChain] = useState<TrustChainResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  async function handleSearch() {
    const name = query.trim()
    if (!name) return
    setLoading(true)
    setError(null)
    setChain(null)
    try {
      const resp = await api.trustChain(name)
      setChain(resp)
      // Auto-expand all levels by default
      setExpanded(new Set(resp.levels.map((_, i) => i)))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch trust chain')
    } finally {
      setLoading(false)
    }
  }

  function toggleLevel(idx: number) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
  }

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg mb-6 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-emerald-500" />
          DNSSEC Trust Chain Explorer
        </h2>
        <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
          View the DNSKEY/DS delegation chain for any domain. Traces the chain of trust from root to the queried zone.
        </p>
      </div>

      {/* Search bar */}
      <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30">
        <form
          onSubmit={(e) => { e.preventDefault(); handleSearch() }}
          className="flex gap-2"
        >
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="example.com"
            className="flex-1 px-3 py-1.5 text-sm border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 rounded-md focus:outline-none focus:ring-1 focus:ring-amber-500"
          />
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-amber-600 hover:bg-amber-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-md"
          >
            <Search className="h-4 w-4" />
            {loading ? 'Tracing...' : 'Trace'}
          </button>
        </form>
      </div>

      {error && (
        <div className="mx-4 mt-3 p-3 rounded-md bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-400 text-xs">
          {error}
        </div>
      )}

      {/* Chain visualization */}
      {chain && chain.levels.length > 0 && (
        <div className="px-4 py-3 space-y-1">
          {chain.levels.map((level, idx) => (
            <div key={level.zone}>
              {/* Level header — always visible */}
              <button
                onClick={() => toggleLevel(idx)}
                className="w-full flex items-center gap-2 px-3 py-2 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 text-left"
              >
                <div className={`w-2 h-2 rounded-full shrink-0 ${
                  level.status === 'secure' ? 'bg-emerald-500' :
                  level.status === 'bogus' ? 'bg-rose-500' :
                  level.status === 'unreachable' ? 'bg-amber-500' :
                  'bg-slate-400'
                }`} />
                <span className="text-sm font-mono text-slate-900 dark:text-white">{level.zone || '(root)'}</span>
                <span className={`text-[11px] px-1.5 py-0.5 rounded-full ${STATUS_CONFIG[level.status]?.bg || ''} ${STATUS_CONFIG[level.status]?.text || ''}`}>
                  {STATUS_CONFIG[level.status]?.label || level.status}
                </span>
                <span className="ml-auto text-slate-400">
                  {expanded.has(idx) ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                </span>
              </button>

              {/* Expanded details */}
              {expanded.has(idx) && (
                <div className="ml-5 pl-3 border-l-2 border-slate-200 dark:border-slate-700 space-y-2 py-2">
                  {level.error && (
                    <div className="text-xs text-rose-600 dark:text-rose-400">{level.error}</div>
                  )}

                  {/* DNSKEY records */}
                  {level.dnskey && level.dnskey.length > 0 && (
                    <div>
                      <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                        DNSKEY ({level.dnskey.length})
                      </h4>
                      <div className="space-y-1">
                        {level.dnskey.map((k, ki) => (
                          <div key={ki} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs font-mono bg-slate-50 dark:bg-slate-950 rounded px-2 py-1.5">
                            <span className={`px-1 rounded text-[10px] font-medium ${
                              k.flags === 257 ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-300' :
                              'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-800 dark:text-cyan-300'
                            }`}>
                              {k.flags === 257 ? 'KSK' : 'ZSK'}
                            </span>
                            <span className="text-slate-600 dark:text-slate-400">tag={k.key_tag}</span>
                            <span className="text-slate-600 dark:text-slate-400">{algLabel(k.algorithm)}</span>
                            <span className="text-slate-400 text-[10px] truncate max-w-[200px]" title={k.key_data}>
                              key={k.key_data.slice(0, 32)}...
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* DS records */}
                  {level.ds && level.ds.length > 0 && (
                    <div>
                      <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                        DS records ({level.ds.length})
                      </h4>
                      <div className="space-y-1">
                        {level.ds.map((ds, di) => (
                          <div key={di} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs font-mono bg-slate-50 dark:bg-slate-950 rounded px-2 py-1.5">
                            <span className="text-slate-600 dark:text-slate-400">tag={ds.key_tag}</span>
                            <span className="text-slate-600 dark:text-slate-400">{algLabel(ds.algorithm)}</span>
                            <span className="text-slate-600 dark:text-slate-400">{DIGEST_LABELS[ds.digest_type] || `Digest ${ds.digest_type}`}</span>
                            <span className="text-slate-400 text-[10px] truncate max-w-[200px]" title={ds.digest}>
                              {ds.digest.slice(0, 32)}...
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* No keys */}
                  {(!level.dnskey || level.dnskey.length === 0) && !level.error && (
                    <div className="text-xs text-slate-400 dark:text-slate-500 italic">
                      No DNSSEC records at this level
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Empty state */}
      {chain && chain.levels.length === 0 && (
        <div className="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400">
          No delegation chain found for this domain.
        </div>
      )}

      {/* No query yet */}
      {!chain && !error && (
        <div className="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400">
          Enter a domain name above to trace its DNSSEC trust chain.
        </div>
      )}
    </div>
  )
}

// ── NTA management ──────────────────────────────────────────────────

function AddNTAForm({ onAdded }: { onAdded: () => void }) {
  const [zone, setZone] = useState('')
  const [hours, setHours] = useState(24)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!zone.trim()) return
    setBusy(true)
    setError(null)
    try {
      await api.addNTA(zone.trim(), hours, reason.trim())
      setZone('')
      setReason('')
      setHours(24)
      onAdded()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to add')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="px-4 py-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-3">Add Negative Trust Anchor</h3>
      <div className="grid grid-cols-1 sm:grid-cols-12 gap-2 items-end">
        <div className="sm:col-span-4">
          <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">Zone</label>
          <input
            type="text"
            value={zone}
            onChange={e => setZone(e.target.value)}
            placeholder="example.test"
            required
            className="w-full px-2 py-1.5 text-sm border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 rounded-md focus:outline-none focus:ring-1 focus:ring-amber-500"
          />
        </div>
        <div className="sm:col-span-2">
          <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">Hours (max 720)</label>
          <input
            type="number"
            min={1}
            max={720}
            value={hours}
            onChange={e => setHours(Number(e.target.value) || 24)}
            className="w-full px-2 py-1.5 text-sm border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 rounded-md focus:outline-none focus:ring-1 focus:ring-amber-500"
          />
        </div>
        <div className="sm:col-span-4">
          <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">Reason</label>
          <input
            type="text"
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="incident #1234"
            className="w-full px-2 py-1.5 text-sm border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 rounded-md focus:outline-none focus:ring-1 focus:ring-amber-500"
          />
        </div>
        <div className="sm:col-span-2">
          <button
            type="submit"
            disabled={busy || !zone.trim()}
            className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-amber-600 hover:bg-amber-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-md"
          >
            <Plus className="h-4 w-4" />
            Install
          </button>
        </div>
      </div>
      {error && (
        <div className="mt-2 text-xs text-rose-600 dark:text-rose-400">{error}</div>
      )}
    </form>
  )
}

export default function DNSSECPage() {
  const [data, setData] = useState<DNSSECStatusResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function fetchData() {
    setLoading(true)
    try {
      const resp = await api.dnssec()
      setData(resp)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to fetch')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 10_000)
    return () => clearInterval(id)
  }, [])

  async function handleRemove(zone: string) {
    if (!confirm(`Remove NTA for ${zone}?`)) return
    try {
      await api.removeNTA(zone)
      fetchData()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to remove')
    }
  }

  return (
    <div className="px-4 sm:px-6 lg:px-8 py-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 dark:text-white">DNSSEC</h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            Validator state, RFC 7646 Negative Trust Anchors, and signed-zone observability.
          </p>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-1.5 text-sm font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-md hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-md bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-400 text-sm">
          {error}
        </div>
      )}

      {/* Status cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-2">Validator</div>
          <StatusBadge enabled={data?.enabled ?? false} />
          {data?.enabled && (
            <p className="mt-2 text-xs text-slate-600 dark:text-slate-400">
              SHA-1 primitives: {data.allow_sha1 ? <strong className="text-amber-600">accepted (legacy)</strong> : <strong className="text-emerald-600">rejected</strong>}
            </p>
          )}
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-2">Active NTAs</div>
          <div className="text-2xl font-semibold text-slate-900 dark:text-white">
            {data?.nta_count ?? 0}
          </div>
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
            Negative trust anchors installed (RFC 7646).
          </p>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-2">NTA overrides</div>
          <div className="text-2xl font-semibold text-slate-900 dark:text-white">
            {data?.nta_matches?.toLocaleString() ?? '0'}
          </div>
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
            Cumulative validations suppressed by an active NTA.
          </p>
        </div>
      </div>

      {/* M5.5 safety-net values */}
      {data?.safety_net && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 mb-6">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white mb-1">Validation Safety Net</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
            Bounds the worst-case CPU and network cost a hostile authoritative can induce per validation. Values reflect the resolver's actual runtime constants.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-md border border-slate-200 dark:border-slate-800 p-3 bg-slate-50 dark:bg-slate-950">
              <div className="text-xs text-slate-500 dark:text-slate-400">Max RRSIG verify attempts</div>
              <div className="text-xl font-semibold text-slate-900 dark:text-white font-mono mt-0.5">{data.safety_net.max_rrsig_verify_attempts}</div>
              <div className="text-[10px] text-slate-500 dark:text-slate-500 mt-1">RFC 4035 §5.3.3 — bounds crypto verifies per RRset</div>
            </div>
            <div className="rounded-md border border-slate-200 dark:border-slate-800 p-3 bg-slate-50 dark:bg-slate-950">
              <div className="text-xs text-slate-500 dark:text-slate-400">Max trust-chain depth</div>
              <div className="text-xl font-semibold text-slate-900 dark:text-white font-mono mt-0.5">{data.safety_net.max_trust_chain_depth}</div>
              <div className="text-[10px] text-slate-500 dark:text-slate-500 mt-1">Caps DNSKEY+DS fetch round-trips per chain walk</div>
            </div>
          </div>
        </div>
      )}

      {/* Trust chain explorer */}
      <TrustChainPanel />

      {/* NTA list */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Negative Trust Anchors</h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Configured via <code className="text-xs px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-800">resolver.dnssec_negative_trust_anchors</code> (format: <code>zone|RFC3339-expiry|reason</code>).
          </p>
        </div>
        {data?.ntas && data.ntas.length > 0 ? (
          <table className="w-full">
            <thead className="bg-slate-50 dark:bg-slate-800/50">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">Zone</th>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">Remaining</th>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">Expires</th>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">Reason</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.ntas.map(nta => (
                <NTARow key={nta.zone} nta={nta} onRemove={handleRemove} />
              ))}
            </tbody>
          </table>
        ) : (
          <div className="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400">
            No NTAs configured. Use the form below to install a temporary validation override, or add entries to <code className="text-xs px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-800">resolver.dnssec_negative_trust_anchors</code> for permanence across restarts.
          </div>
        )}
        {data?.enabled && <AddNTAForm onAdded={fetchData} />}
      </div>
    </div>
  )
}
