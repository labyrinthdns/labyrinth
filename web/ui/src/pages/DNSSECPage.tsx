import { useEffect, useState } from 'react'
import { ShieldCheck, ShieldOff, AlertTriangle, RefreshCw } from 'lucide-react'
import { api } from '@/api/client'
import type { DNSSECStatusResponse, DNSSECNTAEntry } from '@/api/types'

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

function NTARow({ nta }: { nta: DNSSECNTAEntry }) {
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
    </tr>
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
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.ntas.map(nta => (
                <NTARow key={nta.zone} nta={nta} />
              ))}
            </tbody>
          </table>
        ) : (
          <div className="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400">
            No NTAs configured. Add entries to <code className="text-xs px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-800">resolver.dnssec_negative_trust_anchors</code> in the config to install a temporary validation override for a broken zone.
          </div>
        )}
      </div>
    </div>
  )
}
