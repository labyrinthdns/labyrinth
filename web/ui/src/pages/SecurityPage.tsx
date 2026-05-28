import { useEffect, useState } from 'react'
import { Lock, ShieldAlert, Activity, Cookie, RefreshCw, AlertCircle } from 'lucide-react'
import { api } from '@/api/client'
import type { SecurityStatusResponse } from '@/api/types'

// RFC 8914 §4 Extended-DNS-Error info codes — friendly names so the
// operator's "what's failing?" pivot reads as English rather than
// magic numbers. Codes 0-24 land via RFC 8914; 25-27 are post-8914
// IANA-assigned (RFC 9606, RFC 9539, RFC 9276 §3.2 respectively).
const EDE_LABELS: Record<string, string> = {
  '0': 'Other',
  '1': 'Unsupported DNSKEY Algorithm',
  '2': 'Unsupported DS Digest Type',
  '3': 'Stale Answer',
  '4': 'Forged Answer',
  '5': 'DNSSEC Indeterminate',
  '6': 'DNSSEC Bogus',
  '7': 'Signature Expired',
  '8': 'Signature Not Yet Valid',
  '9': 'DNSKEY Missing',
  '10': 'RRSIGs Missing',
  '11': 'No Zone Key Bit Set',
  '12': 'NSEC Missing',
  '13': 'Cached Error',
  '14': 'Not Ready',
  '15': 'Blocked',
  '16': 'Censored',
  '17': 'Filtered',
  '18': 'Prohibited',
  '19': 'Stale NXDOMAIN Answer',
  '20': 'Not Authoritative',
  '21': 'Not Supported',
  '22': 'No Reachable Authority',
  '23': 'Network Error',
  '24': 'Invalid Data',
  '25': 'Signature Expired Before Valid',
  '26': 'Too Early',
  '27': 'Unsupported NSEC3 Iterations',
  '28': 'Unable to Conform to Policy',
  '29': 'Synthesized',
}

// Security panel — operator-facing snapshot of the three defensive
// knobs that determine whether the resolver can be abused as an
// amplifier:
//
//   - DNS Cookies (RFC 7873): on/off + strict §5.4 mode + BADCOOKIE count.
//   - Rate limiter: per-IP query budget, total drops.
//   - RRL: per-prefix per-response-class limit, configuration.
//
// Polls /api/security on a 10s cadence. The counters move on query
// timescales so a faster poll would help, but most installations
// don't need sub-10s observability of cookie counters and the
// cost of a more aggressive poll outweighs the value.

function StatusBadge({ on, onLabel, offLabel }: { on: boolean; onLabel: string; offLabel: string }) {
  if (on) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30">
        {onLabel}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-slate-500/10 text-slate-700 dark:text-slate-400 border border-slate-500/30">
      {offLabel}
    </span>
  )
}

function Card({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-slate-500 dark:text-slate-400">{icon}</span>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
      </div>
      <div className="space-y-2 text-sm">{children}</div>
    </div>
  )
}

function Row({ label, value }: { label: React.ReactNode; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-slate-600 dark:text-slate-400">{label}</span>
      <span className="font-medium text-slate-900 dark:text-slate-100">{value}</span>
    </div>
  )
}

export default function SecurityPage() {
  const [data, setData] = useState<SecurityStatusResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function fetchData() {
    setLoading(true)
    try {
      const resp = await api.security()
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
          <h1 className="text-2xl font-semibold text-slate-900 dark:text-white">Security</h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            DNS Cookies, rate limiting, and RRL — the three knobs that decide whether this resolver can be turned into an amplifier.
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card icon={<Cookie className="h-4 w-4" />} title="DNS Cookies (RFC 7873)">
          <Row label="Status" value={<StatusBadge on={!!data?.cookies.enabled} onLabel="Enabled" offLabel="Disabled" />} />
          <Row
            label="Strict §5.4 mode"
            value={<StatusBadge on={!!data?.cookies.enforce_strict_udp} onLabel="UDP cookie-less rejected" offLabel="Permissive" />}
          />
          <Row label="BADCOOKIE responses" value={(data?.cookies.badcookie_responses ?? 0).toLocaleString()} />
          <p className="pt-2 text-xs text-slate-500 dark:text-slate-400">
            BADCOOKIE fires on either a stale post-rotation cookie OR a §5.4 cookie-less UDP rejection. The count above sums both reasons.
          </p>
        </Card>

        <Card icon={<Activity className="h-4 w-4" />} title="Rate Limit (per-IP)">
          <Row label="Status" value={<StatusBadge on={!!data?.rate_limit.enabled} onLabel="Active" offLabel="Disabled" />} />
          <Row label="Rate" value={`${data?.rate_limit.rate_per_second ?? 0} qps`} />
          <Row label="Burst" value={data?.rate_limit.burst ?? 0} />
          <Row label="Drops" value={(data?.rate_limit.rate_limited_total ?? 0).toLocaleString()} />
          <p className="pt-2 text-xs text-slate-500 dark:text-slate-400">
            Per-client token-bucket. Limits user fairness, not amplification — use RRL for that.
          </p>
        </Card>

        <Card icon={<ShieldAlert className="h-4 w-4" />} title="RRL (per-prefix amplification)">
          <Row label="Status" value={<StatusBadge on={!!data?.rrl.enabled} onLabel="Active" offLabel="Disabled" />} />
          <Row label="Responses/s" value={data?.rrl.responses_per_second ?? 0} />
          <Row label="SLIP ratio" value={`1 / ${data?.rrl.slip_ratio || '∞'}`} />
          <Row label="Prefix v4 / v6" value={`/${data?.rrl.ipv4_prefix ?? 0} · /${data?.rrl.ipv6_prefix ?? 0}`} />
          <p className="pt-2 text-xs text-slate-500 dark:text-slate-400">
            Bins responses by source prefix + response class (NXDOMAIN / error / referral / answer). Standard BIND/Knot amplification defence shape.
          </p>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
        <Card icon={<Lock className="h-4 w-4" />} title="Access Control">
          <Row label="ACL refused" value={(data?.acl_refused_total ?? 0).toLocaleString()} />
          <Row label="Blocklist blocked" value={(data?.blocklist_blocked_total ?? 0).toLocaleString()} />
          <p className="pt-2 text-xs text-slate-500 dark:text-slate-400">
            Counts of queries refused by global / per-zone ACL and queries rewritten by an active blocklist entry.
          </p>
        </Card>

        <Card icon={<AlertCircle className="h-4 w-4" />} title="Extended DNS Errors (RFC 8914)">
          {data?.ede_counts && Object.keys(data.ede_counts).length > 0 ? (
            <>
              {Object.entries(data.ede_counts)
                .sort(([, a], [, b]) => b - a)
                .map(([code, count]) => (
                  <Row
                    key={code}
                    label={
                      <span>
                        <span className="font-mono text-xs text-slate-500 dark:text-slate-500 mr-2">EDE {code}</span>
                        {EDE_LABELS[code] ?? 'Unknown'}
                      </span>
                    }
                    value={count.toLocaleString()}
                  />
                ))}
              <p className="pt-2 text-xs text-slate-500 dark:text-slate-400">
                Per-info-code count of EDEs the resolver has emitted since startup. A spike on code 6 (Bogus) means upstream zones broke; on code 17 (Filtered) means rate-limiting hit real clients.
              </p>
            </>
          ) : (
            <p className="text-xs text-slate-500 dark:text-slate-400">No EDE emissions recorded yet. Counts appear here as the resolver returns diagnostic responses.</p>
          )}
        </Card>
      </div>
    </div>
  )
}
