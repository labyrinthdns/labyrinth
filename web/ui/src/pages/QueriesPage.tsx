import { Pause, Play, Trash2, Wifi, WifiOff, Shield } from 'lucide-react'
import { useQueryStream } from '@/hooks/useWebSocket'
import { formatDuration } from '@/lib/utils'

const RCODE_STYLES: Record<string, string> = {
  NOERROR: 'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400',
  NXDOMAIN: 'bg-yellow-100 dark:bg-yellow-900/40 text-yellow-700 dark:text-yellow-400',
  SERVFAIL: 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-400',
  REFUSED: 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-400',
}

function RcodeBadge({ rcode }: { rcode: string }) {
  const style = RCODE_STYLES[rcode] || 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${style}`}>
      {rcode}
    </span>
  )
}

function CachedBadge({ cached }: { cached: boolean }) {
  if (!cached) return <span className="text-xs text-slate-400">--</span>
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400">
      Cached
    </span>
  )
}

export default function QueriesPage() {
  const { queries, connected, paused, setPaused, clear } = useQueryStream(200)

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Live Queries
          </h1>
          <div className="flex items-center gap-1.5">
            {connected ? (
              <>
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" />
                </span>
                <span className="text-xs text-green-600 dark:text-green-400 font-medium">
                  Connected
                </span>
              </>
            ) : (
              <>
                <WifiOff size={14} className="text-red-500" />
                <span className="text-xs text-red-500 font-medium">
                  Disconnected
                </span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPaused(!paused)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              paused
                ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 hover:bg-green-200 dark:hover:bg-green-900/50'
                : 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 hover:bg-amber-200 dark:hover:bg-amber-900/50'
            }`}
          >
            {paused ? <Play size={14} /> : <Pause size={14} />}
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            onClick={clear}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
          >
            <Trash2 size={14} />
            Clear
          </button>
          <div className="text-xs text-slate-400 ml-2">
            {queries.length} entries
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
        <div className="overflow-x-auto max-h-[calc(100vh-220px)] overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 dark:bg-slate-900 sticky top-0 z-10">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  #
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Time
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Client
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Domain
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Type
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  RCode
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Cached
                </th>
                <th className="text-right px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Duration
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {queries.length === 0 ? (
                <tr>
                  <td
                    colSpan={8}
                    className="px-4 py-12 text-center text-slate-400 dark:text-slate-500"
                  >
                    <div className="flex flex-col items-center gap-2">
                      <Wifi size={24} className="text-slate-300 dark:text-slate-600" />
                      <p>Waiting for queries...</p>
                      <p className="text-xs">
                        Queries will appear here in real-time
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                queries.map((q) => (
                  <tr
                    key={q.id}
                    className="hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors"
                  >
                    <td className="px-4 py-2.5 text-xs font-mono text-slate-400 dark:text-slate-500 whitespace-nowrap">
                      {q.global_num ?? q.id}
                    </td>
                    <td className="px-4 py-2.5 text-xs font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {new Date(q.ts).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-2.5 text-xs font-mono text-slate-600 dark:text-slate-300 whitespace-nowrap">
                      {q.client}
                      {q.client_num != null && (
                        <span className="ml-1.5 text-xs text-slate-400">#{q.client_num}</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-slate-900 dark:text-slate-100 font-medium max-w-xs truncate">
                      {q.qname}
                    </td>
                    <td className="px-4 py-2.5 text-xs font-mono text-slate-500 dark:text-slate-400">
                      {q.qtype}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        {q.blocked ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-400">
                            <Shield size={10} />
                            Blocked
                          </span>
                        ) : (
                          <RcodeBadge rcode={q.rcode} />
                        )}
                        {q.dnssec_status === 'secure' && (
                          <span title="DNSSEC Secure">
                            <Shield size={12} className="text-green-500 dark:text-green-400" />
                          </span>
                        )}
                        {q.dnssec_status === 'bogus' && (
                          <span title="DNSSEC Bogus">
                            <Shield size={12} className="text-red-500 dark:text-red-400" />
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <CachedBadge cached={q.cached} />
                    </td>
                    <td className="px-4 py-2.5 text-right text-xs font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {formatDuration(q.duration_ms)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
