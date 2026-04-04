import { useState, useEffect, useCallback, useMemo, useRef, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Trash2, RefreshCw, Search, Check, X, Loader2, Download } from 'lucide-react'
import { api } from '@/api/client'
import type { BlocklistStats, BlocklistListEntry } from '@/api/types'
import { formatNumber } from '@/lib/utils'

function StatCard({
  label,
  value,
  color,
}: {
  label: string
  value: string
  color: string
}) {
  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-5 shadow-sm">
      <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
    </div>
  )
}

export default function BlocklistPage() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<BlocklistStats | null>(null)
  const [lists, setLists] = useState<BlocklistListEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [message, setMessage] = useState('')
  const [messageType, setMessageType] = useState<'success' | 'error'>('success')
  const [listFilter, setListFilter] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [refreshMs, setRefreshMs] = useState(60000)

  // Quick block/unblock
  const [blockDomain, setBlockDomain] = useState('')
  const [blocking, setBlocking] = useState(false)
  const [unblocking, setUnblocking] = useState(false)

  // Check domain
  const [checkDomain, setCheckDomain] = useState('')
  const [checking, setChecking] = useState(false)
  const [checkResult, setCheckResult] = useState<{ domain: string; blocked: boolean } | null>(null)

  const messageTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (messageTimerRef.current) clearTimeout(messageTimerRef.current)
    }
  }, [])

  function showMessage(msg: string, type: 'success' | 'error' = 'success') {
    setMessage(msg)
    setMessageType(type)
    if (messageTimerRef.current) clearTimeout(messageTimerRef.current)
    messageTimerRef.current = setTimeout(() => setMessage(''), 4000)
  }

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, listsRes] = await Promise.all([
        api.blocklistStats(),
        api.blocklistLists(),
      ])
      setStats(statsRes)
      setLists(listsRes.lists || [])
    } catch {
      // silently ignore
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  useEffect(() => {
    if (!autoRefresh) return
    const interval = setInterval(() => {
      if (document.hidden) return
      void fetchData()
    }, refreshMs)
    return () => clearInterval(interval)
  }, [autoRefresh, refreshMs, fetchData])

  async function handleRefreshAll() {
    setRefreshing(true)
    try {
      await api.blocklistRefresh()
      showMessage('All lists refreshed successfully')
      fetchData()
    } catch (err) {
      showMessage(err instanceof Error ? err.message : 'Refresh failed', 'error')
    } finally {
      setRefreshing(false)
    }
  }

  async function handleBlock(e: FormEvent) {
    e.preventDefault()
    if (!blockDomain.trim()) return

    setBlocking(true)
    try {
      await api.blocklistBlock(blockDomain.trim())
      showMessage(`Blocked: ${blockDomain.trim()}`)
      setBlockDomain('')
      fetchData()
    } catch (err) {
      showMessage(err instanceof Error ? err.message : 'Block failed', 'error')
    } finally {
      setBlocking(false)
    }
  }

  async function handleUnblock() {
    if (!blockDomain.trim()) return

    setUnblocking(true)
    try {
      await api.blocklistUnblock(blockDomain.trim())
      showMessage(`Unblocked: ${blockDomain.trim()}`)
      setBlockDomain('')
      fetchData()
    } catch (err) {
      showMessage(err instanceof Error ? err.message : 'Unblock failed', 'error')
    } finally {
      setUnblocking(false)
    }
  }

  async function handleCheck(e: FormEvent) {
    e.preventDefault()
    if (!checkDomain.trim()) return

    setChecking(true)
    setCheckResult(null)
    try {
      const res = await api.blocklistCheck(checkDomain.trim())
      setCheckResult(res)
    } catch (err) {
      showMessage(err instanceof Error ? err.message : 'Check failed', 'error')
    } finally {
      setChecking(false)
    }
  }

  const inputClass =
    'bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg px-3 py-2 w-full text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-amber-600/50 focus:border-amber-600 transition-colors'

  const filteredLists = useMemo(() => {
    const needle = listFilter.trim().toLowerCase()
    if (!needle) return lists
    return lists.filter((list) =>
      `${list.url} ${list.format} ${list.last_update || ''} ${list.error || ''}`.toLowerCase().includes(needle),
    )
  }, [lists, listFilter])

  function exportListsCSV() {
    if (filteredLists.length === 0) return
    const lines: string[] = []
    lines.push('url,format,enabled,rule_count,last_update,error')
    filteredLists.forEach((list) => {
      lines.push([
        `"${list.url.replace(/"/g, '""')}"`,
        list.format,
        list.enabled ? 'true' : 'false',
        String(list.rule_count),
        `"${(list.last_update || '').replace(/"/g, '""')}"`,
        `"${(list.error || '').replace(/"/g, '""')}"`,
      ].join(','))
    })
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `labyrinth-blocklists-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <Shield size={24} className="text-amber-600 dark:text-amber-400" />
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
          Blocklist
        </h1>
        <button
          onClick={() => setAutoRefresh((v) => !v)}
          className={`ml-auto px-2.5 py-1.5 rounded-lg text-xs font-medium border ${autoRefresh ? 'bg-sky-100 dark:bg-sky-900/30 border-sky-300 dark:border-sky-700 text-sky-700 dark:text-sky-300' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300'}`}
        >
          Auto refresh
        </button>
        <div className="inline-flex items-center gap-1 rounded-lg border border-slate-300 dark:border-slate-600 px-2 py-1 text-xs bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300">
          <span>Every</span>
          <select value={refreshMs} onChange={(e) => setRefreshMs(Number(e.target.value))} className="bg-transparent outline-none">
            <option value={30000} className="text-slate-900">30s</option>
            <option value={60000} className="text-slate-900">60s</option>
          </select>
        </div>
      </div>

      {/* Status message */}
      {message && (
        <div
          className={`text-sm rounded-lg px-4 py-3 ${
            messageType === 'success'
              ? 'bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800 text-green-700 dark:text-green-400'
              : 'bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400'
          }`}
        >
          {message}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 size={24} className="animate-spin text-amber-600" />
        </div>
      ) : (
        <>
          {/* Stats cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <StatCard
              label="Total Rules"
              value={stats ? formatNumber(stats.total_rules) : '0'}
              color="text-slate-900 dark:text-slate-100"
            />
            <StatCard
              label="Total Blocked"
              value={stats ? formatNumber(stats.blocked_total) : '0'}
              color="text-red-600 dark:text-red-400"
            />
            <StatCard
              label="Blocking Mode"
              value={stats?.blocking_mode || 'N/A'}
              color="text-amber-600 dark:text-amber-400"
            />
          </div>

          {/* List management */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 shadow-sm">
            <div className="flex items-center justify-between p-6 pb-4">
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
                <Shield size={16} />
                Block Lists
              </h2>
              <div className="flex items-center gap-2">
                <input
                  value={listFilter}
                  onChange={(e) => setListFilter(e.target.value)}
                  placeholder="Filter lists..."
                  className="rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-2.5 py-1.5 text-xs text-slate-900 dark:text-slate-100"
                />
                <button
                  onClick={exportListsCSV}
                  disabled={filteredLists.length === 0}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors disabled:opacity-50"
                >
                  <Download size={14} />
                  CSV
                </button>
                <button
                  onClick={handleRefreshAll}
                  disabled={refreshing}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 hover:bg-amber-200 dark:hover:bg-amber-900/50 transition-colors"
                >
                  <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
                  Refresh All
                </button>
              </div>
            </div>

            <div className="px-6 pb-4">
              <div className="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
                Source add/remove is managed in Configuration.
                <button
                  onClick={() => navigate('/config')}
                  className="ml-2 underline hover:no-underline font-medium"
                >
                  Open Config
                </button>
              </div>
            </div>

            {/* Lists table */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-slate-50 dark:bg-slate-900">
                  <tr>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      URL
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      Format
                    </th>
                    <th className="text-right px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      Rules
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      Last Update
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="text-right px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                  {filteredLists.length === 0 ? (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-4 py-8 text-center text-sm text-slate-400 dark:text-slate-500"
                      >
                        No lists match current filter
                      </td>
                    </tr>
                  ) : (
                    filteredLists.map((list, i) => (
                      <tr
                        key={`${list.url}-${i}`}
                        className="hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors"
                      >
                        <td className="px-4 py-2.5 text-xs font-mono text-slate-900 dark:text-slate-100 max-w-xs truncate" title={list.url}>
                          {list.url}
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400">
                            {list.format}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-right text-xs font-mono text-slate-500 dark:text-slate-400">
                          {formatNumber(list.rule_count)}
                        </td>
                        <td className="px-4 py-2.5 text-xs text-slate-500 dark:text-slate-400">
                          {list.last_update
                            ? new Date(list.last_update).toLocaleString()
                            : 'Never'}
                        </td>
                        <td className="px-4 py-2.5">
                          {list.error ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-400" title={list.error}>
                              <X size={10} />
                              Error
                            </span>
                          ) : list.enabled ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400">
                              <Check size={10} />
                              Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400">
                              Disabled
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2.5 text-right">
                          <button
                            onClick={() => showMessage('List removal is managed via Configuration > blocklist.lists.', 'error')}
                            className="text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 transition-colors"
                            title="Remove list"
                          >
                            <Trash2 size={14} />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Quick block/unblock + Check */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Quick block/unblock */}
            <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4 flex items-center gap-2">
                <Shield size={16} />
                Quick Block / Unblock
              </h2>
              <form onSubmit={handleBlock} className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1">
                  <input
                    type="text"
                    value={blockDomain}
                    onChange={(e) => setBlockDomain(e.target.value)}
                    className={inputClass}
                    placeholder="example.com"
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={blocking || !blockDomain.trim()}
                  className="bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg font-medium flex items-center justify-center gap-2 transition-colors shrink-0"
                >
                  {blocking ? (
                    <Loader2 size={16} className="animate-spin" />
                  ) : (
                    <X size={16} />
                  )}
                  Block
                </button>
                <button
                  type="button"
                  onClick={handleUnblock}
                  disabled={unblocking || !blockDomain.trim()}
                  className="bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg font-medium flex items-center justify-center gap-2 transition-colors shrink-0"
                >
                  {unblocking ? (
                    <Loader2 size={16} className="animate-spin" />
                  ) : (
                    <Check size={16} />
                  )}
                  Unblock
                </button>
              </form>
            </div>

            {/* Check domain */}
            <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4 flex items-center gap-2">
                <Search size={16} />
                Check Domain
              </h2>
              <form onSubmit={handleCheck} className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1">
                  <input
                    type="text"
                    value={checkDomain}
                    onChange={(e) => setCheckDomain(e.target.value)}
                    className={inputClass}
                    placeholder="example.com"
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={checking || !checkDomain.trim()}
                  className="bg-amber-600 hover:bg-amber-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg font-medium flex items-center justify-center gap-2 transition-colors shrink-0"
                >
                  {checking ? (
                    <Loader2 size={16} className="animate-spin" />
                  ) : (
                    <Search size={16} />
                  )}
                  Check
                </button>
              </form>
              {checkResult && (
                <div className="mt-4 flex items-center gap-2">
                  {checkResult.blocked ? (
                    <>
                      <div className="flex items-center justify-center w-8 h-8 rounded-full bg-red-100 dark:bg-red-900/40">
                        <X size={16} className="text-red-600 dark:text-red-400" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-red-600 dark:text-red-400">Blocked</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">{checkResult.domain} is on the blocklist</p>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="flex items-center justify-center w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/40">
                        <Check size={16} className="text-green-600 dark:text-green-400" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-green-600 dark:text-green-400">Allowed</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">{checkResult.domain} is not blocked</p>
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
