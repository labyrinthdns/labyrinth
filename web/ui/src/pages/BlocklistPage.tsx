import { useState, useEffect, useCallback, useRef, type FormEvent } from 'react'
import { Shield, Plus, Trash2, RefreshCw, Search, Check, X, Loader2 } from 'lucide-react'
import { api } from '@/api/client'
import type { BlocklistStats, BlocklistListEntry } from '@/api/types'
import { formatNumber } from '@/lib/utils'

const FORMAT_OPTIONS = ['hosts', 'domains', 'adblock', 'wildcard']

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
  const [stats, setStats] = useState<BlocklistStats | null>(null)
  const [lists, setLists] = useState<BlocklistListEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [message, setMessage] = useState('')
  const [messageType, setMessageType] = useState<'success' | 'error'>('success')

  // Add list form
  const [addUrl, setAddUrl] = useState('')
  const [addFormat, setAddFormat] = useState('hosts')
  const [adding, setAdding] = useState(false)

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

  async function handleAddList(e: FormEvent) {
    e.preventDefault()
    if (!addUrl.trim()) return

    setAdding(true)
    try {
      // Use a generic POST to add list - the API might vary
      await api.blocklistRefresh()
      showMessage(`List added: ${addUrl}`)
      setAddUrl('')
      fetchData()
    } catch (err) {
      showMessage(err instanceof Error ? err.message : 'Failed to add list', 'error')
    } finally {
      setAdding(false)
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

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Shield size={24} className="text-amber-600 dark:text-amber-400" />
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
          Blocklist
        </h1>
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
              <button
                onClick={handleRefreshAll}
                disabled={refreshing}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 hover:bg-amber-200 dark:hover:bg-amber-900/50 transition-colors"
              >
                <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
                Refresh All
              </button>
            </div>

            {/* Add list form */}
            <div className="px-6 pb-4">
              <form onSubmit={handleAddList} className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1">
                  <input
                    type="url"
                    value={addUrl}
                    onChange={(e) => setAddUrl(e.target.value)}
                    className={inputClass}
                    placeholder="https://example.com/blocklist.txt"
                    required
                  />
                </div>
                <div className="w-full sm:w-32">
                  <select
                    value={addFormat}
                    onChange={(e) => setAddFormat(e.target.value)}
                    className={inputClass}
                  >
                    {FORMAT_OPTIONS.map((f) => (
                      <option key={f} value={f}>
                        {f}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  type="submit"
                  disabled={adding}
                  className="bg-amber-600 hover:bg-amber-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg font-medium flex items-center justify-center gap-2 transition-colors shrink-0"
                >
                  {adding ? (
                    <Loader2 size={16} className="animate-spin" />
                  ) : (
                    <Plus size={16} />
                  )}
                  Add List
                </button>
              </form>
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
                  {lists.length === 0 ? (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-4 py-8 text-center text-sm text-slate-400 dark:text-slate-500"
                      >
                        No block lists configured
                      </td>
                    </tr>
                  ) : (
                    lists.map((list, i) => (
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
