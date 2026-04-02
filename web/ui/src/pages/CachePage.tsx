import { useState, useEffect, useCallback, type FormEvent } from 'react'
import { Database, Search, Trash2, AlertCircle, Loader2 } from 'lucide-react'
import { api } from '@/api/client'
import type { CacheStats, CacheEntry } from '@/api/types'
import { formatNumber } from '@/lib/utils'

const DNS_TYPES = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'TXT', 'SOA', 'SRV', 'PTR']

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

export default function CachePage() {
  const [stats, setStats] = useState<CacheStats | null>(null)
  const [lookupName, setLookupName] = useState('')
  const [lookupType, setLookupType] = useState('A')
  const [lookupResult, setLookupResult] = useState<CacheEntry | null>(null)
  const [lookupError, setLookupError] = useState('')
  const [lookupLoading, setLookupLoading] = useState(false)
  const [flushing, setFlushing] = useState(false)
  const [flushConfirm, setFlushConfirm] = useState(false)
  const [message, setMessage] = useState('')

  const fetchStats = useCallback(async () => {
    try {
      const res = await api.cacheStats() as unknown as CacheStats
      setStats(res)
    } catch {
      // silently ignore
    }
  }, [])

  useEffect(() => {
    fetchStats()
  }, [fetchStats])

  async function handleLookup(e: FormEvent) {
    e.preventDefault()
    if (!lookupName.trim()) return

    setLookupLoading(true)
    setLookupError('')
    setLookupResult(null)

    try {
      const res = await api.cacheLookup(lookupName.trim(), lookupType) as unknown as CacheEntry
      setLookupResult(res)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Lookup failed'
      if (msg.includes('404') || msg.includes('not found')) {
        setLookupError(`"${lookupName.trim()}" (${lookupType}) is not in the cache. Try querying it first with: dig @localhost ${lookupName.trim()} ${lookupType}`)
      } else {
        setLookupError(msg)
      }
    } finally {
      setLookupLoading(false)
    }
  }

  async function handleFlush() {
    if (!flushConfirm) {
      setFlushConfirm(true)
      return
    }

    setFlushing(true)
    try {
      await api.cacheFlush()
      setMessage('Cache flushed successfully')
      setLookupResult(null)
      setFlushConfirm(false)
      fetchStats()
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Flush failed')
    } finally {
      setFlushing(false)
    }

    setTimeout(() => setMessage(''), 3000)
  }

  async function handleDelete() {
    if (!lookupResult) return

    try {
      await api.cacheDelete(lookupResult.name, lookupResult.type)
      setMessage(`Deleted ${lookupResult.name} ${lookupResult.type}`)
      setLookupResult(null)
      fetchStats()
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Delete failed')
    }

    setTimeout(() => setMessage(''), 3000)
  }

  const inputClass =
    'bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg px-3 py-2 w-full text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-amber-600/50 focus:border-amber-600 transition-colors'

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
        Cache Management
      </h1>

      {/* Status message */}
      {message && (
        <div className="bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800 text-green-700 dark:text-green-400 text-sm rounded-lg px-4 py-3">
          {message}
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          label="Total Entries"
          value={stats ? formatNumber(stats.entries) : '0'}
          color="text-slate-900 dark:text-slate-100"
        />
        <StatCard
          label="Positive"
          value={stats ? formatNumber(stats.positive_entries) : '0'}
          color="text-green-600 dark:text-green-400"
        />
        <StatCard
          label="Negative"
          value={stats ? formatNumber(stats.negative_entries) : '0'}
          color="text-red-600 dark:text-red-400"
        />
      </div>

      {/* Lookup + Flush row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Lookup form */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4 flex items-center gap-2">
            <Search size={16} />
            Cache Lookup
          </h2>
          <form onSubmit={handleLookup} className="flex flex-col sm:flex-row gap-3">
            <div className="flex-1">
              <input
                type="text"
                value={lookupName}
                onChange={(e) => setLookupName(e.target.value)}
                className={inputClass}
                placeholder="example.com"
                required
              />
            </div>
            <div className="w-full sm:w-28">
              <select
                value={lookupType}
                onChange={(e) => setLookupType(e.target.value)}
                className={inputClass}
              >
                {DNS_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="submit"
              disabled={lookupLoading}
              className="bg-amber-600 hover:bg-amber-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg font-medium flex items-center justify-center gap-2 transition-colors shrink-0"
            >
              {lookupLoading ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <Search size={16} />
              )}
              Lookup
            </button>
          </form>

          {/* Lookup result message */}
          {lookupError && (
            <div className={`mt-4 flex items-start gap-2 text-sm rounded-lg px-4 py-3 ${
              lookupError.includes('not in the cache')
                ? 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800'
                : 'text-red-600 dark:text-red-400'
            }`}>
              <AlertCircle size={14} className="mt-0.5 shrink-0" />
              {lookupError}
            </div>
          )}

          {/* Lookup result */}
          {lookupResult && (
            <div className="mt-4 bg-slate-50 dark:bg-slate-900 rounded-lg p-4 space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                  Result
                </h3>
                <button
                  onClick={handleDelete}
                  className="flex items-center gap-1 text-xs text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 transition-colors"
                >
                  <Trash2 size={12} />
                  Delete Entry
                </button>
              </div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Name</span>
                  <p className="font-mono text-slate-900 dark:text-slate-100">
                    {lookupResult.name}
                  </p>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Type</span>
                  <p className="font-mono text-slate-900 dark:text-slate-100">
                    {lookupResult.type}
                  </p>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">TTL</span>
                  <p className="font-mono text-slate-900 dark:text-slate-100">
                    {lookupResult.ttl}s
                  </p>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">RCode</span>
                  <p className="font-mono text-slate-900 dark:text-slate-100">
                    {lookupResult.rcode}
                  </p>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Negative</span>
                  <p className={lookupResult.negative ? 'text-red-500' : 'text-green-500'}>
                    {lookupResult.negative ? 'Yes' : 'No'}
                  </p>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Records</span>
                  <p className="font-mono text-slate-900 dark:text-slate-100">
                    {lookupResult.records}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Flush */}
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm flex flex-col">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4 flex items-center gap-2">
            <Database size={16} />
            Cache Actions
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-4 flex-1">
            Flush all cached DNS records. This will temporarily increase query latency
            until the cache is repopulated.
          </p>
          {flushConfirm ? (
            <div className="space-y-3">
              <p className="text-sm text-amber-600 dark:text-amber-400 font-medium">
                Are you sure? This will clear all cached entries.
              </p>
              <div className="flex gap-2">
                <button
                  onClick={handleFlush}
                  disabled={flushing}
                  className="bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition-colors flex-1"
                >
                  {flushing ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <Trash2 size={14} />
                  )}
                  Confirm
                </button>
                <button
                  onClick={() => setFlushConfirm(false)}
                  className="px-4 py-2 rounded-lg text-sm font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors flex-1"
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button
              onClick={handleFlush}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-medium text-sm flex items-center justify-center gap-2 transition-colors w-full"
            >
              <Trash2 size={14} />
              Flush Cache
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
