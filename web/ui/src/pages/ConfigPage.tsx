import { useState, useEffect } from 'react'
import { Settings, Loader2 } from 'lucide-react'
import { api } from '@/api/client'

interface ConfigSection {
  title: string
  keys: string[]
}

const SECTION_MAP: ConfigSection[] = [
  { title: 'Server', keys: ['listen_addr', 'metrics_addr', 'pid_file'] },
  { title: 'Resolver', keys: ['qname_minimization', 'max_concurrent', 'timeout', 'retries', 'root_hints'] },
  { title: 'Cache', keys: ['cache_max_entries', 'cache_min_ttl', 'cache_max_ttl', 'cache_negative_ttl'] },
  { title: 'Security', keys: ['rate_limit_enabled', 'rate_limit_rate', 'rate_limit_burst', 'rate_limit_per_client'] },
  { title: 'Logging', keys: ['log_level', 'log_format', 'log_file'] },
]

function formatValue(val: unknown): string {
  if (val === null || val === undefined) return '--'
  if (typeof val === 'boolean') return val ? 'Enabled' : 'Disabled'
  if (typeof val === 'number') return val.toLocaleString()
  if (typeof val === 'object') return JSON.stringify(val, null, 2)
  return String(val)
}

function formatKey(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

export default function ConfigPage() {
  const [config, setConfig] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    async function fetchConfig() {
      try {
        const res = await api.config()
        setConfig(res)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load config')
      } finally {
        setLoading(false)
      }
    }
    fetchConfig()
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 size={24} className="animate-spin text-amber-600" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
          Configuration
        </h1>
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      </div>
    )
  }

  // Gather all known keys from sections
  const knownKeys = new Set(SECTION_MAP.flatMap((s) => s.keys))

  // Find any keys not in the known sections
  const otherKeys = config
    ? Object.keys(config).filter((k) => !knownKeys.has(k))
    : []

  function renderSection(title: string, keys: string[]) {
    if (!config) return null

    // Only show keys that exist in the config
    const entries = keys
      .filter((k) => k in config)
      .map((k) => ({ key: k, value: config[k] }))

    if (entries.length === 0) return null

    return (
      <div
        key={title}
        className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm"
      >
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4 flex items-center gap-2">
          <Settings size={16} className="text-amber-600" />
          {title}
        </h2>
        <div className="space-y-3">
          {entries.map(({ key, value }) => (
            <div
              key={key}
              className="flex flex-col sm:flex-row sm:items-center sm:justify-between py-2 border-b border-slate-100 dark:border-slate-700/50 last:border-0"
            >
              <span className="text-sm text-slate-500 dark:text-slate-400">
                {formatKey(key)}
              </span>
              <span
                className={`text-sm font-mono mt-1 sm:mt-0 ${
                  typeof value === 'boolean'
                    ? value
                      ? 'text-green-600 dark:text-green-400'
                      : 'text-slate-400 dark:text-slate-500'
                    : 'text-slate-900 dark:text-slate-100'
                }`}
              >
                {formatValue(value)}
              </span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
          Configuration
        </h1>
        <span className="text-xs text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded">
          Read-only
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {SECTION_MAP.map((s) => renderSection(s.title, s.keys))}

        {/* Other / uncategorized keys */}
        {otherKeys.length > 0 && renderSection('Other', otherKeys)}
      </div>
    </div>
  )
}
