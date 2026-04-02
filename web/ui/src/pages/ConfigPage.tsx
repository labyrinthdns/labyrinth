import { useState, useEffect } from 'react'
import {
  Server,
  Globe,
  Database,
  Shield,
  FileText,
  LayoutDashboard,
  Activity,
  Loader2,
} from 'lucide-react'
import { api } from '@/api/client'

interface SectionDef {
  key: string
  title: string
  icon: typeof Server
  fields: { key: string; label: string; format?: 'bool' | 'duration' | 'number' | 'redacted' }[]
}

const sections: SectionDef[] = [
  {
    key: 'server',
    title: 'Server',
    icon: Server,
    fields: [
      { key: 'listen_addr', label: 'Listen Address' },
      { key: 'metrics_addr', label: 'Metrics Address' },
      { key: 'max_udp_size', label: 'Max UDP Size', format: 'number' },
      { key: 'tcp_timeout', label: 'TCP Timeout' },
      { key: 'max_tcp_conns', label: 'Max TCP Connections', format: 'number' },
      { key: 'max_udp_workers', label: 'Max UDP Workers', format: 'number' },
      { key: 'graceful_period', label: 'Graceful Shutdown' },
    ],
  },
  {
    key: 'resolver',
    title: 'Resolver',
    icon: Globe,
    fields: [
      { key: 'max_depth', label: 'Max Resolution Depth', format: 'number' },
      { key: 'max_cname_depth', label: 'Max CNAME Chain', format: 'number' },
      { key: 'upstream_timeout', label: 'Upstream Timeout' },
      { key: 'upstream_retries', label: 'Upstream Retries', format: 'number' },
      { key: 'qname_minimization', label: 'QNAME Minimization', format: 'bool' },
      { key: 'prefer_ipv4', label: 'Prefer IPv4', format: 'bool' },
    ],
  },
  {
    key: 'cache',
    title: 'Cache',
    icon: Database,
    fields: [
      { key: 'max_entries', label: 'Max Entries', format: 'number' },
      { key: 'min_ttl', label: 'Min TTL (seconds)', format: 'number' },
      { key: 'max_ttl', label: 'Max TTL (seconds)', format: 'number' },
      { key: 'negative_max_ttl', label: 'Negative Max TTL', format: 'number' },
      { key: 'sweep_interval', label: 'Sweep Interval' },
      { key: 'serve_stale', label: 'Serve Stale', format: 'bool' },
      { key: 'stale_ttl', label: 'Stale TTL (seconds)', format: 'number' },
    ],
  },
  {
    key: 'security',
    title: 'Security',
    icon: Shield,
    fields: [
      { key: 'rate_limit.enabled', label: 'Rate Limit', format: 'bool' },
      { key: 'rate_limit.rate', label: 'Rate (qps)', format: 'number' },
      { key: 'rate_limit.burst', label: 'Burst', format: 'number' },
      { key: 'rrl.enabled', label: 'Response Rate Limiting', format: 'bool' },
      { key: 'rrl.responses_per_second', label: 'RRL Responses/sec', format: 'number' },
      { key: 'rrl.slip_ratio', label: 'RRL Slip Ratio', format: 'number' },
      { key: 'rrl.ipv4_prefix', label: 'RRL IPv4 Prefix', format: 'number' },
      { key: 'rrl.ipv6_prefix', label: 'RRL IPv6 Prefix', format: 'number' },
    ],
  },
  {
    key: 'logging',
    title: 'Logging',
    icon: FileText,
    fields: [
      { key: 'level', label: 'Log Level' },
      { key: 'format', label: 'Log Format' },
    ],
  },
  {
    key: 'web',
    title: 'Web Dashboard',
    icon: LayoutDashboard,
    fields: [
      { key: 'enabled', label: 'Enabled', format: 'bool' },
      { key: 'addr', label: 'Address' },
      { key: 'query_log_buffer', label: 'Query Log Buffer', format: 'number' },
      { key: 'auth.username', label: 'Admin Username' },
      { key: 'auth.password_hash', label: 'Password Hash', format: 'redacted' },
    ],
  },
  {
    key: 'zabbix',
    title: 'Zabbix',
    icon: Activity,
    fields: [
      { key: 'enabled', label: 'Enabled', format: 'bool' },
      { key: 'addr', label: 'Address' },
    ],
  },
]

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.')
  let current: unknown = obj
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined
    current = (current as Record<string, unknown>)[part]
  }
  return current
}

function formatValue(val: unknown, format?: string): string {
  if (val === null || val === undefined) return '—'
  if (format === 'redacted') return '••••••••'
  if (format === 'bool') return val ? 'Enabled' : 'Disabled'
  if (format === 'number') return typeof val === 'number' ? val.toLocaleString() : String(val)
  if (format === 'duration') {
    // Go durations come as nanoseconds (int64)
    if (typeof val === 'number') {
      const sec = val / 1_000_000_000
      if (sec >= 60) return `${Math.round(sec / 60)}m`
      return `${sec}s`
    }
    return String(val)
  }
  if (typeof val === 'boolean') return val ? 'true' : 'false'
  if (typeof val === 'object') return JSON.stringify(val)
  return String(val)
}

function valueBadgeColor(val: unknown, format?: string): string {
  if (format === 'bool') {
    return val
      ? 'text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/20'
      : 'text-slate-400 dark:text-slate-500 bg-slate-50 dark:bg-slate-800'
  }
  if (format === 'redacted') {
    return 'text-slate-400 dark:text-slate-500'
  }
  return 'text-slate-900 dark:text-slate-100'
}

export default function ConfigPage() {
  const [config, setConfig] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.config()
      .then((res) => setConfig(res))
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load'))
      .finally(() => setLoading(false))
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
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Configuration</h1>
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Configuration</h1>
        <span className="text-xs text-slate-400 bg-slate-100 dark:bg-slate-800 px-3 py-1 rounded-full font-medium">
          Read-only
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {sections.map((section) => {
          const sectionData = config?.[section.key] as Record<string, unknown> | undefined
          if (!sectionData) return null

          const Icon = section.icon

          return (
            <div
              key={section.key}
              className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden"
            >
              {/* Section header */}
              <div className="px-6 py-4 border-b border-slate-100 dark:border-slate-700/50 flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center">
                  <Icon size={16} className="text-amber-600 dark:text-amber-400" />
                </div>
                <h2 className="text-sm font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wide">
                  {section.title}
                </h2>
              </div>

              {/* Fields */}
              <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
                {section.fields.map((field) => {
                  const val = getNestedValue(sectionData, field.key)
                  if (val === undefined) return null

                  return (
                    <div
                      key={field.key}
                      className="px-6 py-3 flex items-center justify-between gap-4 hover:bg-slate-50 dark:hover:bg-slate-750 transition-colors"
                    >
                      <span className="text-sm text-slate-500 dark:text-slate-400 shrink-0">
                        {field.label}
                      </span>
                      <span
                        className={`text-sm font-mono text-right truncate ${valueBadgeColor(val, field.format)} ${
                          field.format === 'bool' ? 'px-2 py-0.5 rounded-md text-xs font-semibold' : ''
                        }`}
                      >
                        {formatValue(val, field.format)}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
