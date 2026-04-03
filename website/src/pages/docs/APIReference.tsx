interface Props { dark: boolean }

function Endpoint({
  dark,
  method,
  path,
  auth,
  description,
}: {
  dark: boolean
  method: string
  path: string
  auth: 'public' | 'jwt'
  description: string
}) {
  const methodStyle = dark ? 'bg-navy-700 text-gold-400 border-navy-600' : 'bg-mist-100 text-navy-800 border-mist-300'
  const authStyle = auth === 'jwt'
    ? 'bg-gold-500/10 text-gold-500 border-gold-500/20'
    : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'

  return (
    <div className={`rounded-xl border mb-3 px-4 py-3 ${dark ? 'border-navy-700 bg-navy-800/30' : 'border-mist-200 bg-white'}`}>
      <div className="flex items-center gap-2 mb-1">
        <span className={`px-2 py-0.5 rounded text-xs font-bold border ${methodStyle}`}>{method}</span>
        <code className={`text-sm font-mono ${dark ? 'text-white' : 'text-navy-900'}`}>{path}</code>
        <span className={`ml-auto px-2 py-0.5 rounded text-xs font-medium border ${authStyle}`}>
          {auth === 'jwt' ? 'JWT Required' : 'Public'}
        </span>
      </div>
      <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>{description}</p>
    </div>
  )
}

export default function APIReference({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-8 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'

  return (
    <div>
      <h1 className={h1}>API Reference</h1>

      <p className={p}>
        The web API is served on the same address as the dashboard (default <code className={ic}>127.0.0.1:9153</code>).
        Most <code className={ic}>/api/*</code> routes require <code className={ic}>Authorization: Bearer &lt;jwt&gt;</code>.
      </p>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          When web mode is enabled, use <code className={ic}>/api/system/health</code> for liveness.
          The legacy <code className={ic}>/health</code> and <code className={ic}>/ready</code> endpoints are only available in standalone metrics mode.
        </p>
      </div>

      <h2 className={h2}>Public Endpoints</h2>
      <Endpoint dark={dark} method="POST" path="/api/auth/login" auth="public" description="Authenticate and receive JWT." />
      <Endpoint dark={dark} method="GET" path="/api/setup/status" auth="public" description="Check setup wizard state." />
      <Endpoint dark={dark} method="POST" path="/api/setup/complete" auth="public" description="Complete first-time setup." />
      <Endpoint dark={dark} method="GET" path="/api/system/health" auth="public" description="Health endpoint in web mode." />
      <Endpoint dark={dark} method="GET" path="/api/system/version" auth="public" description="Build/runtime version info." />
      <Endpoint dark={dark} method="GET" path="/metrics" auth="public" description="Prometheus metrics output." />
      <Endpoint dark={dark} method="GET/POST" path="/dns-query" auth="public" description="DoH endpoint (RFC 8484), available only when web.doh_enabled=true." />

      <h2 className={h2}>Authenticated Endpoints</h2>
      <Endpoint dark={dark} method="GET" path="/api/auth/me" auth="jwt" description="Current authenticated user info." />
      <Endpoint dark={dark} method="POST" path="/api/auth/change-password" auth="jwt" description="Change dashboard password." />
      <Endpoint dark={dark} method="GET" path="/api/stats" auth="jwt" description="Current resolver + cache stats." />
      <Endpoint dark={dark} method="GET" path="/api/stats/timeseries?window=5m" auth="jwt" description="Time-series stats for charts." />
      <Endpoint dark={dark} method="GET" path="/api/stats/top-clients?limit=10" auth="jwt" description="Top clients by query volume." />
      <Endpoint dark={dark} method="GET" path="/api/stats/top-domains?limit=10" auth="jwt" description="Top domains by query volume." />
      <Endpoint dark={dark} method="WS" path="/api/queries/stream" auth="jwt" description="Live query stream over WebSocket." />
      <Endpoint dark={dark} method="GET" path="/api/queries/recent?limit=50" auth="jwt" description="Recent query list." />
      <Endpoint dark={dark} method="GET" path="/api/cache/stats" auth="jwt" description="Cache counters and size." />
      <Endpoint dark={dark} method="GET" path="/api/cache/lookup?name=X&type=A" auth="jwt" description="Lookup specific cache entry." />
      <Endpoint dark={dark} method="GET" path="/api/cache/negative" auth="jwt" description="Inspect negative cache entries." />
      <Endpoint dark={dark} method="POST" path="/api/cache/flush" auth="jwt" description="Flush all cache entries." />
      <Endpoint dark={dark} method="DELETE" path="/api/cache/entry?name=X&type=A" auth="jwt" description="Delete one cache entry." />
      <Endpoint dark={dark} method="GET" path="/api/config" auth="jwt" description="Return active runtime config (sensitive fields redacted)." />
      <Endpoint dark={dark} method="GET" path="/api/system/update/check" auth="jwt" description="Check if update is available." />
      <Endpoint dark={dark} method="POST" path="/api/system/update/apply" auth="jwt" description="Apply update and restart." />
      <Endpoint dark={dark} method="GET" path="/api/blocklist/stats" auth="jwt" description="Blocklist statistics." />
      <Endpoint dark={dark} method="GET" path="/api/blocklist/lists" auth="jwt" description="Configured blocklist sources." />
      <Endpoint dark={dark} method="POST" path="/api/blocklist/refresh" auth="jwt" description="Refresh all blocklist sources now." />
      <Endpoint dark={dark} method="POST" path="/api/blocklist/block" auth="jwt" description="Quick-block a domain." />
      <Endpoint dark={dark} method="POST" path="/api/blocklist/unblock" auth="jwt" description="Quick-unblock a domain." />
      <Endpoint dark={dark} method="GET" path="/api/blocklist/check?domain=X" auth="jwt" description="Check if a domain is blocked." />
      <Endpoint dark={dark} method="GET" path="/api/zabbix/items" auth="jwt" description="List Zabbix metric keys." />
      <Endpoint dark={dark} method="GET" path="/api/zabbix/item?key=X" auth="jwt" description="Get one Zabbix metric value." />
    </div>
  )
}
