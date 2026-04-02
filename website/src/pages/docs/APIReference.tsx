interface Props { dark: boolean }

function Endpoint({ method, path, auth, description, request, response, dark }: {
  method: string
  path: string
  auth: boolean
  description: string
  request?: string
  response: string
  dark: boolean
}) {
  const methodColors: Record<string, string> = {
    GET: 'bg-green-500/20 text-green-400 border-green-500/30',
    POST: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    DELETE: 'bg-red-500/20 text-red-400 border-red-500/30',
  }
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'

  return (
    <div className={`rounded-xl border mb-8 overflow-hidden ${dark ? 'border-navy-700 bg-navy-800/30' : 'border-mist-200 bg-white'}`}>
      <div className={`flex items-center gap-3 px-5 py-3 border-b ${dark ? 'border-navy-700' : 'border-mist-200'}`}>
        <span className={`px-2.5 py-1 rounded text-xs font-bold border ${methodColors[method] || ''}`}>
          {method}
        </span>
        <code className={`text-sm font-mono ${dark ? 'text-white' : 'text-navy-900'}`}>{path}</code>
        {auth && (
          <span className="ml-auto px-2 py-0.5 rounded text-xs font-medium bg-gold-500/10 text-gold-500 border border-gold-500/20">
            Auth Required
          </span>
        )}
      </div>
      <div className="px-5 py-3">
        <p className={`text-sm mb-3 ${dark ? 'text-gray-300' : 'text-navy-700'}`}>{description}</p>
        {request && (
          <>
            <p className={`text-xs font-semibold uppercase tracking-wider mb-2 ${dark ? 'text-gray-500' : 'text-navy-400'}`}>Request Body</p>
            <pre className="code-block p-3 mb-3"><code className="text-xs text-gray-300 font-mono">{request}</code></pre>
          </>
        )}
        <p className={`text-xs font-semibold uppercase tracking-wider mb-2 ${dark ? 'text-gray-500' : 'text-navy-400'}`}>Response <code className={ic}>200</code></p>
        <pre className="code-block p-3"><code className="text-xs text-gray-300 font-mono">{response}</code></pre>
      </div>
    </div>
  )
}

export default function APIReference({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'

  return (
    <div>
      <h1 className={h1}>API Reference</h1>

      <p className={p}>
        Labyrinth exposes a RESTful JSON API on the same port as the web dashboard (default: 9153).
        All endpoints under <code className={ic}>/api/</code> return JSON. Authenticated endpoints
        require a valid JWT in the <code className={ic}>Authorization: Bearer {'<token>'}</code> header.
      </p>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Base URL:</strong> <code className={ic}>http://localhost:9153</code>
          {' '}&mdash; all paths below are relative to this.
        </p>
      </div>

      <h2 className={h2}>Health & Readiness</h2>

      <Endpoint
        dark={dark}
        method="GET"
        path="/health"
        auth={false}
        description="Returns the health status. Always returns 200 if the process is running."
        response={`{
  "status": "ok"
}`}
      />

      <Endpoint
        dark={dark}
        method="GET"
        path="/ready"
        auth={false}
        description="Returns readiness status. Returns 200 when the resolver is ready to accept queries."
        response={`{
  "status": "ready",
  "cache_initialized": true,
  "listener_active": true
}`}
      />

      <h2 className={h2}>Authentication</h2>

      <Endpoint
        dark={dark}
        method="POST"
        path="/api/auth/login"
        auth={false}
        description="Authenticate with username and password. Returns a JWT token."
        request={`{
  "username": "admin",
  "password": "your-password"
}`}
        response={`{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-01-02T15:04:05Z"
}`}
      />

      <Endpoint
        dark={dark}
        method="POST"
        path="/api/auth/setup"
        auth={false}
        description="Create the initial admin account (only works when no account exists)."
        request={`{
  "username": "admin",
  "password": "your-password"
}`}
        response={`{
  "message": "Admin account created",
  "token": "eyJhbGciOiJIUzI1NiIs..."
}`}
      />

      <h2 className={h2}>Statistics</h2>

      <Endpoint
        dark={dark}
        method="GET"
        path="/api/stats"
        auth={true}
        description="Returns current resolver statistics including query counts, cache metrics, and system info."
        response={`{
  "uptime_seconds": 86400,
  "queries": {
    "total": 1247832,
    "per_second": 14.4,
    "by_type": {
      "A": 892341,
      "AAAA": 234567,
      "MX": 45678,
      "NS": 12345,
      "OTHER": 62901
    },
    "by_rcode": {
      "NOERROR": 1100234,
      "NXDOMAIN": 134567,
      "SERVFAIL": 13031
    }
  },
  "cache": {
    "entries": 45678,
    "hit_rate": 0.942,
    "hits": 1175460,
    "misses": 72372,
    "evictions": 1234
  },
  "system": {
    "goroutines": 142,
    "memory_alloc_mb": 128.5,
    "memory_sys_mb": 256.0,
    "num_cpu": 16
  }
}`}
      />

      <h2 className={h2}>Cache Management</h2>

      <Endpoint
        dark={dark}
        method="GET"
        path="/api/cache/entries?prefix=example&limit=50"
        auth={true}
        description="List cache entries. Supports filtering by name prefix and pagination with limit/offset."
        response={`{
  "entries": [
    {
      "name": "example.com.",
      "type": "A",
      "ttl": 2847,
      "rdata": "93.184.216.34",
      "inserted_at": "2025-01-01T12:00:00Z",
      "is_negative": false
    },
    {
      "name": "example.com.",
      "type": "AAAA",
      "ttl": 1523,
      "rdata": "2606:2800:220:1:248:1893:25c8:1946",
      "inserted_at": "2025-01-01T12:22:00Z",
      "is_negative": false
    }
  ],
  "total": 2,
  "has_more": false
}`}
      />

      <Endpoint
        dark={dark}
        method="POST"
        path="/api/cache/flush"
        auth={true}
        description="Flush the entire cache. Returns the number of entries removed."
        response={`{
  "flushed": 45678,
  "message": "Cache flushed"
}`}
      />

      <Endpoint
        dark={dark}
        method="DELETE"
        path="/api/cache/entry?name=example.com.&type=A"
        auth={true}
        description="Remove a specific cache entry by name and type."
        response={`{
  "deleted": true,
  "name": "example.com.",
  "type": "A"
}`}
      />

      <h2 className={h2}>Configuration</h2>

      <Endpoint
        dark={dark}
        method="GET"
        path="/api/config"
        auth={true}
        description="Returns the active configuration (sensitive fields like jwt_secret are redacted)."
        response={`{
  "server": {
    "address": "0.0.0.0",
    "port": 53,
    "tcp_enabled": true,
    "workers": 8
  },
  "resolver": {
    "enable_qname_minimization": true,
    "max_depth": 30
  },
  "cache": {
    "max_entries_per_shard": 10000,
    "serve_stale": true
  },
  "web": {
    "enabled": true,
    "port": 9153,
    "jwt_secret": "[REDACTED]"
  }
}`}
      />

      <h2 className={h2}>Metrics</h2>

      <Endpoint
        dark={dark}
        method="GET"
        path="/metrics"
        auth={false}
        description="Prometheus metrics endpoint. Returns metrics in Prometheus exposition format."
        response={`# HELP labyrinth_queries_total Total DNS queries received
# TYPE labyrinth_queries_total counter
labyrinth_queries_total{type="A"} 892341
labyrinth_queries_total{type="AAAA"} 234567
...`}
      />

      <h2 className={h2}>Error Responses</h2>

      <p className={p}>
        All error responses follow a consistent format:
      </p>

      <pre className="code-block p-4 mb-6"><code className="text-sm text-gray-300 font-mono">{`// 401 Unauthorized
{
  "error": "invalid or expired token"
}

// 400 Bad Request
{
  "error": "missing required field: username"
}

// 404 Not Found
{
  "error": "cache entry not found"
}

// 409 Conflict (setup already complete)
{
  "error": "admin account already exists"
}`}</code></pre>
    </div>
  )
}
