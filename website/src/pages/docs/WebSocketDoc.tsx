interface Props { dark: boolean }

export default function WebSocketDoc({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>WebSocket Query Stream</h1>

      <p className={p}>
        Labyrinth exposes a live DNS query stream over WebSocket at
        <code className={ic}> /api/queries/stream </code>.
        This endpoint powers the dashboard query timeline.
      </p>

      <h2 className={h2}>Connection URL</h2>
      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`ws://localhost:9153/api/queries/stream?token=<JWT_TOKEN>

# With TLS:
wss://dns.example.com/api/queries/stream?token=<JWT_TOKEN>`}</code></pre>

      <p className={p}>
        Authentication is required when admin auth is enabled. You can pass JWT via
        query parameter (<code className={ic}>?token=...</code>) or
        <code className={ic}> Authorization: Bearer ... </code>.
      </p>

      <h2 className={h2}>Quick Test</h2>
      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`TOKEN=$(curl -s -X POST http://localhost:9153/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"your-password"}' | jq -r '.token')

wscat -c "ws://localhost:9153/api/queries/stream?token=$TOKEN"`}</code></pre>

      <h2 className={h2}>Message Format</h2>
      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`{
  "id": 1042,
  "global_num": 1042,
  "client_num": 37,
  "ts": "2026-04-03T11:59:01.234Z",
  "client": "192.168.1.25",
  "qname": "example.com.",
  "qtype": "A",
  "rcode": "NOERROR",
  "cached": true,
  "duration_ms": 0.42,
  "blocked": false,
  "dnssec_status": "secure"
}`}</code></pre>

      <h2 className={h2}>Behavior Notes</h2>
      <ul className={ul}>
        <li>On connect, server sends recent backfill entries first (latest 50).</li>
        <li>After backfill, new queries stream in real time.</li>
        <li>If client is too slow, messages may be dropped to avoid blocking the resolver.</li>
      </ul>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Tip:</strong> implement reconnect with exponential backoff and
          refresh JWT on 401.
        </p>
      </div>
    </div>
  )
}
