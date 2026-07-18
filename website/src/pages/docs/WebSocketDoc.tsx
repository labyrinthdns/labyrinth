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
      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`ws://localhost:9153/api/queries/stream

# With TLS:
wss://dns.example.com/api/queries/stream`}</code></pre>

      <p className={p}>
        The dashboard connects on the same origin, so the browser automatically sends the HttpOnly
        <code className={ic}> labyrinth_token </code> cookie. Non-browser clients can use an
        {' '}<code className={ic}>Authorization: Bearer ...</code> header; the <code className={ic}>?token=...</code>
        fallback is accepted only during a WebSocket upgrade and should be avoided because URLs are logged.
      </p>

      <h2 className={h2}>Browser Example</h2>
      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`// Run after logging in on the dashboard origin.
const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
const socket = new WebSocket(\`${'${scheme}'}//${'${window.location.host}'}/api/queries/stream\`)`}</code></pre>

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
