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
        The WebSocket endpoint provides a real-time stream of DNS queries processed by Labyrinth. This powers
        the "Live Queries" view in the dashboard and can be used by external tools for monitoring or logging.
      </p>

      <h2 className={h2}>Connection URL</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`ws://localhost:9153/ws/queries?token=<JWT_TOKEN>

# With TLS (behind reverse proxy):
wss://dns.example.com/ws/queries?token=<JWT_TOKEN>`}</code></pre>

      <p className={p}>
        The JWT token must be passed as a query parameter because the WebSocket protocol does not support
        custom headers during the upgrade handshake.
      </p>

      <h2 className={h2}>Authentication</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Step 1: Get a JWT token
TOKEN=$(curl -s -X POST http://localhost:9153/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"your-password"}' | jq -r '.token')

# Step 2: Connect to WebSocket
wscat -c "ws://localhost:9153/ws/queries?token=$TOKEN"`}</code></pre>

      <p className={p}>
        If the token is missing or invalid, the server responds with HTTP 401 during the WebSocket upgrade
        and the connection is not established.
      </p>

      <h2 className={h2}>Message Format</h2>

      <p className={p}>
        Each message is a JSON object representing a completed DNS query:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`{
  "timestamp": "2025-01-15T14:32:01.234Z",
  "client_ip": "192.168.1.100",
  "query": {
    "name": "api.github.com.",
    "type": "A",
    "class": "IN"
  },
  "response": {
    "rcode": "NOERROR",
    "answers": [
      {
        "name": "api.github.com.",
        "type": "A",
        "ttl": 60,
        "rdata": "140.82.112.6"
      }
    ],
    "answer_count": 1
  },
  "latency_ms": 2.34,
  "cached": true,
  "protocol": "udp"
}`}</code></pre>

      <h2 className={h2}>Message Fields</h2>

      <table className={`w-full text-sm mb-6 ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
        <thead>
          <tr className={dark ? 'border-b border-navy-700' : 'border-b border-mist-200'}>
            <th className="text-left py-2 pr-4 font-semibold">Field</th>
            <th className="text-left py-2 pr-4 font-semibold">Type</th>
            <th className="text-left py-2 font-semibold">Description</th>
          </tr>
        </thead>
        <tbody>
          {[
            ['timestamp', 'string', 'ISO 8601 timestamp of query completion'],
            ['client_ip', 'string', 'Source IP of the DNS client'],
            ['query.name', 'string', 'Query domain name (FQDN with trailing dot)'],
            ['query.type', 'string', 'Query type (A, AAAA, MX, etc.)'],
            ['response.rcode', 'string', 'Response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)'],
            ['response.answers', 'array', 'Answer records (may be empty for NXDOMAIN)'],
            ['response.answer_count', 'number', 'Total answer count'],
            ['latency_ms', 'number', 'Total processing time in milliseconds'],
            ['cached', 'boolean', 'Whether the response was served from cache'],
            ['protocol', 'string', 'Transport protocol: "udp" or "tcp"'],
          ].map(([field, type, desc]) => (
            <tr key={field} className={dark ? 'border-b border-navy-800' : 'border-b border-mist-100'}>
              <td className="py-2 pr-4"><code className={ic}>{field}</code></td>
              <td className="py-2 pr-4">{type}</td>
              <td className="py-2">{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 className={h2}>Backfill Behavior</h2>

      <p className={p}>
        When a client connects, Labyrinth sends the last 100 queries as a backfill so the dashboard
        immediately shows recent activity. After the backfill, new queries are pushed in real-time as they
        are processed.
      </p>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Throughput:</strong> On high-traffic resolvers (1000+ QPS), the
          WebSocket stream may send hundreds of messages per second. The dashboard UI throttles rendering to
          60fps. External consumers should be prepared to handle high message rates or implement their own
          throttling.
        </p>
      </div>

      <h2 className={h2}>Reconnection</h2>

      <p className={p}>
        The WebSocket connection may drop due to network issues, server restarts, or token expiration.
        Recommended reconnection strategy:
      </p>

      <ul className={ul}>
        <li>Use exponential backoff: 1s, 2s, 4s, 8s, max 30s</li>
        <li>On 401 during reconnect, refresh the JWT token first</li>
        <li>The dashboard implements this automatically</li>
      </ul>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`// Example reconnection logic (JavaScript)
function connect(token) {
  const ws = new WebSocket(\`ws://localhost:9153/ws/queries?token=\${token}\`);
  let retryDelay = 1000;

  ws.onopen = () => {
    retryDelay = 1000; // reset on successful connect
  };

  ws.onmessage = (event) => {
    const query = JSON.parse(event.data);
    console.log(\`[\${query.query.type}] \${query.query.name} -> \${query.response.rcode} (\${query.latency_ms}ms)\`);
  };

  ws.onclose = () => {
    setTimeout(() => {
      retryDelay = Math.min(retryDelay * 2, 30000);
      connect(token);
    }, retryDelay);
  };
}`}</code></pre>
    </div>
  )
}
