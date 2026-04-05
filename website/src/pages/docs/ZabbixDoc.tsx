interface Props { dark: boolean }

export default function ZabbixDoc({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'
  const th = dark ? 'border-b border-navy-700' : 'border-b border-mist-200'
  const td = dark ? 'border-b border-navy-800' : 'border-b border-mist-100'
  const tc = `w-full text-sm mb-6 ${dark ? 'text-gray-300' : 'text-navy-700'}`

  return (
    <div>
      <h1 className={h1}>Zabbix Integration</h1>

      <p className={p}>
        Labyrinth includes a native Zabbix agent protocol implementation, allowing Zabbix Server to poll
        resolver metrics directly without installing a separate Zabbix agent. This is unique among DNS
        resolvers and makes integration with existing Zabbix monitoring infrastructure seamless.
      </p>

      <h2 className={h2}>Enabling the Zabbix Agent</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`zabbix:
  enabled: true
  address: "0.0.0.0"    # listen address
  port: 10050           # standard Zabbix agent port`}</code></pre>

      <p className={p}>
        When enabled, Labyrinth listens on TCP port 10050 (or configured port) and responds to Zabbix
        agent protocol requests.
      </p>

      <h2 className={h2}>HTTP Agent Alternative</h2>

      <p className={p}>
        If you prefer not to use the native agent protocol, Zabbix 4.2+ supports HTTP agents. You can
        poll Labyrinth's JSON API directly:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Zabbix HTTP Agent item configuration:
Type: HTTP agent
URL: http://labyrinth-host:9153/api/stats
Headers: Authorization: Bearer <JWT_TOKEN>
Request method: GET

# Use JSONPath preprocessing to extract values:
# $.cache.hit_rate
# $.queries.per_second
# $.system.goroutines`}</code></pre>

      <h2 className={h2}>Available Zabbix Keys</h2>

      <table className={tc}>
        <thead><tr className={th}>
          <th className="text-left py-2 pr-4 font-semibold">Key</th>
          <th className="text-left py-2 pr-4 font-semibold">Type</th>
          <th className="text-left py-2 font-semibold">Description</th>
        </tr></thead>
        <tbody>
          {[
            ['labyrinth.queries.total', 'counter', 'Total DNS queries received'],
            ['labyrinth.queries.per_second', 'float', 'Current queries per second'],
            ['labyrinth.cache.hit_rate', 'float', 'Cache hit rate (0.0 to 1.0)'],
            ['labyrinth.cache.entries', 'integer', 'Current cache entries'],
            ['labyrinth.cache.hits', 'counter', 'Total cache hits'],
            ['labyrinth.cache.misses', 'counter', 'Total cache misses'],
            ['labyrinth.cache.evictions', 'counter', 'Total evictions'],
            ['labyrinth.upstream.errors', 'counter', 'Total upstream errors'],
            ['labyrinth.rate_limited', 'counter', 'Rate-limited queries'],
            ['labyrinth.rrl_truncated', 'counter', 'RRL-truncated responses'],
            ['labyrinth.uptime', 'integer', 'Uptime in seconds'],
            ['labyrinth.goroutines', 'integer', 'Active goroutines'],
            ['labyrinth.memory.alloc_mb', 'float', 'Heap allocation in MB'],
            ['labyrinth.memory.sys_mb', 'float', 'System memory in MB'],
            ['labyrinth.version', 'string', 'Labyrinth version string'],
            ['labyrinth.health', 'integer', '1 if healthy, 0 if not'],
          ].map(([key, type, desc]) => (
            <tr key={key} className={td}>
              <td className="py-2 pr-4"><code className="text-xs font-mono text-gold-500">{key}</code></td>
              <td className="py-2 pr-4">{type}</td>
              <td className="py-2">{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 className={h2}>Zabbix Server Configuration</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# 1. Add a new host in Zabbix
#    - Host name: labyrinth-dns
#    - Agent interfaces: IP of the Labyrinth server, port 10050

# 2. Test connectivity from Zabbix server:
zabbix_get -s labyrinth-host -p 10050 -k labyrinth.version
# Output: 0.5.1

zabbix_get -s labyrinth-host -p 10050 -k labyrinth.queries.per_second
# Output: 14.4

zabbix_get -s labyrinth-host -p 10050 -k labyrinth.cache.hit_rate
# Output: 0.942`}</code></pre>

      <h2 className={h2}>Template Import</h2>

      <p className={p}>
        A Zabbix template XML file is included in the Labyrinth repository at
        {' '}<code className={ic}>contrib/zabbix/labyrinth-template.xml</code>. Import it into your Zabbix
        server to get pre-configured items, triggers, and graphs:
      </p>

      <ul className={ul}>
        <li><strong>Items:</strong> All metrics listed above with appropriate update intervals</li>
        <li><strong>Triggers:</strong> Alerts for high SERVFAIL rate, low cache hit rate, high memory usage, and agent unreachable</li>
        <li><strong>Graphs:</strong> QPS over time, cache hit rate, memory usage, and upstream latency</li>
        <li><strong>Discovery:</strong> Auto-discovers query types and creates per-type items</li>
      </ul>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Tip:</strong> The native agent protocol is more efficient than HTTP
          polling because Zabbix Server manages the connection lifecycle and scheduling. Use the native agent
          for production deployments with many monitored items.
        </p>
      </div>
    </div>
  )
}
