interface Props { dark: boolean }

type Row = {
  keyName: string
  type: string
  defaultValue: string
  description: string
}

function SectionTable({ dark, rows }: { dark: boolean; rows: Row[] }) {
  const th = dark ? 'border-b border-navy-700' : 'border-b border-mist-200'
  const td = dark ? 'border-b border-navy-800' : 'border-b border-mist-100'
  const tc = `w-full text-sm mb-6 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'

  return (
    <table className={tc}>
      <thead>
        <tr className={th}>
          <th className="text-left py-2 pr-4 font-semibold">Key</th>
          <th className="text-left py-2 pr-4 font-semibold">Type</th>
          <th className="text-left py-2 pr-4 font-semibold">Default</th>
          <th className="text-left py-2 font-semibold">Description</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr className={td} key={r.keyName}>
            <td className="py-2 pr-4"><code className={ic}>{r.keyName}</code></td>
            <td className="py-2 pr-4">{r.type}</td>
            <td className="py-2 pr-4"><code className={ic}>{r.defaultValue}</code></td>
            <td className="py-2">{r.description}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default function Configuration({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Configuration Reference</h1>

      <p className={p}>
        Labyrinth reads configuration from a YAML file (default: <code className="px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500">labyrinth.yaml</code>).
        Precedence order is: CLI flags &gt; environment variables &gt; YAML file &gt; built-in defaults.
      </p>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          These keys match the current runtime schema used by <code className="px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500">config/config.go</code>.
        </p>
      </div>

      <h2 className={h2}>server</h2>
      <SectionTable
        dark={dark}
        rows={[
          { keyName: 'listen_addr', type: 'string', defaultValue: '":53"', description: 'DNS UDP/TCP bind address.' },
          { keyName: 'metrics_addr', type: 'string', defaultValue: '"127.0.0.1:9153"', description: 'Metrics bind address when web is disabled.' },
          { keyName: 'tcp_timeout', type: 'duration', defaultValue: '"10s"', description: 'Timeout for TCP/DoT query handling.' },
          { keyName: 'max_tcp_connections', type: 'int', defaultValue: '256', description: 'Maximum concurrent TCP/DoT connections.' },
          { keyName: 'max_udp_workers', type: 'int', defaultValue: '10000', description: 'Maximum UDP worker concurrency.' },
          { keyName: 'max_tcp_conns_per_client', type: 'int', defaultValue: '16', description: 'Per-source TCP connection cap.' },
          { keyName: 'max_dot_conns_per_client', type: 'int', defaultValue: '16', description: 'Per-source DoT connection cap.' },
          { keyName: 'dot_enabled', type: 'bool', defaultValue: 'false', description: 'Enable DNS-over-TLS listener.' },
          { keyName: 'dot_listen_addr', type: 'string', defaultValue: '":853"', description: 'DoT bind address.' },
          { keyName: 'tls_cert_file', type: 'string', defaultValue: '""', description: 'TLS cert file for DoT.' },
          { keyName: 'tls_key_file', type: 'string', defaultValue: '""', description: 'TLS key file for DoT.' },
        ]}
      />

      <h2 className={h2}>resolver</h2>
      <SectionTable
        dark={dark}
        rows={[
          { keyName: 'max_depth', type: 'int', defaultValue: '30', description: 'Maximum iterative resolution depth.' },
          { keyName: 'max_cname_depth', type: 'int', defaultValue: '10', description: 'Maximum CNAME/DNAME chaining depth.' },
          { keyName: 'upstream_timeout', type: 'duration', defaultValue: '"2s"', description: 'Per-upstream timeout.' },
          { keyName: 'upstream_retries', type: 'int', defaultValue: '3', description: 'Retry count per upstream query.' },
          { keyName: 'max_queries_per_request', type: 'int', defaultValue: '200', description: 'Total outbound query budget per client request.' },
          { keyName: 'request_timeout', type: 'duration', defaultValue: '"20s"', description: 'Wall-clock deadline per client request.' },
          { keyName: 'max_ns_names_per_delegation', type: 'int', defaultValue: '13', description: 'Delegation NS-name cap.' },
          { keyName: 'qname_minimization', type: 'bool', defaultValue: 'true', description: 'Enable RFC 9156 QNAME minimization.' },
          { keyName: 'caps_for_id', type: 'bool', defaultValue: 'true', description: 'Enable RFC 5452 0x20 case randomization for anti-spoofing.' },
          { keyName: 'prefer_ipv4', type: 'bool', defaultValue: 'true', description: 'Prefer IPv4 addresses for upstream contact.' },
          { keyName: 'dnssec_enabled', type: 'bool', defaultValue: 'true', description: 'Enable DNSSEC validation chain.' },
          { keyName: 'harden_below_nxdomain', type: 'bool', defaultValue: 'true', description: 'Enable RFC 8020-style harden-below-NXDOMAIN cache behavior.' },
          { keyName: 'root_hints_refresh', type: 'duration', defaultValue: '"12h"', description: 'Periodic root hints refresh interval.' },
          { keyName: 'dns64_enabled', type: 'bool', defaultValue: 'false', description: 'Enable DNS64 synthesis.' },
          { keyName: 'dns64_prefix', type: 'string', defaultValue: '"64:ff9b::/96"', description: 'DNS64 synthesis prefix.' },
        ]}
      />

      <h2 className={h2}>cache</h2>
      <SectionTable
        dark={dark}
        rows={[
          { keyName: 'max_entries', type: 'int', defaultValue: '100000', description: 'Maximum cache entries.' },
          { keyName: 'min_ttl', type: 'uint32', defaultValue: '5', description: 'Minimum TTL clamp.' },
          { keyName: 'max_ttl', type: 'uint32', defaultValue: '86400', description: 'Maximum TTL clamp.' },
          { keyName: 'negative_max_ttl', type: 'uint32', defaultValue: '3600', description: 'Maximum TTL for negative answers.' },
          { keyName: 'serve_stale', type: 'bool', defaultValue: 'false', description: 'Enable stale-answer serving.' },
          { keyName: 'serve_stale_ttl', type: 'uint32', defaultValue: '30', description: 'TTL value assigned to stale replies.' },
          { keyName: 'stale_max_age', type: 'uint32', defaultValue: '86400', description: 'Maximum age of stale entries eligible for serving.' },
          { keyName: 'prefetch', type: 'bool', defaultValue: 'true', description: 'Enable background prefetch near expiry.' },
          { keyName: 'no_cache_clients', type: 'csv', defaultValue: '""', description: 'Client IPs/CIDRs that bypass cache.' },
        ]}
      />

      <h2 className={h2}>security</h2>
      <SectionTable
        dark={dark}
        rows={[
          { keyName: 'dns_cookies', type: 'bool', defaultValue: 'false', description: 'Enable DNS Cookies (RFC 7873 / RFC 9018) with SipHash-2-4.' },
          { keyName: 'private_address_filter', type: 'bool', defaultValue: 'false', description: 'Strip A/AAAA records pointing at RFC1918/reserved ranges (DNS-rebinding protection). Default off; enable when serving only public names. Hot-reloadable from /api/config/raw.' },
          { keyName: 'rate_limit.enabled', type: 'bool', defaultValue: 'true', description: 'Enable per-IP rate limiting.' },
          { keyName: 'rate_limit.rate', type: 'float64', defaultValue: '50', description: 'Sustained requests per second per IP.' },
          { keyName: 'rate_limit.burst', type: 'int', defaultValue: '100', description: 'Burst allowance per IP.' },
          { keyName: 'rrl.enabled', type: 'bool', defaultValue: 'true', description: 'Enable Response Rate Limiting (anti-amplification).' },
          { keyName: 'rrl.responses_per_second', type: 'float64', defaultValue: '5', description: 'Max identical responses per second.' },
          { keyName: 'rrl.slip_ratio', type: 'int', defaultValue: '2', description: 'TC slip ratio (1 = always slip, 0 = always drop).' },
        ]}
      />

      <h2 className={h2}>web</h2>
      <SectionTable
        dark={dark}
        rows={[
          { keyName: 'enabled', type: 'bool', defaultValue: 'true', description: 'Enable embedded admin dashboard + API.' },
          { keyName: 'addr', type: 'string', defaultValue: '"127.0.0.1:9153"', description: 'Web bind address.' },
          { keyName: 'doh_enabled', type: 'bool', defaultValue: 'false', description: 'Enable DoH endpoint at /dns-query.' },
          { keyName: 'doh3_enabled', type: 'bool', defaultValue: 'false', description: 'Enable DoH over HTTP/3 (QUIC) on /dns-query. Requires web TLS.' },
          { keyName: 'tls_enabled', type: 'bool', defaultValue: 'false', description: 'Serve web API/dashboard over HTTPS directly.' },
          { keyName: 'tls_cert_file', type: 'string', defaultValue: '""', description: 'TLS cert file for web HTTPS.' },
          { keyName: 'tls_key_file', type: 'string', defaultValue: '""', description: 'TLS key file for web HTTPS.' },
          { keyName: 'auto_tls', type: 'bool', defaultValue: 'false', description: 'Enable automatic TLS certificate management.' },
          { keyName: 'auto_tls_cache_dir', type: 'string', defaultValue: '"certs"', description: 'Automatic TLS certificate cache directory.' },
          { keyName: 'auth.username', type: 'string', defaultValue: '""', description: 'Admin username.' },
          { keyName: 'auth.password_hash', type: 'string', defaultValue: '""', description: 'bcrypt password hash.' },
          { keyName: 'query_log_buffer', type: 'int', defaultValue: '1000', description: 'In-memory query log buffer size.' },
          { keyName: 'top_clients_limit', type: 'int', defaultValue: '2000', description: 'Top clients leaderboard size.' },
          { keyName: 'top_domains_limit', type: 'int', defaultValue: '2000', description: 'Top domains leaderboard size.' },
          { keyName: 'alert_error_threshold_pct', type: 'float64', defaultValue: '5', description: 'Dashboard error-rate alert threshold.' },
          { keyName: 'alert_latency_threshold_ms', type: 'int', defaultValue: '250', description: 'Dashboard latency alert threshold.' },
          { keyName: 'auto_update', type: 'bool', defaultValue: 'true', description: 'Enable periodic release checks.' },
          { keyName: 'update_check_interval', type: 'duration', defaultValue: '"24h"', description: 'Release check interval.' },
        ]}
      />

      <h2 className={h2}>daemon, zabbix, blocklist, and cluster</h2>
      <SectionTable
        dark={dark}
        rows={[
          { keyName: 'daemon.enabled', type: 'bool', defaultValue: 'false', description: 'Enable daemon mode from configuration.' },
          { keyName: 'daemon.pid_file', type: 'string', defaultValue: '"/var/run/labyrinth.pid"', description: 'Daemon PID file.' },
          { keyName: 'zabbix.enabled', type: 'bool', defaultValue: 'false', description: 'Enable the native Zabbix agent.' },
          { keyName: 'zabbix.addr', type: 'string', defaultValue: '""', description: 'Native Zabbix agent bind address.' },
          { keyName: 'blocklist.enabled', type: 'bool', defaultValue: 'false', description: 'Enable DNS blocklisting.' },
          { keyName: 'blocklist.refresh_interval', type: 'duration', defaultValue: '"24h"', description: 'Blocklist refresh interval.' },
          { keyName: 'blocklist.blocking_mode', type: 'string', defaultValue: '"nxdomain"', description: 'Blocking response mode.' },
          { keyName: 'cluster.enabled', type: 'bool', defaultValue: 'false', description: 'Enable multi-node coordination.' },
          { keyName: 'cluster.role', type: 'string', defaultValue: '"standalone"', description: 'Cluster role.' },
          { keyName: 'cluster.node_id', type: 'string', defaultValue: '"node-1"', description: 'Local cluster node identifier.' },
        ]}
      />

      <h2 className={h2}>Example: DoH + DoH3 + DoT Enabled</h2>
      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`server:
  listen_addr: "0.0.0.0:53"
  dot_enabled: true
  dot_listen_addr: ":853"
  tls_cert_file: "/etc/labyrinth/certs/dot.crt"
  tls_key_file: "/etc/labyrinth/certs/dot.key"

resolver:
  qname_minimization: true
  dnssec_enabled: true

web:
  enabled: true
  addr: "0.0.0.0:9153"
  doh_enabled: true
  doh3_enabled: true
  tls_enabled: true
  tls_cert_file: "/etc/labyrinth/certs/web.crt"
  tls_key_file: "/etc/labyrinth/certs/web.key"
  auth:
    username: "admin"
    password_hash: "$2a$10$..."
`}</code></pre>
    </div>
  )
}
