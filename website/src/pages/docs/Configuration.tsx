interface Props { dark: boolean }

export default function Configuration({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'
  const th = dark ? 'border-b border-navy-700' : 'border-b border-mist-200'
  const td = dark ? 'border-b border-navy-800' : 'border-b border-mist-100'
  const tc = `w-full text-sm mb-6 ${dark ? 'text-gray-300' : 'text-navy-700'}`

  return (
    <div>
      <h1 className={h1}>Configuration Reference</h1>

      <p className={p}>
        Labyrinth is configured via a YAML file passed with the <code className={ic}>--config</code> flag.
        Every key has a sensible default; you only need to specify values you want to override.
      </p>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">File path:</strong> By convention, use
          {' '}<code className={ic}>/etc/labyrinth/config.yaml</code> on Linux or pass any path
          with <code className={ic}>labyrinth --config /path/to/config.yaml</code>.
        </p>
      </div>

      <h2 className={h2}>server</h2>

      <p className={p}>Controls the DNS listener.</p>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>address</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>"0.0.0.0"</code></td><td className="py-2">Listen address for DNS queries</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>port</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>53</code></td><td className="py-2">Listen port</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>tcp_enabled</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>true</code></td><td className="py-2">Enable TCP listener alongside UDP</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>edns_buffer_size</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>4096</code></td><td className="py-2">EDNS0 UDP buffer size in bytes</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>read_timeout</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"5s"</code></td><td className="py-2">TCP read timeout</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>write_timeout</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"5s"</code></td><td className="py-2">TCP write timeout</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>workers</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>0</code></td><td className="py-2">Number of UDP worker goroutines (0 = GOMAXPROCS)</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>resolver</h2>

      <p className={p}>Controls the recursive resolution engine.</p>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>enable_qname_minimization</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>true</code></td><td className="py-2">RFC 9156 QNAME minimization for privacy</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>max_depth</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>30</code></td><td className="py-2">Maximum resolution depth before aborting</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>max_cname_chain</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>16</code></td><td className="py-2">Maximum CNAME chain length</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>query_timeout</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"10s"</code></td><td className="py-2">Per-upstream query timeout</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>total_timeout</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"30s"</code></td><td className="py-2">Total resolution timeout (all attempts)</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>root_hints_file</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>""</code></td><td className="py-2">Path to root hints file (uses built-in if empty)</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>enable_request_coalescing</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>true</code></td><td className="py-2">Coalesce duplicate in-flight queries</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>dnssec</h2>

      <p className={p}>Controls DNSSEC validation (RFC 4033-4035).</p>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>enabled</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>true</code></td><td className="py-2">Enable DNSSEC validation for all queries</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>blocklist</h2>

      <p className={p}>Controls DNS blocklist filtering (Pi-hole style ad/tracker blocking).</p>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>enabled</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>false</code></td><td className="py-2">Enable DNS blocklist filtering</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>lists</code></td><td className="py-2 pr-4">[]string</td><td className="py-2 pr-4"><code className={ic}>[]</code></td><td className="py-2">URLs of blocklist files (hosts or domain-list format)</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>refresh_interval</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"24h"</code></td><td className="py-2">How often to refresh blocklists from sources</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>cache</h2>

      <p className={p}>Controls the 256-shard concurrent cache.</p>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>max_entries_per_shard</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>10000</code></td><td className="py-2">Max entries per cache shard (total = 256 x this)</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>serve_stale</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>true</code></td><td className="py-2">Serve stale records while refreshing (RFC 8767)</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>stale_ttl</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"24h"</code></td><td className="py-2">How long to serve stale entries</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>negative_ttl</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"900s"</code></td><td className="py-2">TTL for negative (NXDOMAIN/NODATA) cache entries</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>min_ttl</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"60s"</code></td><td className="py-2">Minimum TTL floor for cached entries</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>max_ttl</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"86400s"</code></td><td className="py-2">Maximum TTL cap for cached entries</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>security</h2>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>rate_limit.enabled</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>true</code></td><td className="py-2">Enable per-IP rate limiting</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>rate_limit.requests_per_second</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>100</code></td><td className="py-2">Max queries per second per IP</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>rate_limit.burst</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>200</code></td><td className="py-2">Burst allowance</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>rrl.enabled</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>true</code></td><td className="py-2">Response Rate Limiting</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>rrl.responses_per_second</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>5</code></td><td className="py-2">Identical responses per second before truncation</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>rrl.window</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"15s"</code></td><td className="py-2">RRL sliding window duration</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>logging</h2>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>level</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>"info"</code></td><td className="py-2">Log level: debug, info, warn, error</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>format</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>"json"</code></td><td className="py-2">Output format: json or text</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>output</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>"stderr"</code></td><td className="py-2">Output destination: stderr, stdout, or file path</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>log_queries</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>false</code></td><td className="py-2">Log every DNS query (verbose, use debug level)</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>web</h2>

      <p className={p}>Controls the built-in web dashboard and API.</p>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>enabled</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>true</code></td><td className="py-2">Enable web dashboard</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>address</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>"127.0.0.1"</code></td><td className="py-2">Web server listen address</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>port</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>9153</code></td><td className="py-2">Web server port</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>jwt_secret</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>""</code></td><td className="py-2">JWT signing secret (auto-generated if empty)</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>token_lifetime</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"24h"</code></td><td className="py-2">JWT token expiration</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>cors_origins</code></td><td className="py-2 pr-4">[]string</td><td className="py-2 pr-4"><code className={ic}>["*"]</code></td><td className="py-2">Allowed CORS origins</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>auto_update</h2>

      <p className={p}>Controls the self-update mechanism accessible from the web dashboard.</p>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>enabled</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>true</code></td><td className="py-2">Enable self-update from the web dashboard</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>check_interval</code></td><td className="py-2 pr-4">duration</td><td className="py-2 pr-4"><code className={ic}>"24h"</code></td><td className="py-2">How often to check for new versions</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>daemon</h2>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>pid_file</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>"/var/run/labyrinth.pid"</code></td><td className="py-2">PID file path when running as daemon</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>work_dir</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>"/var/lib/labyrinth"</code></td><td className="py-2">Working directory for the daemon</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>zabbix</h2>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>enabled</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>false</code></td><td className="py-2">Enable native Zabbix agent protocol</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>address</code></td><td className="py-2 pr-4">string</td><td className="py-2 pr-4"><code className={ic}>"0.0.0.0"</code></td><td className="py-2">Zabbix agent listen address</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>port</code></td><td className="py-2 pr-4">int</td><td className="py-2 pr-4"><code className={ic}>10050</code></td><td className="py-2">Zabbix agent listen port</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>access_control</h2>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Key</th><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Default</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>enabled</code></td><td className="py-2 pr-4">bool</td><td className="py-2 pr-4"><code className={ic}>false</code></td><td className="py-2">Enable IP-based ACLs</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>allow</code></td><td className="py-2 pr-4">[]string</td><td className="py-2 pr-4"><code className={ic}>[]</code></td><td className="py-2">Allowed CIDRs (e.g., "10.0.0.0/8")</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>deny</code></td><td className="py-2 pr-4">[]string</td><td className="py-2 pr-4"><code className={ic}>[]</code></td><td className="py-2">Denied CIDRs (evaluated before allow)</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>Example: Production Configuration</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`server:
  address: "0.0.0.0"
  port: 53
  workers: 8
  edns_buffer_size: 4096

resolver:
  enable_qname_minimization: true
  max_depth: 30
  query_timeout: "10s"
  total_timeout: "30s"
  enable_request_coalescing: true

dnssec:
  enabled: true

blocklist:
  enabled: true
  lists:
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    - "https://adaway.org/hosts.txt"
  refresh_interval: "12h"

cache:
  max_entries_per_shard: 50000
  serve_stale: true
  stale_ttl: "48h"
  negative_ttl: "900s"
  min_ttl: "60s"
  max_ttl: "86400s"

security:
  rate_limit:
    enabled: true
    requests_per_second: 200
    burst: 500
  rrl:
    enabled: true
    responses_per_second: 5
    window: "15s"

access_control:
  enabled: true
  allow:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"

web:
  enabled: true
  address: "0.0.0.0"
  port: 9153
  token_lifetime: "12h"

auto_update:
  enabled: true
  check_interval: "24h"

logging:
  level: "info"
  format: "json"
  output: "/var/log/labyrinth/labyrinth.log"

zabbix:
  enabled: true
  port: 10050`}</code></pre>

      <h2 className={h2}>Example: Minimal Home Lab</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`server:
  address: "0.0.0.0"
  port: 53

dnssec:
  enabled: true

blocklist:
  enabled: true
  lists:
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

cache:
  max_entries_per_shard: 5000
  serve_stale: true

web:
  enabled: true
  address: "0.0.0.0"
  port: 9153

logging:
  level: "info"
  format: "text"`}</code></pre>
    </div>
  )
}
