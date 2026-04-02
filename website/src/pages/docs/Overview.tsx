import { Link } from 'react-router-dom'

interface Props { dark: boolean }

export default function Overview({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const th = dark ? 'border-b border-navy-700' : 'border-b border-mist-200'
  const td = dark ? 'border-b border-navy-800' : 'border-b border-mist-100'
  const tc = `w-full text-sm mb-6 ${dark ? 'text-gray-300' : 'text-navy-700'}`

  return (
    <div>
      <h1 className={h1}>What is Labyrinth?</h1>

      <p className={p}>
        Labyrinth is a high-performance, pure Go recursive DNS resolver designed for production environments.
        It ships as a single, statically-linked binary with zero external dependencies &mdash; no C libraries,
        no runtime requirements, no configuration files to hunt for. Start it, point your clients at it, and
        you have a fully functional recursive DNS resolver with a built-in web dashboard.
      </p>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">TL;DR:</strong> Labyrinth resolves DNS queries from the root of
          the DNS hierarchy, caches aggressively with 256 lock-free shards, exposes Prometheus and Zabbix
          metrics, and includes a full React web dashboard &mdash; all in a ~7 MB binary.
        </p>
      </div>

      <h2 className={h2}>Key Features</h2>

      <ul className={ul}>
        <li><strong>Recursive resolution</strong> from root hints through TLD and authoritative servers, with QNAME minimization (RFC 9156)</li>
        <li><strong>256-shard concurrent cache</strong> with FNV-1a hashing, TTL decay, negative caching (RFC 2308), and serve-stale (RFC 8767)</li>
        <li><strong>Built-in web dashboard</strong> &mdash; a React 19 SPA served directly from the binary, with live WebSocket query stream, cache analytics, and a first-time setup wizard</li>
        <li><strong>Full observability</strong> &mdash; Prometheus metrics endpoint, native Zabbix agent protocol, structured JSON logging, health and readiness probes</li>
        <li><strong>Security</strong> &mdash; bailiwick enforcement, TXID and source port randomization, per-IP rate limiting, response rate limiting (RRL), and IP-based ACLs</li>
        <li><strong>Daemon mode</strong> with PID files, signal handling (SIGHUP for config reload, SIGUSR1/2 for diagnostics), and systemd integration</li>
        <li><strong>Benchmark tool</strong> (<code className={ic}>labyrinth-bench</code>) with distributed coordinator/runner architecture and a web UI for results</li>
      </ul>

      <h2 className={h2}>Architecture Overview</h2>

      <p className={p}>
        Labyrinth follows a clean, modular architecture with clearly separated concerns:
      </p>

      <pre className="code-block p-4 mb-6"><code className="text-sm text-gray-300 font-mono">{`DNS Clients ──▶ UDP/TCP Listener ──▶ Resolver Engine ──▶ Sharded Cache
                       │                    │
                       ▼                    ▼
                 Security Layer      Upstream Servers
                 (ACL, RRL, Rate)    (Root → TLD → Auth)
                       │
              Web Dashboard ◀── JWT Auth ◀── Browser
                       │
              Observability
              (Prometheus, Zabbix, Logs)`}</code></pre>

      <p className={p}>
        The <strong>DNS Listener</strong> accepts UDP and TCP queries on port 53 with full EDNS0 support (4096-byte buffers).
        Queries pass through the <strong>Security Layer</strong> for ACL checks and rate limiting before reaching
        the <strong>Resolver Engine</strong>. The resolver checks the <strong>Sharded Cache</strong> first; on a miss,
        it performs iterative resolution starting from the root servers.
      </p>

      <h2 className={h2}>When to Use Labyrinth</h2>

      <p className={p}>
        Labyrinth is ideal when you want a self-contained DNS resolver without operational complexity.
        Here is how it compares to alternatives:
      </p>

      <table className={tc}>
        <thead>
          <tr className={th}>
            <th className="text-left py-2 pr-4 font-semibold">Feature</th>
            <th className="text-left py-2 pr-4 font-semibold">Labyrinth</th>
            <th className="text-left py-2 pr-4 font-semibold">Unbound</th>
            <th className="text-left py-2 pr-4 font-semibold">BIND 9</th>
            <th className="text-left py-2 font-semibold">CoreDNS</th>
          </tr>
        </thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4">Language</td><td className="py-2 pr-4">Go</td><td className="py-2 pr-4">C</td><td className="py-2 pr-4">C</td><td className="py-2">Go</td></tr>
          <tr className={td}><td className="py-2 pr-4">Dependencies</td><td className="py-2 pr-4">None</td><td className="py-2 pr-4">OpenSSL, libevent</td><td className="py-2 pr-4">Many</td><td className="py-2">Plugin-based</td></tr>
          <tr className={td}><td className="py-2 pr-4">Web Dashboard</td><td className="py-2 pr-4 text-gold-500">Built-in</td><td className="py-2 pr-4">No</td><td className="py-2 pr-4">No</td><td className="py-2">No</td></tr>
          <tr className={td}><td className="py-2 pr-4">Single Binary</td><td className="py-2 pr-4 text-gold-500">Yes</td><td className="py-2 pr-4">Yes</td><td className="py-2 pr-4">No</td><td className="py-2">Yes</td></tr>
          <tr className={td}><td className="py-2 pr-4">Recursive</td><td className="py-2 pr-4">Yes</td><td className="py-2 pr-4">Yes</td><td className="py-2 pr-4">Yes</td><td className="py-2">Via plugin</td></tr>
          <tr className={td}><td className="py-2 pr-4">DNSSEC Validation</td><td className="py-2 pr-4">Planned</td><td className="py-2 pr-4">Yes</td><td className="py-2 pr-4">Yes</td><td className="py-2">Via plugin</td></tr>
          <tr className={td}><td className="py-2 pr-4">Prometheus Metrics</td><td className="py-2 pr-4 text-gold-500">Built-in</td><td className="py-2 pr-4">With exporter</td><td className="py-2 pr-4">With exporter</td><td className="py-2">Built-in</td></tr>
          <tr className={td}><td className="py-2 pr-4">Zabbix Agent</td><td className="py-2 pr-4 text-gold-500">Built-in</td><td className="py-2 pr-4">No</td><td className="py-2 pr-4">No</td><td className="py-2">No</td></tr>
        </tbody>
      </table>

      <p className={p}>
        Choose Labyrinth when you want <strong>minimal operational overhead</strong>, a <strong>built-in management UI</strong>,
        and <strong>native monitoring integration</strong>. For environments requiring DNSSEC validation today,
        Unbound or BIND remain the proven choices.
      </p>

      <h2 className={h2}>Next Steps</h2>

      <ul className={ul}>
        <li><Link to="/docs/installation" className="text-gold-500 hover:underline">Installation</Link> &mdash; get Labyrinth running on your system</li>
        <li><Link to="/docs/quick-start" className="text-gold-500 hover:underline">Quick Start</Link> &mdash; resolve your first query in under a minute</li>
        <li><Link to="/docs/configuration" className="text-gold-500 hover:underline">Configuration</Link> &mdash; complete reference for every config key</li>
      </ul>
    </div>
  )
}
