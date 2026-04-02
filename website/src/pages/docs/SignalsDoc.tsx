interface Props { dark: boolean }

export default function SignalsDoc({ dark }: Props) {
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
      <h1 className={h1}>Signal Handling</h1>

      <p className={p}>
        Labyrinth responds to standard Unix signals for graceful shutdown, configuration reload, and
        runtime diagnostics. This page documents each signal and its behavior.
      </p>

      <h2 className={h2}>Signal Reference</h2>

      <table className={tc}>
        <thead><tr className={th}>
          <th className="text-left py-2 pr-4 font-semibold">Signal</th>
          <th className="text-left py-2 pr-4 font-semibold">Action</th>
          <th className="text-left py-2 font-semibold">Description</th>
        </tr></thead>
        <tbody>
          <tr className={td}>
            <td className="py-2 pr-4"><code className={ic}>SIGINT</code></td>
            <td className="py-2 pr-4">Graceful Shutdown</td>
            <td className="py-2">Stops accepting new queries, finishes in-flight queries, then exits</td>
          </tr>
          <tr className={td}>
            <td className="py-2 pr-4"><code className={ic}>SIGTERM</code></td>
            <td className="py-2 pr-4">Graceful Shutdown</td>
            <td className="py-2">Same as SIGINT. Used by systemd and daemon stop command</td>
          </tr>
          <tr className={td}>
            <td className="py-2 pr-4"><code className={ic}>SIGHUP</code></td>
            <td className="py-2 pr-4">Configuration Reload</td>
            <td className="py-2">Reloads config file without restarting. Updates rate limits, ACLs, logging, and cache settings</td>
          </tr>
          <tr className={td}>
            <td className="py-2 pr-4"><code className={ic}>SIGUSR1</code></td>
            <td className="py-2 pr-4">Dump Statistics</td>
            <td className="py-2">Writes current statistics to the log (queries, cache, memory, goroutines)</td>
          </tr>
          <tr className={td}>
            <td className="py-2 pr-4"><code className={ic}>SIGUSR2</code></td>
            <td className="py-2 pr-4">Dump Cache Info</td>
            <td className="py-2">Writes per-shard cache statistics to the log (entry count, hit/miss per shard)</td>
          </tr>
        </tbody>
      </table>

      <h2 className={h2}>SIGINT / SIGTERM &mdash; Graceful Shutdown</h2>

      <p className={p}>
        When Labyrinth receives SIGINT (Ctrl+C) or SIGTERM (from systemd, kill, or daemon stop):
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Ctrl+C in foreground mode
^C
[INFO] Received SIGINT, initiating graceful shutdown...
[INFO] DNS listener stopped, no new queries accepted
[INFO] Waiting for 3 in-flight queries to complete...
[INFO] All queries completed
[INFO] Web server stopped
[INFO] Zabbix agent stopped
[INFO] Cache contains 45,678 entries (not persisted)
[INFO] PID file removed
[INFO] Labyrinth shutdown complete

# Or send SIGTERM
kill -TERM $(cat /var/run/labyrinth.pid)

# Equivalent daemon command
labyrinth --daemon stop`}</code></pre>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Timeout:</strong> Graceful shutdown waits up to 10 seconds for
          in-flight queries to complete. After 10 seconds, remaining queries are abandoned and the process exits.
          A second SIGINT/SIGTERM during the grace period forces an immediate exit.
        </p>
      </div>

      <h2 className={h2}>SIGHUP &mdash; Configuration Reload</h2>

      <p className={p}>
        SIGHUP triggers a hot reload of the configuration file. The resolver continues serving queries
        during the reload with zero downtime.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Edit the config file
vim /etc/labyrinth/config.yaml

# Send SIGHUP to reload
kill -HUP $(cat /var/run/labyrinth.pid)

# Log output:
[INFO] Received SIGHUP, reloading configuration...
[INFO] Configuration reloaded from /etc/labyrinth/config.yaml
[INFO] Rate limit updated: 100 → 200 rps
[INFO] ACL updated: 3 allow rules, 1 deny rule
[INFO] Log level changed: info → debug`}</code></pre>

      <p className={p}>
        The following settings can be changed with a SIGHUP reload (no restart needed):
      </p>

      <ul className={`list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
        <li>Rate limit settings (<code className={ic}>security.rate_limit.*</code>)</li>
        <li>RRL settings (<code className={ic}>security.rrl.*</code>)</li>
        <li>Access control lists (<code className={ic}>access_control.*</code>)</li>
        <li>Logging level and format (<code className={ic}>logging.*</code>)</li>
        <li>Cache TTL limits (<code className={ic}>cache.min_ttl</code>, <code className={ic}>cache.max_ttl</code>)</li>
        <li>Serve-stale settings</li>
      </ul>

      <p className={p}>
        Settings that require a restart:
      </p>

      <ul className={`list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
        <li>Listen address/port (<code className={ic}>server.address</code>, <code className={ic}>server.port</code>)</li>
        <li>Web dashboard address/port</li>
        <li>Cache shard count or max entries per shard</li>
        <li>Zabbix agent address/port</li>
      </ul>

      <h2 className={h2}>SIGUSR1 &mdash; Dump Statistics</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`kill -USR1 $(cat /var/run/labyrinth.pid)

# Log output:
[INFO] === Labyrinth Statistics Dump ===
[INFO] Uptime: 14d 3h 22m
[INFO] Queries: 1,247,832 total (14.4/s current)
[INFO] Cache: 45,678 entries, 94.2% hit rate
[INFO]   Hits: 1,175,460  Misses: 72,372  Evictions: 1,234
[INFO]   Stale served: 567
[INFO] Rate limited: 234 queries
[INFO] RRL truncated: 89 responses
[INFO] ACL denied: 12 queries
[INFO] System: 142 goroutines, 128.5 MB heap, 16 CPUs
[INFO] =================================`}</code></pre>

      <h2 className={h2}>SIGUSR2 &mdash; Dump Cache Info</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`kill -USR2 $(cat /var/run/labyrinth.pid)

# Log output:
[INFO] === Cache Shard Statistics ===
[INFO] Shard   0: 178 entries, 4521 hits, 312 misses
[INFO] Shard   1: 195 entries, 3892 hits, 287 misses
[INFO] Shard   2: 167 entries, 5234 hits, 401 misses
[INFO] ...
[INFO] Shard 255: 183 entries, 4102 hits, 298 misses
[INFO] Total: 45,678 entries across 256 shards
[INFO] Min/Max entries per shard: 142 / 212
[INFO] ================================`}</code></pre>

      <p className={p}>
        This is useful for diagnosing uneven cache distribution or identifying hot shards.
      </p>

      <h2 className={h2}>Sending Signals in Practice</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Using PID file
kill -HUP $(cat /var/run/labyrinth.pid)

# Using pgrep
kill -USR1 $(pgrep -f labyrinth)

# Using systemd (for SIGHUP reload)
systemctl reload labyrinth

# Using systemd (for stop)
systemctl stop labyrinth`}</code></pre>
    </div>
  )
}
