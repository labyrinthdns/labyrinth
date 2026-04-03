interface Props { dark: boolean }

export default function SignalsDoc({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'
  const th = dark ? 'border-b border-navy-700' : 'border-b border-mist-200'
  const td = dark ? 'border-b border-navy-800' : 'border-b border-mist-100'
  const tc = `w-full text-sm mb-6 ${dark ? 'text-gray-300' : 'text-navy-700'}`

  return (
    <div>
      <h1 className={h1}>Signal Handling</h1>

      <p className={p}>
        Labyrinth supports Unix signals for shutdown and operational diagnostics.
        The table below reflects current runtime behavior.
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
            <td className="py-2 pr-4">Graceful shutdown</td>
            <td className="py-2">Stops servers, waits for grace period, exits.</td>
          </tr>
          <tr className={td}>
            <td className="py-2 pr-4"><code className={ic}>SIGTERM</code></td>
            <td className="py-2 pr-4">Graceful shutdown</td>
            <td className="py-2">Same shutdown path as SIGINT.</td>
          </tr>
          <tr className={td}>
            <td className="py-2 pr-4"><code className={ic}>SIGUSR1</code></td>
            <td className="py-2 pr-4">Flush cache</td>
            <td className="py-2">Flushes DNS cache and logs final entry count.</td>
          </tr>
          <tr className={td}>
            <td className="py-2 pr-4"><code className={ic}>SIGUSR2</code></td>
            <td className="py-2 pr-4">Cache stats</td>
            <td className="py-2">Logs cache entry snapshot.</td>
          </tr>
          <tr className={td}>
            <td className="py-2 pr-4"><code className={ic}>SIGHUP</code></td>
            <td className="py-2 pr-4">Reload request log</td>
            <td className="py-2">Currently logs reload request only; restart required to apply config changes.</td>
          </tr>
        </tbody>
      </table>

      <h2 className={h2}>Examples</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Graceful shutdown
kill -TERM $(cat /var/run/labyrinth.pid)

# Flush cache
kill -USR1 $(cat /var/run/labyrinth.pid)

# Log cache entry snapshot
kill -USR2 $(cat /var/run/labyrinth.pid)

# Request reload (informational; restart still required)
kill -HUP $(cat /var/run/labyrinth.pid)`}</code></pre>

      <h2 className={h2}>Restart-Required Settings</h2>

      <p className={p}>
        Changing listener addresses and TLS settings requires restart. Typical examples:
      </p>

      <ul className={`list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
        <li><code className={ic}>server.listen_addr</code></li>
        <li><code className={ic}>server.dot_enabled</code> and DoT TLS files</li>
        <li><code className={ic}>web.addr</code> and web TLS files</li>
        <li><code className={ic}>cache.max_entries</code></li>
      </ul>
    </div>
  )
}
