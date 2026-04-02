interface Props { dark: boolean }

export default function DaemonMode({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Daemon Mode</h1>

      <p className={p}>
        Labyrinth can run as a background daemon with PID file management and command-line controls for
        starting, stopping, and checking status. This is useful on systems without systemd or when you
        prefer self-contained process management.
      </p>

      <h2 className={h2}>Starting as a Daemon</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Start Labyrinth in daemon mode (forks to background)
labyrinth --config /etc/labyrinth/config.yaml --daemon

# Output:
# Labyrinth daemon started (PID 12345)
# PID file: /var/run/labyrinth.pid`}</code></pre>

      <p className={p}>
        The <code className={ic}>--daemon</code> flag causes Labyrinth to:
      </p>

      <ul className={ul}>
        <li>Fork the process to the background</li>
        <li>Write the PID to the configured PID file</li>
        <li>Close stdin and redirect stdout/stderr to the log output</li>
        <li>Return control to the terminal immediately</li>
      </ul>

      <h2 className={h2}>Daemon Commands</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Start the daemon
labyrinth --daemon --config /etc/labyrinth/config.yaml

# Check if the daemon is running
labyrinth --daemon status
# Output: Labyrinth is running (PID 12345)
# -- or --
# Output: Labyrinth is not running

# Stop the daemon gracefully (sends SIGTERM)
labyrinth --daemon stop
# Output: Labyrinth daemon stopped (PID 12345)

# Restart the daemon (stop + start)
labyrinth --daemon restart --config /etc/labyrinth/config.yaml
# Output: Labyrinth daemon stopped (PID 12345)
# Output: Labyrinth daemon started (PID 12346)`}</code></pre>

      <h2 className={h2}>PID File</h2>

      <p className={p}>
        The PID file is written when the daemon starts and removed on clean shutdown. Configure its location:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`daemon:
  pid_file: "/var/run/labyrinth.pid"    # default
  work_dir: "/var/lib/labyrinth"        # working directory`}</code></pre>

      <p className={p}>
        If a PID file already exists and the process is running, <code className={ic}>--daemon</code> will refuse
        to start and print an error. Remove the stale PID file manually if the previous instance crashed
        without cleanup:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Check if the PID in the file is actually running
cat /var/run/labyrinth.pid
# 12345

ps -p 12345
# No output = stale PID file

# Remove stale PID file
rm /var/run/labyrinth.pid

# Now start normally
labyrinth --daemon --config /etc/labyrinth/config.yaml`}</code></pre>

      <h2 className={h2}>systemd vs Daemon Mode</h2>

      <p className={p}>
        For modern Linux systems, systemd is the preferred way to manage Labyrinth:
      </p>

      <table className={`w-full text-sm mb-6 ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
        <thead>
          <tr className={dark ? 'border-b border-navy-700' : 'border-b border-mist-200'}>
            <th className="text-left py-2 pr-4 font-semibold">Feature</th>
            <th className="text-left py-2 pr-4 font-semibold">systemd</th>
            <th className="text-left py-2 font-semibold">Daemon Mode</th>
          </tr>
        </thead>
        <tbody>
          {[
            ['Auto-restart on crash', 'Yes (Restart=on-failure)', 'No'],
            ['Log management', 'journald integration', 'File-based logging'],
            ['Resource limits', 'cgroups (MemoryMax, etc.)', 'ulimits only'],
            ['Boot startup', 'WantedBy=multi-user.target', 'rc.local / crontab @reboot'],
            ['Security hardening', 'ProtectSystem, NoNewPrivileges', 'Not available'],
            ['Process supervision', 'Built-in', 'PID file only'],
            ['Platform support', 'Linux only', 'Any Unix-like OS'],
          ].map(([feature, systemd, daemon]) => (
            <tr key={feature} className={dark ? 'border-b border-navy-800' : 'border-b border-mist-100'}>
              <td className="py-2 pr-4">{feature}</td>
              <td className="py-2 pr-4">{systemd}</td>
              <td className="py-2">{daemon}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Recommendation:</strong> Use systemd on Linux for production deployments.
          Use daemon mode on macOS, FreeBSD, or other Unix systems where systemd is not available.
        </p>
      </div>

      <h2 className={h2}>Running in Foreground</h2>

      <p className={p}>
        Without <code className={ic}>--daemon</code>, Labyrinth runs in the foreground. This is useful for:
      </p>

      <ul className={ul}>
        <li>Docker containers (the container runtime manages the process)</li>
        <li>systemd (<code className={ic}>Type=simple</code> expects the process to stay in the foreground)</li>
        <li>Development and debugging</li>
        <li>Running under process managers like supervisord</li>
      </ul>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Foreground (Ctrl+C to stop)
labyrinth --config config.yaml

# Foreground with debug logging
labyrinth --config config.yaml --log-level debug`}</code></pre>
    </div>
  )
}
