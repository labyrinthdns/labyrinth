import { Link } from 'react-router-dom'

interface Props { dark: boolean }

export default function DashboardSetup({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Dashboard Setup</h1>

      <p className={p}>
        Labyrinth includes a full-featured web dashboard built with React 19. The dashboard SPA is embedded
        directly in the Go binary &mdash; there are no external files to serve. This page covers enabling,
        configuring, and using the dashboard.
      </p>

      <h2 className={h2}>Enabling the Dashboard</h2>

      <p className={p}>
        The web dashboard is enabled by default. You can control it through the <code className={ic}>web</code> section
        of your config:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`web:
  enabled: true           # set to false to disable entirely
  address: "0.0.0.0"      # listen address (use 127.0.0.1 for local-only)
  port: 9153              # HTTP port`}</code></pre>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Security note:</strong> The default listen address is <code className={ic}>127.0.0.1</code>,
          which only accepts connections from localhost. Change to <code className={ic}>0.0.0.0</code> only if you need
          remote access, and ensure you have proper authentication configured.
        </p>
      </div>

      <h2 className={h2}>First-Time Setup Wizard</h2>

      <p className={p}>
        When you first access the dashboard (no admin account exists yet), Labyrinth displays a setup wizard
        that guides you through:
      </p>

      <ul className={ul}>
        <li><strong>Step 1:</strong> Welcome screen with system information</li>
        <li><strong>Step 2:</strong> Create an administrator username and password</li>
        <li><strong>Step 3:</strong> Confirm settings and complete setup</li>
      </ul>

      <p className={p}>
        After completing the wizard, you are automatically logged in and redirected to the main dashboard.
      </p>

      <h2 className={h2}>Admin Account</h2>

      <p className={p}>
        The admin account is created during the setup wizard or via the CLI:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Generate a password hash
labyrinth hash --password "your-secure-password"
# $2a$10$K7L/FqkZx...

# The hash is stored in the resolver's data directory
# Default: /var/lib/labyrinth/auth.json`}</code></pre>

      <p className={p}>
        You can reset the admin account by deleting the <code className={ic}>auth.json</code> file and restarting
        Labyrinth. The setup wizard will appear again on next dashboard access.
      </p>

      <h2 className={h2}>Accessing the Dashboard</h2>

      <p className={p}>
        Navigate to <code className={ic}>http://{'<server-ip>'}:9153</code> in any modern browser.
        The dashboard features:
      </p>

      <ul className={ul}>
        <li><strong>Overview</strong> &mdash; queries per second, cache hit rate, uptime, memory usage</li>
        <li><strong>Live Query Stream</strong> &mdash; real-time WebSocket feed of DNS queries and responses</li>
        <li><strong>Cache Management</strong> &mdash; browse, search, and flush cache entries</li>
        <li><strong>System Stats</strong> &mdash; goroutine count, memory allocation, upstream server health</li>
        <li><strong>Configuration</strong> &mdash; view the active configuration (read-only)</li>
      </ul>

      <h2 className={h2}>Theme Toggle</h2>

      <p className={p}>
        The dashboard supports both dark and light themes. Click the sun/moon icon in the top navigation bar
        to toggle. Your preference is saved in the browser's local storage and persists across sessions.
      </p>

      <h2 className={h2}>Reverse Proxy Setup</h2>

      <p className={p}>
        If you want to serve the dashboard behind a reverse proxy (nginx, Caddy, etc.):
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# nginx example
server {
    listen 443 ssl;
    server_name dns.example.com;

    location / {
        proxy_pass http://127.0.0.1:9153;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}`}</code></pre>

      <p className={p}>
        See <Link to="/docs/authentication" className="text-gold-500 hover:underline">Authentication</Link> for
        JWT configuration and <Link to="/docs/websocket" className="text-gold-500 hover:underline">WebSocket</Link> for
        live query stream setup behind proxies.
      </p>
    </div>
  )
}
