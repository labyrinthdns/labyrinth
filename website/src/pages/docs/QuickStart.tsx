import { Link } from 'react-router-dom'

interface Props { dark: boolean }

export default function QuickStart({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Quick Start</h1>

      <p className={p}>
        This guide walks you through installing Labyrinth, resolving your first DNS query, and accessing
        the web dashboard. You will be up and running in under two minutes.
      </p>

      <h2 className={h2}>Step 1: Install</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | bash`}</code></pre>

      <p className={p}>
        This downloads the latest release binary and installs it to <code className={ic}>/usr/local/bin/labyrinth</code>.
        See <Link to="/docs/installation" className="text-gold-500 hover:underline">Installation</Link> for
        alternative methods (Docker, from source, etc.).
      </p>

      <h2 className={h2}>Step 2: Create a Config File</h2>

      <p className={p}>
        Create a minimal <code className={ic}>config.yaml</code> file. Labyrinth will use sensible defaults
        for anything not specified:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# config.yaml - minimal configuration
server:
  address: "0.0.0.0"
  port: 53

resolver:
  enable_qname_minimization: true

cache:
  max_entries_per_shard: 10000
  serve_stale: true

web:
  enabled: true
  address: "0.0.0.0"
  port: 9153`}</code></pre>

      <h2 className={h2}>Step 3: Start Labyrinth</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Start in the foreground (use --daemon for background mode)
sudo labyrinth --config config.yaml`}</code></pre>

      <p className={p}>
        You should see output like:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`[INFO] Labyrinth DNS v1.3.0 starting
[INFO] Loading configuration from config.yaml
[INFO] Cache initialized: 256 shards, 10000 entries per shard
[INFO] DNS listener started on 0.0.0.0:53 (UDP+TCP)
[INFO] Web dashboard listening on http://0.0.0.0:9153
[INFO] Ready to resolve queries`}</code></pre>

      <h2 className={h2}>Step 4: Test with dig</h2>

      <p className={p}>
        Open another terminal and verify that resolution works:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Query the A record for example.com
dig @127.0.0.1 example.com A

# Expected output (truncated):
;; ANSWER SECTION:
example.com.        3600    IN    A    93.184.216.34

;; Query time: 42 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)

# Query again - should be much faster (cached)
dig @127.0.0.1 example.com A

;; Query time: 0 msec`}</code></pre>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Note:</strong> The first query takes ~40-100ms as Labyrinth iterates
          from root servers. Subsequent queries for the same name return from cache in under 50 microseconds.
        </p>
      </div>

      <h2 className={h2}>Step 5: Open the Dashboard</h2>

      <p className={p}>
        Navigate to <code className={ic}>http://localhost:9153</code> in your browser. On first access,
        you will see the setup wizard.
      </p>

      <h2 className={h2}>Step 6: Create an Admin Account</h2>

      <p className={p}>
        The setup wizard prompts you to create an administrator account. Enter a username and password.
        Labyrinth hashes the password using its built-in <code className={ic}>labyrinth hash</code> utility
        (bcrypt-based) and stores the credentials locally.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# You can also create credentials from the command line:
labyrinth hash --password "your-secure-password"

# Output:
$2a$10$K7L/FqkZ...hashed...password`}</code></pre>

      <h2 className={h2}>Step 7: Verify Everything Works</h2>

      <p className={p}>
        Once logged in to the dashboard, verify:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Check multiple record types
dig @127.0.0.1 google.com A
dig @127.0.0.1 google.com AAAA
dig @127.0.0.1 google.com MX
dig @127.0.0.1 cloudflare.com NS

# Check health endpoint
curl -s http://localhost:9153/health
# {"status":"ok"}

# Check readiness
curl -s http://localhost:9153/ready
# {"status":"ready"}`}</code></pre>

      <p className={p}>
        The dashboard should show live queries streaming in as you run <code className={ic}>dig</code> commands.
      </p>

      <h2 className={h2}>Next Steps</h2>

      <p className={p}>
        Now that you have a running resolver, you can:
      </p>

      <ul className={`list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
        <li><Link to="/docs/configuration" className="text-gold-500 hover:underline">Configure</Link> every aspect of the resolver</li>
        <li><Link to="/docs/security" className="text-gold-500 hover:underline">Set up security</Link> with ACLs and rate limiting</li>
        <li><Link to="/docs/monitoring" className="text-gold-500 hover:underline">Enable monitoring</Link> with Prometheus or Zabbix</li>
        <li><Link to="/docs/daemon-mode" className="text-gold-500 hover:underline">Run as a daemon</Link> for production deployments</li>
      </ul>
    </div>
  )
}
