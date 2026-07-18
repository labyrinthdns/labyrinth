interface Props { dark: boolean }

export default function Installation({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const h3 = `text-lg font-semibold mt-6 mb-3 ${dark ? 'text-gray-200' : 'text-navy-800'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Installation</h1>

      <p className={p}>
        Labyrinth can be installed in several ways. Choose the method that best fits your environment.
      </p>

      <h2 className={h2}>One-Line Install Script</h2>

      <p className={p}>
        The fastest way to get started on Linux or macOS. The script auto-detects your OS and architecture,
        installs the binary at <code className={ic}>/opt/labyrinth/bin/labyrinth</code>, and creates a
        {' '}<code className={ic}>/usr/local/bin/labyrinth</code> symlink.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | bash`}</code></pre>

      <p className={p}>
        Use installer flags to select a release or skip systemd setup:
      </p>

      <ul className={ul}>
        <li><code className={ic}>--version TAG</code> &mdash; install a specific release (default: latest)</li>
        <li><code className={ic}>--no-service</code> &mdash; install binaries without creating a systemd service</li>
      </ul>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Install a specific version
curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | \\
  bash -s -- --version v0.8.31`}</code></pre>

      <h2 className={h2}>Build from Source</h2>

      <h3 className={h3}>Prerequisites</h3>

      <ul className={ul}>
        <li>Go 1.26.5 or later</li>
        <li>Node.js 22 or later and npm</li>
        <li>Git</li>
        <li>Make (optional, for convenience targets)</li>
      </ul>

      <h3 className={h3}>Build Steps</h3>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Clone the repository
git clone https://github.com/labyrinthdns/labyrinth.git
cd labyrinth

# Build the embedded dashboard, then the main binary
cd web/ui
npm ci
npm run build
cd ../..
go build -o labyrinth .

# Build the benchmark tool (optional)
go build -o labyrinth-bench ./cmd/labyrinth-bench

# Verify the build
./labyrinth -version`}</code></pre>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Tip:</strong> For production builds, use
          {' '}<code className={ic}>CGO_ENABLED=0</code> to produce a fully static binary with no libc dependency.
        </p>
      </div>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`CGO_ENABLED=0 go build -ldflags="-s -w" -o labyrinth .`}</code></pre>

      <h2 className={h2}>Docker</h2>

      <p className={p}>
        Official images are published to GitHub Container Registry (GHCR) for every release. The safe default publishes only DNS; the admin dashboard remains container-local until you configure authentication and explicitly publish it.
      </p>

      <h3 className={h3}>Quick Run</h3>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`docker run -d \\
  --name labyrinth \\
  -p 53:53/udp \\
  -p 53:53/tcp \\
  -v "$PWD/labyrinth.yaml:/etc/labyrinth/labyrinth.yaml:ro" \\
  ghcr.io/labyrinthdns/labyrinth:latest \\
  -config /etc/labyrinth/labyrinth.yaml`}</code></pre>

      <h3 className={h3}>Docker Compose</h3>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`services:
  labyrinth:
    image: ghcr.io/labyrinthdns/labyrinth:latest
    container_name: labyrinth
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      # After setting web.auth and web.addr in labyrinth.yaml:
      # - "127.0.0.1:9153:9153"
    volumes:
      - ./labyrinth.yaml:/etc/labyrinth/labyrinth.yaml:ro
      - labyrinth-data:/var/lib/labyrinth
    command: ["-config", "/etc/labyrinth/labyrinth.yaml"]

volumes:
  labyrinth-data:`}</code></pre>

      <h3 className={h3}>Publishing the Authenticated Dashboard</h3>

      <p className={p}>
        First set non-empty <code className={ic}>web.auth</code> credentials and <code className={ic}>web.addr: "0.0.0.0:9153"</code> in the mounted configuration. Then publish the admin port on a trusted host interface or behind an authenticated TLS reverse proxy:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`docker run -d \\
  --name labyrinth \\
  -p 53:53/udp \\
  -p 53:53/tcp \\
  -p 127.0.0.1:9153:9153 \\
  -v /path/to/labyrinth.yaml:/etc/labyrinth/labyrinth.yaml:ro \\
  ghcr.io/labyrinthdns/labyrinth:latest \\
  -config /etc/labyrinth/labyrinth.yaml`}</code></pre>

      <h2 className={h2}>Manual Binary Download</h2>

      <p className={p}>
        Download pre-built binaries from the GitHub releases page:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Linux amd64
curl -Lo labyrinth https://github.com/labyrinthdns/labyrinth/releases/latest/download/labyrinth-linux-amd64
chmod +x labyrinth
sudo mv labyrinth /usr/local/bin/

# Linux arm64
curl -Lo labyrinth https://github.com/labyrinthdns/labyrinth/releases/latest/download/labyrinth-linux-arm64
chmod +x labyrinth
sudo mv labyrinth /usr/local/bin/

# macOS arm64 (Apple Silicon)
curl -Lo labyrinth https://github.com/labyrinthdns/labyrinth/releases/latest/download/labyrinth-darwin-arm64
chmod +x labyrinth
sudo mv labyrinth /usr/local/bin/`}</code></pre>

      <h2 className={h2}>systemd Service Setup</h2>

      <p className={p}>
        For production Linux deployments, run Labyrinth as a systemd service:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Create a system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin labyrinth

# Create directories
sudo mkdir -p /etc/labyrinth /var/lib/labyrinth
sudo chown labyrinth:labyrinth /var/lib/labyrinth

# Copy binary and config
sudo cp labyrinth /usr/local/bin/
sudo cp labyrinth.yaml /etc/labyrinth/

# Create the systemd unit file
sudo tee /etc/systemd/system/labyrinth.service > /dev/null << 'EOF'
[Unit]
Description=Labyrinth DNS Resolver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=labyrinth
Group=labyrinth
ExecStart=/usr/local/bin/labyrinth -config /etc/labyrinth/labyrinth.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# Security hardening
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/labyrinth
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now labyrinth

# Check status
sudo systemctl status labyrinth`}</code></pre>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Note:</strong> The <code className={ic}>CAP_NET_BIND_SERVICE</code> capability
          allows Labyrinth to bind to port 53 without running as root. This is the recommended production setup.
        </p>
      </div>

      <h2 className={h2}>Verify Installation</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Check the version
labyrinth -version

# Test a quick resolve
labyrinth -config labyrinth.yaml &
dig @127.0.0.1 example.com A

# Access the dashboard
open http://localhost:9153`}</code></pre>
    </div>
  )
}
