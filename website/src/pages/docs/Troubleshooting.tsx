interface Props { dark: boolean }

export default function Troubleshooting({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const h3 = `text-lg font-semibold mt-6 mb-3 ${dark ? 'text-gray-200' : 'text-navy-800'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'
  const warn = `p-4 rounded-lg border-l-4 border-red-500 mb-6 ${dark ? 'bg-red-900/20' : 'bg-red-50'}`

  return (
    <div>
      <h1 className={h1}>Troubleshooting</h1>

      <p className={p}>
        This page covers common issues you may encounter when running Labyrinth, with step-by-step
        solutions for each.
      </p>

      <h2 className={h2}>Port 53 Already in Use</h2>

      <div className={warn}>
        <p className={`text-sm ${dark ? 'text-red-300' : 'text-red-700'}`}>
          <strong>Error:</strong> <code className={ic}>listen udp 0.0.0.0:53: bind: address already in use</code>
        </p>
      </div>

      <p className={p}>
        Another service is already using port 53. Common culprits:
      </p>

      <h3 className={h3}>On Ubuntu/Debian: systemd-resolved</h3>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Check what's using port 53
sudo ss -tulnp | grep :53

# If it's systemd-resolved, disable the stub listener:
sudo sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved

# Or disable systemd-resolved entirely:
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved

# Update /etc/resolv.conf to point to Labyrinth:
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf`}</code></pre>

      <h3 className={h3}>On macOS: mDNSResponder</h3>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Use an alternative port
server:
  listen_addr: "0.0.0.0:5353"

# Then configure macOS to use it:
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1`}</code></pre>

      <h3 className={h3}>Docker: Host network mode</h3>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Stop any host DNS services first, then use host networking:
docker run -d --network host \\
  ghcr.io/labyrinthdns/labyrinth:latest`}</code></pre>

      <h2 className={h2}>Permission Denied</h2>

      <div className={warn}>
        <p className={`text-sm ${dark ? 'text-red-300' : 'text-red-700'}`}>
          <strong>Error:</strong> <code className={ic}>listen udp 0.0.0.0:53: bind: permission denied</code>
        </p>
      </div>

      <p className={p}>
        Binding to ports below 1024 requires elevated privileges. Solutions (in order of preference):
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Option 1: Use capabilities (recommended)
sudo setcap cap_net_bind_service=+ep /usr/local/bin/labyrinth

# Option 2: systemd with AmbientCapabilities (if using systemd)
# Add to [Service] section:
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Option 3: Run as root (not recommended)
sudo labyrinth --config config.yaml`}</code></pre>

      <h2 className={h2}>High Latency on First Queries</h2>

      <p className={p}>
        The first query for any uncached domain requires iterative resolution (root → TLD → authoritative),
        which typically takes 40-200ms. This is normal behavior.
      </p>

      <ul className={ul}>
        <li><strong>Verify cache is working:</strong> Second query for the same domain should be under 1ms</li>
        <li><strong>Check upstream connectivity:</strong> Can the server reach root nameservers?</li>
        <li><strong>Check firewall:</strong> Ensure outbound UDP/TCP port 53 is open</li>
      </ul>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Test upstream connectivity
dig @198.41.0.4 . NS +norecurse
# Should return a list of root servers

# If this fails, check firewall:
sudo iptables -L -n | grep 53
# Ensure outbound DNS is allowed`}</code></pre>

      <h2 className={h2}>Cache Not Working</h2>

      <p className={p}>
        If repeated queries for the same domain are slow:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Check cache stats
curl -s http://localhost:9153/api/stats -H "Authorization: Bearer $TOKEN" | jq '.cache'

# Expected: hit_rate > 0.0, entries > 0
# If entries is 0 and hit_rate is 0, cache may not be initializing

# Check logs for cache errors
journalctl -u labyrinth | grep -i cache

# Dump cache shard info
kill -USR2 $(cat /var/run/labyrinth.pid)`}</code></pre>

      <p className={p}>
        Common causes:
      </p>

      <ul className={ul}>
        <li><code className={ic}>cache.max_entries</code> set to 0 or very low</li>
        <li>Cache is being evicted due to size limits (increase <code className={ic}>cache.max_entries</code>)</li>
        <li>Upstream responses have very low TTLs (check <code className={ic}>cache.min_ttl</code>)</li>
      </ul>

      <h2 className={h2}>Dashboard Not Loading</h2>

      <p className={p}>
        If you cannot access the web dashboard:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# 1. Verify the web server is running
curl -v http://localhost:9153/api/system/health
# Should return {"status":"ok"}

# 2. Check if web is enabled in config
grep -A3 "web:" /etc/labyrinth/config.yaml

# 3. Check listen address
# If address is "127.0.0.1", you can only access from localhost
# Change to "0.0.0.0" for remote access

# 4. Check firewall
sudo iptables -L -n | grep 9153
# Or: sudo ufw status

# 5. Check if port is actually listening
ss -tlnp | grep 9153`}</code></pre>

      <h2 className={h2}>Upstream Timeouts</h2>

      <div className={warn}>
        <p className={`text-sm ${dark ? 'text-red-300' : 'text-red-700'}`}>
          <strong>Log:</strong> <code className={ic}>upstream timeout server=198.41.0.4 duration_ms=5000</code>
        </p>
      </div>

      <p className={p}>
        Upstream timeouts can indicate network issues or overloaded upstream servers.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Test direct upstream connectivity
dig @198.41.0.4 com. NS +norecurse +timeout=5

# Check for packet loss
ping -c 10 198.41.0.4

# Check DNS traffic is not being blocked
sudo tcpdump -i any port 53 -n -c 20

# If behind a NAT, check conntrack table
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max
# If count is near max, increase max or reduce timeout:
sysctl -w net.netfilter.nf_conntrack_max=1048576`}</code></pre>

      <p className={p}>
        Remediation:
      </p>

      <ul className={ul}>
        <li>Increase <code className={ic}>resolver.upstream_timeout</code> if the upstream is slow but reachable</li>
        <li>Enable <code className={ic}>cache.serve_stale</code> to serve cached answers during upstream outages</li>
        <li>Check if a firewall or IDS is dropping outbound DNS</li>
        <li>Ensure conntrack table is not exhausted (see above)</li>
      </ul>

      <h2 className={h2}>High Memory Usage</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Check Go heap stats
curl -s http://localhost:9153/api/stats -H "Authorization: Bearer $TOKEN" | jq '.system'

# If memory_alloc_mb is much higher than expected:
# 1. Reduce cache size
cache:
  max_entries: 50000

# 2. Set Go memory limit
GOMEMLIMIT=2GiB labyrinth --config config.yaml

# 3. Force a GC cycle (debug only)
kill -USR1 $(cat /var/run/labyrinth.pid)
# Check memory again after stats dump`}</code></pre>

      <h2 className={h2}>Getting Help</h2>

      <p className={p}>
        If you are stuck:
      </p>

      <ul className={ul}>
        <li>Enable debug logging: <code className={ic}>logging.level: "debug"</code> and SIGHUP to reload</li>
        <li>Dump statistics: <code className={ic}>kill -USR1 $(pgrep labyrinth)</code></li>
        <li>Check the <a href="https://github.com/labyrinthdns/labyrinth/issues" target="_blank" rel="noopener noreferrer" className="text-gold-500 hover:underline">GitHub Issues</a> page</li>
        <li>Include version (<code className={ic}>labyrinth --version</code>), OS, and relevant logs when reporting issues</li>
      </ul>
    </div>
  )
}
