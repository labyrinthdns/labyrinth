import { Link } from 'react-router-dom'

interface Props { dark: boolean }

export default function PerformanceTuning({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Performance Tuning</h1>

      <p className={p}>
        Labyrinth is fast out of the box, but production deployments handling thousands of queries per second
        benefit from careful tuning. This guide covers cache sizing, worker configuration, OS-level tuning,
        and benchmarking methodology.
      </p>

      <h2 className={h2}>Cache Sizing</h2>

      <p className={p}>
        The cache is the single most impactful performance knob. A larger cache means more hits, less upstream
        traffic, and lower latency. See the <Link to="/docs/caching" className="text-gold-500 hover:underline">Caching</Link> page
        for sizing guidelines.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Start with this and monitor evictions
cache:
  max_entries: 100000

# If labyrinth_cache_evictions_total is growing fast, increase:
cache:
  max_entries: 500000`}</code></pre>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Key metric:</strong> Watch <code className={ic}>labyrinth_cache_evictions_total</code>.
          If this counter is growing, you are losing cached entries prematurely. Increase <code className={ic}>cache.max_entries</code>.
        </p>
      </div>

      <h2 className={h2}>Worker Configuration</h2>

      <p className={p}>
        The <code className={ic}>server.max_udp_workers</code> setting controls maximum UDP handler concurrency.
        The default is conservative for high-throughput setups and can be lowered on smaller systems.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Auto (recommended for most cases)
server:
  max_udp_workers: 10000

# Manual override for specific hardware
server:
  max_udp_workers: 2000`}</code></pre>

      <p className={p}>
        Guidelines:
      </p>

      <ul className={ul}>
        <li>Start with defaults and load test before tuning</li>
        <li>Lower values can reduce memory pressure on small VMs</li>
        <li>Excessively high values can increase context-switch overhead</li>
      </ul>

      <h2 className={h2}>OS Tuning (Linux)</h2>

      <p className={p}>
        The operating system can be a bottleneck if not properly configured. Apply these settings for
        high-throughput DNS serving:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# /etc/security/limits.d/labyrinth.conf
# Increase file descriptor limits
labyrinth  soft  nofile  65535
labyrinth  hard  nofile  65535

# /etc/sysctl.d/99-labyrinth.conf
# Increase UDP buffer sizes
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# Increase connection tracking (if using conntrack)
net.netfilter.nf_conntrack_max = 1048576

# Increase network backlog
net.core.netdev_max_backlog = 50000
net.core.somaxconn = 4096

# Apply sysctl changes
sudo sysctl -p /etc/sysctl.d/99-labyrinth.conf`}</code></pre>

      <h2 className={h2}>systemd Resource Limits</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# /etc/systemd/system/labyrinth.service.d/limits.conf
[Service]
LimitNOFILE=65535
LimitNPROC=65535

# Apply
sudo systemctl daemon-reload
sudo systemctl restart labyrinth`}</code></pre>

      <h2 className={h2}>NUMA Considerations</h2>

      <p className={p}>
        On multi-socket NUMA systems, pin Labyrinth to a single NUMA node for best performance.
        Cross-NUMA memory access adds significant latency to cache operations.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Check NUMA topology
numactl --hardware

# Pin to NUMA node 0
numactl --cpunodebind=0 --membind=0 labyrinth --config config.yaml

# Or in systemd:
[Service]
ExecStart=/usr/bin/numactl --cpunodebind=0 --membind=0 /usr/local/bin/labyrinth --config /etc/labyrinth/config.yaml`}</code></pre>

      <h2 className={h2}>Go Runtime Tuning</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Set max CPUs (defaults to all available)
GOMAXPROCS=16 labyrinth --config config.yaml

# Tune GC target percentage (default 100)
# Lower = more frequent GC, lower memory, slightly more CPU
# Higher = less frequent GC, higher memory, slightly less CPU
GOGC=200 labyrinth --config config.yaml

# For low-latency workloads, consider memory limit
GOMEMLIMIT=4GiB labyrinth --config config.yaml`}</code></pre>

      <h2 className={h2}>Benchmarking Methodology</h2>

      <p className={p}>
        Follow this methodology for reliable performance measurements:
      </p>

      <ul className={ul}>
        <li><strong>Warm the cache first.</strong> Run a benchmark pass, discard results, then run the real benchmark.</li>
        <li><strong>Use a realistic domain list.</strong> Top-1000 domains or your actual query logs.</li>
        <li><strong>Test both cached and uncached.</strong> Cached shows resolver throughput; uncached shows resolution speed.</li>
        <li><strong>Run from a separate machine.</strong> Benchmarking on the same machine introduces noise from resource contention.</li>
        <li><strong>Run for at least 60 seconds.</strong> Short benchmarks are noisy. 5 minutes is ideal.</li>
        <li><strong>Monitor system metrics.</strong> Watch CPU, memory, and network during the benchmark.</li>
        <li><strong>Run multiple iterations.</strong> Take the median of at least 3 runs.</li>
      </ul>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Recommended benchmark sequence:

# 1. Warm cache (discard results)
labyrinth-bench --server 10.0.0.5:53 --duration 30s --concurrency 50

# 2. Cached performance (the main benchmark)
labyrinth-bench --server 10.0.0.5:53 --duration 120s --concurrency 100 --json > cached.json

# 3. Uncached performance (flush cache first)
curl -X POST http://10.0.0.5:9153/api/cache/flush -H "Authorization: Bearer $TOKEN"
labyrinth-bench --server 10.0.0.5:53 --duration 120s --concurrency 100 --json > uncached.json

# 4. Compare results
jq '.qps_avg' cached.json uncached.json`}</code></pre>
    </div>
  )
}
