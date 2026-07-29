interface Props { dark: boolean }

export default function BenchmarkTool({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Benchmark Tool</h1>

      <p className={p}>
        Labyrinth ships with <code className={ic}>labyrinth-bench</code>, a high-performance DNS benchmarking
        tool. It supports both quick single-node benchmarks and distributed mode with a coordinator and
        multiple runner nodes for testing at scale.
      </p>

      <h2 className={h2}>Building labyrinth-bench</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Build from source
cd labyrinth
go build -o labyrinth-bench ./cmd/labyrinth-bench

# Or download from releases
curl -Lo labyrinth-bench \\
  https://github.com/labyrinthdns/labyrinth/releases/latest/download/labyrinth-bench-linux-amd64
chmod +x labyrinth-bench`}</code></pre>

      <h2 className={h2}>Quick Mode</h2>

      <p className={p}>
        The simplest way to benchmark your resolver:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Basic benchmark: 10,000 queries to localhost
labyrinth-bench --server 127.0.0.1:53 --count 10000

# With concurrency and duration
labyrinth-bench --server 127.0.0.1:53 \\
  --duration 30s \\
  --concurrency 50 \\
  --qps 0           # 0 = unlimited, as fast as possible

# Query specific domains from a file
labyrinth-bench --server 127.0.0.1:53 \\
  --domains domains.txt \\
  --duration 60s \\
  --concurrency 100`}</code></pre>

      <p className={p}>
        Example output:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`Labyrinth DNS Benchmark
═══════════════════════════════════════════════════════
Target:        127.0.0.1:53
Duration:      30.00s
Concurrency:   50
Total Queries: 847,234

Results:
  QPS (avg):     28,241
  QPS (peak):    31,445

Latency:
  Min:           0.024ms
  P50:           1.42ms
  P90:           3.21ms
  P99:           8.67ms
  P99.9:         24.31ms
  Max:           89.45ms

Response Codes:
  NOERROR:       842,123 (99.4%)
  NXDOMAIN:      4,892  (0.6%)
  SERVFAIL:      219    (0.0%)

Errors:
  Timeouts:      14
  Network:       0
═══════════════════════════════════════════════════════`}</code></pre>

      <h2 className={h2}>Distributed Mode</h2>

      <p className={p}>
        For realistic large-scale testing, <code className={ic}>labyrinth-bench</code> supports a distributed
        architecture with a coordinator that orchestrates multiple runner nodes:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# On runner nodes (one or more machines):
labyrinth-bench --mode runner \\
  --listen 0.0.0.0:9200

# On the coordinator:
labyrinth-bench --mode coordinator \\
  --runners 10.0.1.10:9200,10.0.1.11:9200,10.0.1.12:9200 \\
  --server 10.0.0.5:53 \\
  --duration 120s \\
  --concurrency 200 \\
  --domains domains.txt \\
  --web 0.0.0.0:9201`}</code></pre>

      <p className={p}>
        The coordinator:
      </p>

      <ul className={ul}>
        <li>Distributes the domain list to all runners</li>
        <li>Synchronizes start/stop across all nodes</li>
        <li>Collects results and computes aggregate statistics</li>
        <li>Serves a web UI at the <code className={ic}>--web</code> address for live progress</li>
      </ul>

      <h2 className={h2}>Domain List Format</h2>

      <p className={p}>
        The domains file is a plain text file with one domain per line:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# domains.txt
google.com
facebook.com
amazon.com
github.com
cloudflare.com
example.com
stackoverflow.com
wikipedia.org
youtube.com
reddit.com`}</code></pre>

      <p className={p}>
        If no domains file is specified, <code className={ic}>labyrinth-bench</code> uses a built-in list of the
        top 1000 domains.
      </p>

      <h2 className={h2}>Interpreting Results</h2>

      <ul className={ul}>
        <li><strong>QPS:</strong> Queries per second. Higher is better. Compare against your deployment targets.</li>
        <li><strong>P50 latency:</strong> Median latency. Should be under 5ms for cached queries.</li>
        <li><strong>P99 latency:</strong> Tail latency. Keep this under 50ms for good user experience.</li>
        <li><strong>SERVFAIL rate:</strong> Should be well under 1%. High rates indicate upstream issues.</li>
        <li><strong>Timeouts:</strong> Should be zero for local/cached benchmarks. Some timeouts are normal for uncached queries to slow upstream servers.</li>
      </ul>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Benchmarking tip:</strong> Run the benchmark twice. The first run
          warms the cache; the second run measures cached performance. Compare the two to see the impact of
          caching on your workload.
        </p>
      </div>

      <h2 className={h2}>Web UI</h2>

      <p className={p}>
        When using <code className={ic}>--web</code>, <code className={ic}>labyrinth-bench</code> serves a
        real-time dashboard showing:
      </p>

      <ul className={ul}>
        <li>Live QPS graph (updated every second)</li>
        <li>Latency histogram (P50, P90, P99)</li>
        <li>Response code distribution pie chart</li>
        <li>Per-runner status and throughput</li>
        <li>Overall progress and ETA</li>
      </ul>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Quick mode with web UI
labyrinth-bench --server 127.0.0.1:53 \\
  --duration 60s \\
  --concurrency 100 \\
  --web 0.0.0.0:9201

# Open http://localhost:9201 in your browser`}</code></pre>

      <h2 className={h2}>CLI Reference</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`labyrinth-bench [flags]

Flags:
  --server string       Target DNS server (host:port) (required)
  --count int           Number of queries to send (0 = use --duration)
  --duration duration   Benchmark duration (e.g., 30s, 5m)
  --concurrency int     Number of concurrent workers (default: 10)
  --qps int             Target QPS rate limit (0 = unlimited)
  --domains string      Path to domains file (one per line)
  --type string         Query type: A, AAAA, MX, etc. (default: A)
  --mode string         Mode: quick, runner, coordinator (default: quick)
  --runners string      Comma-separated runner addresses (coordinator mode)
  --listen string       Listen address for runner mode
  --web string          Web UI listen address (e.g., 0.0.0.0:9201)
  --json                Output results as JSON
  --timeout duration    Per-query timeout (default: 5s)`}</code></pre>
    </div>
  )
}
