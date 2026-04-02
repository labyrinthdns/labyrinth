interface Props { dark: boolean }

export default function Monitoring({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'
  const th = dark ? 'border-b border-navy-700' : 'border-b border-mist-200'
  const td = dark ? 'border-b border-navy-800' : 'border-b border-mist-100'
  const tc = `w-full text-sm mb-6 ${dark ? 'text-gray-300' : 'text-navy-700'}`

  return (
    <div>
      <h1 className={h1}>Monitoring</h1>

      <p className={p}>
        Labyrinth provides comprehensive monitoring through Prometheus metrics, health/ready probes,
        and structured logging. This page documents every available metric and how to integrate with
        common monitoring stacks.
      </p>

      <h2 className={h2}>Prometheus Metrics</h2>

      <p className={p}>
        Metrics are exposed at <code className={ic}>GET /metrics</code> on the web dashboard port (default: 9153).
        No authentication is required for the metrics endpoint.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Prometheus scrape config
scrape_configs:
  - job_name: 'labyrinth'
    static_configs:
      - targets: ['labyrinth-host:9153']
    scrape_interval: 15s`}</code></pre>

      <h2 className={h2}>Available Metrics</h2>

      <table className={tc}>
        <thead><tr className={th}>
          <th className="text-left py-2 pr-4 font-semibold">Metric</th>
          <th className="text-left py-2 pr-4 font-semibold">Type</th>
          <th className="text-left py-2 font-semibold">Description</th>
        </tr></thead>
        <tbody>
          {[
            ['labyrinth_queries_total', 'counter', 'Total DNS queries received, labeled by type (A, AAAA, MX, etc.)'],
            ['labyrinth_queries_per_second', 'gauge', 'Current queries per second (1-minute rolling average)'],
            ['labyrinth_responses_total', 'counter', 'Total responses sent, labeled by rcode (NOERROR, NXDOMAIN, SERVFAIL)'],
            ['labyrinth_query_duration_seconds', 'histogram', 'Query processing duration in seconds'],
            ['labyrinth_cache_hits_total', 'counter', 'Total cache hits'],
            ['labyrinth_cache_misses_total', 'counter', 'Total cache misses'],
            ['labyrinth_cache_entries', 'gauge', 'Current number of cache entries'],
            ['labyrinth_cache_evictions_total', 'counter', 'Total cache evictions due to shard capacity'],
            ['labyrinth_cache_stale_served_total', 'counter', 'Total stale entries served (RFC 8767)'],
            ['labyrinth_upstream_queries_total', 'counter', 'Total queries sent to upstream servers'],
            ['labyrinth_upstream_duration_seconds', 'histogram', 'Upstream query round-trip time'],
            ['labyrinth_upstream_errors_total', 'counter', 'Total upstream query failures'],
            ['labyrinth_rate_limited_total', 'counter', 'Total queries rate-limited'],
            ['labyrinth_rrl_truncated_total', 'counter', 'Total responses truncated by RRL'],
            ['labyrinth_acl_denied_total', 'counter', 'Total queries denied by ACL'],
            ['labyrinth_coalesced_queries_total', 'counter', 'Total queries served by request coalescing'],
          ].map(([metric, type, desc]) => (
            <tr key={metric} className={td}>
              <td className="py-2 pr-4"><code className="text-xs font-mono text-gold-500">{metric}</code></td>
              <td className="py-2 pr-4">{type}</td>
              <td className="py-2 text-xs">{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 className={h2}>Process Metrics</h2>

      <p className={p}>
        Labyrinth also exposes standard Go runtime metrics:
      </p>

      <table className={tc}>
        <thead><tr className={th}>
          <th className="text-left py-2 pr-4 font-semibold">Metric</th>
          <th className="text-left py-2 font-semibold">Description</th>
        </tr></thead>
        <tbody>
          {[
            ['process_cpu_seconds_total', 'Total CPU time consumed'],
            ['process_resident_memory_bytes', 'Resident memory size'],
            ['go_goroutines', 'Number of active goroutines'],
            ['go_memstats_alloc_bytes', 'Current heap allocation in bytes'],
            ['go_memstats_sys_bytes', 'Total memory obtained from OS'],
            ['go_gc_duration_seconds', 'GC pause duration distribution'],
          ].map(([metric, desc]) => (
            <tr key={metric} className={td}>
              <td className="py-2 pr-4"><code className="text-xs font-mono text-gold-500">{metric}</code></td>
              <td className="py-2">{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 className={h2}>Grafana Dashboard</h2>

      <p className={p}>
        Recommended Grafana panels for a Labyrinth dashboard:
      </p>

      <ul className={ul}>
        <li><strong>Queries Per Second</strong> &mdash; <code className={ic}>rate(labyrinth_queries_total[5m])</code></li>
        <li><strong>Cache Hit Rate</strong> &mdash; <code className={ic}>labyrinth_cache_hits_total / (labyrinth_cache_hits_total + labyrinth_cache_misses_total)</code></li>
        <li><strong>P99 Latency</strong> &mdash; <code className={ic}>histogram_quantile(0.99, rate(labyrinth_query_duration_seconds_bucket[5m]))</code></li>
        <li><strong>Error Rate</strong> &mdash; <code className={ic}>rate(labyrinth_responses_total&#123;rcode="SERVFAIL"&#125;[5m])</code></li>
        <li><strong>Cache Entries</strong> &mdash; <code className={ic}>labyrinth_cache_entries</code></li>
        <li><strong>Upstream Latency</strong> &mdash; <code className={ic}>histogram_quantile(0.50, rate(labyrinth_upstream_duration_seconds_bucket[5m]))</code></li>
      </ul>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Tip:</strong> Set up alerts on <code className={ic}>labyrinth_upstream_errors_total</code> increasing
          rapidly and cache hit rate dropping below 80%. These are early indicators of upstream issues.
        </p>
      </div>

      <h2 className={h2}>Health & Readiness Endpoints</h2>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Health check (is the process alive?)
curl -s http://localhost:9153/health
# {"status":"ok"}

# Readiness check (is the resolver ready for queries?)
curl -s http://localhost:9153/ready
# {"status":"ready","cache_initialized":true,"listener_active":true}`}</code></pre>

      <p className={p}>
        Use <code className={ic}>/health</code> for container liveness probes and <code className={ic}>/ready</code> for
        readiness probes in Kubernetes or Docker health checks:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Docker health check
HEALTHCHECK --interval=30s --timeout=3s \\
  CMD curl -f http://localhost:9153/health || exit 1`}</code></pre>

      <h2 className={h2}>Structured Logging</h2>

      <p className={p}>
        Labyrinth supports JSON and text log formats. JSON is recommended for production as it integrates
        with log aggregation systems (ELK, Loki, Datadog, etc.).
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`logging:
  level: "info"       # debug, info, warn, error
  format: "json"      # json or text
  output: "stderr"    # stderr, stdout, or /path/to/file
  log_queries: false  # log every DNS query (verbose)

# Example JSON log output:
{"level":"info","ts":"2025-01-15T14:32:01Z","msg":"query resolved","name":"example.com.","type":"A","rcode":"NOERROR","latency_ms":2.34,"cached":true}
{"level":"warn","ts":"2025-01-15T14:32:02Z","msg":"upstream timeout","server":"198.41.0.4","duration_ms":5000}`}</code></pre>
    </div>
  )
}
