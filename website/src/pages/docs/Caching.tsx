interface Props { dark: boolean }

export default function Caching({ dark }: Props) {
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
      <h1 className={h1}>Caching</h1>

      <p className={p}>
        Labyrinth's cache is the core component that makes repeated DNS lookups nearly instantaneous. It uses
        a sharded architecture for high-concurrency access without lock contention, combined with TTL-based
        expiration and RFC-compliant stale serving.
      </p>

      <h2 className={h2}>256-Shard Architecture</h2>

      <p className={p}>
        The cache is divided into 256 independent shards. Each shard has its own lock and hash map, so
        concurrent reads and writes on different shards never contend with each other. This design scales
        linearly with the number of CPU cores.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`Cache Layout:
┌─────────┐ ┌─────────┐ ┌─────────┐     ┌─────────┐
│ Shard 0 │ │ Shard 1 │ │ Shard 2 │ ... │Shard 255│
│ RWMutex │ │ RWMutex │ │ RWMutex │     │ RWMutex │
│ HashMap │ │ HashMap │ │ HashMap │     │ HashMap │
└─────────┘ └─────────┘ └─────────┘     └─────────┘
     ▲            ▲           ▲               ▲
     └────────────┴───────────┴───────────────┘
                 FNV-1a(name + type) & 0xFF`}</code></pre>

      <h2 className={h2}>FNV-1a Hashing</h2>

      <p className={p}>
        The shard is selected by computing an FNV-1a hash of the query name (lowercased) concatenated with
        the query type, then taking the lowest 8 bits. FNV-1a was chosen for its excellent distribution
        properties and speed (no allocations, constant-time computation).
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`func shardIndex(name string, qtype uint16) uint8 {
    h := fnv1aInit
    for _, c := range toLower(name) {
        h ^= uint32(c)
        h *= fnv1aPrime
    }
    h ^= uint32(qtype)
    h *= fnv1aPrime
    return uint8(h & 0xFF)
}`}</code></pre>

      <h2 className={h2}>TTL Decay</h2>

      <p className={p}>
        When a record is cached, Labyrinth stores the absolute expiration time (insertion time + TTL).
        On every cache read, the returned TTL is the remaining time until expiration, not the original TTL.
        This ensures clients see accurate, decreasing TTL values just like a real authoritative server.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`Insert: name=example.com type=A ttl=3600 at T=0
Read at T=1000: returns TTL=2600
Read at T=3500: returns TTL=100
Read at T=3601: expired → cache miss → re-resolve`}</code></pre>

      <p className={p}>
        TTL values are clamped to the configured <code className={ic}>cache.min_ttl</code> and <code className={ic}>cache.max_ttl</code> bounds
        at insertion time.
      </p>

      <h2 className={h2}>Negative Caching (RFC 2308)</h2>

      <p className={p}>
        Labyrinth caches negative responses (NXDOMAIN and NODATA) as specified by RFC 2308. The TTL for
        negative cache entries is derived from the SOA record's minimum TTL field in the authority section,
        capped by <code className={ic}>cache.negative_max_ttl</code>.
      </p>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Response Type</th><th className="text-left py-2 font-semibold">Cached As</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4">NXDOMAIN (name does not exist)</td><td className="py-2">Negative entry with SOA minimum TTL</td></tr>
          <tr className={td}><td className="py-2 pr-4">NODATA (name exists, type does not)</td><td className="py-2">Negative entry with SOA minimum TTL</td></tr>
          <tr className={td}><td className="py-2 pr-4">SERVFAIL</td><td className="py-2">Not cached (transient error)</td></tr>
          <tr className={td}><td className="py-2 pr-4">REFUSED</td><td className="py-2">Not cached</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>Serve-Stale (RFC 8767)</h2>

      <p className={p}>
        When enabled (<code className={ic}>cache.serve_stale: true</code>), Labyrinth can serve expired cache entries
        while asynchronously refreshing them in the background. This dramatically improves availability when
        upstream servers are temporarily unreachable.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`Normal flow:
  Client query → Cache HIT (TTL > 0) → Return cached answer

Stale serving flow:
  Client query → Cache entry expired (TTL = 0, serve_stale = true)
    ├── Return stale answer immediately (TTL set to 30s)
    └── Background goroutine re-resolves and updates cache`}</code></pre>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Availability:</strong> Serve-stale means your DNS resolution stays
          functional even during upstream outages. Stale responses are returned with TTL
          <code className={ic}> cache.serve_stale_ttl </code> (default: 30 seconds)
          past their original expiration. When serving stale, an Extended DNS Error (RFC 8914, info code 3: Stale Answer)
          is attached to the response for clients that support EDNS0.
        </p>
      </div>

      <h2 className={h2}>Eviction Strategy</h2>

      <p className={p}>
        When cache reaches its <code className={ic}>cache.max_entries</code> limit, Labyrinth uses the following
        eviction strategy:
      </p>

      <ul className={ul}>
        <li><strong>Expired entries first</strong> &mdash; any entries past their TTL (and stale TTL) are removed</li>
        <li><strong>Closest to expiration</strong> &mdash; if still over capacity, entries closest to their expiration time are evicted</li>
        <li><strong>Negative entries</strong> &mdash; negative cache entries are evicted before positive ones</li>
      </ul>

      <h2 className={h2}>Cache Sizing Guidelines</h2>

      <p className={p}>
        Each cache entry consumes approximately 200-500 bytes depending on the record type and name length.
        Here are recommended settings for different deployment sizes:
      </p>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Deployment</th><th className="text-left py-2 pr-4 font-semibold">cache.max_entries</th><th className="text-left py-2 pr-4 font-semibold">Total Entries</th><th className="text-left py-2 font-semibold">Est. Memory</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4">Home / small office</td><td className="py-2 pr-4">25,000</td><td className="py-2 pr-4">25,000</td><td className="py-2">~5-15 MB</td></tr>
          <tr className={td}><td className="py-2 pr-4">Medium network</td><td className="py-2 pr-4">100,000</td><td className="py-2 pr-4">100,000</td><td className="py-2">~20-60 MB</td></tr>
          <tr className={td}><td className="py-2 pr-4">Large enterprise</td><td className="py-2 pr-4">500,000</td><td className="py-2 pr-4">500,000</td><td className="py-2">~100-300 MB</td></tr>
          <tr className={td}><td className="py-2 pr-4">Very high volume</td><td className="py-2 pr-4">1,000,000</td><td className="py-2 pr-4">1,000,000</td><td className="py-2">~200-600 MB</td></tr>
        </tbody>
      </table>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Rule of thumb:</strong> Start with <code className={ic}>cache.max_entries: 100000</code> and
          monitor the <code className={ic}>labyrinth_cache_evictions_total</code> Prometheus metric. If evictions
          are frequent, increase <code className={ic}>cache.max_entries</code>.
        </p>
      </div>
    </div>
  )
}
