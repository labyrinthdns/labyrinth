interface Props { dark: boolean }

export default function Resolution({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Recursive Resolution</h1>

      <p className={p}>
        Labyrinth is a fully recursive resolver. Unlike forwarders that delegate to upstream resolvers (like 8.8.8.8),
        Labyrinth starts from the DNS root and iteratively navigates the hierarchy to find authoritative answers.
        This section explains how that process works internally.
      </p>

      <h2 className={h2}>The Iterative Resolution Process</h2>

      <p className={p}>
        When a client queries <code className={ic}>www.example.com A</code> and the answer is not in cache,
        Labyrinth follows these steps:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`Step 1: Query root server (e.g., a.root-servers.net)
        "Who handles .com?"
        Response: Referral to .com TLD servers

Step 2: Query .com TLD server (e.g., a.gtld-servers.net)
        "Who handles example.com?"
        Response: Referral to example.com authoritative servers

Step 3: Query authoritative server (e.g., ns1.example.com)
        "What is the A record for www.example.com?"
        Response: A 93.184.216.34 (authoritative answer)`}</code></pre>

      <p className={p}>
        Each step involves sending a DNS query over UDP (falling back to TCP if the response is truncated)
        and processing the referral or answer.
      </p>

      <h2 className={h2}>Root Hints</h2>

      <p className={p}>
        Resolution starts with root hints &mdash; the IP addresses of the 13 DNS root server clusters (a.root-servers.net
        through m.root-servers.net). Labyrinth includes these addresses at compile time, so no external root hints
        file is needed. You can override them with the <code className={ic}>resolver.root_hints_file</code> config key.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Built-in root hints (partial)
a.root-servers.net.    198.41.0.4      2001:503:ba3e::2:30
b.root-servers.net.    170.247.170.2   2801:1b8:10::b
c.root-servers.net.    192.33.4.12     2001:500:2::c
...
m.root-servers.net.    202.12.27.33    2001:dc3::35`}</code></pre>

      <h2 className={h2}>QNAME Minimization</h2>

      <p className={p}>
        By default, Labyrinth implements QNAME minimization (RFC 9156). Instead of sending the full query name
        to each server in the chain, it only sends the minimum labels needed for that delegation level:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`Without QNAME minimization:
  Root server sees:  "www.example.com"
  TLD server sees:   "www.example.com"
  Auth server sees:  "www.example.com"

With QNAME minimization:
  Root server sees:  "com" (just the TLD)
  TLD server sees:   "example.com" (just the delegation point)
  Auth server sees:  "www.example.com" (full query)`}</code></pre>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Privacy benefit:</strong> QNAME minimization prevents intermediate servers
          from learning the full domain you are resolving. The root server never sees that you are looking
          up <code className={ic}>secret-project.internal.example.com</code> &mdash; it only sees <code className={ic}>com</code>.
        </p>
      </div>

      <h2 className={h2}>CNAME Chasing</h2>

      <p className={p}>
        When the resolver encounters a CNAME record, it transparently follows the chain to the final answer.
        For example:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`Client queries: www.example.com A

Step 1: www.example.com → CNAME → cdn.example.net
Step 2: cdn.example.net → CNAME → edge.cdn-provider.com
Step 3: edge.cdn-provider.com → A → 203.0.113.42

Response to client includes the full CNAME chain + final A record.`}</code></pre>

      <p className={p}>
        The maximum CNAME chain length is configurable via <code className={ic}>resolver.max_cname_chain</code> (default: 16).
        Labyrinth aborts resolution and returns SERVFAIL if the chain exceeds this limit, preventing infinite loops.
      </p>

      <h2 className={h2}>Delegation Handling</h2>

      <p className={p}>
        When a nameserver responds with a referral (authority section with NS records, no answer), Labyrinth:
      </p>

      <ul className={ul}>
        <li>Extracts NS records from the authority section</li>
        <li>Checks the additional section for glue records (A/AAAA of the NS servers)</li>
        <li>If glue is missing, resolves the NS server names before continuing (this is a sub-query)</li>
        <li>Selects the fastest nameserver based on previous RTT measurements</li>
        <li>Continues resolution at the new delegation level</li>
      </ul>

      <h2 className={h2}>Bailiwick Enforcement</h2>

      <p className={p}>
        Bailiwick checking prevents cache poisoning by rejecting records that a nameserver is not authoritative for.
        A nameserver for <code className={ic}>example.com</code> can provide records for <code className={ic}>sub.example.com</code>
        {' '}but NOT for <code className={ic}>evil.com</code>. Any out-of-bailiwick records in the additional section are silently discarded.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Response from ns1.example.com (authoritative for example.com):

;; AUTHORITY SECTION:
example.com.    86400   IN  NS  ns1.example.com.    ← Accepted (in bailiwick)

;; ADDITIONAL SECTION:
ns1.example.com.  3600  IN  A  203.0.113.1         ← Accepted (in bailiwick)
evil.com.          300   IN  A  192.0.2.666         ← REJECTED (out of bailiwick)`}</code></pre>

      <h2 className={h2}>Loop Detection</h2>

      <p className={p}>
        The resolver tracks the set of nameservers queried at each delegation level. If it encounters a loop
        (being referred back to a nameserver it already queried for the same query), it aborts with SERVFAIL.
        The <code className={ic}>resolver.max_depth</code> setting (default: 30) provides a hard upper bound on
        resolution depth as an additional safety net.
      </p>

      <h2 className={h2}>Request Coalescing</h2>

      <p className={p}>
        When multiple clients query the same name simultaneously and it is not cached, Labyrinth coalesces
        these into a single upstream resolution. The first query triggers the resolution; subsequent identical
        queries wait for the same result. This dramatically reduces upstream traffic under load.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`Time 0ms:   Client A queries example.com A → starts resolution
Time 2ms:   Client B queries example.com A → joins existing resolution
Time 3ms:   Client C queries example.com A → joins existing resolution
Time 45ms:  Resolution completes → all three clients get the answer

Without coalescing: 3 upstream queries
With coalescing:    1 upstream query`}</code></pre>

      <p className={p}>
        Request coalescing is enabled by default and can be toggled with <code className={ic}>resolver.enable_request_coalescing</code>.
      </p>
    </div>
  )
}
