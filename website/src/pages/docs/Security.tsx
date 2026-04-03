interface Props { dark: boolean }

export default function Security({ dark }: Props) {
  const h1 = `text-3xl font-bold mb-6 ${dark ? 'text-white' : 'text-navy-900'}`
  const h2 = `text-xl font-semibold mt-10 mb-4 ${dark ? 'text-white' : 'text-navy-900'}`
  const p = `mb-4 leading-relaxed ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const ul = `list-disc pl-6 mb-4 space-y-1 ${dark ? 'text-gray-300' : 'text-navy-700'}`
  const info = `p-4 rounded-lg border-l-4 border-gold-500 mb-6 ${dark ? 'bg-navy-800/50' : 'bg-gold-500/5'}`
  const ic = 'px-1.5 py-0.5 rounded text-sm font-mono bg-navy-800 text-gold-500'
  const cb = 'code-block p-4 mb-6'

  return (
    <div>
      <h1 className={h1}>Security</h1>

      <p className={p}>
        Labyrinth implements multiple layers of security to protect against DNS spoofing, amplification attacks,
        and unauthorized use. This page covers each mechanism and how to configure it.
      </p>

      <h2 className={h2}>Bailiwick Enforcement</h2>

      <p className={p}>
        Bailiwick checking is the most fundamental DNS security measure. It prevents a nameserver from poisoning
        the cache with records it has no authority over. When Labyrinth receives a response from a nameserver
        authoritative for <code className={ic}>example.com</code>, it only accepts records within that zone:
      </p>

      <ul className={ul}>
        <li><code className={ic}>sub.example.com</code> &mdash; accepted (within bailiwick)</li>
        <li><code className={ic}>example.com</code> &mdash; accepted (exact match)</li>
        <li><code className={ic}>evil.com</code> &mdash; rejected and discarded</li>
        <li><code className={ic}>com</code> &mdash; rejected (parent zone, out of bailiwick)</li>
      </ul>

      <p className={p}>
        This is always enabled and cannot be disabled.
      </p>

      <h2 className={h2}>Transaction ID Randomization</h2>

      <p className={p}>
        Every outgoing DNS query uses a cryptographically random 16-bit transaction ID generated from
        {' '}<code className={ic}>crypto/rand</code>. This makes it infeasible for an attacker to guess the TXID
        and inject a spoofed response (a Kaminsky-style attack requires guessing the correct TXID from 65,536 possibilities).
      </p>

      <h2 className={h2}>Source Port Randomization</h2>

      <p className={p}>
        In addition to TXID randomization, Labyrinth uses a random ephemeral source port for each outgoing query.
        Combined with the 16-bit TXID, this gives approximately 2 billion possible combinations (16 bits TXID x ~15 bits
        of port entropy), making blind spoofing attacks impractical.
      </p>

      <h2 className={h2}>DNSSEC Validation</h2>

      <p className={p}>
        Labyrinth performs full DNSSEC validation (RFC 4033-4035) to cryptographically verify the authenticity
        and integrity of DNS responses. When enabled, every response is validated through the chain of trust
        from the root zone down to the queried domain.
      </p>

      <ul className={ul}>
        <li><strong>RSA</strong> (RSASHA1, RSASHA256, RSASHA512) &mdash; widely deployed across most zones</li>
        <li><strong>ECDSA</strong> (ECDSAP256SHA256, ECDSAP384SHA384) &mdash; used by many modern zones including the root</li>
        <li><strong>ED25519</strong> &mdash; next-generation algorithm with smaller signatures and faster verification</li>
      </ul>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`dnssec:
  enabled: true    # enabled by default`}</code></pre>

      <p className={p}>
        When a DNSSEC-signed domain fails validation, Labyrinth returns SERVFAIL to the client, preventing
        spoofed or tampered responses from reaching end users. Validated responses are cached with their
        authentication status, so subsequent queries benefit from the validation without additional overhead.
      </p>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Note:</strong> DNSSEC validation adds latency to the first query
          for a domain (additional DNSKEY and DS lookups), but these are cached aggressively. For unsigned
          domains, there is no performance impact.
        </p>
      </div>

      <h2 className={h2}>Per-IP Rate Limiting</h2>

      <p className={p}>
        Rate limiting prevents any single client from overwhelming the resolver. It uses a token bucket algorithm
        per source IP:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`security:
  rate_limit:
    enabled: true
    requests_per_second: 100    # sustained rate
    burst: 200                  # initial burst allowance`}</code></pre>

      <p className={p}>
        When a client exceeds the rate limit, Labyrinth responds with REFUSED (RCODE 5). The rate limiter
        uses minimal memory (one token bucket per active source IP, automatically cleaned up after inactivity).
      </p>

      <h2 className={h2}>Response Rate Limiting (RRL)</h2>

      <p className={p}>
        RRL prevents the resolver from being used as a DNS amplification vector. It tracks identical responses
        (same query name, type, and response code) and limits the rate at which they are sent:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`security:
  rrl:
    enabled: true
    responses_per_second: 5     # max identical responses/sec
    window: "15s"               # sliding window duration`}</code></pre>

      <p className={p}>
        When the limit is exceeded, Labyrinth sets the TC (truncation) bit instead of dropping the response,
        forcing legitimate clients to retry over TCP while making the resolver useless for UDP amplification attacks.
      </p>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Why TC instead of DROP:</strong> Dropping responses silently
          would cause legitimate clients to time out. Setting TC forces a TCP retry, which is fast for
          real clients but expensive for attackers (TCP requires a handshake, defeating amplification).
        </p>
      </div>

      <h2 className={h2}>Access Control Lists (ACL)</h2>

      <p className={p}>
        ACLs restrict which IP addresses can query the resolver. This is essential for any resolver exposed
        to the internet &mdash; an open resolver is a prime target for amplification attacks.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`access_control:
  enabled: true
  deny:
    - "0.0.0.0/0"            # deny all by default
  allow:
    - "10.0.0.0/8"           # internal networks
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"          # localhost
    - "::1/128"              # IPv6 localhost`}</code></pre>

      <p className={p}>
        ACL evaluation order:
      </p>

      <ul className={ul}>
        <li>Deny rules are checked first</li>
        <li>If denied, the query is immediately dropped (no response)</li>
        <li>Allow rules are checked next</li>
        <li>If not explicitly allowed and ACL is enabled, the query is dropped</li>
      </ul>

      <h2 className={h2}>Best Practices</h2>

      <ul className={ul}>
        <li><strong>Keep DNSSEC enabled.</strong> It is on by default and protects against cache poisoning and response tampering.</li>
        <li><strong>Never run an open resolver.</strong> Always enable ACLs if the resolver is reachable from the internet.</li>
        <li><strong>Enable RRL</strong> even on internal resolvers as defense-in-depth against compromised internal hosts.</li>
        <li><strong>Use rate limiting</strong> to prevent any single client from monopolizing resolver resources.</li>
        <li><strong>Bind to specific interfaces</strong> rather than 0.0.0.0 if the resolver only serves a single network.</li>
        <li><strong>Run as non-root</strong> with <code className={ic}>CAP_NET_BIND_SERVICE</code> for port 53 access.</li>
        <li><strong>Monitor</strong> the <code className={ic}>labyrinth_rate_limited_total</code> and <code className={ic}>labyrinth_rrl_truncated_total</code> metrics for signs of attacks.</li>
      </ul>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`# Recommended production security config
dnssec:
  enabled: true

security:
  rate_limit:
    enabled: true
    requests_per_second: 200
    burst: 500
  rrl:
    enabled: true
    responses_per_second: 5
    window: "15s"

access_control:
  enabled: true
  allow:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
    - "::1/128"`}</code></pre>
    </div>
  )
}
