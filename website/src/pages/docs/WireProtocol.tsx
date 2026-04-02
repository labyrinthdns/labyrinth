interface Props { dark: boolean }

export default function WireProtocol({ dark }: Props) {
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
      <h1 className={h1}>DNS Wire Protocol</h1>

      <p className={p}>
        Labyrinth implements a complete DNS wire format parser and serializer from scratch in pure Go. This section
        documents the on-the-wire message format that Labyrinth handles, based on RFC 1035 and extensions.
      </p>

      <h2 className={h2}>Message Structure</h2>

      <p className={p}>
        Every DNS message (query or response) follows the same structure:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`+---------------------+
|        Header       |  12 bytes, always present
+---------------------+
|       Question      |  variable, the query being asked
+---------------------+
|        Answer       |  variable, RRs answering the question
+---------------------+
|      Authority      |  variable, RRs pointing to authoritative servers
+---------------------+
|      Additional     |  variable, RRs with extra information (glue, OPT)
+---------------------+`}</code></pre>

      <h2 className={h2}>Header Fields</h2>

      <p className={p}>
        The 12-byte header contains:
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                         |  Transaction ID (16 bits)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE     |  Flags (16 bits)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                       |  Number of questions
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                       |  Number of answers
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                       |  Number of authority RRs
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                       |  Number of additional RRs
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+`}</code></pre>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Field</th><th className="text-left py-2 pr-4 font-semibold">Bits</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4">ID</td><td className="py-2 pr-4">16</td><td className="py-2">Transaction identifier, randomized by Labyrinth for security</td></tr>
          <tr className={td}><td className="py-2 pr-4">QR</td><td className="py-2 pr-4">1</td><td className="py-2">0 = query, 1 = response</td></tr>
          <tr className={td}><td className="py-2 pr-4">Opcode</td><td className="py-2 pr-4">4</td><td className="py-2">0 = QUERY (only opcode Labyrinth handles)</td></tr>
          <tr className={td}><td className="py-2 pr-4">AA</td><td className="py-2 pr-4">1</td><td className="py-2">Authoritative Answer (set by auth servers)</td></tr>
          <tr className={td}><td className="py-2 pr-4">TC</td><td className="py-2 pr-4">1</td><td className="py-2">Truncated (response too large for UDP)</td></tr>
          <tr className={td}><td className="py-2 pr-4">RD</td><td className="py-2 pr-4">1</td><td className="py-2">Recursion Desired (set by clients)</td></tr>
          <tr className={td}><td className="py-2 pr-4">RA</td><td className="py-2 pr-4">1</td><td className="py-2">Recursion Available (set by Labyrinth in responses)</td></tr>
          <tr className={td}><td className="py-2 pr-4">RCODE</td><td className="py-2 pr-4">4</td><td className="py-2">0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED</td></tr>
        </tbody>
      </table>

      <h2 className={h2}>Name Compression</h2>

      <p className={p}>
        DNS names use label compression to reduce message size. A label can be a length-prefixed string or a
        pointer (two bytes starting with bits <code className={ic}>11</code>) referencing an earlier position in the message.
      </p>

      <pre className={cb}><code className="text-sm text-gray-300 font-mono">{`Uncompressed: www.example.com
Encoded:      03 77 77 77  07 65 78 61 6d 70 6c 65  03 63 6f 6d  00
              ^^           ^^                         ^^           ^^
              len=3 "www"  len=7 "example"            len=3 "com"  terminator

With compression pointer:
If "example.com" already appeared at offset 0x1A:
Encoded:      03 77 77 77  C0 1A
              ^^           ^^ ^^
              len=3 "www"  pointer to offset 0x1A`}</code></pre>

      <p className={p}>
        Labyrinth's parser handles both compressed and uncompressed names. The serializer uses compression to
        minimize response sizes, which is especially important for UDP responses limited to 512 bytes (or the
        EDNS0 buffer size).
      </p>

      <h2 className={h2}>Supported Record Types</h2>

      <table className={tc}>
        <thead><tr className={th}><th className="text-left py-2 pr-4 font-semibold">Type</th><th className="text-left py-2 pr-4 font-semibold">Value</th><th className="text-left py-2 font-semibold">Description</th></tr></thead>
        <tbody>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>A</code></td><td className="py-2 pr-4">1</td><td className="py-2">IPv4 address (4 bytes)</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>NS</code></td><td className="py-2 pr-4">2</td><td className="py-2">Nameserver delegation</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>CNAME</code></td><td className="py-2 pr-4">5</td><td className="py-2">Canonical name alias</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>SOA</code></td><td className="py-2 pr-4">6</td><td className="py-2">Start of Authority</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>PTR</code></td><td className="py-2 pr-4">12</td><td className="py-2">Pointer for reverse DNS</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>MX</code></td><td className="py-2 pr-4">15</td><td className="py-2">Mail exchange</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>TXT</code></td><td className="py-2 pr-4">16</td><td className="py-2">Text records (SPF, DKIM, etc.)</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>AAAA</code></td><td className="py-2 pr-4">28</td><td className="py-2">IPv6 address (16 bytes)</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>SRV</code></td><td className="py-2 pr-4">33</td><td className="py-2">Service locator</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>OPT</code></td><td className="py-2 pr-4">41</td><td className="py-2">EDNS0 pseudo-record</td></tr>
          <tr className={td}><td className="py-2 pr-4"><code className={ic}>CAA</code></td><td className="py-2 pr-4">257</td><td className="py-2">Certificate Authority Authorization</td></tr>
        </tbody>
      </table>

      <p className={p}>
        Unknown record types are handled as opaque RDATA &mdash; Labyrinth caches and forwards them without
        attempting to parse the record-specific data.
      </p>

      <h2 className={h2}>EDNS0 (RFC 6891)</h2>

      <p className={p}>
        EDNS0 extends DNS beyond the original 512-byte UDP limit. Labyrinth sets an EDNS0 OPT pseudo-record
        in the additional section of every query it sends, advertising a buffer size of 4096 bytes (configurable
        via <code className={ic}>server.edns_buffer_size</code>).
      </p>

      <div className={info}>
        <p className={`text-sm ${dark ? 'text-gray-300' : 'text-navy-700'}`}>
          <strong className="text-gold-500">Important:</strong> If a client does not include an OPT record,
          Labyrinth limits the UDP response to 512 bytes and sets the TC (Truncated) bit if the response
          does not fit, signaling the client to retry over TCP.
        </p>
      </div>

      <h2 className={h2}>TCP Fallback</h2>

      <p className={p}>
        When a UDP response is truncated (TC bit set), clients retry over TCP. Labyrinth's TCP handler:
      </p>

      <ul className={ul}>
        <li>Reads the 2-byte length prefix per RFC 1035 section 4.2.2</li>
        <li>Supports persistent connections (multiple queries per TCP session)</li>
        <li>Enforces read/write timeouts (<code className={ic}>server.read_timeout</code>, <code className={ic}>server.write_timeout</code>)</li>
        <li>Handles responses up to 65535 bytes (the TCP length field maximum)</li>
      </ul>
    </div>
  )
}
