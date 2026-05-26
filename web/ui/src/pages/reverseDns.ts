// ipToReverseDNSName converts a plain IPv4/IPv6 literal into its
// in-addr.arpa / ip6.arpa form so a PTR trace works as the user expects.
// RFC 1035 §3.5 (IPv4) and RFC 3596 §2.5 (IPv6). Returns null when the
// input is not a recognisable IP — the caller then falls back to the raw
// string and the resolver returns its usual NXDOMAIN-from-the-root
// behaviour, which is exactly what should happen for a non-IP input
// under type=PTR.
export function ipToReverseDNSName(input: string): string | null {
  const s = input.trim()
  if (s === '') return null

  const v4 = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (v4) {
    const parts = [v4[1], v4[2], v4[3], v4[4]].map(Number)
    if (parts.every((n) => n >= 0 && n <= 255)) {
      return parts[3] + '.' + parts[2] + '.' + parts[1] + '.' + parts[0] + '.in-addr.arpa'
    }
    return null
  }

  if (s.includes(':')) {
    const expanded = expandIPv6(s)
    if (expanded === null) return null
    const nibbles = expanded.replace(/:/g, '')
    if (nibbles.length !== 32) return null
    return nibbles.split('').reverse().join('.') + '.ip6.arpa'
  }

  return null
}

// expandIPv6 normalises an IPv6 string to the eight 4-hex-digit groups
// joined by colons (e.g. "2001:db8::1" → "2001:0db8:0000:0000:0000:0000:0000:0001").
// Returns null for malformed input. Embedded IPv4 ("::ffff:1.2.3.4") is not
// handled — we don't need it here since PTR traces of IPv4-mapped IPv6 are
// vanishingly rare in practice.
function expandIPv6(s: string): string | null {
  if (s.includes('.')) return null
  const doubleColon = s.indexOf('::')
  let groups: string[]
  if (doubleColon === -1) {
    groups = s.split(':')
    if (groups.length !== 8) return null
  } else {
    const before = s.slice(0, doubleColon)
    const after = s.slice(doubleColon + 2)
    const head = before === '' ? [] : before.split(':')
    const tail = after === '' ? [] : after.split(':')
    if (head.length + tail.length > 7) return null
    const zerosNeeded = 8 - head.length - tail.length
    const fill: string[] = []
    for (let i = 0; i < zerosNeeded; i++) fill.push('0')
    groups = head.concat(fill).concat(tail)
  }
  const out: string[] = []
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null
    out.push(g.toLowerCase().padStart(4, '0'))
  }
  return out.join(':')
}
