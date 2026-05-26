import { describe, it, expect } from 'vitest'
import { ipToReverseDNSName } from './reverseDns'

describe('ipToReverseDNSName', () => {
  // Pins Fix C for v0.6.17: when the user types a bare IP and selects
  // PTR in the trace UI, the request must be rewritten to the canonical
  // arpa form. Without this, the resolver iterates from the root for a
  // sequence of digit labels (e.g. "236") and bottoms out at NXDOMAIN —
  // confusing operators into thinking the resolver itself is broken
  // (see the 46.20.5.236 trace in the v0.6.16 cycle).
  it('rewrites IPv4 to in-addr.arpa with reversed label order (RFC 1035 §3.5)', () => {
    expect(ipToReverseDNSName('147.185.133.153')).toBe('153.133.185.147.in-addr.arpa')
    expect(ipToReverseDNSName('1.2.3.4')).toBe('4.3.2.1.in-addr.arpa')
    expect(ipToReverseDNSName('0.0.0.0')).toBe('0.0.0.0.in-addr.arpa')
    expect(ipToReverseDNSName('255.255.255.255')).toBe('255.255.255.255.in-addr.arpa')
  })

  it('trims whitespace before classification', () => {
    expect(ipToReverseDNSName('  1.2.3.4  ')).toBe('4.3.2.1.in-addr.arpa')
  })

  it('rejects IPv4 with out-of-range octets', () => {
    // RFC 1035 §3.5 octets are 0-255; 256 must NOT silently parse.
    expect(ipToReverseDNSName('256.0.0.1')).toBeNull()
    expect(ipToReverseDNSName('1.2.3.999')).toBeNull()
  })

  it('passes through non-IP names unchanged (caller falls back to raw)', () => {
    expect(ipToReverseDNSName('example.com')).toBeNull()
    expect(ipToReverseDNSName('1.2.3')).toBeNull() // partial IPv4
    expect(ipToReverseDNSName('')).toBeNull()
    expect(ipToReverseDNSName('   ')).toBeNull()
  })

  it('rewrites IPv6 to nibble-reversed ip6.arpa (RFC 3596 §2.5)', () => {
    // Canonical form expanded then reversed nibble-by-nibble.
    const got = ipToReverseDNSName('2001:db8::1')
    expect(got).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
    )
  })

  it('handles fully-written IPv6 with no :: shorthand', () => {
    const got = ipToReverseDNSName('2001:0db8:0000:0000:0000:0000:0000:0001')
    expect(got).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
    )
  })

  it('handles "::" alone (the all-zeros IPv6 unspecified address)', () => {
    const got = ipToReverseDNSName('::')
    expect(got).toBe(
      '0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa',
    )
  })

  it('rejects malformed IPv6 (too many groups, bad hex, embedded IPv4)', () => {
    expect(ipToReverseDNSName('2001:db8:::1')).toBeNull() // two ::
    expect(ipToReverseDNSName('2001:db8:zzzz::1')).toBeNull() // non-hex
    expect(ipToReverseDNSName('::ffff:1.2.3.4')).toBeNull() // embedded v4 (we don't handle)
    expect(ipToReverseDNSName('1:2:3:4:5:6:7:8:9')).toBeNull() // 9 groups
  })
})
