package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestRFC6303_MatchesRFC1918Reverse pins Y28 happy path: a PTR query
// for a 10.0.0.0/8 address short-circuits to NXDOMAIN inside the
// resolver, so the public root never sees the leak. Same for the
// 172.16-31 and 192.168 ranges.
func TestRFC6303_MatchesRFC1918Reverse(t *testing.T) {
	cases := []string{
		"1.0.0.10.in-addr.arpa",      // 10/8
		"5.4.3.2.10.in-addr.arpa",    // nested under 10/8
		"99.16.172.in-addr.arpa",     // 172.16/12 lower edge
		"1.31.172.in-addr.arpa",      // 172.16/12 upper edge
		"77.168.192.in-addr.arpa",    // 192.168/16
		"5.4.254.169.in-addr.arpa", // 169.254.4.5 (link-local), reverse-form
		"1.0.0.127.in-addr.arpa",     // loopback
		"99.0.in-addr.arpa",          // 0/8
		"99.2.0.192.in-addr.arpa",    // TEST-NET-1
	}
	for _, name := range cases {
		got := rfc6303LocallyServed(name, dns.TypePTR, dns.ClassIN)
		if got == nil {
			t.Errorf("rfc6303LocallyServed(%q) = nil, want NXDOMAIN", name)
			continue
		}
		if got.RCODE != dns.RCodeNXDomain {
			t.Errorf("rfc6303LocallyServed(%q) rcode = %d, want NXDOMAIN", name, got.RCODE)
		}
	}
}

// TestRFC6303_MatchesIPv6ULAReverse pins coverage for IPv6 unique-local
// (fc00::/7 → d.f.ip6.arpa) and IPv6 link-local (fe80::/10 → 8.e.f /
// 9.e.f / a.e.f / b.e.f under ip6.arpa).
func TestRFC6303_MatchesIPv6ULAReverse(t *testing.T) {
	cases := []string{
		// ULA: an fdXX::… address whose reverse ends in d.f.ip6.arpa
		"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
		"d.f.ip6.arpa",
		// Link-local: fe80::1 → 1.0...0.0.0.8.e.f.ip6.arpa
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
		"a.e.f.ip6.arpa",
	}
	for _, name := range cases {
		got := rfc6303LocallyServed(name, dns.TypePTR, dns.ClassIN)
		if got == nil {
			t.Errorf("rfc6303LocallyServed(%q) = nil, want NXDOMAIN", name)
		}
	}
}

// TestRFC6303_DoesNotMatchPublicReverse pins the negative side: a
// public-IP reverse must NOT be short-circuited locally. Otherwise we
// would NXDOMAIN every real reverse lookup, which is much worse than
// leaking private-network reverse queries.
func TestRFC6303_DoesNotMatchPublicReverse(t *testing.T) {
	cases := []string{
		"1.1.1.1.in-addr.arpa",      // public Cloudflare
		"8.8.8.8.in-addr.arpa",      // public Google
		"153.133.185.147.in-addr.arpa", // the operator's broken-but-public reverse
		"example.com",                // not a reverse at all
		"google.com",
	}
	for _, name := range cases {
		if got := rfc6303LocallyServed(name, dns.TypePTR, dns.ClassIN); got != nil {
			t.Errorf("rfc6303LocallyServed(%q) = %+v, want nil (public reverse must not short-circuit)", name, got)
		}
	}
}

// TestRFC6303_PartialSuffixMatchRejected pins a subtle correctness
// guard: "fake-10.in-addr.arpa" must NOT match "10.in-addr.arpa".
// HasSuffix(name, ".10.in-addr.arpa") would accept it; we use
// HasSuffix(name, "."+zone) to require a label boundary. This test
// regression-locks that guard.
func TestRFC6303_PartialSuffixMatchRejected(t *testing.T) {
	if got := rfc6303LocallyServed("fake-10.in-addr.arpa", dns.TypePTR, dns.ClassIN); got != nil {
		t.Errorf("partial-suffix 'fake-10.in-addr.arpa' must NOT match RFC 6303 zone 10.in-addr.arpa, got %+v", got)
	}
}
