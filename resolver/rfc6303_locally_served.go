package resolver

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// rfc6303LocallyServed returns a synthesised NXDOMAIN ResolveResult for
// reverse-DNS queries that fall under an RFC 6303 §3 locally-served
// zone, or nil if the name is not a locally-served reverse. Sibling of
// specialUseResponse but scoped to private/test/loopback IP reverses
// rather than forward special-use TLDs.
//
// Motivation (RFC 6303 §2): if a stub or recursive resolver lets a
// reverse query for "10.0.0.1" leak to the public root, the root sees
// the entire RFC 1918 reverse traffic of every misconfigured LAN on
// the Internet — pure noise that also reveals each origin's private
// network structure. The same problem applies to:
//
//   - RFC 1918 private space (10/8, 172.16/12, 192.168/16)
//   - RFC 3927 link-local (169.254/16)
//   - RFC 5737 documentation (TEST-NET-1/2/3)
//   - RFC 1122 current-network and loopback (0/8, 127/8)
//   - RFC 4193 IPv6 ULA (fc00::/7 → d.f.ip6.arpa)
//   - RFC 4291 IPv6 link-local (fe80::/10 → 8/9/a/b.e.f.ip6.arpa)
//
// The RFC requires resolvers to "respond authoritatively" with an
// empty answer; we do that by returning NXDOMAIN with no authority,
// matching what an empty local zone would produce. The forward name
// short-circuit happens before any upstream query so no traffic
// escapes.
//
// Operators who genuinely want these reverses to traverse the public
// DNS can configure them as forward zones; the forward table is
// consulted before this short-circuit in ResolveWithECS, so an
// explicit operator decision wins.
func rfc6303LocallyServed(name string, qtype uint16, qclass uint16) *ResolveResult {
	_ = qtype
	_ = qclass
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if n == "" {
		return nil
	}
	if !isRFC6303Zone(n) {
		return nil
	}
	return &ResolveResult{RCODE: dns.RCodeNXDomain}
}

// isRFC6303Zone reports whether `name` (lowercased, no trailing dot)
// is at or below one of the RFC 6303 §3 locally-served zones.
func isRFC6303Zone(name string) bool {
	for _, zone := range rfc6303Zones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}

// rfc6303Zones enumerates the locally-served reverse zones we
// short-circuit. The 172.16/12 block expands to sixteen /12-aligned
// in-addr.arpa zones (16.172 through 31.172) per RFC 6303 §3.2.
var rfc6303Zones = []string{
	// IPv4 — RFC 1918 private space.
	"10.in-addr.arpa",
	"16.172.in-addr.arpa",
	"17.172.in-addr.arpa",
	"18.172.in-addr.arpa",
	"19.172.in-addr.arpa",
	"20.172.in-addr.arpa",
	"21.172.in-addr.arpa",
	"22.172.in-addr.arpa",
	"23.172.in-addr.arpa",
	"24.172.in-addr.arpa",
	"25.172.in-addr.arpa",
	"26.172.in-addr.arpa",
	"27.172.in-addr.arpa",
	"28.172.in-addr.arpa",
	"29.172.in-addr.arpa",
	"30.172.in-addr.arpa",
	"31.172.in-addr.arpa",
	"168.192.in-addr.arpa",
	// IPv4 — RFC 3927 link-local.
	"254.169.in-addr.arpa",
	// IPv4 — RFC 5737 documentation prefixes.
	"2.0.192.in-addr.arpa",
	"100.51.198.in-addr.arpa",
	"113.0.203.in-addr.arpa",
	// IPv4 — RFC 1122 "this network" and loopback.
	"0.in-addr.arpa",
	"127.in-addr.arpa",
	// IPv6 — RFC 4193 ULA (fc00::/7 maps to two nibbles d/f).
	"d.f.ip6.arpa",
	// IPv6 — RFC 4291 link-local (fe80::/10 covers the four
	// /12-aligned nibble prefixes 8/9/a/b under e.f).
	"8.e.f.ip6.arpa",
	"9.e.f.ip6.arpa",
	"a.e.f.ip6.arpa",
	"b.e.f.ip6.arpa",
}
