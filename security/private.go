package security

import (
	"net"

	"github.com/labyrinthdns/labyrinth/dns"
)

// reservedV4 lists IPv4 ranges that must never appear in a public DNS answer
// (RFC 1918, CGNAT, loopback, link-local, multicast, broadcast, TEST-NETs,
// benchmarking, future-use, etc.). Used to harden against DNS rebinding.
var reservedV4 = []*net.IPNet{
	cidr("0.0.0.0/8"),         // RFC 1122 "this network"
	cidr("10.0.0.0/8"),        // RFC 1918
	cidr("100.64.0.0/10"),     // RFC 6598 CGNAT
	cidr("127.0.0.0/8"),       // RFC 1122 loopback
	cidr("169.254.0.0/16"),    // RFC 3927 link-local
	cidr("172.16.0.0/12"),     // RFC 1918
	cidr("192.0.0.0/24"),      // RFC 6890 IETF protocol assignments
	cidr("192.0.2.0/24"),      // RFC 5737 TEST-NET-1
	cidr("192.168.0.0/16"),    // RFC 1918
	cidr("198.18.0.0/15"),     // RFC 2544 benchmarking
	cidr("198.51.100.0/24"),   // RFC 5737 TEST-NET-2
	cidr("203.0.113.0/24"),    // RFC 5737 TEST-NET-3
	cidr("224.0.0.0/4"),       // RFC 5771 multicast
	cidr("240.0.0.0/4"),       // RFC 1112 reserved (covers 255.255.255.255)
}

// reservedV6 lists IPv6 ranges that must never appear in a public DNS answer.
// IPv4-mapped IPv6 (::ffff:0:0/96) is intentionally excluded — we unwrap
// such addresses to their IPv4 form first and re-evaluate via reservedV4.
var reservedV6 = []*net.IPNet{
	cidr("::1/128"),         // loopback
	cidr("::/128"),          // unspecified
	cidr("64:ff9b::/96"),    // RFC 6052 well-known NAT64
	cidr("64:ff9b:1::/48"),  // RFC 8215 local-use NAT64
	cidr("100::/64"),        // RFC 6666 discard-only
	cidr("2001::/23"),       // RFC 2928 IETF protocol assignments (covers Teredo, ORCHID, etc.)
	cidr("2001:db8::/32"),   // RFC 3849 documentation
	cidr("2002::/16"),       // RFC 3056 6to4 (encodes IPv4)
	cidr("fc00::/7"),        // RFC 4193 ULA
	cidr("fe80::/10"),       // RFC 4291 link-local
	cidr("ff00::/8"),        // RFC 4291 multicast
}

func cidr(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		// Programmer error in the table above — fail loudly at init.
		panic("security: malformed reserved CIDR " + s + ": " + err.Error())
	}
	return n
}

// FilterPrivateAddresses removes A/AAAA records that contain private,
// loopback, link-local, multicast, broadcast, CGNAT, TEST-NET, IPv4-mapped
// IPv6, NAT64, 6to4, documentation, or otherwise non-publicly-routable
// addresses. Prevents DNS rebinding attacks where an external domain
// resolves to an internal IP.
func FilterPrivateAddresses(answers []dns.ResourceRecord) []dns.ResourceRecord {
	filtered := make([]dns.ResourceRecord, 0, len(answers))
	for _, rr := range answers {
		if isPrivateAddressRecord(rr) {
			continue
		}
		filtered = append(filtered, rr)
	}
	return filtered
}

// IsReservedIP reports whether ip falls in any non-publicly-routable range
// recognized by FilterPrivateAddresses. Exposed for use elsewhere in the
// codebase (e.g. ACL checks, metrics dimensions).
func IsReservedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Collapse IPv4-mapped IPv6 (::ffff:a.b.c.d) to its IPv4 form so an
	// attacker can't bypass the v4 list by encoding 192.168.x.y as v6.
	if v4 := ip.To4(); v4 != nil {
		for _, n := range reservedV4 {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range reservedV6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateAddressRecord(rr dns.ResourceRecord) bool {
	switch rr.Type {
	case dns.TypeA:
		if len(rr.RData) != 4 {
			return false
		}
		return IsReservedIP(net.IP(rr.RData))
	case dns.TypeAAAA:
		if len(rr.RData) != 16 {
			return false
		}
		return IsReservedIP(net.IP(rr.RData))
	default:
		return false
	}
}
