package security

import (
	"net"

	"github.com/labyrinthdns/labyrinth/dns"
)

// FilterPrivateAddresses removes A/AAAA records that contain private,
// loopback, or link-local addresses. This prevents DNS rebinding attacks
// where an external domain resolves to an internal IP.
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

func isPrivateAddressRecord(rr dns.ResourceRecord) bool {
	switch rr.Type {
	case dns.TypeA:
		if len(rr.RData) != 4 {
			return false
		}
		ip := net.IP(rr.RData)
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	case dns.TypeAAAA:
		if len(rr.RData) != 16 {
			return false
		}
		ip := net.IP(rr.RData)
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	default:
		return false
	}
}
