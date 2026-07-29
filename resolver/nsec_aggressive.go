package resolver

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// nsecZoneFromAuthority returns the zone owner (lowercased, no trailing
// dot) the NSEC intervals in `authority` belong to. The zone is the SOA's
// owner name — RFC 2308 §3 requires authority sections of negative
// responses to carry an SOA at the apex of the closest enclosing zone,
// and that owner is exactly the zone we want to key intervals under.
// Returns "" when no SOA is present (defensive — the response would be
// unusable for negative caching anyway).
func nsecZoneFromAuthority(authority []dns.ResourceRecord) string {
	for _, rr := range authority {
		if rr.Type == dns.TypeSOA {
			return strings.ToLower(strings.TrimSuffix(rr.Name, "."))
		}
	}
	return ""
}

// minNegativeTTL returns the SOA-derived negative TTL per RFC 2308 §5:
// min(SOA RR TTL, SOA.MINIMUM). Used by the RFC 8198 NSEC-interval
// registration so the synth-cache's expiry matches the negative TTL the
// regular cache would use for the same response — without this the two
// caches would drift and a synthesised reply could outlive the cached
// NXDOMAIN it was derived from. Returns 0 when no SOA is present.
func minNegativeTTL(authority []dns.ResourceRecord) uint32 {
	for _, rr := range authority {
		if rr.Type != dns.TypeSOA {
			continue
		}
		soa, err := dns.ParseSOA(rr.RData, 0)
		if err != nil || soa == nil {
			return rr.TTL
		}
		if rr.TTL < soa.Minimum {
			return rr.TTL
		}
		return soa.Minimum
	}
	return 0
}
