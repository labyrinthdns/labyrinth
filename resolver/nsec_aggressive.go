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
		ttl := sanitizeNegTTL(rr.TTL)
		soa, err := dns.ParseSOA(rr.RData, 0)
		if err != nil || soa == nil {
			return ttl
		}
		if m := sanitizeNegTTL(soa.Minimum); m < ttl {
			return m
		}
		return ttl
	}
	return 0
}

// sanitizeNegTTL mirrors the cache's RFC 2181 §8 guard: TTLs with the top
// bit set are "positive values with the MSB set" only by accident of a
// hostile or broken signer, and MUST be treated as zero. Without it an
// authoritative could ship a ~68-year negative TTL and pin a synthesised
// denial in the aggressive-use index effectively forever.
func sanitizeNegTTL(ttl uint32) uint32 {
	if ttl&0x80000000 != 0 {
		return 0
	}
	return ttl
}

// aggressiveNegTTL returns how long an RFC 8198 aggressive-use interval
// built from `denialType` records (TypeNSEC or TypeNSEC3) may be held.
//
// RFC 2308 §5 sets the base — min(SOA RR TTL, SOA.MINIMUM) — and RFC 9077
// §4 tightens it on top. RFC 9077 updates RFC 8198 §5.1 so that a resolver
// MUST NOT synthesise a denial beyond the TTL of the NSEC/NSEC3 record the
// denial actually rests on. RFC 9077 §3 also requires signers to publish
// those records with exactly that SOA-derived TTL, so for a conforming zone
// this clamp is a no-op; it only bites when a signer emits a *shorter*
// NSEC/NSEC3 TTL than the SOA implies. In that case the unclamped code
// would keep answering from a proof the zone owner already considers
// expired — synthesising NXDOMAIN for names that may since have been
// created.
//
// The clamp is computed per denial type because the two indices are
// registered separately: a zone signed with NSEC has no NSEC3 records to
// clamp against (and vice versa), so passing the wrong type's minimum
// would either over-tighten or silently skip the bound.
//
// Returns 0 when there is no SOA to derive a base TTL from, which callers
// treat as "do not register".
func aggressiveNegTTL(authority []dns.ResourceRecord, denialType uint16) uint32 {
	ttl := minNegativeTTL(authority)
	if ttl == 0 {
		return 0
	}
	if rrTTL, ok := minDenialRRTTL(authority, denialType); ok && rrTTL < ttl {
		return rrTTL
	}
	return ttl
}

// minDenialRRTTL returns the smallest TTL among the `denialType` records in
// `authority`, and whether any were present. An NXDOMAIN proof carries
// several NSEC/NSEC3 records (closest encloser, next closer, wildcard); the
// synthesised answer is only as fresh as the shortest-lived of them.
func minDenialRRTTL(authority []dns.ResourceRecord, denialType uint16) (uint32, bool) {
	var min uint32
	found := false
	for _, rr := range authority {
		if rr.Type != denialType {
			continue
		}
		ttl := sanitizeNegTTL(rr.TTL)
		if !found || ttl < min {
			min = ttl
			found = true
		}
	}
	return min, found
}
