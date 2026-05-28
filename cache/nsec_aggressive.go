package cache

import (
	"strings"
	"sync"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// RFC 8198 aggressive use of DNSSEC-validated cache.
//
// When the resolver receives a Secure NXDOMAIN response, the authority
// section contains NSEC records that prove a gap in the zone — every name
// strictly between an NSEC's owner and its next-domain field does not
// exist. RFC 8198 §5.4 says a validator MAY use a cached, validated NSEC
// to synthesize NXDOMAIN for any name falling in that gap, without going
// upstream. For a popular signed zone (.com, .org, the ccTLDs) with a lot
// of random-subdomain garbage traffic, the same NSEC interval covers many
// unrelated nonexistent queries, so the cache hit rate climbs sharply and
// the auth server load drops by an order of magnitude.
//
// This file implements a per-zone NSEC interval index decoupled from the
// main cache: the resolver registers an interval after a successful
// Secure denial, and on a subsequent cache miss the resolver calls
// LookupNSECCovers to ask "is qname provably nonexistent under any
// cached interval?". Only Secure intervals are stored — synthesising
// from an unsigned interval would be an unauthenticated negative answer.

// nsecInterval records one cached (owner, next) NSEC range plus the
// signed authority records needed to reconstruct a verifiable response.
type nsecInterval struct {
	owner     string // canonical, lowercase, no trailing dot
	next      string // canonical, lowercase, no trailing dot
	expiresAt time.Time
	// authority is the full authority section we cached (SOA, NSEC, RRSIGs).
	// Downstream validators chasing AD need these RRSIGs intact.
	authority []dns.ResourceRecord
	// soa is a pointer into authority for fast access.
	soa *dns.ResourceRecord
	// origTTL records the negative TTL used when registering. Synthesised
	// responses inherit this TTL minus the elapsed wall-clock so they decay
	// naturally to zero at expiresAt.
	origTTL uint32
	// negTTLFloor stamps the synth-response TTL when the caller wants a
	// fixed floor rather than the decayed live value.
	registeredAt time.Time
	// typeBitmap is the parsed NSEC RR's type-bitmap (RFC 4034 §4.1.2).
	// Required for RFC 8198 §5.4 NODATA aggressive use: if qname's
	// owner matches this NSEC's owner AND qtype is NOT in the bitmap,
	// the NSEC is itself authenticated proof that qname exists but the
	// requested type does not — synth NODATA without going upstream.
	typeBitmap []uint16
}

// MaxNSECZones caps the number of distinct DNSSEC-signed zones the
// aggressive-use NSEC index will track at once. Each entry holds the
// SOA + NSEC + RRSIG bytes needed to reconstruct a verifiable synth
// response, so per-entry memory is non-trivial (a few KB). An
// attacker who controls many DNSSEC-signed sibling zones — easy to
// arrange by registering siblings under a TLD they control, or by
// chaining delegations through their auth — can flood the resolver
// with Secure NXDOMAIN responses whose SOAs name distinct zones,
// growing `byZone` without bound. The per-zone interval list is
// already capped (256), but the zone count was not. 50k tracked
// zones is far above any realistic legitimate workload (the resolver
// would have to actively query into 50k distinct signed zones to
// benefit from any one of them) and small enough that the worst-
// case footprint stays bounded to a few hundred MB. When the cap is
// reached, the OLDEST-registeredAt zone (the one whose newest
// entry's registeredAt is oldest) is evicted to make room.
const MaxNSECZones = 50_000

// nsecIndex is the per-zone collection of cached intervals.
type nsecIndex struct {
	mu sync.RWMutex
	// keyed by zone (lowercase, no trailing dot). Zone is derived from the
	// SOA owner name on the registering response.
	byZone map[string][]nsecInterval
}

func newNSECIndex() *nsecIndex {
	return &nsecIndex{byZone: make(map[string][]nsecInterval)}
}

// evictOldestZoneLocked drops the zone whose freshest interval has the
// oldest registeredAt timestamp. Caller holds idx.mu in write mode.
// O(n*k) where n = zones, k = avg intervals per zone (max 256), so
// O(12.8M) worst-case for n=50000 — runs at most once per registration
// after the cap is reached and only on first growth past the cap.
func (idx *nsecIndex) evictOldestZoneLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for zone, intervals := range idx.byZone {
		// Use the freshest interval's registeredAt as the zone's
		// activity timestamp. A zone whose newest interval was
		// registered long ago is the right one to drop.
		var newest time.Time
		for _, iv := range intervals {
			if iv.registeredAt.After(newest) {
				newest = iv.registeredAt
			}
		}
		if first || newest.Before(oldestTime) {
			oldestKey = zone
			oldestTime = newest
			first = false
		}
	}
	if oldestKey != "" {
		delete(idx.byZone, oldestKey)
	}
}

// RegisterNSECInterval stores the NSEC intervals from a Secure NXDOMAIN
// response so future queries that fall in the same gap can be answered
// from cache. The caller MUST have verified the response as Secure; this
// method does not re-validate. negTTL is the negative TTL the caller
// already extracted (min(SOA TTL, SOA Minimum) per RFC 2308). authority
// is the full authority section, copied here for later replay.
func (c *Cache) RegisterNSECInterval(zone string, negTTL uint32, authority []dns.ResourceRecord) {
	if c.nsecIdx == nil || negTTL == 0 || len(authority) == 0 {
		return
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if zone == "" {
		// We refuse to index the root zone — synth-NXDOMAIN for arbitrary
		// names anchored at the root would be too aggressive and would
		// shadow real zones the cache hasn't yet seen.
		return
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(negTTL) * time.Second)
	authCopy := cloneRRs(authority)
	var soa *dns.ResourceRecord
	for i := range authCopy {
		if authCopy[i].Type == dns.TypeSOA {
			soa = &authCopy[i]
			break
		}
	}

	var harvested []nsecInterval
	for _, rr := range authCopy {
		if rr.Type != dns.TypeNSEC {
			continue
		}
		nsec, err := dns.ParseNSEC(rr.RData, 0)
		if err != nil || nsec.NextDomainName == "" {
			continue
		}
		owner := strings.ToLower(strings.TrimSuffix(rr.Name, "."))
		next := strings.ToLower(strings.TrimSuffix(nsec.NextDomainName, "."))
		if owner == "" || next == "" {
			continue
		}
		harvested = append(harvested, nsecInterval{
			owner:        owner,
			next:         next,
			expiresAt:    expiresAt,
			authority:    authCopy,
			soa:          soa,
			origTTL:      negTTL,
			registeredAt: now,
			typeBitmap:   append([]uint16(nil), nsec.TypeBitMaps...),
		})
	}
	if len(harvested) == 0 {
		return
	}

	c.nsecIdx.mu.Lock()
	defer c.nsecIdx.mu.Unlock()
	// Cap-enforced LRU eviction on NEW zone insertion. Existing
	// zone updates are exempt — they don't grow the map and the
	// fresh interval is exactly what we want to keep.
	if _, exists := c.nsecIdx.byZone[zone]; !exists && len(c.nsecIdx.byZone) >= MaxNSECZones {
		c.nsecIdx.evictOldestZoneLocked()
	}
	// Dedup: when the same interval is registered repeatedly, replace the
	// older entry (newer expiry wins). Limit per-zone to avoid unbounded
	// growth on hostile traffic.
	const maxPerZone = 256
	existing := c.nsecIdx.byZone[zone]
	for _, iv := range harvested {
		replaced := false
		for i := range existing {
			if existing[i].owner == iv.owner && existing[i].next == iv.next {
				existing[i] = iv
				replaced = true
				break
			}
		}
		if !replaced {
			existing = append(existing, iv)
		}
	}
	// Prune expired and cap.
	live := existing[:0]
	for _, iv := range existing {
		if iv.expiresAt.After(now) {
			live = append(live, iv)
		}
	}
	if len(live) > maxPerZone {
		live = live[len(live)-maxPerZone:]
	}
	c.nsecIdx.byZone[zone] = live
}

// LookupNSECCovers checks whether any cached Secure NSEC interval proves
// qname nonexistent. Returns a synthesized Entry whose Authority carries
// the original SOA + NSEC + RRSIG so downstream validators can confirm
// the AD verdict, and DNSSECStatus="secure" so the server sets AD on the
// response. Returns ok=false when no covering interval is cached.
//
// The lookup walks parent labels of qname to find every plausibly-
// authoritative zone for the name and consults that zone's interval list.
// Within each zone the search is linear; per-zone interval count is
// bounded by RegisterNSECInterval.
//
// This function returns either:
//   - NXDOMAIN entry: a cached NSEC interval STRICTLY covers qname (the
//     classic RFC 8198 §5.2 use case);
//   - NODATA entry (RFC 8198 §5.4 + qtype != 0): a cached NSEC owner
//     EXACTLY matches qname and qtype is absent from its type bitmap.
//
// The qtype is honoured only on the NODATA path; pass 0 to skip the
// NODATA check and only consider interval-coverage NXDOMAIN.
func (c *Cache) LookupNSECCovers(qname string, qclass uint16) (*Entry, bool) {
	return c.lookupNSEC(qname, 0, qclass)
}

// LookupNSECCoversTyped is the qtype-aware variant for RFC 8198 §5.4
// NSEC NODATA aggressive use. Pass the real qtype so a cached
// owner-match NSEC can prove "qname exists but not for this type."
func (c *Cache) LookupNSECCoversTyped(qname string, qtype uint16, qclass uint16) (*Entry, bool) {
	return c.lookupNSEC(qname, qtype, qclass)
}

func (c *Cache) lookupNSEC(qname string, qtype uint16, qclass uint16) (*Entry, bool) {
	if c.nsecIdx == nil {
		return nil, false
	}
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	if q == "" {
		return nil, false
	}

	now := time.Now()
	// Walk parent labels: for "a.b.example.com", check zones
	// "a.b.example.com", "b.example.com", "example.com", "com".
	name := q
	for name != "" {
		c.nsecIdx.mu.RLock()
		intervals := c.nsecIdx.byZone[name]
		c.nsecIdx.mu.RUnlock()
		// First pass: RFC 8198 §5.4 NODATA — a cached NSEC whose owner
		// EXACTLY matches qname and whose type bitmap excludes qtype
		// is authenticated proof of NODATA. Skipped when qtype == 0.
		if qtype != 0 {
			for _, iv := range intervals {
				if !iv.expiresAt.After(now) {
					continue
				}
				if iv.owner != q {
					continue
				}
				if typeBitmapHas(iv.typeBitmap, qtype) {
					continue // type present — not NODATA
				}
				// RFC 4035 §5.4 / RFC 6840 §4.4 — refuse to use a
				// parent-side delegation NSEC (NS bit set, SOA bit
				// clear) as authoritative NODATA proof for the child
				// zone. The delegation NSEC's bitmap reflects only the
				// types the PARENT publishes at the delegation point
				// (NS, RRSIG, NSEC); it cannot speak to A/AAAA/MX/etc.
				// that the CHILD zone may serve. Without this guard,
				// an attacker who injects a delegation NSEC into a
				// (NODATA-classified) response would let the aggressive
				// cache synthesise NODATA for arbitrary child-zone
				// records, hiding their real existence.
				if typeBitmapHas(iv.typeBitmap, dns.TypeNS) &&
					!typeBitmapHas(iv.typeBitmap, dns.TypeSOA) {
					continue
				}
				if entry, ok := c.buildNSECSynthEntry(iv, now, NegNoData, dns.RCodeNoError); ok {
					if c.metrics != nil {
						c.metrics.IncNSECAggressiveSynthNoData()
					}
					return entry, true
				}
			}
		}
		// Second pass: RFC 8198 §5.2 NXDOMAIN — interval coverage.
		for _, iv := range intervals {
			if !iv.expiresAt.After(now) {
				continue
			}
			if !nsecIntervalCovers(iv.owner, iv.next, q) {
				continue
			}
			if entry, ok := c.buildNSECSynthEntry(iv, now, NegNXDomain, dns.RCodeNXDomain); ok {
				if c.metrics != nil {
					c.metrics.IncNSECAggressiveSynthNX()
				}
				return entry, true
			}
		}
		// Strip leftmost label.
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			break
		}
		name = name[dot+1:]
	}
	return nil, false
}

// buildNSECSynthEntry materialises an Entry from a cached interval —
// shared by the NXDOMAIN (RFC 8198 §5.2) and NODATA (RFC 8198 §5.4)
// synthesis paths. Re-stamps every authority TTL to the live remaining
// value so a downstream client sees a coherent expiry rather than the
// frozen original. Returns ok=false when the entry has already lost
// every second of remaining life since the lookup started.
func (c *Cache) buildNSECSynthEntry(iv nsecInterval, now time.Time, negType NegativeType, rcode uint8) (*Entry, bool) {
	remaining := uint32(iv.expiresAt.Sub(now).Seconds())
	if remaining == 0 {
		return nil, false
	}
	authCopy := cloneRRs(iv.authority)
	for i := range authCopy {
		authCopy[i].TTL = remaining
	}
	var soa *dns.ResourceRecord
	for i := range authCopy {
		if authCopy[i].Type == dns.TypeSOA {
			soa = &authCopy[i]
			break
		}
	}
	return &Entry{
		Authority:    authCopy,
		InsertedAt:   now.Add(-time.Duration(iv.origTTL-remaining) * time.Second),
		OrigTTL:      iv.origTTL,
		Negative:     true,
		NegType:      negType,
		SOA:          soa,
		RCODE:        rcode,
		DNSSECStatus: "secure",
	}, true
}

// typeBitmapHas reports whether qtype appears in a parsed NSEC/NSEC3
// type-bitmap window. The bitmap is the flat slice of type codes that
// ParseNSEC / ParseNSEC3 produce; a linear scan is fine because real-
// world bitmaps stay small (most NSECs hold ≤ 8 types — A, AAAA,
// MX, TXT, NS, SOA, RRSIG, NSEC).
func typeBitmapHas(bitmap []uint16, qtype uint16) bool {
	for _, t := range bitmap {
		if t == qtype {
			return true
		}
	}
	return false
}

// nsecIntervalCovers reports whether qname falls strictly between owner
// and next in DNSSEC canonical order. Handles wrap-around for the zone's
// last NSEC where owner sorts after next. RFC 4034 §6.1 canonical name
// ordering: case-insensitive, label-wise from rightmost (TLD) toward
// leftmost. We reuse a label-byte compare equivalent to the dnssec
// package's nsecCoversName, duplicated here only to avoid creating a
// cache→dnssec dependency cycle.
func nsecIntervalCovers(owner, next, qname string) bool {
	cmpOwner := canonicalNameCompare(qname, owner)
	cmpNext := canonicalNameCompare(qname, next)
	if canonicalNameCompare(owner, next) < 0 {
		return cmpOwner > 0 && cmpNext < 0
	}
	// Wrap: qname > owner OR qname < next.
	return cmpOwner > 0 || cmpNext < 0
}

func canonicalNameCompare(a, b string) int {
	aLabels := splitCanonicalLabels(a)
	bLabels := splitCanonicalLabels(b)
	aIdx := len(aLabels) - 1
	bIdx := len(bLabels) - 1
	for aIdx >= 0 && bIdx >= 0 {
		la := aLabels[aIdx]
		lb := bLabels[bIdx]
		if cmp := compareLabelBytes(la, lb); cmp != 0 {
			return cmp
		}
		aIdx--
		bIdx--
	}
	switch {
	case aIdx < 0 && bIdx < 0:
		return 0
	case aIdx < 0:
		return -1
	default:
		return 1
	}
}

func splitCanonicalLabels(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

func compareLabelBytes(a, b string) int {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
