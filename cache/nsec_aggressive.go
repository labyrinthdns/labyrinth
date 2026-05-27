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
}

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
		})
	}
	if len(harvested) == 0 {
		return
	}

	c.nsecIdx.mu.Lock()
	defer c.nsecIdx.mu.Unlock()
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
func (c *Cache) LookupNSECCovers(qname string, qclass uint16) (*Entry, bool) {
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
		for _, iv := range intervals {
			if !iv.expiresAt.After(now) {
				continue
			}
			if !nsecIntervalCovers(iv.owner, iv.next, q) {
				continue
			}
			remaining := uint32(iv.expiresAt.Sub(now).Seconds())
			if remaining == 0 {
				continue
			}
			authCopy := cloneRRs(iv.authority)
			// Re-stamp every authority TTL to the live remaining value so
			// downstream clients see a coherent expiry.
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
			synth := &Entry{
				Authority:    authCopy,
				InsertedAt:   now.Add(-time.Duration(iv.origTTL-remaining) * time.Second),
				OrigTTL:      iv.origTTL,
				Negative:     true,
				NegType:      NegNXDomain,
				SOA:          soa,
				RCODE:        dns.RCodeNXDomain,
				DNSSECStatus: "secure",
			}
			return synth, true
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
