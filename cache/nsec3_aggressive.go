package cache

import (
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

var (
	errUnsupportedNSEC3Alg = errors.New("cache: unsupported NSEC3 hash algorithm")
	errTooManyNSEC3Iters   = errors.New("cache: NSEC3 iterations exceed RFC 9276 ceiling")
)

// nsec3Base32 is the NSEC3 base32hex (RFC 4648 §7) decoder without padding,
// used to decode the leftmost label of an NSEC3 owner name.
var nsec3Base32 = base32.HexEncoding.WithPadding(base32.NoPadding)

func nsec3Base32Decode(s string) ([]byte, error) {
	return nsec3Base32.DecodeString(s)
}

// RFC 8198 §5.3 aggressive use of cached NSEC3 records.
//
// Sibling of the NSEC index in nsec_aggressive.go but with the extra
// step that NSEC3 owner names are SHA-1 hashes of the original names.
// To prove qname is in a cached interval we must:
//
//  1. Locate the zone the cached NSEC3 belongs to (parent-label walk).
//  2. Hash qname using THAT NSEC3's own algorithm/iterations/salt
//     (different intervals in the same zone may carry different
//     parameters during a transition; we ignore that edge by indexing
//     each interval with its own parameters).
//  3. Compare the qname hash against ownerHash..nextHash in canonical
//     (big-endian byte) order, accounting for the zone wrap at the
//     last NSEC3.
//
// We intentionally SKIP opt-out NSEC3s (flag bit 0 == 1). RFC 5155 §6
// makes opt-out an authenticated denial only for signed delegations;
// an opt-out NSEC3 cannot prove that an UNSIGNED name in its gap does
// not exist, and aggressive synthesis from opt-out is the classic
// "Reduce Reuse Recycle" pitfall (RFC 8198 §6 / RFC 9276). Skipping
// these entirely is the simplest safe policy for now — covers ~95% of
// the signed Internet (the major TLDs that already moved off opt-out).

// nsec3Interval is one cached (ownerHash, nextHash) range plus the
// parameters needed to re-hash an arbitrary qname against the same
// scheme.
type nsec3Interval struct {
	ownerHash    []byte // raw bytes (not base32hex)
	nextHash     []byte // raw bytes (not base32hex)
	hashAlg      uint8
	iterations   uint16
	salt         []byte
	expiresAt    time.Time
	authority    []dns.ResourceRecord
	soa          *dns.ResourceRecord
	origTTL      uint32
	registeredAt time.Time
	// typeBitmap enables RFC 8198 §5.4 NODATA aggressive use — if
	// hash(qname) == ownerHash AND qtype is absent from this bitmap,
	// the NSEC3 itself authenticates "qname exists but not for this
	// type" and the resolver can synth NODATA without going upstream.
	typeBitmap []uint16
}

// nsec3Index is the per-zone collection of cached NSEC3 intervals.
// Same MaxNSECZones cap applies as for the NSEC index (declared in
// nsec_aggressive.go) — the threat model and per-entry footprint are
// equivalent.
type nsec3Index struct {
	mu     sync.RWMutex
	byZone map[string][]nsec3Interval
}

func newNSEC3Index() *nsec3Index {
	return &nsec3Index{byZone: make(map[string][]nsec3Interval)}
}

// evictOldestZoneLocked drops the zone whose freshest interval has the
// oldest registeredAt timestamp. Counterpart to nsecIndex's eviction.
// Caller holds idx.mu in write mode.
func (idx *nsec3Index) evictOldestZoneLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for zone, intervals := range idx.byZone {
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

// RegisterNSEC3Interval is the NSEC3 counterpart of
// RegisterNSECInterval. The caller MUST have validated the response
// as Secure; this method does not re-validate. Opt-out NSEC3s are
// dropped silently because their denial guarantees do not extend to
// aggressive synthesis.
func (c *Cache) RegisterNSEC3Interval(zone string, negTTL uint32, authority []dns.ResourceRecord) {
	if c.nsec3Idx == nil || negTTL == 0 || len(authority) == 0 {
		return
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if zone == "" {
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

	var harvested []nsec3Interval
	for _, rr := range authCopy {
		if rr.Type != dns.TypeNSEC3 {
			continue
		}
		nsec3, err := dns.ParseNSEC3(rr.RData)
		if err != nil || len(nsec3.NextHash) == 0 {
			continue
		}
		// RFC 5155 §6 / RFC 8198 §6 — opt-out flag (LSB of Flags) means
		// the NSEC3 does NOT authoritatively cover the unsigned-name
		// space between owner and next. Aggressive synthesis under
		// opt-out would manufacture NXDOMAIN for names the zone simply
		// never proved nonexistent. Skip.
		if nsec3.Flags&0x01 != 0 {
			continue
		}
		// Owner name is "<base32hex_hash>.<zone>". Extract first label,
		// decode to raw hash bytes; bail on malformed owners.
		ownerHash, ok := extractNSEC3OwnerHash(rr.Name)
		if !ok {
			continue
		}
		harvested = append(harvested, nsec3Interval{
			ownerHash:    ownerHash,
			nextHash:     append([]byte(nil), nsec3.NextHash...),
			hashAlg:      nsec3.HashAlgorithm,
			iterations:   nsec3.Iterations,
			salt:         append([]byte(nil), nsec3.Salt...),
			expiresAt:    expiresAt,
			authority:    authCopy,
			soa:          soa,
			origTTL:      negTTL,
			registeredAt: now,
			typeBitmap:   append([]uint16(nil), nsec3.TypeBitMaps...),
		})
	}
	if len(harvested) == 0 {
		return
	}

	c.nsec3Idx.mu.Lock()
	defer c.nsec3Idx.mu.Unlock()
	// Cap-enforced LRU eviction on NEW zone insertion.
	if _, exists := c.nsec3Idx.byZone[zone]; !exists && len(c.nsec3Idx.byZone) >= MaxNSECZones {
		c.nsec3Idx.evictOldestZoneLocked()
	}
	const maxPerZone = 256
	existing := c.nsec3Idx.byZone[zone]
	for _, iv := range harvested {
		replaced := false
		for i := range existing {
			if equalBytes(existing[i].ownerHash, iv.ownerHash) && equalBytes(existing[i].nextHash, iv.nextHash) {
				existing[i] = iv
				replaced = true
				break
			}
		}
		if !replaced {
			existing = append(existing, iv)
		}
	}
	live := existing[:0]
	for _, iv := range existing {
		if iv.expiresAt.After(now) {
			live = append(live, iv)
		}
	}
	if len(live) > maxPerZone {
		live = live[len(live)-maxPerZone:]
	}
	c.nsec3Idx.byZone[zone] = live
}

// LookupNSEC3Covers checks whether any cached NSEC3 interval proves
// qname nonexistent under the interval's hash scheme. Returns either
// a synthesized NXDOMAIN (interval coverage, RFC 8198 §5.2) or NODATA
// (owner-hash match with qtype absent from the bitmap, RFC 8198 §5.4),
// carrying the original SOA + NSEC3 + RRSIG so a downstream validator
// can confirm the AD verdict.
//
// qtype=0 disables the NODATA path (covers callers that only want
// NXDOMAIN). LookupNSEC3CoversTyped is the qtype-aware variant.
func (c *Cache) LookupNSEC3Covers(qname string, qclass uint16) (*Entry, bool) {
	return c.lookupNSEC3(qname, 0, qclass)
}

// LookupNSEC3CoversTyped is the qtype-aware variant that enables the
// RFC 8198 §5.4 NSEC3 NODATA aggressive-use path.
func (c *Cache) LookupNSEC3CoversTyped(qname string, qtype uint16, qclass uint16) (*Entry, bool) {
	return c.lookupNSEC3(qname, qtype, qclass)
}

func (c *Cache) lookupNSEC3(qname string, qtype uint16, qclass uint16) (*Entry, bool) {
	if c.nsec3Idx == nil {
		return nil, false
	}
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	if q == "" {
		return nil, false
	}

	now := time.Now()
	name := q
	for name != "" {
		c.nsec3Idx.mu.RLock()
		intervals := c.nsec3Idx.byZone[name]
		c.nsec3Idx.mu.RUnlock()
		// First pass: NODATA via exact owner-hash match (§5.4).
		if qtype != 0 {
			for _, iv := range intervals {
				if !iv.expiresAt.After(now) {
					continue
				}
				qHash, err := computeNSEC3HashForCache(q, iv.hashAlg, iv.iterations, iv.salt)
				if err != nil {
					continue
				}
				if !equalBytes(qHash, iv.ownerHash) {
					continue
				}
				if typeBitmapHas(iv.typeBitmap, qtype) {
					continue
				}
				// RFC 4035 §5.4 / RFC 6840 §4.4 — same delegation-NSEC
				// guard as the NSEC sibling in nsec_aggressive.go: a
				// parent-side NSEC3 at the zone cut has NS set and SOA
				// clear; its bitmap can only deny types the PARENT
				// publishes at the delegation point, never types the
				// CHILD zone may serve. Without this gate an injected
				// delegation NSEC3 would synthesise NODATA for child-
				// zone records, hiding their real existence.
				if typeBitmapHas(iv.typeBitmap, dns.TypeNS) &&
					!typeBitmapHas(iv.typeBitmap, dns.TypeSOA) {
					continue
				}
				if entry, ok := c.buildNSEC3SynthEntry(iv, now, NegNoData, dns.RCodeNoError); ok {
					if c.metrics != nil {
						c.metrics.IncNSEC3AggressiveSynthND()
					}
					return entry, true
				}
			}
		}
		// Second pass: NXDOMAIN via interval coverage (§5.2).
		for _, iv := range intervals {
			if !iv.expiresAt.After(now) {
				continue
			}
			qHash, err := computeNSEC3HashForCache(q, iv.hashAlg, iv.iterations, iv.salt)
			if err != nil {
				continue
			}
			if !nsec3HashCovers(iv.ownerHash, iv.nextHash, qHash) {
				continue
			}
			if entry, ok := c.buildNSEC3SynthEntry(iv, now, NegNXDomain, dns.RCodeNXDomain); ok {
				if c.metrics != nil {
					c.metrics.IncNSEC3AggressiveSynthNX()
				}
				return entry, true
			}
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			break
		}
		name = name[dot+1:]
	}
	return nil, false
}

// buildNSEC3SynthEntry materialises an Entry from a cached NSEC3
// interval, shared between the NXDOMAIN (§5.2) and NODATA (§5.4)
// synthesis paths. Mirror of buildNSECSynthEntry in the NSEC file.
func (c *Cache) buildNSEC3SynthEntry(iv nsec3Interval, now time.Time, negType NegativeType, rcode uint8) (*Entry, bool) {
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

// extractNSEC3OwnerHash decodes the leftmost label of an NSEC3 owner
// name (base32hex extended) to raw hash bytes. Returns (nil,false) if
// the label is malformed.
func extractNSEC3OwnerHash(owner string) ([]byte, bool) {
	owner = strings.TrimSuffix(owner, ".")
	dot := strings.IndexByte(owner, '.')
	if dot <= 0 {
		return nil, false
	}
	label := strings.ToUpper(owner[:dot])
	hash, err := nsec3Base32Decode(label)
	if err != nil {
		return nil, false
	}
	return hash, true
}

// nsec3HashCovers reports whether qHash falls strictly between
// ownerHash and nextHash in big-endian byte order, accounting for the
// zone wrap at the last NSEC3 (where ownerHash > nextHash).
func nsec3HashCovers(ownerHash, nextHash, qHash []byte) bool {
	cmpOwner := bytesCompare(qHash, ownerHash)
	cmpNext := bytesCompare(qHash, nextHash)
	if bytesCompare(ownerHash, nextHash) < 0 {
		return cmpOwner > 0 && cmpNext < 0
	}
	// Wrap.
	return cmpOwner > 0 || cmpNext < 0
}

func bytesCompare(a, b []byte) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// computeNSEC3HashForCache duplicates dnssec.ComputeNSEC3Hash locally
// to avoid creating a cache→dnssec dependency cycle (cache is the
// lower-level package). Algorithm 1 (SHA-1) is the only one defined
// by RFC 5155, but we keep the algorithm parameter so the function
// reads obviously-correct rather than constant-folded.
func computeNSEC3HashForCache(name string, algorithm uint8, iterations uint16, salt []byte) ([]byte, error) {
	if algorithm != 1 {
		return nil, errUnsupportedNSEC3Alg
	}
	const maxIters = 100 // RFC 9276 §3.2 — match dnssec.MaxNSEC3Iterations
	if iterations > maxIters {
		return nil, errTooManyNSEC3Iters
	}
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	wire := nameToWireForNSEC3(name)
	h := sha1.New()
	h.Write(wire)
	h.Write(salt)
	hash := h.Sum(nil)
	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(hash)
		h.Write(salt)
		hash = h.Sum(nil)
	}
	return hash, nil
}

func nameToWireForNSEC3(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			out = append(out, 0)
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return out
}
