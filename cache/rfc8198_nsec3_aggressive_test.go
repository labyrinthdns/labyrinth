package cache

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// newFakeNSEC3Authority builds a minimal authority section containing
// one SOA and one NSEC3 RR with the requested flags byte. The owner
// hash and next hash are arbitrary 4-byte values — enough for the
// registration filter to inspect Flags and accept/reject; downstream
// lookup is not exercised here.
func newFakeNSEC3Authority(t *testing.T, flags uint8) []dns.ResourceRecord {
	t.Helper()
	owner := make([]byte, 4)
	binary.BigEndian.PutUint32(owner, 0x12345678)
	next := make([]byte, 4)
	binary.BigEndian.PutUint32(next, 0x87654321)

	// NSEC3 RDATA = hashAlg(1) | flags(1) | iters(2) | saltLen(1) | salt(0)
	// | hashLen(1) | nextHash(4) | typeBitmaps(0)
	rdata := []byte{
		1,           // hashAlg = SHA-1
		flags,       // flags (opt-out bit if set by caller)
		0x00, 0x00,  // iterations = 0
		0x00,        // salt length = 0
		byte(len(next)),
	}
	rdata = append(rdata, next...)

	soa := dns.ResourceRecord{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300,
		RData: []byte{0}, RDLength: 1, // placeholder; we only need TYPE
	}
	nsec3 := dns.ResourceRecord{
		Name:     nsec3Base32.EncodeToString(owner) + ".example.com",
		Type:     dns.TypeNSEC3,
		Class:    dns.ClassIN,
		TTL:      300,
		RData:    rdata,
		RDLength: uint16(len(rdata)),
	}
	return []dns.ResourceRecord{soa, nsec3}
}

// TestNSEC3HashCovers_StrictlyBetween pins the canonical-order check
// used by the NSEC3 aggressive lookup. The qname's hash must fall
// STRICTLY between ownerHash and nextHash; equal-to-owner or
// equal-to-next is not "covered" (those are the existence proofs,
// not denial proofs).
func TestNSEC3HashCovers_StrictlyBetween(t *testing.T) {
	owner := []byte{0x10, 0x20, 0x30}
	next := []byte{0x10, 0x20, 0x50}

	if !nsec3HashCovers(owner, next, []byte{0x10, 0x20, 0x40}) {
		t.Error("hash 0x102040 must be covered by 0x102030..0x102050")
	}
	if nsec3HashCovers(owner, next, owner) {
		t.Error("hash == owner is not a denial proof")
	}
	if nsec3HashCovers(owner, next, next) {
		t.Error("hash == next is not a denial proof")
	}
	if nsec3HashCovers(owner, next, []byte{0x10, 0x20, 0x29}) {
		t.Error("hash 0x102029 (below owner) must NOT be covered")
	}
	if nsec3HashCovers(owner, next, []byte{0x10, 0x20, 0x60}) {
		t.Error("hash 0x102060 (above next) must NOT be covered")
	}
}

// TestNSEC3HashCovers_ZoneWrap pins the wrap-around case: the LAST
// NSEC3 in canonical hash order has ownerHash > nextHash (it points
// back to the first NSEC3 to close the ring). A qname hash either
// greater than owner OR less than next is covered.
func TestNSEC3HashCovers_ZoneWrap(t *testing.T) {
	owner := []byte{0xf0, 0x00}
	next := []byte{0x10, 0x00}

	if !nsec3HashCovers(owner, next, []byte{0xff, 0x99}) {
		t.Error("hash 0xff99 > owner 0xf000 must be covered by the wrap interval")
	}
	if !nsec3HashCovers(owner, next, []byte{0x05, 0x00}) {
		t.Error("hash 0x0500 < next 0x1000 must be covered by the wrap interval")
	}
	if nsec3HashCovers(owner, next, []byte{0x80, 0x00}) {
		t.Error("hash 0x8000 (between next and owner) must NOT be covered by wrap")
	}
}

// TestComputeNSEC3HashForCache_AlgorithmAndIterationGates pins the
// safety rails. Algorithm != 1 is rejected (only SHA-1 is defined per
// RFC 5155). Iterations > 100 is rejected (RFC 9276 §3.2 — DoS guard).
func TestComputeNSEC3HashForCache_AlgorithmAndIterationGates(t *testing.T) {
	if _, err := computeNSEC3HashForCache("example.com", 2, 0, nil); err == nil {
		t.Error("algorithm 2 must be rejected (RFC 5155 defines only 1)")
	}
	if _, err := computeNSEC3HashForCache("example.com", 1, 200, nil); err == nil {
		t.Error("iterations 200 must be rejected (RFC 9276 ceiling 100)")
	}
	if _, err := computeNSEC3HashForCache("example.com", 1, 0, nil); err != nil {
		t.Errorf("alg=1, iters=0 must succeed, got %v", err)
	}
}

// TestExtractNSEC3OwnerHash_ParsesLeftmostLabel pins the helper that
// turns an NSEC3 owner name like "ABCDEFGH....example.com" into raw
// hash bytes (base32hex decoded). The hash bytes are what
// nsec3HashCovers compares against.
func TestExtractNSEC3OwnerHash_ParsesLeftmostLabel(t *testing.T) {
	// Encode a known 4-byte hash to base32hex (no padding, uppercase).
	src := []byte{0x12, 0x34, 0x56, 0x78}
	label := nsec3Base32.EncodeToString(src)
	owner := label + ".example.com"

	hash, ok := extractNSEC3OwnerHash(owner)
	if !ok {
		t.Fatalf("expected to parse owner %q", owner)
	}
	if len(hash) != len(src) {
		t.Fatalf("hash length = %d, want %d", len(hash), len(src))
	}
	for i := range src {
		if hash[i] != src[i] {
			t.Errorf("hash byte %d = %#x, want %#x", i, hash[i], src[i])
		}
	}
}

// TestExtractNSEC3OwnerHash_RejectsMalformed: an owner without dots
// or with a non-base32 leftmost label is a parser-failure, not a
// silent zero-hash. Otherwise random RR types could be mis-indexed.
func TestExtractNSEC3OwnerHash_RejectsMalformed(t *testing.T) {
	if _, ok := extractNSEC3OwnerHash("noseparator"); ok {
		t.Error("missing dot must be rejected")
	}
	if _, ok := extractNSEC3OwnerHash(".empty.label"); ok {
		t.Error("empty leftmost label must be rejected")
	}
	if _, ok := extractNSEC3OwnerHash("@@@@.example.com"); ok {
		t.Error("non-base32 leftmost label must be rejected")
	}
}

// TestRegisterNSEC3Interval_SkipsOptOut pins the safety policy: any
// NSEC3 with the opt-out flag (LSB) set is dropped at registration
// time. RFC 5155 §6 makes opt-out an authenticated denial only for
// signed delegations, so aggressive synthesis from an opt-out NSEC3
// would manufacture NXDOMAIN for names the zone never proved
// nonexistent.
func TestRegisterNSEC3Interval_SkipsOptOut(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	// Synthetic authority section with one opt-out NSEC3 (flags=0x01).
	// We don't need a real zone — RegisterNSEC3Interval is the unit.
	// If it filtered correctly, the index has zero intervals.
	// Build a minimal NSEC3 RR with opt-out and a SOA so the registrar
	// has something to copy. The internal index check is what we want
	// to observe.
	authority := newFakeNSEC3Authority(t, 0x01) // opt-out set
	c.RegisterNSEC3Interval("example.com", 300, authority)

	c.nsec3Idx.mu.RLock()
	defer c.nsec3Idx.mu.RUnlock()
	if got := len(c.nsec3Idx.byZone["example.com"]); got != 0 {
		t.Errorf("opt-out NSEC3 should be skipped; index has %d entries", got)
	}
}

// TestRegisterNSEC3Interval_AcceptsNonOptOut: same scenario but flags=0,
// so the NSEC3 IS indexed. Confirms the opt-out filter does not also
// reject the normal case (a regression guard for the §6 boundary).
func TestRegisterNSEC3Interval_AcceptsNonOptOut(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	authority := newFakeNSEC3Authority(t, 0x00) // opt-out clear
	c.RegisterNSEC3Interval("example.com", 300, authority)

	c.nsec3Idx.mu.RLock()
	defer c.nsec3Idx.mu.RUnlock()
	if got := len(c.nsec3Idx.byZone["example.com"]); got != 1 {
		t.Errorf("non-opt-out NSEC3 should be indexed; got %d entries", got)
	}
}
