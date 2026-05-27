package cache

import (
	"crypto/sha1"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestLookupNSEC3_NODATA_OwnerHashMatchTypeAbsent pins Y33 happy path
// (parallel to the NSEC §5.4 path): when a cached NSEC3's owner hash
// equals SHA-1(qname) under the cached parameters AND qtype is not in
// the cached type bitmap, the typed lookup synthesises NODATA.
func TestLookupNSEC3_NODATA_OwnerHashMatchTypeAbsent(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)

	// Pre-compute SHA-1(qname) under iterations=0, salt=nil so we know
	// what ownerHash to plant.
	qname := "noaaaa.example.com"
	qHash := nsec3Hash(qname)

	authority := newFakeNSEC3AuthorityWithBitmap(t, qHash, []byte{0xff, 0xff}, 0x00, []uint16{dns.TypeA, dns.TypeRRSIG})
	c.RegisterNSEC3Interval("example.com", 300, authority)

	got, ok := c.LookupNSEC3CoversTyped(qname, dns.TypeAAAA, dns.ClassIN)
	if !ok {
		t.Fatal("typed NSEC3 lookup must hit: owner hash matches and AAAA not in bitmap")
	}
	if got.RCODE != dns.RCodeNoError {
		t.Errorf("rcode = %d, want NOERROR (NODATA)", got.RCODE)
	}
	if got.NegType != NegNoData {
		t.Errorf("NegType = %d, want NegNoData", got.NegType)
	}
}

// TestLookupNSEC3_NODATA_TypePresentSkipsSynth: when qtype IS in the
// bitmap the NSEC3 does NOT prove NODATA — synthesis must be skipped.
// We also expect the §5.2 (NXDOMAIN coverage) pass to miss because
// the qname's hash equals the owner hash, not strictly inside the
// (owner, next) interval.
func TestLookupNSEC3_NODATA_TypePresentSkipsSynth(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	qname := "host.example.com"
	qHash := nsec3Hash(qname)

	authority := newFakeNSEC3AuthorityWithBitmap(t, qHash, []byte{0xff, 0xff}, 0x00, []uint16{dns.TypeA, dns.TypeAAAA})
	c.RegisterNSEC3Interval("example.com", 300, authority)

	if _, ok := c.LookupNSEC3CoversTyped(qname, dns.TypeA, dns.ClassIN); ok {
		t.Error("NSEC3 synth must NOT fire when qtype is in the cached bitmap")
	}
}

// TestLookupNSEC3_QtypeZeroDisablesNODATA: the untyped wrapper
// (`LookupNSEC3Covers`) must keep the pre-Y33 NXDOMAIN-only behaviour
// so existing call sites don't accidentally pick up NODATA synthesis.
func TestLookupNSEC3_QtypeZeroDisablesNODATA(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	qname := "h.example.com"
	qHash := nsec3Hash(qname)

	authority := newFakeNSEC3AuthorityWithBitmap(t, qHash, []byte{0xff, 0xff}, 0x00, []uint16{dns.TypeA})
	c.RegisterNSEC3Interval("example.com", 300, authority)

	if _, ok := c.LookupNSEC3Covers(qname, dns.ClassIN); ok {
		t.Error("untyped LookupNSEC3Covers must NOT synth NODATA on owner-hash match")
	}
}

// nsec3Hash computes SHA-1 of a name in DNS wire form with no salt
// and zero iterations — matches the fixture's NSEC3 parameters.
func nsec3Hash(name string) []byte {
	wire := nameToWireForNSEC3(name + ".")
	h := sha1.Sum(wire)
	return h[:]
}

// newFakeNSEC3AuthorityWithBitmap is the §5.4-aware variant of
// newFakeNSEC3Authority: it lets the test specify the type-bitmap so
// the NODATA path can be exercised with a known qtype absence.
func newFakeNSEC3AuthorityWithBitmap(t *testing.T, ownerHash, nextHash []byte, flags uint8, types []uint16) []dns.ResourceRecord {
	t.Helper()
	// NSEC3 RDATA = hashAlg(1) | flags(1) | iters(2) | saltLen(1)=0
	// | hashLen(1) | nextHash(N) | typeBitmap
	rdata := []byte{
		1,          // hashAlg = SHA-1
		flags,      // flags
		0x00, 0x00, // iterations = 0
		0x00, // saltLen = 0
		byte(len(nextHash)),
	}
	rdata = append(rdata, nextHash...)
	rdata = append(rdata, serialiseTypeBitmap(types)...)

	soa := dns.ResourceRecord{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300,
		RData: []byte{0}, RDLength: 1,
	}
	nsec3 := dns.ResourceRecord{
		Name:     nsec3Base32.EncodeToString(ownerHash) + ".example.com",
		Type:     dns.TypeNSEC3,
		Class:    dns.ClassIN,
		TTL:      300,
		RData:    rdata,
		RDLength: uint16(len(rdata)),
	}
	return []dns.ResourceRecord{soa, nsec3}
}
