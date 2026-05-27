package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// newFakeNSECAuthority builds a minimal authority section containing a
// placeholder SOA and one NSEC RR with the requested owner, next, and
// type-bitmap. The NSEC RDATA is hand-assembled so we control the
// bitmap exactly; ParseNSEC reads it back through the normal path.
func newFakeNSECAuthority(t *testing.T, owner, next string, types []uint16) []dns.ResourceRecord {
	t.Helper()
	// Wire-format next-domain-name + serialised type bitmap.
	nameWire := nameToDNSWire(next)
	rdata := append([]byte(nil), nameWire...)
	rdata = append(rdata, serialiseTypeBitmap(types)...)

	soa := dns.ResourceRecord{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300,
		RData: []byte{0}, RDLength: 1,
	}
	nsec := dns.ResourceRecord{
		Name:     owner,
		Type:     dns.TypeNSEC,
		Class:    dns.ClassIN,
		TTL:      300,
		RData:    rdata,
		RDLength: uint16(len(rdata)),
	}
	return []dns.ResourceRecord{soa, nsec}
}

// nameToDNSWire converts a dotted name to length-prefixed DNS wire
// format with a trailing root label. Test helper duplicated to avoid
// touching the dns package's internal helpers.
func nameToDNSWire(name string) []byte {
	var out []byte
	if name == "" || name == "." {
		return []byte{0}
	}
	for _, label := range splitLabels(name) {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0)
	return out
}

func splitLabels(name string) []string {
	var labels []string
	cur := ""
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if cur != "" {
				labels = append(labels, cur)
			}
			cur = ""
			continue
		}
		cur += string(name[i])
	}
	if cur != "" {
		labels = append(labels, cur)
	}
	return labels
}

// serialiseTypeBitmap produces the RFC 4034 §4.1.2 type-bitmap wire
// format: groups of (window, bitmaplen, bitmap-bytes). For test
// fixtures we only emit window 0 (types < 256), which covers A, AAAA,
// MX, NS, SOA, TXT, NSEC, RRSIG — everything the tests touch.
func serialiseTypeBitmap(types []uint16) []byte {
	if len(types) == 0 {
		return nil
	}
	// Find max byte position for window 0.
	maxByte := 0
	for _, tt := range types {
		if tt >= 256 {
			continue
		}
		b := int(tt) / 8
		if b > maxByte {
			maxByte = b
		}
	}
	bitmap := make([]byte, maxByte+1)
	for _, tt := range types {
		if tt >= 256 {
			continue
		}
		bitmap[tt/8] |= 0x80 >> (tt % 8)
	}
	out := []byte{0, byte(len(bitmap))}
	out = append(out, bitmap...)
	return out
}

// TestTypeBitmapHas pins the helper that drives RFC 8198 §5.4 NODATA
// synthesis. A type-bitmap parsed from an NSEC/NSEC3 RR holds the type
// codes the auth claims exist at that owner; if qtype is NOT in the
// list, the NSEC itself authenticates NODATA for qname/qtype.
func TestTypeBitmapHas(t *testing.T) {
	bm := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS, dns.TypeRRSIG}
	if !typeBitmapHas(bm, dns.TypeA) {
		t.Error("A must be reported present")
	}
	if !typeBitmapHas(bm, dns.TypeRRSIG) {
		t.Error("RRSIG must be reported present")
	}
	if typeBitmapHas(bm, dns.TypeTXT) {
		t.Error("TXT must be reported absent (not in the bitmap)")
	}
	if typeBitmapHas(nil, dns.TypeA) {
		t.Error("nil bitmap must report all types absent")
	}
}

// TestLookupNSEC_NODATA_OwnerMatchTypeAbsent pins the Y32 happy path:
// when a Secure NXDOMAIN/NODATA response is cached and its NSEC RR's
// owner name EXACTLY matches qname, the type-bitmap excludes qtype,
// and the entry is still fresh, the typed lookup returns a synthesised
// NODATA entry (RCODE=NOERROR, NegType=NegNoData).
func TestLookupNSEC_NODATA_OwnerMatchTypeAbsent(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	// Build authority: SOA + NSEC whose owner is "host.example.com" and
	// whose bitmap claims only A (not AAAA — we'll query for AAAA).
	authority := newFakeNSECAuthority(t, "host.example.com", "next.example.com", []uint16{dns.TypeA, dns.TypeRRSIG})
	c.RegisterNSECInterval("example.com", 300, authority)

	got, ok := c.LookupNSECCoversTyped("host.example.com", dns.TypeAAAA, dns.ClassIN)
	if !ok {
		t.Fatal("typed lookup must hit: owner matches qname and AAAA not in bitmap")
	}
	if got.RCODE != dns.RCodeNoError {
		t.Errorf("rcode = %d, want NOERROR (NODATA)", got.RCODE)
	}
	if got.NegType != NegNoData {
		t.Errorf("NegType = %d, want NegNoData", got.NegType)
	}
	if got.DNSSECStatus != "secure" {
		t.Errorf("DNSSECStatus = %q, want secure", got.DNSSECStatus)
	}
}

// TestLookupNSEC_NODATA_TypePresentSkipsSynth pins the negative side:
// when qtype IS present in the cached NSEC's bitmap, the synthesis
// must NOT fire (it would lie about the type's absence). The lookup
// falls through to the NXDOMAIN coverage check and ultimately misses
// because qname == owner is not strictly between owner and next.
func TestLookupNSEC_NODATA_TypePresentSkipsSynth(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	authority := newFakeNSECAuthority(t, "host.example.com", "next.example.com", []uint16{dns.TypeA, dns.TypeAAAA})
	c.RegisterNSECInterval("example.com", 300, authority)

	if _, ok := c.LookupNSECCoversTyped("host.example.com", dns.TypeA, dns.ClassIN); ok {
		t.Error("synth must NOT fire when qtype is in the cached bitmap")
	}
}

// TestLookupNSEC_NXDomainStillWorks regression-locks the §5.2 path:
// when qname falls strictly between owner and next, we still get
// NXDOMAIN (the §5.4 typed path must not break the existing behaviour).
func TestLookupNSEC_NXDomainStillWorks(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	authority := newFakeNSECAuthority(t, "alpha.example.com", "delta.example.com", []uint16{dns.TypeA})
	c.RegisterNSECInterval("example.com", 300, authority)

	got, ok := c.LookupNSECCoversTyped("charlie.example.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("NXDOMAIN coverage must still work after §5.4 wiring")
	}
	if got.NegType != NegNXDomain {
		t.Errorf("NegType = %d, want NegNXDomain", got.NegType)
	}
	if got.RCODE != dns.RCodeNXDomain {
		t.Errorf("RCODE = %d, want NXDOMAIN", got.RCODE)
	}
}

// TestLookupNSEC_QtypeZeroDisablesNODATA: passing qtype=0 (the
// untyped LookupNSECCovers wrapper) keeps the pre-Y32 NXDOMAIN-only
// behaviour. Otherwise a caller that just wants NXDOMAIN check would
// accidentally pick up a NODATA synth.
func TestLookupNSEC_QtypeZeroDisablesNODATA(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	authority := newFakeNSECAuthority(t, "host.example.com", "next.example.com", []uint16{dns.TypeA})
	c.RegisterNSECInterval("example.com", 300, authority)

	if _, ok := c.LookupNSECCovers("host.example.com", dns.ClassIN); ok {
		t.Error("untyped LookupNSECCovers must NOT synth NODATA on owner-match")
	}
}
