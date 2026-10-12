package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestLookupNSECCoversTyped_CNAMEOwnerNoNODATA pins RFC 4035 §3.1.3.1 /
// RFC 6840 §4.3: an NSEC or NSEC3 whose owner is qname and whose bitmap
// holds CNAME proves the name is an alias, not that qtype is absent. Live,
// an NSEC "sigfail CNAME RRSIG NSEC" cached from a sibling NXDOMAIN turned
// `sigfail.verteiltesysteme.net AAAA` into an AD=1 NODATA, hiding the CNAME.
func TestLookupNSECCoversTyped_CNAMEOwnerNoNODATA(t *testing.T) {
	cname := []uint16{dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC}

	c := NewCache(1024, 60, 86400, 3600, nil)
	c.RegisterNSECInterval("example.com", 300, newFakeNSECAuthority(t, "alias.example.com", "next.example.com", cname))
	if got, ok := c.LookupNSECCoversTyped("alias.example.com", dns.TypeAAAA, dns.ClassIN); ok {
		t.Errorf("NSEC: synthesised rcode=%d NegType=%d for a CNAME owner", got.RCODE, got.NegType)
	}

	c3 := NewCache(1024, 60, 86400, 3600, nil)
	c3.RegisterNSEC3Interval("example.com", 300,
		newFakeNSEC3AuthorityWithBitmap(t, nsec3Hash("alias.example.com"), []byte{0xff, 0xff}, 0x00, cname))
	if got, ok := c3.LookupNSEC3CoversTyped("alias.example.com", dns.TypeAAAA, dns.ClassIN); ok {
		t.Errorf("NSEC3: synthesised rcode=%d NegType=%d for a CNAME owner", got.RCODE, got.NegType)
	}
}
