package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestLookupNSEC3_NODATA_ApexNSEC3DoesNotDenyDS: the child's apex NSEC3
// (NS+SOA) never lists DS because DS lives in the parent zone, so it must
// not synthesise NODATA for "<apex> DS" — while other absent apex types
// still synthesise.
func TestLookupNSEC3_NODATA_ApexNSEC3DoesNotDenyDS(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	apex := []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM}
	c.RegisterNSEC3Interval("example.com", 300, newFakeNSEC3AuthorityWithBitmap(t, nsec3Hash("example.com"), []byte{0xff, 0xff}, 0, apex))

	if _, ok := c.LookupNSEC3CoversTyped("example.com.", dns.TypeDS, dns.ClassIN); ok {
		t.Error("apex NSEC3 must not synthesise NODATA for DS")
	}
	if _, ok := c.LookupNSEC3CoversTyped("example.com.", dns.TypeTXT, dns.ClassIN); !ok {
		t.Error("apex NSEC3 must still synthesise NODATA for an absent apex type")
	}
}
