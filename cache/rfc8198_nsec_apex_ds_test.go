package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestLookupNSEC_NODATA_ApexNSECDoesNotDenyDS: the child's apex NSEC
// (NS+SOA) never lists DS because DS lives in the parent zone, so it must
// not synthesise NODATA for "<apex> DS" — while other absent apex types
// still synthesise.
func TestLookupNSEC_NODATA_ApexNSECDoesNotDenyDS(t *testing.T) {
	c := NewCache(1024, 60, 86400, 3600, nil)
	c.RegisterNSECInterval("example.com", 300, newFakeNSECAuthority(t, "example.com", "a.example.com", []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY}))

	if _, ok := c.LookupNSECCoversTyped("example.com.", dns.TypeDS, dns.ClassIN); ok {
		t.Error("apex NSEC must not synthesise NODATA for DS")
	}
	if _, ok := c.LookupNSECCoversTyped("example.com.", dns.TypeTXT, dns.ClassIN); !ok {
		t.Error("apex NSEC must still synthesise NODATA for an absent apex type")
	}
}
