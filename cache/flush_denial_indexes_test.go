package cache

import (
	"github.com/labyrinthdns/labyrinth/dns"
	"testing"
)

func TestFlushClearsAggressiveDenialIndexes(t *testing.T) {
	c := NewCache(1000, 1, 86400, 3600, nil)
	auth := []dns.ResourceRecord{soaForZone("example.com", 300, 300), {Name: "foo.example.com", Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 300, RData: buildNSECRData(t, "hop.example.com")}}
	c.RegisterNSECInterval("example.com", 300, auth)
	next := make([]byte, 20)
	for i := range next {
		next[i] = 255
	}
	rdata := append([]byte{1, 0, 0, 0, 0, 20}, next...)
	n3 := []dns.ResourceRecord{soaForZone("example.com", 300, 300), {Name: nsec3Base32.EncodeToString(make([]byte, 20)) + ".example.com", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: rdata}}
	c.RegisterNSEC3Interval("example.com", 300, n3)
	if _, ok := c.LookupNSEC3Covers("h.example.com", dns.ClassIN); !ok {
		t.Fatal("NSEC3 control absent")
	}
	c.Store("positive.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{TTL: 300, RData: []byte{1}}}, nil)
	if _, ok := c.LookupNSECCovers("h.example.com", dns.ClassIN); !ok {
		t.Fatal("before-flush control missing")
	}
	c.Flush()
	_, positive := c.Get("positive.example.com", dns.TypeA, dns.ClassIN)
	_, negative := c.LookupNSECCovers("h.example.com", dns.ClassIN)
	t.Logf("EXPECTED: positive=false negative=false ACTUAL: positive=%v negative=%v", positive, negative)
	if positive {
		t.Fatal("ordinary-flush control failed")
	}
	_, negative3 := c.LookupNSEC3Covers("h.example.com", dns.ClassIN)
	t.Logf("EXPECTED: NSEC3=false ACTUAL: NSEC3=%v", negative3)
	if negative || negative3 {
		t.Fatal("PROBLEM CONFIRMED")
	}
	c.Flush()
	c.RegisterNSECInterval("example.com", 300, auth)
	if _, ok := c.LookupNSECCovers("h.example.com", dns.ClassIN); !ok {
		t.Fatal("register-after-flush edge failed")
	}
	c.Flush()
	if _, ok := c.LookupNSECCovers("h.example.com", dns.ClassIN); ok {
		t.Fatal("repeat flush edge failed")
	}
	(&Cache{}).Flush()
	t.Log("FIX VERIFIED")
}
