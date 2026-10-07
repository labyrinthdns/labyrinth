package cache

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestAggressiveAuthorityTTL(t *testing.T) {
	for _, kind := range []string{"NSEC", "NSEC3"} {
		for _, tc := range []struct {
			name                            string
			proof, soa, sig, negative, want uint32
		}{
			{"equal", 300, 300, 300, 300, 300},
			{"short_proof", 30, 300, 300, 300, 30},
			{"short_signature", 300, 300, 15, 300, 15},
			{"short_soa", 300, 10, 300, 300, 10},
			{"short_negative", 300, 300, 300, 5, 5},
			{"zero_proof", 0, 300, 300, 300, 0},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					c := NewCache(1024, 1, 86400, 3600, nil)
					name := "h.example.com"
					var auth []dns.ResourceRecord
					var register func(string, uint32, []dns.ResourceRecord)
					var lookup func() (*Entry, bool)
					if kind == "NSEC" {
						auth = []dns.ResourceRecord{soaForZone("example.com", tc.soa, 300), {Name: "foo.example.com", Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: tc.proof, RData: buildNSECRData(t, "hop.example.com")}}
						register = c.RegisterNSECInterval
						lookup = func() (*Entry, bool) { return c.LookupNSECCovers(name, dns.ClassIN) }
					} else {
						h := nsec3Hash(name)
						auth = newFakeNSEC3AuthorityWithBitmap(t, h, h, 0, []uint16{dns.TypeA})
						auth[0].TTL = tc.soa
						auth[1].TTL = tc.proof
						register = c.RegisterNSEC3Interval
						lookup = func() (*Entry, bool) { return c.LookupNSEC3CoversTyped(name, dns.TypeAAAA, dns.ClassIN) }
					}
					auth = append(auth, dns.ResourceRecord{Name: "example.com", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: tc.sig})
					register("example.com", tc.negative, auth)
					entry, ok := lookup()
					if tc.want == 0 {
						if ok {
							t.Fatal("zero-lifetime proof was returned")
						}
						return
					}
					if !ok {
						t.Fatal("fresh proof missing")
					}
					if entry.OrigTTL != tc.want {
						t.Fatalf("OrigTTL=%d, want %d", entry.OrigTTL, tc.want)
					}
					for _, rr := range entry.Authority {
						if rr.TTL != tc.want {
							t.Fatalf("TTL=%d, want %d", rr.TTL, tc.want)
						}
					}
					// The clock belongs to the synctest bubble; no real delay is used.
					time.Sleep(time.Duration(tc.want) * time.Second)
					if _, ok := lookup(); ok {
						t.Fatal("proof returned at exact expiration")
					}
				})
			})
		}
	}
}
