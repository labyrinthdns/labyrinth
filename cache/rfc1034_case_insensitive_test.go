package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestCache_LookupIsCaseInsensitive pins Y55: RFC 1034 §3.1 and RFC
// 4343 say "domain name comparisons for all present domain functions
// are case-insensitive." A cache that stores "Example.COM" under one
// key and "example.com" under another would silently double-allocate
// entries on every mixed-case query, defeat the 0x20 anti-spoofing
// defence (which deliberately sends mixed-case to the upstream but
// expects to cache the lowercase answer), and break the integration
// with the DNSSEC validator (which canonicalises to lowercase per
// RFC 4034 §6.2).
//
// We pin three concrete invariants the cache must satisfy:
//   1. Store(lower) then Get(MIXED) → hits
//   2. Store(MIXED) then Get(lower) → hits
//   3. Both forms map to ONE entry, not two
//
// The store/get path internally lower-cases the key, but pinning at
// the public surface guards against a refactor that lifted the lower
// call out of one path and not the other.
func TestCache_LookupIsCaseInsensitive(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(100, 5, 86400, 3600, m)

	rec := []dns.ResourceRecord{{
		Name: "x", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}

	t.Run("stored lower, looked up MIXED", func(t *testing.T) {
		c.Store("case-pin.example.com", dns.TypeA, dns.ClassIN, rec, nil)
		if _, ok := c.Get("Case-Pin.EXAMPLE.com", dns.TypeA, dns.ClassIN); !ok {
			t.Errorf("Get(\"Case-Pin.EXAMPLE.com\") missed an entry stored as \"case-pin.example.com\" (RFC 1034 §3.1 violation)")
		}
	})

	t.Run("stored MIXED, looked up lower", func(t *testing.T) {
		c.Store("REVERSE.Case.test", dns.TypeA, dns.ClassIN, rec, nil)
		if _, ok := c.Get("reverse.case.test", dns.TypeA, dns.ClassIN); !ok {
			t.Errorf("Get(\"reverse.case.test\") missed an entry stored as \"REVERSE.Case.test\" — Store path is not lowering")
		}
	})

	t.Run("mixed and lower share one entry, not two", func(t *testing.T) {
		c2 := NewCache(100, 5, 86400, 3600, m)
		// Store same name twice with different case; if the cache were
		// case-sensitive there would now be two entries.
		c2.Store("shared.example.", dns.TypeA, dns.ClassIN, rec, nil)
		c2.Store("SHARED.EXAMPLE.", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
			Name: "x", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 600, RDLength: 4, RData: []byte{10, 0, 0, 2}, // distinct RDATA
		}}, nil)

		// The second Store must have REPLACED the first under the same
		// case-folded key. Pin the size, not the exact records — the
		// observable invariant is "one entry, not two."
		stats := c2.Stats()
		if stats.Entries != 1 {
			t.Errorf("entries = %d, want 1 (case-folded names must map to a single key)", stats.Entries)
		}
	})
}
