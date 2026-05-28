package cache

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestGetStale_RejectsEntryPastStaleMaxAge pins RFC 8767 §3.3:
// "validators SHOULD limit the staleness ... to between 1 and 3 days
// at most." The cache exposes `staleMaxAge` (seconds) as the operator-
// configurable ceiling on how far past expiry an entry may still be
// served. The serve-stale path is a fallback for upstream outages —
// an unbounded ceiling would mean a single inserted entry, never
// re-fetched (long-tail name accessed once and not again for months),
// would still be served stale forever. Worse, if the legitimate auth
// server changed the record in the interim, our resolver would keep
// returning the OLD answer indefinitely — the antithesis of what
// caching is supposed to do.
//
// The pin drives three scenarios on a cache with `staleMaxAge=2`:
//
//   1. Entry expired-for 0s past TTL → served (within window).
//   2. Entry expired-for 3s past TTL (> staleMaxAge) → NOT served.
//   3. Bound-test: staleMaxAge=0 means "no ceiling" → always served.
//
// A refactor that swapped the inequality direction or replaced
// `> staleMaxAge` with `>=` would change case-2's behaviour at a
// 1-second granularity and slip through under most timing tolerances —
// the explicit case-3 anchor proves the 0=disabled convention is also
// preserved.
func TestGetStale_RejectsEntryPastStaleMaxAge(t *testing.T) {
	t.Run("within stale window — served", func(t *testing.T) {
		c := NewCacheWithStale(100, 1, 86400, 3600, true, 30, metrics.NewMetrics())
		c.SetStaleMaxAge(5)
		seedAndExpire(t, c, "y69-window.example.com", 1, 0)
		time.Sleep(1100 * time.Millisecond) // expired-for ~0.1s
		if _, ok := c.GetStale("y69-window.example.com", dns.TypeA, dns.ClassIN); !ok {
			t.Errorf("entry within staleMaxAge=5 window was rejected — operators rely on this for upstream-outage robustness (RFC 8767 §3.1)")
		}
	})

	t.Run("past stale window — rejected", func(t *testing.T) {
		// expiredFor is computed as uint32(time.Since.Seconds()) - OrigTTL.
		// Use OrigTTL=1, staleMaxAge=1, sleep ≥3.5s → expiredFor floors
		// to 2, > 1 → rejected. Sleeping less would float around the
		// inclusive boundary due to integer truncation.
		c := NewCacheWithStale(100, 1, 86400, 3600, true, 30, metrics.NewMetrics())
		c.SetStaleMaxAge(1)
		seedAndExpire(t, c, "y69-past.example.com", 1, 0)
		time.Sleep(3500 * time.Millisecond)
		if _, ok := c.GetStale("y69-past.example.com", dns.TypeA, dns.ClassIN); ok {
			t.Errorf("entry expired past staleMaxAge=1s was still served — RFC 8767 §3.3 ceiling not enforced; rotted answers can persist indefinitely after upstream outage")
		}
	})

	t.Run("staleMaxAge=0 means disabled — always served", func(t *testing.T) {
		c := NewCacheWithStale(100, 1, 86400, 3600, true, 30, metrics.NewMetrics())
		// SetStaleMaxAge(0) opts out of the ceiling — the default,
		// but we exercise the setter to prove the 0=disabled convention.
		c.SetStaleMaxAge(0)
		seedAndExpire(t, c, "y69-disabled.example.com", 1, 0)
		time.Sleep(1500 * time.Millisecond)
		if _, ok := c.GetStale("y69-disabled.example.com", dns.TypeA, dns.ClassIN); !ok {
			t.Errorf("staleMaxAge=0 must mean 'no ceiling' (operator opt-out) — regression flipped 0 to mean 'serve nothing'")
		}
	})
}

func seedAndExpire(t *testing.T, c *Cache, qname string, ttl uint32, _ time.Duration) {
	t.Helper()
	c.Store(qname, dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
		TTL: ttl, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}, nil)
}
