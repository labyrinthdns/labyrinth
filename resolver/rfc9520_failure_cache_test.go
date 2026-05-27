package resolver

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestFailureCache_PutThenGetReplaysSameRcode pins Y26 happy path:
// after Put records a (name, type, class) failure, Get returns the
// same RCODE and reason within the TTL window. This is the
// short-circuit that prevents retry storms against a broken auth.
func TestFailureCache_PutThenGetReplaysSameRcode(t *testing.T) {
	c := newFailureCache(64, 5*time.Second)
	c.Put("133.185.147.in-addr.arpa", dns.TypeNS, dns.ClassIN, dns.RCodeServFail, "no-reachable-authority")

	rcode, reason, hit := c.Get("133.185.147.in-addr.arpa", dns.TypeNS, dns.ClassIN)
	if !hit {
		t.Fatal("expected cache hit for just-recorded failure")
	}
	if rcode != dns.RCodeServFail {
		t.Errorf("rcode = %d, want %d", rcode, dns.RCodeServFail)
	}
	if reason != "no-reachable-authority" {
		t.Errorf("reason = %q, want no-reachable-authority", reason)
	}
}

// TestFailureCache_TTLExpiresEntry pins the upper bound: RFC 9520 §4
// caps the failure cache TTL at 5 seconds so a transient outage
// recovers quickly. After the TTL passes a Get must miss so the
// resolver re-attempts upstream.
func TestFailureCache_TTLExpiresEntry(t *testing.T) {
	c := newFailureCache(64, 2*time.Millisecond)
	c.Put("flaky.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	time.Sleep(10 * time.Millisecond)
	if _, _, hit := c.Get("flaky.example", dns.TypeA, dns.ClassIN); hit {
		t.Error("expected miss after TTL, got hit (entry not evicted)")
	}
}

// TestFailureCache_DifferentKeysIndependent: a failure for type A
// must not pollute type AAAA, and a failure for name X must not
// pollute name Y. Otherwise an SERVFAIL on one query breaks the
// whole cache key space for that name.
func TestFailureCache_DifferentKeysIndependent(t *testing.T) {
	c := newFailureCache(64, 5*time.Second)
	c.Put("a.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")

	if _, _, hit := c.Get("a.example", dns.TypeAAAA, dns.ClassIN); hit {
		t.Error("AAAA must miss when only A was recorded")
	}
	if _, _, hit := c.Get("b.example", dns.TypeA, dns.ClassIN); hit {
		t.Error("b.example must miss when only a.example was recorded")
	}
}

// TestFailureCache_EvictsOldestWhenFull pins the bounded-growth
// guarantee. capacity=2; insert three entries; verify only the two
// newest survive.
func TestFailureCache_EvictsOldestWhenFull(t *testing.T) {
	c := newFailureCache(2, 5*time.Second)
	c.Put("first.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	time.Sleep(2 * time.Millisecond)
	c.Put("second.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	time.Sleep(2 * time.Millisecond)
	c.Put("third.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")

	if _, _, hit := c.Get("first.example", dns.TypeA, dns.ClassIN); hit {
		t.Error("oldest 'first.example' should have been evicted")
	}
	if _, _, hit := c.Get("third.example", dns.TypeA, dns.ClassIN); !hit {
		t.Error("newest 'third.example' should be present")
	}
}

// TestFailureCache_DisabledByZeroCapacity: capacity <= 0 disables the
// cache entirely so operators who prefer the legacy retry-every-time
// behaviour can keep it. Put becomes a no-op, Get always misses.
func TestFailureCache_DisabledByZeroCapacity(t *testing.T) {
	c := newFailureCache(0, 5*time.Second)
	c.Put("any.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	if _, _, hit := c.Get("any.example", dns.TypeA, dns.ClassIN); hit {
		t.Error("disabled cache must miss")
	}
	if c.Len() != 0 {
		t.Errorf("disabled cache length = %d, want 0", c.Len())
	}
}

// TestFailureCache_NilReceiverSafe pins the defensive contract: a
// Resolver constructed in a minimal test path may have a nil
// failureCache. Methods on nil must not panic.
func TestFailureCache_NilReceiverSafe(t *testing.T) {
	var c *failureCache
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil cache must not panic: %v", r)
		}
	}()
	c.Put("any", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	if _, _, hit := c.Get("any", dns.TypeA, dns.ClassIN); hit {
		t.Error("nil cache must miss")
	}
	if got := c.Len(); got != 0 {
		t.Errorf("nil cache length = %d, want 0", got)
	}
}
