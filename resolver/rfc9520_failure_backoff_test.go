package resolver

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// failureEntryTTL reads an entry's current hold time. Test helper.
func failureEntryTTL(c *failureCache, name string, qtype uint16) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries[failureKey(name, qtype, dns.ClassIN)].ttl
}

// expireFailureEntry ages an entry so it has just expired.
func expireFailureEntry(c *failureCache, name string, qtype uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := failureKey(name, qtype, dns.ClassIN)
	e := c.entries[key]
	e.insertedAt = time.Now().Add(-e.ttl - time.Millisecond)
	c.entries[key] = e
}

// TestFailureCache_BackoffDoublesToMax pins RFC 9520 §3.2: a persistent
// failure is held longer after each retry that fails again, up to the
// configured maximum (never past 5 minutes). Live: www.newsisfree.com is
// asked every ~6 s by a blog ping list; with a fixed 5 s hold every ask
// was a full iteration plus a public-fallback timeout.
func TestFailureCache_BackoffDoublesToMax(t *testing.T) {
	c := newFailureCacheBackoff(64, 5*time.Second, 5*time.Minute)
	const name = "www.newsisfree.com"
	want := []time.Duration{5, 10, 20, 40, 80, 160, 300, 300}
	for i, w := range want {
		c.Put(name, dns.TypeA, dns.ClassIN, dns.RCodeServFail, "no-reachable-authority")
		if got := failureEntryTTL(c, name, dns.TypeA); got != w*time.Second {
			t.Fatalf("failure %d: ttl = %v, want %v", i+1, got, w*time.Second)
		}
		if _, _, hit := c.Get(name, dns.TypeA, dns.ClassIN); !hit {
			t.Fatalf("failure %d: fresh entry missed", i+1)
		}
		expireFailureEntry(c, name, dns.TypeA)
		if _, _, hit := c.Get(name, dns.TypeA, dns.ClassIN); hit {
			t.Fatalf("failure %d: expired entry hit", i+1)
		}
	}
}

// TestFailureCache_ConcurrentPutKeepsTTL: two in-flight requests for the
// same name failing together are one failure, not two backoff steps.
func TestFailureCache_ConcurrentPutKeepsTTL(t *testing.T) {
	c := newFailureCacheBackoff(64, 5*time.Second, 5*time.Minute)
	c.Put("dead.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	c.Put("dead.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	if got := failureEntryTTL(c, "dead.example", dns.TypeA); got != 5*time.Second {
		t.Errorf("ttl = %v after a Put on a fresh entry, want 5s", got)
	}
}

// TestFailureCache_ForgetResetsBackoff: once the name resolves again its
// next failure starts at the minimum, so a one-off outage heals fast.
func TestFailureCache_ForgetResetsBackoff(t *testing.T) {
	c := newFailureCacheBackoff(64, 5*time.Second, 5*time.Minute)
	c.Put("flap.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	expireFailureEntry(c, "flap.example", dns.TypeA)
	c.Put("flap.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	if got := failureEntryTTL(c, "flap.example", dns.TypeA); got != 10*time.Second {
		t.Fatalf("second failure ttl = %v, want 10s", got)
	}
	c.Forget("flap.example", dns.TypeA, dns.ClassIN)
	if c.Len() != 0 {
		t.Fatalf("Forget left %d entries", c.Len())
	}
	c.Put("flap.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	if got := failureEntryTTL(c, "flap.example", dns.TypeA); got != 5*time.Second {
		t.Errorf("failure after Forget: ttl = %v, want 5s", got)
	}
}

// TestFailureCache_QuietPeriodResetsBackoff: a failure that recurs only
// after the entry has been expired for longer than the maximum is a new
// failure, and the stale entry is evicted on lookup.
func TestFailureCache_QuietPeriodResetsBackoff(t *testing.T) {
	c := newFailureCacheBackoff(64, 5*time.Millisecond, 20*time.Millisecond)
	c.Put("quiet.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	time.Sleep(40 * time.Millisecond)
	if _, _, hit := c.Get("quiet.example", dns.TypeA, dns.ClassIN); hit {
		t.Fatal("entry still hit after its ttl")
	}
	if c.Len() != 0 {
		t.Fatalf("entry expired past ttl+max not evicted (len %d)", c.Len())
	}
	c.Put("quiet.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	if got := failureEntryTTL(c, "quiet.example", dns.TypeA); got != 5*time.Millisecond {
		t.Errorf("ttl after quiet period = %v, want the minimum", got)
	}
}

// TestFailureCache_BackoffBounds: the maximum is capped at the RFC's 5
// minutes and never below the minimum.
func TestFailureCache_BackoffBounds(t *testing.T) {
	if c := newFailureCacheBackoff(1, 5*time.Second, time.Hour); c.maxTTL != 5*time.Minute {
		t.Errorf("maxTTL = %v, want capped at 5m", c.maxTTL)
	}
	if c := newFailureCacheBackoff(1, 30*time.Second, 10*time.Second); c.maxTTL != 30*time.Second {
		t.Errorf("maxTTL = %v, want raised to minTTL", c.maxTTL)
	}
	if c := newFailureCache(1, 5*time.Second); c.maxTTL != 5*time.Second {
		t.Errorf("fixed-ttl cache maxTTL = %v, want 5s (no backoff)", c.maxTTL)
	}
}

// TestResolver_SuccessForgetsFailure: a name that resolves after failing
// drops its failure entry, so its next failure is held the minimum again.
func TestResolver_SuccessForgetsFailure(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(), QDCount: 1, ANCount: 1},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{192, 0, 2, 1},
			}},
		}
	})
	defer mock.close()
	r := testResolver(t, mock)
	r.failureCache.Put("www.back.lab", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "")
	expireFailureEntry(r.failureCache, "www.back.lab", dns.TypeA)

	res, err := r.Resolve("www.back.lab", dns.TypeA, dns.ClassIN)
	if err != nil || res == nil || res.RCODE != dns.RCodeNoError {
		t.Fatalf("res=%+v err=%v, want an answer", res, err)
	}
	if n := r.failureCache.Len(); n != 0 {
		t.Errorf("failure entry survived a successful resolution (len %d)", n)
	}
}
