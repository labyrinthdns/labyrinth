package cache

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestGetStale_TriggersAsyncRefresh pins Y29 happy path: when GetStale
// returns a stale entry to the caller, the cache MUST also kick off a
// background refresh via the prefetch hook. Without this, every
// upstream outage hands a long-tail name a stale answer with no path
// back to fresh data short of TTL-bound re-resolution from upstream.
//
// We use a tiny prefetch hook that bumps a counter, sleep briefly so
// the goroutine can run, and verify the counter incremented exactly
// once per stale serve.
func TestGetStale_TriggersAsyncRefresh(t *testing.T) {
	c := NewCacheWithStale(1024, 60, 86400, 3600, true, 30, nil)
	c.SetPrefetchEnabled(true)
	var refreshCalls atomic.Int32
	c.SetPrefetchFunc(func(name string, qtype, qclass uint16) {
		refreshCalls.Add(1)
	})

	// Insert an entry that has already expired by hand-rolling the
	// InsertedAt timestamp.
	c.Store("flaky.example", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "flaky.example", Type: dns.TypeA, Class: dns.ClassIN, TTL: 1,
		RData: []byte{1, 2, 3, 4}, RDLength: 4,
	}}, nil)
	// Force-expire: rewind the stored entry's InsertedAt to T-10s with TTL=1.
	idx := c.shardIndex("flaky.example")
	s := &c.shards[idx]
	s.mu.Lock()
	for k, e := range s.entries {
		if k.name == "flaky.example" {
			e.InsertedAt = time.Now().Add(-7200 * time.Second)
			e.OrigTTL = 60
		}
	}
	s.mu.Unlock()

	_, ok := c.GetStale("flaky.example", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("expected stale hit; entry should be past TTL but within staleMaxAge")
	}

	// Give the spawned goroutine a moment to schedule.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && refreshCalls.Load() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if got := refreshCalls.Load(); got != 1 {
		t.Errorf("prefetch invocations after stale serve = %d, want 1 (RFC 8767 §3.1)", got)
	}
}

// TestGetStale_NoPrefetchWhenDisabled pins the operator-opt-out path:
// if EnablePrefetch was never called (the cache was constructed
// without the prefetch hook), stale serves still succeed but no
// goroutine is spawned. Otherwise enabling serve-stale would secretly
// also enable prefetch.
func TestGetStale_NoPrefetchWhenDisabled(t *testing.T) {
	c := NewCacheWithStale(1024, 60, 86400, 3600, true, 30, nil)
	// Deliberately NOT calling EnablePrefetch / SetPrefetchFunc.

	c.Store("noprefetch.example", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "noprefetch.example", Type: dns.TypeA, Class: dns.ClassIN, TTL: 1,
		RData: []byte{5, 6, 7, 8}, RDLength: 4,
	}}, nil)
	idx := c.shardIndex("noprefetch.example")
	s := &c.shards[idx]
	s.mu.Lock()
	for k, e := range s.entries {
		if k.name == "noprefetch.example" {
			e.InsertedAt = time.Now().Add(-7200 * time.Second)
			e.OrigTTL = 60
		}
	}
	s.mu.Unlock()

	// Stale serve must still succeed.
	if _, ok := c.GetStale("noprefetch.example", dns.TypeA, dns.ClassIN); !ok {
		t.Error("stale serve must work without prefetch enabled")
	}
	// No prefetchFunc to call, so nothing to count — the test is that
	// we did NOT panic / NOT block on a nil hook.
}
