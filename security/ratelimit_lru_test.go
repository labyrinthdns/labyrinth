package security

import (
	"container/heap"
	"testing"
	"time"
)

// MaxRateLimiterClients documents that Allow "evicts the OLDEST (least
// recently used) bucket to make room for the new client" and that the eviction
// heap is a "min-heap of (ip, lastTime) pairs ... to find the least-recently-
// used entry in O(log n)". The heap node is a separate struct from the map's
// tokenBucket, so the bucket's lastTime and the heap node's lastTime have to be
// advanced together — otherwise the heap silently degrades to first-connection
// order and the cap drops the busiest clients first.
//
// RRL in this package already pairs the two (see RRL.AllowResponse) and
// TestRRL_EvictionHeapRefreshesExistingEntry pins it; these tests pin the same
// invariant for RateLimiter, where it was missing.
//
// Only the ORDER of the lastTime values matters below, never their magnitude,
// so the 5 ms gaps between steps make the ordering unambiguous without making
// the result depend on machine speed.

func rlLRUTest(rate float64, burst, max int) *RateLimiter {
	rl := NewRateLimiter(rate, burst)
	rl.maxClients = max // test-only override of the 1M production cap
	return rl
}

// allowAt admits clientIP, asserting it was allowed, then advances the clock
// far enough that the next call gets a strictly newer lastTime.
func allowAt(t *testing.T, rl *RateLimiter, clientIP string) {
	t.Helper()
	if !rl.Allow(clientIP) {
		t.Fatalf("setup: first request from %s was rate limited", clientIP)
	}
	time.Sleep(5 * time.Millisecond)
}

func clientTracked(rl *RateLimiter, clientIP string) bool {
	_, ok := rl.clients[clientIP]
	return ok
}

// The busiest client must not be the eviction victim just because it happened
// to connect first.
func TestRateLimiterCapEvictsLeastRecentlyUsed(t *testing.T) {
	rl := rlLRUTest(1, 2, 2)

	// 10.0.0.1 connects first.
	allowAt(t, rl, "10.0.0.1")
	// 10.0.0.2 connects second and is never used again.
	allowAt(t, rl, "10.0.0.2")

	// 10.0.0.1 keeps querying, so it is now the most recently used client.
	if !rl.Allow("10.0.0.1") {
		t.Fatal("setup: established client 10.0.0.1 was rate limited")
	}
	time.Sleep(5 * time.Millisecond)

	// The cap is reached, so admitting 10.0.0.3 forces an eviction.
	allowAt(t, rl, "10.0.0.3")

	if !clientTracked(rl, "10.0.0.1") {
		t.Error("10.0.0.1 was evicted even though it is the most recently used client; " +
			"eviction follows first-connection order instead of least-recently-used " +
			"as documented at MaxRateLimiterClients")
	}
	if clientTracked(rl, "10.0.0.2") {
		t.Error("10.0.0.2 survived eviction although it has been idle since it first arrived")
	}
}

// Boundary: with no refresh at all, first-seen order and least-recently-used
// order agree, so the oldest client is evicted either way. Guards against a fix
// that simply stops evicting or evicts the wrong end of the heap.
func TestRateLimiterCapEvictsOldestWhenOrderAgrees(t *testing.T) {
	rl := rlLRUTest(1, 2, 2)

	allowAt(t, rl, "10.0.0.1")
	allowAt(t, rl, "10.0.0.2")
	allowAt(t, rl, "10.0.0.3")

	if clientTracked(rl, "10.0.0.1") {
		t.Error("10.0.0.1 was the least recently used client and should have been evicted")
	}
	if !clientTracked(rl, "10.0.0.2") || !clientTracked(rl, "10.0.0.3") {
		t.Error("a newer client was evicted instead of the least recently used one")
	}
}

// The cap must keep bounding the map, and evicting a different client must not
// hand the surviving client a fresh full burst.
func TestRateLimiterCapBoundsMapAndKeepsBusyBudget(t *testing.T) {
	rl := rlLRUTest(1, 2, 2)

	allowAt(t, rl, "10.0.0.1")
	allowAt(t, rl, "10.0.0.2")
	// Spend 10.0.0.1's whole burst so its budget state is observable.
	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.1")
	if rl.Allow("10.0.0.1") {
		t.Fatal("setup: 10.0.0.1 still had tokens after exhausting its burst")
	}
	allowAt(t, rl, "10.0.0.3")

	if n := len(rl.clients); n > 2 {
		t.Errorf("client map holds %d entries, cap is 2", n)
	}
	if !clientTracked(rl, "10.0.0.1") {
		t.Fatal("10.0.0.1 was evicted while it was the only active client")
	}
	if rl.Allow("10.0.0.1") {
		t.Error("10.0.0.1 regained a full burst after another client was admitted; " +
			"its accumulated budget must survive the eviction of a different client")
	}
}

// Every tracked client must keep a usable handle on its own heap node, or the
// heap silently stops tracking the map and refreshHeapEntryLocked turns into a
// no-op. Checks the invariant across both ways an entry enters the heap: the
// push in Allow, and the rebuild inside evictOldestLocked.
//
// The rebuild path is reached in production when the stale-skip loop in
// evictOldestLocked drains every node whose IP is no longer in the map — the
// heap empties while live clients remain, and the next eviction rebuilds it
// from the map. Draining the heap directly reproduces exactly that state.
func TestRateLimiterHeapNodesStayWiredToBuckets(t *testing.T) {
	rl := rlLRUTest(1, 2, 3)

	allowAt(t, rl, "10.0.0.1")
	allowAt(t, rl, "10.0.0.2")
	allowAt(t, rl, "10.0.0.3")

	// Simulate the stale-skip drain: nodes whose IP left the map are popped
	// and skipped, leaving the heap empty with live clients still tracked.
	for rl.evictHeap.Len() > 0 {
		heap.Pop(rl.evictHeap)
	}

	// Admitting a new client hits the cap, so evictOldestLocked takes the
	// rebuild-from-map branch.
	allowAt(t, rl, "10.0.0.4")

	if rl.evictHeap.Len() == 0 {
		t.Fatal("heap is empty after the rebuild path ran")
	}
	for ip, tb := range rl.clients {
		if tb.entry == nil {
			t.Errorf("%s has no eviction heap node wired", ip)
			continue
		}
		idx := tb.entry.index
		if idx < 0 || idx >= rl.evictHeap.Len() || (*rl.evictHeap)[idx] != tb.entry {
			t.Errorf("%s heap node index %d does not point at its own entry", ip, idx)
		}
		if tb.entry.lastTime != tb.lastTime {
			t.Errorf("%s heap node lastTime %v is out of sync with bucket lastTime %v",
				ip, tb.entry.lastTime, tb.lastTime)
		}
	}
}
