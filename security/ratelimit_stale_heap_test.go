package security

import (
	"testing"
	"time"
)

// The cleanup tick deletes idle buckets from the map but leaves their eviction
// heap nodes behind. When such an IP comes back it gets a fresh bucket and a
// fresh heap node, so the heap then holds two nodes naming the same IP. The
// older, stale node sorts first; eviction must recognise it as stale by node
// identity rather than by "the IP is in the map", or it deletes the client's
// live — most recently used — bucket instead of the least recently used one.

// rlSetLastTime pins a bucket's lastTime (and its heap node) so the test
// controls LRU order without depending on clock resolution.
func rlSetLastTime(rl *RateLimiter, clientIP string, at time.Time) {
	tb := rl.clients[clientIP]
	tb.lastTime = at
	rl.refreshHeapEntryLocked(tb)
}

// rlDropIdle reproduces the cleanup tick's map deletion for one client, which
// leaves the client's heap node in place.
func rlDropIdle(rl *RateLimiter, clientIP string) {
	delete(rl.clients, clientIP)
}

func TestRateLimiterCapIgnoresStaleHeapNodeOfReturningClient(t *testing.T) {
	rl := rlLRUTest(1, 5, 3)
	base := time.Now().Add(-time.Hour)

	rl.Allow("10.0.0.9")
	rlSetLastTime(rl, "10.0.0.9", base)
	rlDropIdle(rl, "10.0.0.9") // idle → removed by cleanup, heap node stays

	rl.Allow("10.0.0.1")
	rlSetLastTime(rl, "10.0.0.1", base.Add(1*time.Minute))
	rl.Allow("10.0.0.2")
	rlSetLastTime(rl, "10.0.0.2", base.Add(2*time.Minute))
	rl.Allow("10.0.0.9") // returns: newest bucket
	rlSetLastTime(rl, "10.0.0.9", base.Add(3*time.Minute))

	rl.Allow("10.0.0.77") // cap reached

	if !clientTracked(rl, "10.0.0.9") {
		t.Fatal("returning client 10.0.0.9 (most recently used) was evicted via its stale heap node")
	}
	if clientTracked(rl, "10.0.0.1") {
		t.Fatal("least recently used client 10.0.0.1 survived the cap eviction")
	}
	if len(rl.clients) != 3 {
		t.Fatalf("tracked clients = %d, want cap 3", len(rl.clients))
	}
}

func TestRateLimiterCapSkipsRepeatedStaleNodesForSameClient(t *testing.T) {
	rl := rlLRUTest(1, 5, 3)
	base := time.Now().Add(-time.Hour)

	// The same client cycles through cleanup twice, leaving two stale nodes.
	for i := 0; i < 2; i++ {
		rl.Allow("10.0.0.9")
		rlSetLastTime(rl, "10.0.0.9", base.Add(time.Duration(i)*time.Second))
		rlDropIdle(rl, "10.0.0.9")
	}
	rl.Allow("10.0.0.1")
	rlSetLastTime(rl, "10.0.0.1", base.Add(1*time.Minute))
	rl.Allow("10.0.0.2")
	rlSetLastTime(rl, "10.0.0.2", base.Add(2*time.Minute))
	rl.Allow("10.0.0.9")
	rlSetLastTime(rl, "10.0.0.9", base.Add(3*time.Minute))

	for i, ip := range []string{"10.0.0.77", "10.0.0.78"} {
		rl.Allow(ip)
		rlSetLastTime(rl, ip, base.Add(time.Duration(4+i)*time.Minute))
	}

	// LRU order: .1 then .2 evicted; .9 and the two newcomers remain.
	for _, ip := range []string{"10.0.0.9", "10.0.0.77", "10.0.0.78"} {
		if !clientTracked(rl, ip) {
			t.Fatalf("%s evicted out of LRU order", ip)
		}
	}
	if len(rl.clients) != 3 {
		t.Fatalf("tracked clients = %d, want cap 3", len(rl.clients))
	}
}
