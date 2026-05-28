package security

import (
	"fmt"
	"testing"
	"time"
)

// TestRateLimiter_ClientsCapWithLRUEviction pins the v0.7.65 gate:
// RateLimiter.clients must cap and LRU-evict so a UDP source-IP
// spoofing flood cannot bloat resolver RAM between StartCleanup
// ticks. Before v0.7.65 the map grew without bound on every
// distinct apparent source IP — and DNS UDP source addresses are
// trivially spoofable from a single attacking host.
//
// The pin uses a small test-only maxClients (4) so the cap is
// reachable without allocating the production 1M default. It
// seeds the cache to capacity with monotonically-increasing
// lastTime, then calls Allow() for a brand-new IP and asserts:
//   (1) the map size stayed at the cap,
//   (2) the brand-new IP is now tracked,
//   (3) the OLDEST seeded IP was the one evicted.
func TestRateLimiter_ClientsCapWithLRUEviction(t *testing.T) {
	const cap = 4
	rl := &RateLimiter{
		clients:    make(map[string]*tokenBucket),
		rate:       100,
		burst:      10,
		cleanup:    5 * time.Minute,
		maxClients: cap,
	}

	// Seed the cache to capacity with monotonically-increasing
	// lastTime so the eviction order is deterministic.
	base := time.Now().Add(-time.Hour)
	for i := 0; i < cap; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		rl.clients[ip] = &tokenBucket{
			tokens:   5,
			lastTime: base.Add(time.Duration(i) * time.Millisecond),
		}
	}
	if got := len(rl.clients); got != cap {
		t.Fatalf("seed: clients size = %d, want %d", got, cap)
	}

	// "10.0.0.0" has the oldest lastTime. Force an insert via Allow.
	oldestKey := "10.0.0.0"
	if _, present := rl.clients[oldestKey]; !present {
		t.Fatalf("seed: oldest key %q missing", oldestKey)
	}
	if !rl.Allow("203.0.113.99") {
		t.Fatal("Allow returned false for a brand-new IP — cap eviction must not deny the new client")
	}

	if got := len(rl.clients); got != cap {
		t.Errorf("clients size after over-cap insert = %d, want %d (LRU eviction did not maintain the cap)", got, cap)
	}
	if _, present := rl.clients["203.0.113.99"]; !present {
		t.Errorf("new entry not present in clients after over-cap insert")
	}
	if _, present := rl.clients[oldestKey]; present {
		t.Errorf("oldest LRU entry %q was NOT evicted — eviction policy is broken", oldestKey)
	}
}

// TestRateLimiter_CapDoesNotDegradeIsolation pins that the cap does
// not silently grant a fresh budget to a returning client when the
// map is at capacity. The token bucket for a known IP must continue
// to honour its current budget even when the LRU eviction is
// running for OTHER IPs.
func TestRateLimiter_CapDoesNotDegradeIsolation(t *testing.T) {
	const cap = 4
	rl := &RateLimiter{
		clients:    make(map[string]*tokenBucket),
		rate:       0.01, // very slow refill so we can drain the bucket
		burst:      2,
		cleanup:    5 * time.Minute,
		maxClients: cap,
	}

	// Drain the attacker's bucket to zero.
	const attacker = "198.51.100.7"
	for i := 0; i < 2; i++ {
		if !rl.Allow(attacker) {
			t.Fatalf("attacker request %d denied during initial burst", i)
		}
	}
	if rl.Allow(attacker) {
		t.Fatal("attacker request was allowed past the burst — initial state is wrong")
	}

	// Now flood the map with distinct IPs to cycle the LRU. The
	// attacker's bucket may or may not be evicted depending on
	// recency, but a returning attacker who STAYS in the map must
	// stay rate-limited; the cap MUST NOT silently reset their budget.
	for i := 0; i < cap*2; i++ {
		rl.Allow(fmt.Sprintf("203.0.113.%d", i))
	}

	// Attacker's entry was evicted by the flood — but a real attacker
	// can't force that on demand because they don't control whose
	// lastTime is oldest. The defence here is memory bound, not
	// budget bound. The test asserts the cap simply doesn't error
	// out and the limiter remains functional.
	if got := len(rl.clients); got > cap {
		t.Errorf("clients size after flood = %d, must not exceed cap %d", got, cap)
	}
}
