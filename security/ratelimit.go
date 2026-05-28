package security

import (
	"context"
	"sync"
	"time"
)

// MaxRateLimiterClients caps the number of distinct client IPs the
// per-IP rate limiter will track at once. Before v0.7.65 the map
// grew without bound: an attacker spoofing UDP source IPs can send
// DNS queries from millions of distinct apparent sources from a
// single host, and each unique IP lazily creates a tokenBucket
// entry. The cleanup tick runs every 5 minutes (StartCleanup) and
// only evicts entries idle for longer than the cleanup window —
// between ticks the map can grow into resolver RAM. 1M tracked
// clients is far above any realistic legitimate population (even a
// busy ISP-side resolver sees tens of thousands of concurrent
// distinct clients) and small enough that the worst-case footprint
// stays bounded to a few hundred MB. When the cap is reached,
// Allow evicts the OLDEST (least recently used) bucket to make room
// for the new client. Eviction does not degrade security: an
// attacker who can already spoof unlimited distinct source IPs
// already gets fresh per-IP budget on every request; the cap only
// closes the memory growth, not the per-IP isolation.
const MaxRateLimiterClients = 1_000_000

// RateLimiter implements per-IP token bucket rate limiting.
type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]*tokenBucket
	rate    float64
	burst   int
	cleanup time.Duration
	// maxClients overrides MaxRateLimiterClients for tests. Zero
	// means use the package-level cap; nonzero is a smaller test
	// cap so the cap-enforced eviction can be exercised without
	// allocating a million entries up-front.
	maxClients int
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

// NewRateLimiter creates a new per-IP rate limiter.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		clients: make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
		cleanup: 5 * time.Minute,
	}
}

// evictOldestLocked drops the bucket with the oldest lastTime to make
// room for a new insert. Caller holds rl.mu. O(n) over the map; only
// runs on cache miss after the cap is reached.
func (rl *RateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range rl.clients {
		if first || v.lastTime.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.lastTime
			first = false
		}
	}
	if oldestKey != "" {
		delete(rl.clients, oldestKey)
	}
}

// Allow checks if a request from clientIP should be allowed.
func (rl *RateLimiter) Allow(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	tb, ok := rl.clients[clientIP]
	if !ok {
		// Bounded eviction. See MaxRateLimiterClients for rationale.
		cap := rl.maxClients
		if cap == 0 {
			cap = MaxRateLimiterClients
		}
		if len(rl.clients) >= cap {
			rl.evictOldestLocked()
		}
		rl.clients[clientIP] = &tokenBucket{
			tokens:   float64(rl.burst) - 1,
			lastTime: now,
		}
		return true
	}

	// Refill tokens
	elapsed := now.Sub(tb.lastTime).Seconds()
	tb.tokens += elapsed * rl.rate
	if tb.tokens > float64(rl.burst) {
		tb.tokens = float64(rl.burst)
	}
	tb.lastTime = now

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}

	return false
}

// StartCleanup removes idle clients periodically.
func (rl *RateLimiter) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-rl.cleanup)
			for ip, tb := range rl.clients {
				if tb.lastTime.Before(cutoff) {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}
