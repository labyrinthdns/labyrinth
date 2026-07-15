package security

import (
	"container/heap"
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

// evictHeapEntry tracks an IP and its lastTime for the eviction min-heap.
// container/heap maintains the index field for Fix operations.
type evictHeapEntry struct {
	ip       string
	lastTime time.Time
	index    int
}

// evictHeap implements heap.Interface as a min-heap ordered by lastTime.
// Used alongside map[string]*tokenBucket so evictOldestLocked can find
// the least-recently-used entry in O(log n) instead of O(n).
type evictHeap []*evictHeapEntry

func (h evictHeap) Len() int           { return len(h) }
func (h evictHeap) Less(i, j int) bool { return h[i].lastTime.Before(h[j].lastTime) }
func (h evictHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *evictHeap) Push(x interface{}) {
	n := len(*h)
	entry := x.(*evictHeapEntry)
	entry.index = n
	*h = append(*h, entry)
}
func (h *evictHeap) Pop() interface{} {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	entry.index = -1
	*h = old[0 : n-1]
	return entry
}

// RateLimiter implements per-IP token bucket rate limiting.
type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]*tokenBucket
	// evictHeap is a min-heap of (ip, lastTime) pairs for O(log n)
	// eviction of the oldest entry when the client cap is reached.
	// Lazy-initialised; entries may become stale when the cleanup tick
	// removes map entries — evictOldestLocked skips stale heap entries.
	evictHeap *evictHeap
	rate      float64
	burst     int
	cleanup   time.Duration
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

// evictOldestLocked drops the entry with the oldest lastTime using the
// eviction min-heap (O(log n)). When the heap is empty (first call, or
// after a cleanup-tick drained all entries) it rebuilds from the map.
// Caller holds rl.mu.
func (rl *RateLimiter) evictOldestLocked() {
	if rl.evictHeap == nil || rl.evictHeap.Len() == 0 {
		// First eviction or heap exhausted: rebuild from map.
		h := make(evictHeap, 0, len(rl.clients))
		rl.evictHeap = &h
		for ip, tb := range rl.clients {
			heap.Push(rl.evictHeap, &evictHeapEntry{ip: ip, lastTime: tb.lastTime})
		}
	}
	for rl.evictHeap.Len() > 0 {
		he := heap.Pop(rl.evictHeap).(*evictHeapEntry)
		if _, exists := rl.clients[he.ip]; exists {
			delete(rl.clients, he.ip)
			return
		}
		// Stale entry (already evicted by cleanup tick). Skip and
		// continue — the heap may have accumulated stale entries
		// between cleanup cycles.
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
		// Push to the eviction heap so future cap-evictions can find
		// this entry in O(log n). Lazy-initialise if this is the
		// very first client.
		if rl.evictHeap == nil {
			h := make(evictHeap, 0, cap)
			rl.evictHeap = &h
		}
		heap.Push(rl.evictHeap, &evictHeapEntry{ip: clientIP, lastTime: now})
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
			// Trim stale heap entries when they significantly
			// outnumber live map entries. The heap accumulates
			// stale entries (cleaned from the map but still in
			// the heap) between cleanup cycles; rebuild keeps
			// the heap size proportional to the map.
			if rl.evictHeap != nil && rl.evictHeap.Len() > len(rl.clients)*2+1 {
				h := make(evictHeap, 0, len(rl.clients))
				for ip, tb := range rl.clients {
					heap.Push(&h, &evictHeapEntry{ip: ip, lastTime: tb.lastTime})
				}
				rl.evictHeap = &h
			}
			rl.mu.Unlock()
		}
	}
}
