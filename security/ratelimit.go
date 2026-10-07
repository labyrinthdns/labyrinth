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
	// The heap only ever holds *evictHeapEntry; comma-ok documents that.
	entry, _ := x.(*evictHeapEntry)
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
	// entry is this bucket's node in evictHeap. The heap node is a separate
	// struct with its own lastTime copy, so advancing lastTime here leaves
	// the heap stale unless refreshHeapEntryLocked re-sinks the node.
	entry *evictHeapEntry
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
			tb.entry = &evictHeapEntry{ip: ip, lastTime: tb.lastTime}
			heap.Push(rl.evictHeap, tb.entry)
		}
	}
	for rl.evictHeap.Len() > 0 {
		he, _ := heap.Pop(rl.evictHeap).(*evictHeapEntry)
		if _, exists := rl.clients[he.ip]; exists {
			delete(rl.clients, he.ip)
			return
		}
		// Stale entry (already evicted by cleanup tick). Skip and
		// continue — the heap may have accumulated stale entries
		// between cleanup cycles.
	}
}

// refreshHeapEntryLocked re-sinks tb's eviction heap node after tb.lastTime
// advanced, so evictOldestLocked keeps honouring the least-recently-used
// contract documented at MaxRateLimiterClients. The heap node is a distinct
// struct from the map's tokenBucket, so updating tb.lastTime alone leaves the
// heap ordered by first-seen time — the same reason RRL.AllowResponse pairs
// entry.lastTime = now with heap.Fix (see RRL.AllowResponse).
//
// Caller holds rl.mu. The identity check degrades a desynchronised bucket to a
// no-op rather than letting heap.Fix panic on the request path.
func (rl *RateLimiter) refreshHeapEntryLocked(tb *tokenBucket) {
	if rl.evictHeap == nil || tb.entry == nil {
		return
	}
	idx := tb.entry.index
	if idx < 0 || idx >= rl.evictHeap.Len() || (*rl.evictHeap)[idx] != tb.entry {
		return
	}
	tb.entry.lastTime = tb.lastTime
	heap.Fix(rl.evictHeap, idx)
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
		tb := &tokenBucket{
			tokens:   float64(rl.burst) - 1,
			lastTime: now,
		}
		rl.clients[clientIP] = tb
		// Push to the eviction heap so future cap-evictions can find
		// this entry in O(log n). Lazy-initialise if this is the
		// very first client.
		if rl.evictHeap == nil {
			h := make(evictHeap, 0, cap)
			rl.evictHeap = &h
		}
		tb.entry = &evictHeapEntry{ip: clientIP, lastTime: now}
		heap.Push(rl.evictHeap, tb.entry)
		return true
	}

	// Refill tokens
	elapsed := now.Sub(tb.lastTime).Seconds()
	tb.tokens += elapsed * rl.rate
	if tb.tokens > float64(rl.burst) {
		tb.tokens = float64(rl.burst)
	}
	tb.lastTime = now
	// The bucket just became the most recently used client, so its eviction
	// heap node has to follow — otherwise the heap keeps ordering by
	// first-seen time and the cap drops the busiest clients first.
	rl.refreshHeapEntryLocked(tb)

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
					tb.entry = &evictHeapEntry{ip: ip, lastTime: tb.lastTime}
					heap.Push(&h, tb.entry)
				}
				rl.evictHeap = &h
			}
			rl.mu.Unlock()
		}
	}
}
