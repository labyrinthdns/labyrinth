package resolver

import (
	"strconv"
	"sync"
	"time"
)

// failureCacheEntry records the outcome of a failed resolution so a
// repeated query for the same (name, type, class) returns immediately
// instead of re-traversing the broken delegation. RFC 9520 §4 sets the
// recommended TTL at 1–5 seconds — short enough that genuine transient
// failures heal quickly, long enough that a downstream client retry
// loop does not stampede the broken auth.
type failureCacheEntry struct {
	rcode         uint8
	failureReason string
	insertedAt    time.Time
}

// failureCache implements RFC 9520 (negative caching of resolution
// failures). It is intentionally orthogonal to the answer cache: the
// answer cache stores RCODEs that came WITH cryptographic proof from
// the auth chain (NXDOMAIN with NSEC, NODATA with NSEC) and may keep
// them for hours per the SOA MINIMUM field. This cache stores
// resolution failures — the resolver could not get any authoritative
// answer at all — and keeps them for at most a few seconds so a
// flapping auth recovers quickly.
//
// Without this cache, a broken upstream (e.g. all four NS REFUSING for
// a delegation, like the operator's 153.133.185.147.in-addr.arpa case)
// triggers a full root-down iteration on every client retry. With it,
// the resolver pays the cost once per `ttl` window.
type failureCache struct {
	mu       sync.Mutex
	entries  map[string]failureCacheEntry
	capacity int
	ttl      time.Duration
}

// newFailureCache constructs the cache. capacity <= 0 disables the
// cache (Get always misses, Put is a no-op) so operators who prefer
// the legacy retry-every-time behaviour can keep it. ttl <= 0 falls
// back to the RFC 9520 §4 upper bound of 5 seconds.
func newFailureCache(capacity int, ttl time.Duration) *failureCache {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	if capacity <= 0 {
		return &failureCache{capacity: 0, ttl: ttl}
	}
	return &failureCache{
		entries:  make(map[string]failureCacheEntry, capacity),
		capacity: capacity,
		ttl:      ttl,
	}
}

// failureKey is the cache-key shape: lowercase name | qtype | qclass.
// The resolver lowercases its input before consulting the cache, so
// this is just join-with-pipe.
func failureKey(name string, qtype uint16, qclass uint16) string {
	return name + "|" + strconv.Itoa(int(qtype)) + "|" + strconv.Itoa(int(qclass))
}

// Get returns a cached failure outcome, or (false) if no fresh entry
// exists. Stale entries are evicted on lookup so a long-running
// resolver does not retain dead failure state.
func (c *failureCache) Get(name string, qtype uint16, qclass uint16) (uint8, string, bool) {
	if c == nil || c.capacity == 0 {
		return 0, "", false
	}
	key := failureKey(name, qtype, qclass)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return 0, "", false
	}
	if time.Since(e.insertedAt) > c.ttl {
		delete(c.entries, key)
		return 0, "", false
	}
	return e.rcode, e.failureReason, true
}

// Put records (name, qtype, qclass) → (rcode, reason). When capacity
// is reached the oldest entry by insertedAt is evicted; capacity is
// typically large enough (4096) that this branch fires rarely under
// normal operation.
func (c *failureCache) Put(name string, qtype uint16, qclass uint16, rcode uint8, failureReason string) {
	if c == nil || c.capacity == 0 {
		return
	}
	key := failureKey(name, qtype, qclass)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.capacity {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range c.entries {
			if first || v.insertedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.insertedAt
				first = false
			}
		}
		delete(c.entries, oldestKey)
	}

	c.entries[key] = failureCacheEntry{
		rcode:         rcode,
		failureReason: failureReason,
		insertedAt:    time.Now(),
	}
}

// Len returns the current entry count. Test helper.
func (c *failureCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
