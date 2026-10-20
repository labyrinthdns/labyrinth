package resolver

import (
	"strconv"
	"sync"
	"time"
)

// failureCacheEntry records the outcome of a failed resolution so a
// repeated query for the same (name, type, class) returns immediately
// instead of re-traversing the broken delegation.
type failureCacheEntry struct {
	rcode         uint8
	failureReason string
	insertedAt    time.Time
	// ttl is this entry's hold time. It starts at the cache's minimum and
	// doubles each time the failure recurs (RFC 9520 §3.2 backoff).
	ttl time.Duration
}

// failureCache implements RFC 9520 (negative caching of resolution
// failures). It is intentionally orthogonal to the answer cache: the
// answer cache stores RCODEs that came WITH cryptographic proof from
// the auth chain (NXDOMAIN with NSEC, NODATA with NSEC) and may keep
// them for hours per the SOA MINIMUM field. This cache stores
// resolution failures — the resolver could not get any authoritative
// answer at all.
//
// RFC 9520 §3.2: failures are cached for at least 1 second and at most
// 5 minutes, and a persistent failure SHOULD get an exponential or
// linear backoff ("the initial time ... might be set to 5 seconds and
// increased after each retry that results in another resolution
// failure, up to a configurable maximum"). An entry starts at minTTL;
// when the name fails again within maxTTL of the entry expiring, the
// new entry holds twice as long, up to maxTTL. A success (Forget) or a
// quiet period longer than maxTTL starts the next failure at minTTL
// again, so a one-off outage still heals within minTTL.
//
// Without this cache, a broken upstream (e.g. all four NS REFUSING for
// a delegation, like the operator's 153.133.185.147.in-addr.arpa case)
// triggers a full root-down iteration on every client retry. Without
// the backoff, a client that keeps asking for a dead name (live: blog
// ping lists, www.newsisfree.com every ~6 s) pays a full iteration plus
// the public fallback once per minTTL window, forever.
type failureCache struct {
	mu       sync.Mutex
	entries  map[string]failureCacheEntry
	capacity int
	minTTL   time.Duration
	maxTTL   time.Duration
}

// failureCacheMaxTTL is the RFC 9520 §3.2 / RFC 2308 ceiling: resolution
// failures MUST NOT be cached for longer than 5 minutes.
const failureCacheMaxTTL = 5 * time.Minute

// newFailureCache constructs a cache with a fixed ttl (no backoff).
// capacity <= 0 disables the cache (Get always misses, Put is a no-op)
// so operators who prefer the legacy retry-every-time behaviour can keep
// it. ttl <= 0 falls back to 5 seconds.
func newFailureCache(capacity int, ttl time.Duration) *failureCache {
	return newFailureCacheBackoff(capacity, ttl, ttl)
}

// newFailureCacheBackoff constructs a cache whose entries start at minTTL
// and back off exponentially to maxTTL for persistent failures. minTTL
// <= 0 falls back to 5 seconds; maxTTL is raised to minTTL when smaller
// and capped at the RFC's 5 minutes.
func newFailureCacheBackoff(capacity int, minTTL, maxTTL time.Duration) *failureCache {
	if minTTL <= 0 {
		minTTL = 5 * time.Second
	}
	if maxTTL > failureCacheMaxTTL {
		maxTTL = failureCacheMaxTTL
	}
	if minTTL > maxTTL {
		maxTTL = minTTL
	}
	if capacity <= 0 {
		return &failureCache{capacity: 0, minTTL: minTTL, maxTTL: maxTTL}
	}
	return &failureCache{
		entries:  make(map[string]failureCacheEntry, capacity),
		capacity: capacity,
		minTTL:   minTTL,
		maxTTL:   maxTTL,
	}
}

// failureKey is the cache-key shape: lowercase name | qtype | qclass.
// The resolver lowercases its input before consulting the cache, so
// this is just join-with-pipe.
func failureKey(name string, qtype uint16, qclass uint16) string {
	return name + "|" + strconv.Itoa(int(qtype)) + "|" + strconv.Itoa(int(qclass))
}

// Get returns a cached failure outcome, or (false) if no fresh entry
// exists. An expired entry is kept for maxTTL past its expiry so a
// recurring failure can back off; after that it is evicted on lookup so
// a long-running resolver does not retain dead failure state.
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
	age := time.Since(e.insertedAt)
	if age > e.ttl {
		if age > e.ttl+c.maxTTL {
			delete(c.entries, key)
		}
		return 0, "", false
	}
	return e.rcode, e.failureReason, true
}

// Put records (name, qtype, qclass) → (rcode, reason). A failure that
// recurs within maxTTL of the previous entry's expiry is held twice as
// long as that entry, up to maxTTL; a Put while the previous entry is
// still fresh (concurrent requests failing together) keeps its ttl.
// When capacity is reached the oldest entry by insertedAt is evicted;
// capacity is typically large enough (4096) that this branch fires
// rarely under normal operation.
func (c *failureCache) Put(name string, qtype uint16, qclass uint16, rcode uint8, failureReason string) {
	if c == nil || c.capacity == 0 {
		return
	}
	key := failureKey(name, qtype, qclass)

	c.mu.Lock()
	defer c.mu.Unlock()

	ttl := c.minTTL
	prev, exists := c.entries[key]
	if exists {
		age := time.Since(prev.insertedAt)
		switch {
		case age <= prev.ttl:
			ttl = prev.ttl
		case age <= prev.ttl+c.maxTTL:
			ttl = min(prev.ttl*2, c.maxTTL)
		}
	}

	if !exists && len(c.entries) >= c.capacity {
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
		ttl:           ttl,
	}
}

// Forget drops the entry for (name, qtype, qclass) after a successful
// resolution, so the name's next failure starts again at minTTL.
func (c *failureCache) Forget(name string, qtype uint16, qclass uint16) {
	if c == nil || c.capacity == 0 {
		return
	}
	key := failureKey(name, qtype, qclass)
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
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
