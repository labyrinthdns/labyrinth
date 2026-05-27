package resolver

import (
	"sync"
	"time"
)

// serverCookieEntry stores one auth's server cookie alongside the
// timestamp it was last seen, so stale entries can be evicted under the
// LRU-style cap and TTL bounds (RFC 9018 §4.3 — cookies SHOULD have a
// short lifetime; one hour matches the operator state-machine the spec
// describes).
type serverCookieEntry struct {
	cookie []byte
	seenAt time.Time
}

// serverCookieCache is the per-IP store of recently-observed server
// cookies that backs RFC 7873 §5.3 ("a resolver SHOULD cache the most
// recently-received server cookie for each upstream"). Future outbound
// queries to that IP pre-emptively include the cached cookie, so an
// auth that enforces cookies sees a recognised client on the FIRST
// query rather than after a BADCOOKIE round-trip. Without this cache,
// every cold query to a cookie-enforcing auth pays an extra RTT.
//
// Bounded by `capacity` so a resolver with churning peers cannot grow
// unbounded; oldest-evicted-first when full, on the principle that the
// most useful cookies are the ones we are still actively using.
type serverCookieCache struct {
	mu       sync.Mutex
	entries  map[string]serverCookieEntry
	capacity int
	ttl      time.Duration
}

// newServerCookieCache constructs the cache. capacity <= 0 disables
// caching (the empty-cache behaviour is "always send client cookie
// only", which is the Y24 path; cookie persistence is the SHOULD this
// type provides on top of that). ttl <= 0 falls back to one hour per
// RFC 9018 §4.3.
func newServerCookieCache(capacity int, ttl time.Duration) *serverCookieCache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	if capacity <= 0 {
		return &serverCookieCache{capacity: 0, ttl: ttl}
	}
	return &serverCookieCache{
		entries:  make(map[string]serverCookieEntry, capacity),
		capacity: capacity,
		ttl:      ttl,
	}
}

// Get returns the cached server cookie for upstream IP, or nil if no
// fresh entry exists. Stale entries (older than ttl) are evicted on
// lookup so a long-lived resolver does not accumulate dead state.
func (c *serverCookieCache) Get(ip string) []byte {
	if c == nil || c.capacity == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[ip]
	if !ok {
		return nil
	}
	if time.Since(e.seenAt) > c.ttl {
		delete(c.entries, ip)
		return nil
	}
	out := make([]byte, len(e.cookie))
	copy(out, e.cookie)
	return out
}

// Put records (ip → cookie). Replaces any prior entry for the same IP.
// When capacity is reached, the oldest entry by seenAt is evicted so a
// pathological peer cannot crowd out actively-used cookies.
func (c *serverCookieCache) Put(ip string, cookie []byte) {
	if c == nil || c.capacity == 0 || len(cookie) == 0 {
		return
	}
	stored := make([]byte, len(cookie))
	copy(stored, cookie)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[ip]; !exists && len(c.entries) >= c.capacity {
		// Evict oldest by seenAt. Cost is O(n) but n is bounded by
		// capacity (default 1024 — well below pathological), and Put
		// fires at most once per outbound query, so even at 10k QPS
		// the eviction scan stays in the microsecond range.
		var oldestIP string
		var oldestTime time.Time
		first := true
		for k, v := range c.entries {
			if first || v.seenAt.Before(oldestTime) {
				oldestIP = k
				oldestTime = v.seenAt
				first = false
			}
		}
		delete(c.entries, oldestIP)
	}

	c.entries[ip] = serverCookieEntry{cookie: stored, seenAt: time.Now()}
}

// Len returns the current number of cached entries. Test helper.
func (c *serverCookieCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
