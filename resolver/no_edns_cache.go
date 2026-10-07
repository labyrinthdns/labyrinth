package resolver

import (
	"sync"
	"time"
)

// noEDNSCache is a bounded, TTL-limited set of upstream IPs confirmed to
// reject EDNS queries (RFC 6891 §7 FORMERR, confirmed by a second query). Nil-safe:
// a resolver built without one simply never skips EDNS.
type noEDNSCache struct {
	mu       sync.Mutex
	entries  map[string]time.Time
	capacity int
	ttl      time.Duration
}

func newNoEDNSCache(capacity int, ttl time.Duration) *noEDNSCache {
	return &noEDNSCache{
		entries:  make(map[string]time.Time, capacity),
		capacity: capacity,
		ttl:      ttl,
	}
}

// Has reports whether ip has a fresh entry, evicting it when expired.
func (c *noEDNSCache) Has(ip string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seen, ok := c.entries[ip]
	if !ok {
		return false
	}
	if time.Since(seen) > c.ttl {
		delete(c.entries, ip)
		return false
	}
	return true
}

// Put records ip, evicting the oldest entry when the cache is full.
func (c *noEDNSCache) Put(ip string) {
	if c == nil || c.capacity <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[ip]; !exists && len(c.entries) >= c.capacity {
		var oldestIP string
		var oldest time.Time
		first := true
		for k, v := range c.entries {
			if first || v.Before(oldest) {
				oldestIP, oldest, first = k, v, false
			}
		}
		delete(c.entries, oldestIP)
	}
	c.entries[ip] = time.Now()
}
