package cache

import (
	"strings"
	"sync"
	"time"

	"github.com/labyrinth-dns/labyrinth/dns"
	"github.com/labyrinth-dns/labyrinth/metrics"
)

const shardCount = 256

// Cache is a sharded in-memory DNS cache with TTL-based expiration.
type Cache struct {
	shards     [shardCount]shard
	maxEntries int
	minTTL     uint32
	maxTTL     uint32
	negMaxTTL  uint32
	serveStale bool
	staleTTL   uint32
	metrics    *metrics.Metrics
}

type shard struct {
	mu      sync.RWMutex
	entries map[cacheKey]*Entry
}

type cacheKey struct {
	name  string
	qtype uint16
	class uint16
}

// NewCache creates a new sharded DNS cache.
func NewCache(maxEntries int, minTTL, maxTTL, negMaxTTL uint32, m *metrics.Metrics) *Cache {
	return NewCacheWithStale(maxEntries, minTTL, maxTTL, negMaxTTL, false, 30, m)
}

// NewCacheWithStale creates a cache with optional serve-stale support (RFC 8767).
func NewCacheWithStale(maxEntries int, minTTL, maxTTL, negMaxTTL uint32, serveStale bool, staleTTL uint32, m *metrics.Metrics) *Cache {
	c := &Cache{
		maxEntries: maxEntries,
		minTTL:     minTTL,
		maxTTL:     maxTTL,
		negMaxTTL:  negMaxTTL,
		serveStale: serveStale,
		staleTTL:   staleTTL,
		metrics:    m,
	}
	for i := range c.shards {
		c.shards[i].entries = make(map[cacheKey]*Entry, 512)
	}
	return c
}

func (c *Cache) shardIndex(name string) uint8 {
	h := fnv32a(name)
	return uint8(h)
}

func fnv32a(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// Get retrieves an entry from the cache with TTL decay.
func (c *Cache) Get(name string, qtype uint16, class uint16) (*Entry, bool) {
	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	idx := c.shardIndex(name)

	s := &c.shards[idx]
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		return nil, false
	}

	remaining := entry.RemainingTTL()
	if remaining == 0 {
		// Don't delete expired entries if serve-stale is enabled;
		// they may still be served via GetStale on upstream failure.
		if !c.serveStale {
			s.mu.Lock()
			delete(s.entries, key)
			s.mu.Unlock()
			if c.metrics != nil {
				c.metrics.IncCacheEvictions("expired")
			}
		}
		return nil, false
	}

	decayed := entry.WithDecayedTTL(remaining)
	return decayed, true
}

// GetStale retrieves an expired entry from the cache for serve-stale (RFC 8767).
// Returns the entry with staleTTL if serve-stale is enabled and the entry exists but is expired.
func (c *Cache) GetStale(name string, qtype uint16, class uint16) (*Entry, bool) {
	if !c.serveStale {
		return nil, false
	}

	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	idx := c.shardIndex(name)

	s := &c.shards[idx]
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		return nil, false
	}

	// Only serve stale if entry is actually expired
	if entry.RemainingTTL() > 0 {
		return nil, false
	}

	// Return with stale TTL
	stale := entry.WithDecayedTTL(c.staleTTL)
	return stale, true
}

// Store caches a positive DNS result.
func (c *Cache) Store(name string, qtype uint16, class uint16, answers []dns.ResourceRecord, authority []dns.ResourceRecord) {
	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	idx := c.shardIndex(name)

	ttl := c.extractTTL(answers)
	ttl = c.clampTTL(ttl)

	entry := &Entry{
		Records:    cloneRRs(answers),
		Authority:  cloneRRs(authority),
		InsertedAt: time.Now(),
		OrigTTL:    ttl,
	}

	s := &c.shards[idx]
	s.mu.Lock()
	s.entries[key] = entry
	c.enforceMaxEntriesLocked(s)
	s.mu.Unlock()
}

// StoreNegative caches a negative DNS result (NXDOMAIN/NODATA).
func (c *Cache) StoreNegative(name string, qtype uint16, class uint16, negType NegativeType, rcode uint8, authority []dns.ResourceRecord) {
	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	idx := c.shardIndex(name)

	ttl := c.extractNegativeTTL(authority)
	ttl = c.clampNegativeTTL(ttl)

	var soa *dns.ResourceRecord
	for i, rr := range authority {
		if rr.Type == dns.TypeSOA {
			soa = &authority[i]
			break
		}
	}

	entry := &Entry{
		Authority:  cloneRRs(authority),
		InsertedAt: time.Now(),
		OrigTTL:    ttl,
		Negative:   true,
		NegType:    negType,
		SOA:        soa,
		RCODE:      rcode,
	}

	s := &c.shards[idx]
	s.mu.Lock()
	s.entries[key] = entry
	c.enforceMaxEntriesLocked(s)
	s.mu.Unlock()
}

func (c *Cache) extractTTL(records []dns.ResourceRecord) uint32 {
	if len(records) == 0 {
		return c.minTTL
	}
	minTTL := records[0].TTL
	for _, rr := range records[1:] {
		if rr.TTL < minTTL {
			minTTL = rr.TTL
		}
	}
	return minTTL
}

func (c *Cache) extractNegativeTTL(authority []dns.ResourceRecord) uint32 {
	for _, rr := range authority {
		if rr.Type == dns.TypeSOA && rr.RData != nil && len(rr.RData) > 0 {
			// RDATA is decompressed: MNAME(labels) + RNAME(labels) + 5×uint32
			// SOA.Minimum is the last uint32. Parse it properly.
			soa, err := dns.ParseSOA(rr.RData, 0)
			if err == nil {
				// RFC 2308: use min(SOA RR TTL, SOA.Minimum)
				ttl := rr.TTL
				if soa.Minimum < ttl {
					ttl = soa.Minimum
				}
				return ttl
			}
			// Fallback to RR TTL if SOA parse fails
			return rr.TTL
		}
	}
	return 60 // fallback: 1 minute
}

func (c *Cache) clampTTL(ttl uint32) uint32 {
	if ttl < c.minTTL {
		return c.minTTL
	}
	if ttl > c.maxTTL {
		return c.maxTTL
	}
	return ttl
}

func (c *Cache) clampNegativeTTL(ttl uint32) uint32 {
	if ttl < c.minTTL {
		return c.minTTL
	}
	if ttl > c.negMaxTTL {
		return c.negMaxTTL
	}
	return ttl
}

func (c *Cache) enforceMaxEntriesLocked(s *shard) {
	if c.maxEntries <= 0 {
		return
	}
	for len(s.entries) > c.maxEntries/shardCount+1 {
		// Evict entry closest to expiry
		var evictKey cacheKey
		var minRemaining uint32 = ^uint32(0)
		found := false

		for k, e := range s.entries {
			rem := e.RemainingTTL()
			if rem < minRemaining {
				minRemaining = rem
				evictKey = k
				found = true
			}
		}
		if found {
			delete(s.entries, evictKey)
			if c.metrics != nil {
				c.metrics.IncCacheEvictions("capacity")
			}
		} else {
			break
		}
	}
}

func cloneRRs(rrs []dns.ResourceRecord) []dns.ResourceRecord {
	if rrs == nil {
		return nil
	}
	cloned := make([]dns.ResourceRecord, len(rrs))
	copy(cloned, rrs)
	for i, rr := range cloned {
		if rr.RData != nil {
			cloned[i].RData = make([]byte, len(rr.RData))
			copy(cloned[i].RData, rr.RData)
		}
	}
	return cloned
}
