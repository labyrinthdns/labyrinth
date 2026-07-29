package cache

import (
	"context"
	"time"
)

// MinSweepInterval is the floor StartSweeper applies to its interval
// argument. time.NewTicker(0) panics, so a YAML cache.sweep_interval: 0
// (or a /api/config/raw PUT that planted a zero value) would crash the
// resolver at boot. 10 ms is just above the panic threshold and well
// below any legitimate operator setting (the default is 60 s); kept
// low to avoid disturbing existing fast-tick tests that pass sub-second
// intervals deliberately.
const MinSweepInterval = 10 * time.Millisecond

// StartSweeper runs a background goroutine that periodically evicts expired entries.
// Floors interval at MinSweepInterval so a bad config never crashes the sweeper.
func (c *Cache) StartSweeper(ctx context.Context, interval time.Duration) {
	if interval < MinSweepInterval {
		interval = MinSweepInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sweep()
		}
	}
}

func (c *Cache) sweep() {
	evicted := 0
	now := time.Now()

	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		evicted += s.evictExpiredLocked(now)
		if len(s.entries) > 0 && s.evictQ.Len() == 0 {
			// Compatibility path for entries inserted without queue metadata.
			evicted += s.evictExpiredFallbackLocked()
		}

		s.mu.Unlock()
	}

	if evicted > 0 && c.metrics != nil {
		c.metrics.AddCacheEvictions("sweep", evicted)
	}
}

// Flush clears all cache entries.
func (c *Cache) Flush() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.resetEntries()
		s.mu.Unlock()
	}
}

// CacheStats holds cache statistics.
type CacheStats struct {
	Entries         int
	PositiveEntries int
	NegativeEntries int
}

// Stats returns current cache statistics.
func (c *Cache) Stats() CacheStats {
	var total int
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		total += len(s.entries)
		s.mu.RUnlock()
	}
	return CacheStats{Entries: total}
}

// DetailedStats returns detailed cache statistics including positive/negative breakdowns.
func (c *Cache) DetailedStats() CacheStats {
	var total, positive, negative int
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		for _, entry := range s.entries {
			total++
			if entry.Negative {
				negative++
			} else {
				positive++
			}
		}
		s.mu.RUnlock()
	}
	return CacheStats{
		Entries:         total,
		PositiveEntries: positive,
		NegativeEntries: negative,
	}
}
