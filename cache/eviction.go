package cache

import (
	"context"
	"time"
)

// StartSweeper runs a background goroutine that periodically evicts expired entries.
func (c *Cache) StartSweeper(ctx context.Context, interval time.Duration) {
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

	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()

		for key, entry := range s.entries {
			if entry.RemainingTTL() == 0 {
				delete(s.entries, key)
				evicted++
			}
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
