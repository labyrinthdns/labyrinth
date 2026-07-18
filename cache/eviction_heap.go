package cache

import (
	"container/heap"
	"time"
)

type evictionItem struct {
	key       cacheKey
	entry     *Entry
	expiresAt time.Time
}

type evictionQueue []evictionItem

// evictionMetadataFactor bounds lazy heap metadata relative to live entries.
// Stores intentionally append rather than search O(n) for an old key, but a
// hot key overwritten indefinitely must not grow the heap without bound.
const evictionMetadataFactor = 2

func (q evictionQueue) Len() int { return len(q) }

func (q evictionQueue) Less(i, j int) bool { return q[i].expiresAt.Before(q[j].expiresAt) }

func (q evictionQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

func (q *evictionQueue) Push(x any) {
	*q = append(*q, x.(evictionItem))
}

func (q *evictionQueue) Pop() any {
	old := *q
	n := len(old)
	item := old[n-1]
	*q = old[:n-1]
	return item
}

func (s *shard) resetEntries() {
	s.entries = make(map[cacheKey]*Entry, defaultShardMapCapacity)
	s.evictQ = make(evictionQueue, 0, defaultShardMapCapacity)
	heap.Init(&s.evictQ)
}

func (s *shard) pushEvictionEntry(key cacheKey, entry *Entry) {
	heap.Push(&s.evictQ, evictionItem{
		key:       key,
		entry:     entry,
		expiresAt: entry.InsertedAt.Add(time.Duration(entry.OrigTTL) * time.Second),
	})
	s.maybeCompactEvictionQueueLocked()
}

// maybeCompactEvictionQueueLocked rebuilds the heap from live map entries once
// lazy metadata exceeds a small multiple of live state. This keeps overwrite
// and delete-heavy workloads O(live entries) in memory while preserving cheap
// O(log n) normal stores.
func (s *shard) maybeCompactEvictionQueueLocked() {
	// Allow a small absolute cushion so normal inserts do not rebuild on
	// every other store when a shard contains only one or two entries. Empty
	// shards need no metadata at all, so release it eagerly after deletion.
	maxMetadata := len(s.entries)*evictionMetadataFactor + 16
	if len(s.entries) > 0 && len(s.evictQ) <= maxMetadata {
		return
	}
	if len(s.entries) == 0 && len(s.evictQ) == 0 {
		return
	}

	q := make(evictionQueue, 0, len(s.entries))
	for key, entry := range s.entries {
		q = append(q, evictionItem{
			key:       key,
			entry:     entry,
			expiresAt: entry.InsertedAt.Add(time.Duration(entry.OrigTTL) * time.Second),
		})
	}
	s.evictQ = q
	heap.Init(&s.evictQ)
}

func (s *shard) nextEvictionKeyLocked() (cacheKey, bool) {
	for s.evictQ.Len() > 0 {
		item := heap.Pop(&s.evictQ).(evictionItem)
		current, ok := s.entries[item.key]
		if !ok || current != item.entry {
			continue
		}
		return item.key, true
	}

	// Fallback path for tests or direct map mutations that bypass Store/StoreNegative.
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
	return evictKey, found
}

func (s *shard) evictExpiredLocked(now time.Time) int {
	evicted := 0

	for s.evictQ.Len() > 0 {
		item := s.evictQ[0]
		if item.expiresAt.After(now) {
			break
		}

		item = heap.Pop(&s.evictQ).(evictionItem)
		current, ok := s.entries[item.key]
		if !ok || current != item.entry {
			continue
		}
		if current.RemainingTTL() > 0 {
			continue
		}

		delete(s.entries, item.key)
		evicted++
	}

	return evicted
}

func (s *shard) evictExpiredFallbackLocked() int {
	evicted := 0
	for key, entry := range s.entries {
		if entry.RemainingTTL() == 0 {
			delete(s.entries, key)
			evicted++
		}
	}
	return evicted
}
