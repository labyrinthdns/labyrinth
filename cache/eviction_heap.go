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
