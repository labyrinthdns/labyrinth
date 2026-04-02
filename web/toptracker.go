package web

import (
	"sort"
	"sync"
)

// TopEntry represents a single entry in a top-N leaderboard.
type TopEntry struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// TopTracker is a concurrent top-N tracker that counts occurrences of string keys.
type TopTracker struct {
	mu     sync.Mutex
	counts map[string]int64
	limit  int
}

// NewTopTracker creates a new TopTracker with the given limit.
func NewTopTracker(limit int) *TopTracker {
	if limit <= 0 {
		limit = 20
	}
	return &TopTracker{
		counts: make(map[string]int64),
		limit:  limit,
	}
}

// Inc increments the count for the given key.
// If the map exceeds limit*10, low-count entries are pruned.
func (t *TopTracker) Inc(key string) {
	t.mu.Lock()
	t.counts[key]++
	if len(t.counts) > t.limit*10 {
		t.prune()
	}
	t.mu.Unlock()
}

// prune removes low-count entries to keep the map size manageable.
// Must be called with t.mu held.
func (t *TopTracker) prune() {
	entries := make([]TopEntry, 0, len(t.counts))
	for k, v := range t.counts {
		entries = append(entries, TopEntry{Key: k, Count: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	// Keep only the top limit*2 entries
	keep := t.limit * 2
	if keep > len(entries) {
		keep = len(entries)
	}

	t.counts = make(map[string]int64, keep)
	for i := 0; i < keep; i++ {
		t.counts[entries[i].Key] = entries[i].Count
	}
}

// Top returns the top N entries sorted descending by count.
func (t *TopTracker) Top(n int) []TopEntry {
	t.mu.Lock()
	entries := make([]TopEntry, 0, len(t.counts))
	for k, v := range t.counts {
		entries = append(entries, TopEntry{Key: k, Count: v})
	}
	t.mu.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	if n > len(entries) {
		n = len(entries)
	}
	return entries[:n]
}
