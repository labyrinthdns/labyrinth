package cache

import (
	"testing"
	"time"
)

func TestShardResetEntriesAndQueueHelpers(t *testing.T) {
	s := &shard{}
	s.resetEntries()

	if s.entries == nil {
		t.Fatalf("resetEntries should initialize entries map")
	}
	if s.evictQ == nil {
		t.Fatalf("resetEntries should initialize eviction queue")
	}
	if s.evictQ.Len() != 0 {
		t.Fatalf("new eviction queue should be empty")
	}
}

func TestNextEvictionKeyLocked_SkipsStaleQueueEntries(t *testing.T) {
	s := &shard{}
	s.resetEntries()

	k1 := cacheKey{name: "one", qtype: 1, class: 1}
	k2 := cacheKey{name: "two", qtype: 1, class: 1}

	now := time.Now()
	e1 := &Entry{InsertedAt: now.Add(-10 * time.Second), OrigTTL: 15}
	e2 := &Entry{InsertedAt: now.Add(-2 * time.Second), OrigTTL: 15}

	s.entries[k1] = e1
	s.entries[k2] = e2
	s.pushEvictionEntry(k1, e1)
	s.pushEvictionEntry(k2, e2)

	// Make first queue entry stale by replacing map pointer.
	s.entries[k1] = &Entry{InsertedAt: e1.InsertedAt, OrigTTL: e1.OrigTTL}

	got, ok := s.nextEvictionKeyLocked()
	if !ok {
		t.Fatalf("expected an eviction key")
	}
	if got != k2 {
		t.Fatalf("expected stale queue entry to be skipped; got %#v want %#v", got, k2)
	}
}

func TestNextEvictionKeyLocked_FallbackMapScan(t *testing.T) {
	s := &shard{}
	s.resetEntries()

	k1 := cacheKey{name: "earliest", qtype: 1, class: 1}
	k2 := cacheKey{name: "later", qtype: 1, class: 1}

	now := time.Now()
	s.entries[k1] = &Entry{InsertedAt: now.Add(-6 * time.Second), OrigTTL: 10}
	s.entries[k2] = &Entry{InsertedAt: now.Add(-1 * time.Second), OrigTTL: 10}

	// Empty queue forces fallback map scan.
	s.evictQ = s.evictQ[:0]

	got, ok := s.nextEvictionKeyLocked()
	if !ok {
		t.Fatalf("expected key from fallback scan")
	}
	if got != k1 {
		t.Fatalf("expected key with smallest remaining TTL; got %#v want %#v", got, k1)
	}

	s.entries = map[cacheKey]*Entry{}
	_, ok = s.nextEvictionKeyLocked()
	if ok {
		t.Fatalf("expected no key when entries map is empty")
	}
}

func TestEvictExpiredLocked_UsesHeapOrdering(t *testing.T) {
	s := &shard{}
	s.resetEntries()

	now := time.Now()
	expiredKey := cacheKey{name: "expired", qtype: 1, class: 1}
	freshKey := cacheKey{name: "fresh", qtype: 1, class: 1}

	expired := &Entry{InsertedAt: now.Add(-10 * time.Second), OrigTTL: 1}
	fresh := &Entry{InsertedAt: now, OrigTTL: 60}

	s.entries[expiredKey] = expired
	s.entries[freshKey] = fresh
	s.pushEvictionEntry(expiredKey, expired)
	s.pushEvictionEntry(freshKey, fresh)

	evicted := s.evictExpiredLocked(now)
	if evicted != 1 {
		t.Fatalf("expected exactly one eviction, got %d", evicted)
	}
	if _, ok := s.entries[expiredKey]; ok {
		t.Fatalf("expected expired key to be evicted")
	}
	if _, ok := s.entries[freshKey]; !ok {
		t.Fatalf("expected fresh key to remain")
	}
}

func TestEvictExpiredFallbackLocked_ScansWithoutQueue(t *testing.T) {
	s := &shard{}
	s.resetEntries()
	s.evictQ = s.evictQ[:0]

	now := time.Now()
	s.entries[cacheKey{name: "old", qtype: 1, class: 1}] = &Entry{InsertedAt: now.Add(-5 * time.Second), OrigTTL: 1}
	s.entries[cacheKey{name: "new", qtype: 1, class: 1}] = &Entry{InsertedAt: now, OrigTTL: 120}

	evicted := s.evictExpiredFallbackLocked()
	if evicted != 1 {
		t.Fatalf("expected one fallback eviction, got %d", evicted)
	}
	if len(s.entries) != 1 {
		t.Fatalf("expected one entry left after fallback sweep, got %d", len(s.entries))
	}
}

func TestEvictExpiredLocked_SkipsStalePointerEntries(t *testing.T) {
	s := &shard{}
	s.resetEntries()

	now := time.Now()
	key := cacheKey{name: "stale", qtype: 1, class: 1}
	original := &Entry{InsertedAt: now.Add(-10 * time.Second), OrigTTL: 1}
	current := &Entry{InsertedAt: now, OrigTTL: 300}

	s.entries[key] = original
	s.pushEvictionEntry(key, original)
	s.entries[key] = current // queue pointer becomes stale

	evicted := s.evictExpiredLocked(now)
	if evicted != 0 {
		t.Fatalf("expected stale queue pointer to be ignored, got %d evictions", evicted)
	}
	if _, ok := s.entries[key]; !ok {
		t.Fatalf("expected current entry to remain")
	}
}

func TestEvictExpiredLocked_SkipsIfEntryTTLWasExtended(t *testing.T) {
	s := &shard{}
	s.resetEntries()

	now := time.Now()
	key := cacheKey{name: "extended", qtype: 1, class: 1}
	entry := &Entry{InsertedAt: now.Add(-10 * time.Second), OrigTTL: 1}
	s.entries[key] = entry
	s.pushEvictionEntry(key, entry)

	// Queue thinks the entry is expired, but entry TTL was extended after enqueue.
	entry.OrigTTL = 3600

	evicted := s.evictExpiredLocked(now)
	if evicted != 0 {
		t.Fatalf("expected no eviction when remaining TTL is positive, got %d", evicted)
	}
	if _, ok := s.entries[key]; !ok {
		t.Fatalf("expected extended entry to remain")
	}
}
