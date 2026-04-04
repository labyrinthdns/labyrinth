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
