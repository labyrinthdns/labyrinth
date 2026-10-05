package cache

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestNextEvictionKeyLocked_MaxTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &shard{}
		s.resetEntries()
		maxKey := cacheKey{name: "max.test", qtype: 1, class: 1}
		s.entries[maxKey] = &Entry{InsertedAt: time.Now(), OrigTTL: ^uint32(0)}
		if got, ok := s.nextEvictionKeyLocked(); !ok || got != maxKey {
			t.Errorf("maximum TTL entry: got (%+v, %v), want (%+v, true)", got, ok, maxKey)
		}
		lowerKey := cacheKey{name: "lower.test", qtype: 1, class: 1}
		s.entries[lowerKey] = &Entry{InsertedAt: time.Now(), OrigTTL: 60}
		if got, ok := s.nextEvictionKeyLocked(); !ok || got != lowerKey {
			t.Errorf("mixed TTL entries: got (%+v, %v), want (%+v, true)", got, ok, lowerKey)
		}
		delete(s.entries, maxKey)
		delete(s.entries, lowerKey)
		if got, ok := s.nextEvictionKeyLocked(); ok {
			t.Errorf("empty map selected %+v", got)
		}
	})
}
