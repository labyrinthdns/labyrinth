package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestGetExpiredDoesNotDeleteConcurrentRefresh pins that Get's expired-entry
// delete removes only the entry it read. Get releases the read lock before
// taking the write lock, so a Store refreshing the same name can land in
// between; deleting by key alone threw that fresh answer away and sent the
// next query upstream again. Whatever the interleaving, the refreshed entry
// must be in the cache once both calls return.
func TestGetExpiredDoesNotDeleteConcurrentRefresh(t *testing.T) {
	c := NewCache(100000, 1, 86400, 3600, nil)
	name := "refresh.example.com"
	key := cacheKey{name: name, qtype: dns.TypeA, class: dns.ClassIN}
	s := &c.shards[c.shardIndex(name)]
	answer := []dns.ResourceRecord{{Name: name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{192, 0, 2, 1}}}

	for i := 0; i < 20000; i++ {
		expired := &Entry{InsertedAt: time.Now().Add(-time.Hour), OrigTTL: 60}
		s.mu.Lock()
		s.entries[key] = expired
		s.pushEvictionEntry(key, expired)
		s.mu.Unlock()

		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			c.Get(name, dns.TypeA, dns.ClassIN)
		}()
		go func() {
			defer wg.Done()
			<-start
			c.Store(name, dns.TypeA, dns.ClassIN, answer, nil)
		}()
		close(start)
		wg.Wait()

		if _, ok := c.Get(name, dns.TypeA, dns.ClassIN); !ok {
			t.Fatalf("iteration %d: the refreshed entry was deleted by a concurrent expired-entry Get", i)
		}
	}
}
