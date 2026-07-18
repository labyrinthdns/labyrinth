package cache

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestGetStale_DeduplicatesConcurrentRefresh(t *testing.T) {
	c := NewCacheWithStale(1024, 1, 86400, 3600, true, 30, nil)
	c.SetStaleMaxAge(3600)
	c.SetPrefetchEnabled(true)

	var refreshes atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	c.SetPrefetchFunc(func(name string, qtype, qclass uint16) {
		if refreshes.Add(1) == 1 {
			close(started)
		}
		<-release
	})

	name := "stale-dedup.example"
	c.Store(name, dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: name, Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}, nil)
	idx := c.shardIndex(name)
	s := &c.shards[idx]
	s.mu.Lock()
	entry := s.entries[cacheKey{name: name, qtype: dns.TypeA, class: dns.ClassIN}]
	entry.InsertedAt = time.Now().Add(-2 * time.Second)
	entry.OrigTTL = 1
	s.mu.Unlock()

	const callers = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			<-start
			if _, ok := c.GetStale(name, dns.TypeA, dns.ClassIN); !ok {
				t.Error("expected stale hit")
			}
		}()
	}
	close(start)
	wg.Wait()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	if got := refreshes.Load(); got != 1 {
		t.Fatalf("refresh calls = %d, want exactly 1 for one stale generation", got)
	}
	close(release)
}

func TestEvictionMetadataBoundedOnOverwrite(t *testing.T) {
	c := NewCache(1024, 1, 86400, 3600, nil)
	name := "hot-key.example"
	answers := []dns.ResourceRecord{{
		Name: name, Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}

	for i := 0; i < 10_000; i++ {
		c.Store(name, dns.TypeA, dns.ClassIN, answers, nil)
	}

	s := &c.shards[c.shardIndex(name)]
	s.mu.RLock()
	defer s.mu.RUnlock()
	maxMetadata := len(s.entries)*evictionMetadataFactor + 16
	if got := len(s.evictQ); got > maxMetadata {
		t.Fatalf("eviction metadata grew to %d for %d live entries; bound is %d", got, len(s.entries), maxMetadata)
	}
}

func TestEvictionMetadataReleasedWhenLastEntryDeleted(t *testing.T) {
	c := NewCache(1024, 1, 86400, 3600, nil)
	name := "delete-metadata.example"
	c.Store(name, dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: name, Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}, nil)
	if !c.Delete(name, dns.TypeA, dns.ClassIN) {
		t.Fatal("Delete returned false")
	}

	s := &c.shards[c.shardIndex(name)]
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) != 0 || len(s.evictQ) != 0 {
		t.Fatalf("empty shard retained state: entries=%d metadata=%d", len(s.entries), len(s.evictQ))
	}
}
