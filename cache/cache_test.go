package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/labyrinth-dns/labyrinth/dns"
	"github.com/labyrinth-dns/labyrinth/metrics"
)

func TestCacheStoreAndGet(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name:     "example.com",
		Type:     dns.TypeA,
		Class:    dns.ClassIN,
		TTL:      300,
		RDLength: 4,
		RData:    []byte{93, 184, 216, 34},
	}}

	c.Store("example.com", dns.TypeA, dns.ClassIN, answers, nil)

	entry, ok := c.Get("example.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(entry.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(entry.Records))
	}
	if entry.Records[0].TTL > 300 {
		t.Errorf("TTL should be <= 300, got %d", entry.Records[0].TTL)
	}
}

func TestCacheMiss(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	_, ok := c.Get("nonexistent.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Fatal("expected cache miss")
	}
}

func TestCacheTTLClamping(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// TTL=0 should be clamped to minTTL=5
	answers := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 0, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("zero.com", dns.TypeA, dns.ClassIN, answers, nil)

	entry, ok := c.Get("zero.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if entry.Records[0].TTL == 0 {
		t.Error("TTL should be clamped from 0 to minTTL")
	}
}

func TestCaseInsensitive(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "Example.COM", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("Example.COM", dns.TypeA, dns.ClassIN, answers, nil)

	_, ok := c.Get("example.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("expected case-insensitive cache hit")
	}
}

func TestNegativeCache(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	authority := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 600, RDLength: 0, RData: nil,
	}}

	c.StoreNegative("nxdomain.example.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, authority)

	entry, ok := c.Get("nxdomain.example.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("expected negative cache hit")
	}
	if !entry.Negative {
		t.Error("expected negative flag")
	}
	if entry.NegType != NegNXDomain {
		t.Errorf("expected NegNXDomain, got %d", entry.NegType)
	}
}

func TestCacheFlush(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("example.com", dns.TypeA, dns.ClassIN, answers, nil)

	c.Flush()

	_, ok := c.Get("example.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Fatal("expected cache miss after flush")
	}

	stats := c.Stats()
	if stats.Entries != 0 {
		t.Errorf("expected 0 entries after flush, got %d", stats.Entries)
	}
}

func TestCacheStats(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	for i := 0; i < 10; i++ {
		answers := []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 2, 3, 4},
		}}
		c.Store("example"+string(rune('0'+i))+".com", dns.TypeA, dns.ClassIN, answers, nil)
	}

	stats := c.Stats()
	if stats.Entries != 10 {
		t.Errorf("expected 10 entries, got %d", stats.Entries)
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(10000, 5, 86400, 3600, m)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 50 writers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			answers := []dns.ResourceRecord{{
				Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{byte(id), 2, 3, 4},
			}}
			for {
				select {
				case <-stop:
					return
				default:
					c.Store("test"+string(rune(id+'A'))+".com", dns.TypeA, dns.ClassIN, answers, nil)
				}
			}
		}(i)
	}

	// 50 readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					c.Get("test"+string(rune(id+'A'))+".com", dns.TypeA, dns.ClassIN)
				}
			}
		}(i)
	}

	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestGetExpiredServeStaleKeepsEntry(t *testing.T) {
	// Cover the c.serveStale branch in Get() where expired entries are NOT deleted
	m := metrics.NewMetrics()
	c := NewCacheWithStale(1000, 1, 86400, 3600, true, 30, m)

	answers := []dns.ResourceRecord{{
		Name: "stalekeep.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("stalekeep.com", dns.TypeA, dns.ClassIN, answers, nil)

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Get should return false (expired) but NOT delete the entry
	_, ok := c.Get("stalekeep.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("Get should return false for expired entry")
	}

	// Entry should still exist because serveStale=true prevents deletion
	stats := c.Stats()
	if stats.Entries != 1 {
		t.Errorf("expired entry should NOT be deleted when serveStale=true, got %d entries", stats.Entries)
	}

	// Verify GetStale can still retrieve it
	entry, ok := c.GetStale("stalekeep.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("GetStale should return the preserved expired entry")
	}
	if entry.Records[0].TTL != 30 {
		t.Errorf("stale TTL should be 30, got %d", entry.Records[0].TTL)
	}
}

func TestExtractTTLEmptyRecords(t *testing.T) {
	// Cover the len(records)==0 branch in extractTTL
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	ttl := c.extractTTL(nil)
	if ttl != 5 {
		t.Errorf("extractTTL(nil) should return minTTL=5, got %d", ttl)
	}

	ttl = c.extractTTL([]dns.ResourceRecord{})
	if ttl != 5 {
		t.Errorf("extractTTL([]) should return minTTL=5, got %d", ttl)
	}
}

func TestClampTTLMax(t *testing.T) {
	// Cover the ttl > c.maxTTL branch in clampTTL
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	ttl := c.clampTTL(999999)
	if ttl != 86400 {
		t.Errorf("clampTTL(999999) should return maxTTL=86400, got %d", ttl)
	}
}

func TestClampNegativeTTLMax(t *testing.T) {
	// Cover the ttl > c.negMaxTTL branch in clampNegativeTTL
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	ttl := c.clampNegativeTTL(999999)
	if ttl != 3600 {
		t.Errorf("clampNegativeTTL(999999) should return negMaxTTL=3600, got %d", ttl)
	}
}

func TestEnforceMaxEntriesEviction(t *testing.T) {
	// Cover enforceMaxEntriesLocked with actual eviction
	m := metrics.NewMetrics()
	// maxEntries=2 means each shard allows maxEntries/shardCount+1 = 2/256+1 = 1 entry
	c := NewCache(2, 5, 86400, 3600, m)

	// Insert many entries; some will land in the same shard and trigger eviction
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("evict%d.com", i)
		answers := []dns.ResourceRecord{{
			Name: name, Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 2, 3, 4},
		}}
		c.Store(name, dns.TypeA, dns.ClassIN, answers, nil)
	}

	// With maxEntries=2, each shard should have at most 1 entry (2/256+1 = 1)
	stats := c.Stats()
	if stats.Entries >= 100 {
		t.Errorf("eviction should have removed entries, got %d (expected much less than 100)", stats.Entries)
	}

	// Verify no shard has more than maxEntries/shardCount+1 entries
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		count := len(s.entries)
		s.mu.RUnlock()
		maxPerShard := c.maxEntries/shardCount + 1
		if count > maxPerShard {
			t.Errorf("shard %d has %d entries, max allowed is %d", i, count, maxPerShard)
		}
	}
}

func TestGetStaleNotFound(t *testing.T) {
	// Cover the !ok branch in GetStale where entry doesn't exist
	m := metrics.NewMetrics()
	c := NewCacheWithStale(1000, 5, 86400, 3600, true, 30, m)

	_, ok := c.GetStale("nonexistent.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("GetStale should return false for nonexistent entry")
	}
}

func TestGetExpiredServeStaleDisabledDeletesEntry(t *testing.T) {
	// Cover the !c.serveStale branch in Get() that deletes expired entries
	// and calls metrics.IncCacheEvictions("expired")
	m := metrics.NewMetrics()
	c := NewCacheWithStale(1000, 1, 86400, 3600, false, 30, m)

	answers := []dns.ResourceRecord{{
		Name: "expire-del.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("expire-del.com", dns.TypeA, dns.ClassIN, answers, nil)

	time.Sleep(2 * time.Second)

	// Get should return false AND delete the entry since serveStale=false
	_, ok := c.Get("expire-del.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("Get should return false for expired entry")
	}

	// Entry should be deleted
	stats := c.Stats()
	if stats.Entries != 0 {
		t.Errorf("expired entry should be deleted when serveStale=false, got %d entries", stats.Entries)
	}
}

func TestExtractTTLMultipleRecords(t *testing.T) {
	// Cover the loop body in extractTTL that finds min TTL from multiple records
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	records := []dns.ResourceRecord{
		{Name: "a.com", Type: dns.TypeA, TTL: 600, RDLength: 4, RData: []byte{1, 2, 3, 4}},
		{Name: "a.com", Type: dns.TypeA, TTL: 100, RDLength: 4, RData: []byte{5, 6, 7, 8}},
		{Name: "a.com", Type: dns.TypeA, TTL: 300, RDLength: 4, RData: []byte{9, 10, 11, 12}},
	}

	ttl := c.extractTTL(records)
	if ttl != 100 {
		t.Errorf("extractTTL should return minimum=100, got %d", ttl)
	}
}

func TestExtractNegativeTTLSOAParseFails(t *testing.T) {
	// Cover the fallback to rr.TTL when SOA parse fails (bad RDATA)
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	authority := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 120, RDLength: 3, RData: []byte{0xFF, 0xFF, 0xFF}, // invalid SOA RDATA
	}}

	ttl := c.extractNegativeTTL(authority)
	if ttl != 120 {
		t.Errorf("expected fallback TTL=120 (SOA RR TTL), got %d", ttl)
	}
}

func TestClampNegativeTTLMin(t *testing.T) {
	// Cover the ttl < c.minTTL branch in clampNegativeTTL
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	ttl := c.clampNegativeTTL(1)
	if ttl != 5 {
		t.Errorf("clampNegativeTTL(1) should return minTTL=5, got %d", ttl)
	}
}

func TestEnforceMaxEntriesDisabled(t *testing.T) {
	// Cover the maxEntries <= 0 early return in enforceMaxEntriesLocked
	m := metrics.NewMetrics()
	c := NewCache(0, 5, 86400, 3600, m) // maxEntries=0 means no limit

	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("nolimit%d.com", i)
		answers := []dns.ResourceRecord{{
			Name: name, Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 2, 3, 4},
		}}
		c.Store(name, dns.TypeA, dns.ClassIN, answers, nil)
	}

	stats := c.Stats()
	if stats.Entries != 50 {
		t.Errorf("with maxEntries=0, all 50 entries should be kept, got %d", stats.Entries)
	}
}

func TestStartSweeperRunsSweep(t *testing.T) {
	// Cover the ticker.C case in StartSweeper that calls sweep()
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "sweepertest.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("sweepertest.com", dns.TypeA, dns.ClassIN, answers, nil)

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.StartSweeper(ctx, 100*time.Millisecond)
		close(done)
	}()

	// Wait enough time for at least one sweep tick
	time.Sleep(300 * time.Millisecond)
	cancel()

	<-done

	stats := c.Stats()
	if stats.Entries != 0 {
		t.Errorf("sweeper should have evicted expired entry, got %d", stats.Entries)
	}
}

func TestGetExpiredNilMetrics(t *testing.T) {
	// Cover the Get expired-delete path with nil metrics
	c := NewCacheWithStale(1000, 1, 86400, 3600, false, 30, nil)

	answers := []dns.ResourceRecord{{
		Name: "nilmetrics.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("nilmetrics.com", dns.TypeA, dns.ClassIN, answers, nil)

	time.Sleep(2 * time.Second)

	_, ok := c.Get("nilmetrics.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("expected miss for expired entry")
	}
}
