package cache

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// ---------------------------------------------------------------------------
// LookupAll: covers cache.go:394-413 (0% coverage)
// ---------------------------------------------------------------------------

func TestLookupAll_MultipleTypes(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answersA := []dns.ResourceRecord{{
		Name: "multi.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	answersAAAA := []dns.ResourceRecord{{
		Name: "multi.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
		TTL: 300, RDLength: 16, RData: make([]byte, 16),
	}}
	answersMX := []dns.ResourceRecord{{
		Name: "multi.com", Type: dns.TypeMX, Class: dns.ClassIN,
		TTL: 300, RDLength: 2, RData: []byte{0, 10},
	}}

	c.Store("multi.com", dns.TypeA, dns.ClassIN, answersA, nil)
	c.Store("multi.com", dns.TypeAAAA, dns.ClassIN, answersAAAA, nil)
	c.Store("multi.com", dns.TypeMX, dns.ClassIN, answersMX, nil)

	// Also store a different name in the same shard (should not be returned)
	otherAnswers := []dns.ResourceRecord{{
		Name: "other.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{5, 6, 7, 8},
	}}
	c.Store("other.com", dns.TypeA, dns.ClassIN, otherAnswers, nil)

	results := c.LookupAll("multi.com", dns.ClassIN)
	if len(results) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(results))
	}

	// Verify all returned entries have decayed TTL
	for _, entry := range results {
		if len(entry.Records) != 1 {
			t.Errorf("expected 1 record per entry, got %d", len(entry.Records))
		}
		if entry.Records[0].TTL > 300 {
			t.Errorf("TTL should be <= 300, got %d", entry.Records[0].TTL)
		}
	}
}

func TestLookupAll_Empty(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	results := c.LookupAll("nonexistent.com", dns.ClassIN)
	if len(results) != 0 {
		t.Errorf("expected 0 entries for nonexistent name, got %d", len(results))
	}
}

func TestLookupAll_SkipsExpired(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "expiring.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("expiring.com", dns.TypeA, dns.ClassIN, answers, nil)

	// Manually set InsertedAt far in the past to force expiry
	name := "expiring.com"
	key := cacheKey{name: name, qtype: dns.TypeA, class: dns.ClassIN}
	idx := c.shardIndex(name)
	s := &c.shards[idx]
	s.mu.Lock()
	if entry, ok := s.entries[key]; ok {
		entry.InsertedAt = time.Now().Add(-1 * time.Hour)
		entry.OrigTTL = 1
	}
	s.mu.Unlock()

	results := c.LookupAll("expiring.com", dns.ClassIN)
	if len(results) != 0 {
		t.Errorf("expected 0 entries (expired), got %d", len(results))
	}
}

func TestLookupAll_DifferentClass(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "classtest.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("classtest.com", dns.TypeA, dns.ClassIN, answers, nil)

	// Query with different class should not return results
	results := c.LookupAll("classtest.com", 3) // CH class
	if len(results) != 0 {
		t.Errorf("expected 0 entries for different class, got %d", len(results))
	}
}

func TestLookupAll_CaseInsensitive(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "UPPER.COM", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("UPPER.COM", dns.TypeA, dns.ClassIN, answers, nil)

	results := c.LookupAll("upper.com", dns.ClassIN)
	if len(results) != 1 {
		t.Errorf("expected 1 entry (case insensitive), got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// GetWithECS: cover expired entry path (cache.go:561, remaining==0)
// ---------------------------------------------------------------------------

func TestGetWithECS_ExpiredEntry(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "ecs-expire.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.StoreWithECS("ecs-expire.com", dns.TypeA, dns.ClassIN, "10.0.0.0/24", answers, nil)

	// Manually expire the entry
	name := "ecs-expire.com"
	key := cacheKey{name: name, qtype: dns.TypeA, class: dns.ClassIN, ecsPrefix: "10.0.0.0/24"}
	idx := c.shardIndex(name)
	s := &c.shards[idx]
	s.mu.Lock()
	if entry, ok := s.entries[key]; ok {
		entry.InsertedAt = time.Now().Add(-1 * time.Hour)
		entry.OrigTTL = 1
	}
	s.mu.Unlock()

	_, ok := c.GetWithECS("ecs-expire.com", dns.TypeA, dns.ClassIN, "10.0.0.0/24")
	if ok {
		t.Error("expected miss for expired ECS entry")
	}
}

// ---------------------------------------------------------------------------
// Get: cover the prefetch threshold==0 branch (cache.go:132-134)
// This happens when OrigTTL < 10 so OrigTTL/10 == 0, and threshold becomes 1.
// ---------------------------------------------------------------------------

func TestGet_PrefetchThresholdZero(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)
	c.SetPrefetchEnabled(true)

	c.SetPrefetchFunc(func(name string, qtype, qclass uint16) {
		// no-op; we just need the path executed
	})

	// OrigTTL=5, so threshold = 5/10 = 0, which gets set to 1.
	// Inject entry with remaining TTL=0 (almost expired but still > 0)
	// Actually we need remaining < threshold(=1), which means remaining=0 won't work
	// (it exits earlier). We need OrigTTL where OrigTTL/10==0, and remaining < 1.
	// But remaining is uint32 so it can't be < 1 and > 0. The branch at line 132
	// sets threshold=1 when OrigTTL/10==0. For this to trigger prefetch, we need
	// remaining < 1 which is impossible for uint32 > 0. However, the branch
	// itself (threshold=0 -> threshold=1) is what we need to cover.

	// Let's inject with OrigTTL=5 (threshold = 5/10 = 0 -> becomes 1)
	// and remaining = a value that's < threshold after correction.
	// Actually we need: remaining > 0 AND remaining < threshold(1).
	// Since remaining is uint32 and must be > 0 (line 130 checks remaining > 0),
	// the smallest remaining > 0 is 1. But 1 < 1 is false.
	// So threshold=1 means prefetch never triggers... unless remaining equals 0
	// which doesn't enter the block.
	//
	// Wait - the condition is: remaining < threshold && entry.tryPrefetch()
	// With threshold=1, remaining must be < 1, i.e., 0. But remaining > 0 is checked.
	// So this branch (threshold=0 becoming 1) is covered but never leads to prefetch.
	// We still need to exercise the code path where threshold == 0 gets set to 1.

	nearExpiryEntry := &Entry{
		Records: []dns.ResourceRecord{{
			Name: "thresh.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 5, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
		InsertedAt: time.Now().Add(-4 * time.Second), // remaining = ~1
		OrigTTL:    5,                                 // 5/10 = 0, threshold becomes 1
	}
	name := "thresh.com"
	idx := c.shardIndex(name)
	s := &c.shards[idx]
	s.mu.Lock()
	s.entries[cacheKey{name: name, qtype: dns.TypeA, class: dns.ClassIN}] = nearExpiryEntry
	s.mu.Unlock()

	_, ok := c.Get("thresh.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("expected cache hit")
	}
	// The threshold=1 path is exercised even if prefetch doesn't trigger
	// because remaining >= threshold. The important thing is the code line
	// `threshold = 1` at line 133 is executed.
}

// ---------------------------------------------------------------------------
// checkParentNXDomain: cover parent=="" branch (cache.go:154-155)
// ---------------------------------------------------------------------------

func TestCheckParentNXDomain_SingleLabelName(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)
	c.SetHardenBelowNX(true)

	// Store NXDOMAIN for a single-label TLD
	authority := []dns.ResourceRecord{{
		Name: "com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 600, RDLength: 0, RData: nil,
	}}
	c.StoreNegative("com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, authority)

	// Query for "sub.com" -> walks up to "com" -> finds NXDOMAIN
	entry, ok := c.Get("sub.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("expected harden-below-nxdomain hit for sub.com")
	}
	if entry.RCODE != dns.RCodeNXDomain {
		t.Errorf("expected NXDOMAIN rcode, got %d", entry.RCODE)
	}

	// Query with a name that walks to single-label parent that is ""
	// after the dot. e.g. "x." -> dotIdx=1, parent="" -> break
	// This is covered when the name traversal reaches a point where
	// parent is empty.
	_, ok = c.Get("x", dns.TypeA, dns.ClassIN)
	// "x" has no dot, so checkParentNXDomain immediately breaks
	if ok {
		t.Error("expected miss for single-label name with no NXDOMAIN parent")
	}
}

// ---------------------------------------------------------------------------
// checkParentNXDomain: cover parent=="" break (cache.go:154-155)
// This happens when the name has a trailing dot, e.g. "sub.com."
// After walking: name="sub.com." -> dotIdx=3, parent="com." -> dotIdx=3,
// parent="." -> dotIdx=0, parent="" -> break
// ---------------------------------------------------------------------------

func TestCheckParentNXDomain_ParentEmptyBreak(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)
	c.SetHardenBelowNX(true)

	// No NXDOMAIN entries stored. Query with a name that will walk up to "." then ""
	// The name "sub.com." has a trailing dot. After lowercasing: "sub.com."
	// Iteration 1: dotIdx=3, parent="com." -> no NX entry
	// Iteration 2: name="com.", dotIdx=3, parent="." -> no NX entry
	// Iteration 3: name=".", dotIdx=0, parent="" -> break
	_, ok := c.Get("sub.com.", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("expected miss, no NXDOMAIN entries stored")
	}
}

// ---------------------------------------------------------------------------
// enforceMaxEntriesLocked: cover the !found break (cache.go:358-359)
// This is the unreachable branch. We can't actually trigger it under normal
// conditions because the loop only runs when entries exist. But let's ensure
// the eviction code with metrics=nil is exercised thoroughly.
// ---------------------------------------------------------------------------

func TestEnforceMaxEntries_EvictionWithMetrics(t *testing.T) {
	m := metrics.NewMetrics()
	// maxEntries=2 -> per shard limit = 2/256+1 = 1
	c := NewCache(2, 5, 86400, 3600, m)

	// Insert enough entries to guarantee at least one shard collision
	for i := 0; i < 512; i++ {
		name := "evict" + string(rune('A'+i%26)) + string(rune('a'+i/26%26)) + string(rune('0'+i%10)) + ".com"
		answers := []dns.ResourceRecord{{
			Name: name, Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 2, 3, 4},
		}}
		c.Store(name, dns.TypeA, dns.ClassIN, answers, nil)
	}

	stats := c.Stats()
	if stats.Entries >= 512 {
		t.Errorf("eviction should have removed entries, got %d", stats.Entries)
	}
}

// ---------------------------------------------------------------------------
// checkParentNXDomain: cover expired parent entry path
// When parent NXDOMAIN is found but has expired (remaining==0), continue walking.
// ---------------------------------------------------------------------------

func TestCheckParentNXDomain_ExpiredParent(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)
	c.SetHardenBelowNX(true)

	// Store NXDOMAIN for "parent.com" with very short TTL
	c.StoreNegative("parent.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, nil)

	// Manually expire the entry
	name := "parent.com"
	key := cacheKey{name: name, qtype: 0, class: dns.ClassIN}
	idx := c.shardIndex(name)
	s := &c.shards[idx]
	s.mu.Lock()
	if entry, ok := s.entries[key]; ok {
		entry.InsertedAt = time.Now().Add(-1 * time.Hour)
		entry.OrigTTL = 1
	}
	s.mu.Unlock()

	// Query for "sub.parent.com" should NOT find NXDOMAIN (parent is expired)
	_, ok := c.Get("sub.parent.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("expected miss when parent NXDOMAIN is expired")
	}
}
