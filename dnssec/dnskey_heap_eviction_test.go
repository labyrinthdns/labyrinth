package dnssec

import (
	"fmt"
	"testing"
	"time"
)

// MaxDNSKEYCacheEntries caps keyCache, but the eviction enforcing it used to
// scan the whole map for the oldest fetchedAt, while holding v.mu in write
// mode, on the DNSSEC validation path (fetchDNSKEYRRSet runs from
// validateResponseImpl, signersAuthenticatedInsecure, validateTrustChainForKey
// and validateDenialResponseN).
//
// The cap's docstring names the attacker who keeps the map full: "an attacker
// driving the resolver to fetch DNSKEYs for distinct zones can pin gigabytes of
// cache with normal query rates." Under exactly that pattern every fetch is a
// new-zone insert at the cap, so every fetch pays the full scan.
//
// The heap node is a separate object from the *dnskeyCache it indexes, because
// storeDNSKEY reallocates that pointer on every insert — including a plain
// refresh of an existing zone — so an index stored on the entry would be
// discarded with it. This is the same separate-node arrangement as
// security/ratelimit.go's tokenBucket/evictHeapEntry pair.
//
// Timing here is only a complexity assertion, never a correctness one: the same
// eviction is measured at two map sizes and the ratio compared, so an O(log n)
// eviction yields ~1 and an O(n) one yields the size ratio.

const (
	dnskeyEvictSmallN  = 12_500
	dnskeyEvictLargeN  = 50_000
	dnskeyEvictReps    = 3
	dnskeyEvictTrials  = 3
	dnskeyEvictMaxRate = 3.0
)

func dnskeyEvictZone(i int) string {
	return fmt.Sprintf("z%d.d%d.e%d.test.", i/65536, (i/65536)%65536, i%65536)
}

func dnskeyEvictFilled(n int) *Validator {
	v := &Validator{keyCache: make(map[string]*dnskeyCache)}
	for i := 0; i < n; i++ {
		v.storeDNSKEY(dnskeyEvictZone(i), nil, nil, time.Hour)
	}
	return v
}

func dnskeyEvictCost(v *Validator) time.Duration {
	best := time.Duration(1<<62 - 1)
	for t := 0; t < dnskeyEvictTrials; t++ {
		v.mu.Lock()
		start := time.Now()
		for i := 0; i < dnskeyEvictReps; i++ {
			v.evictOldestDNSKEYLocked()
		}
		elapsed := time.Since(start)
		v.mu.Unlock()
		if elapsed < best {
			best = elapsed
		}
	}
	return best
}

// A capped eviction must not grow with the size of the map it protects.
func TestDNSKEYCacheEvictionCostIsIndependentOfMapSize(t *testing.T) {
	small := dnskeyEvictFilled(dnskeyEvictSmallN)
	large := dnskeyEvictFilled(dnskeyEvictLargeN)

	if got := len(small.keyCache); got != dnskeyEvictSmallN {
		t.Fatalf("setup: small keyCache holds %d entries, want %d", got, dnskeyEvictSmallN)
	}
	if got := len(large.keyCache); got != dnskeyEvictLargeN {
		t.Fatalf("setup: large keyCache holds %d entries, want %d", got, dnskeyEvictLargeN)
	}

	smallCost := dnskeyEvictCost(small)
	largeCost := dnskeyEvictCost(large)
	ratio := float64(largeCost) / float64(smallCost)

	t.Logf("evicting %d entries: %v at N=%d, %v at N=%d (%.2fx for a %.1fx larger map)",
		dnskeyEvictReps, smallCost, dnskeyEvictSmallN, largeCost, dnskeyEvictLargeN,
		ratio, float64(dnskeyEvictLargeN)/float64(dnskeyEvictSmallN))

	if ratio >= dnskeyEvictMaxRate {
		t.Errorf("eviction cost grew %.2fx when the map grew %.1fx (%v at N=%d -> %v at N=%d); "+
			"evictOldestDNSKEYLocked must not scan the attacker-controlled map under v.mu",
			ratio, float64(dnskeyEvictLargeN)/float64(dnskeyEvictSmallN),
			smallCost, dnskeyEvictSmallN, largeCost, dnskeyEvictLargeN)
	}
}

// Eviction must still drop the least recently FETCHED entry, not the
// first-seen one. storeDNSKEY reallocates the cached pointer on the refresh
// below, which is exactly the reallocation the separate-node heap must survive.
func TestDNSKEYCacheEvictionRemovesLeastRecentlyFetched(t *testing.T) {
	v := &Validator{keyCache: make(map[string]*dnskeyCache)}
	v.storeDNSKEY("a.test.", nil, nil, time.Hour)
	v.storeDNSKEY("b.test.", nil, nil, time.Hour)

	// Refresh the FIRST zone so first-seen and LRU order disagree.
	time.Sleep(2 * time.Millisecond)
	v.storeDNSKEY("a.test.", nil, nil, time.Hour)

	v.mu.Lock()
	v.evictOldestDNSKEYLocked()
	v.mu.Unlock()

	if _, ok := v.keyCache["b.test."]; ok {
		t.Error("the least recently fetched zone survived eviction")
	}
	if _, ok := v.keyCache["a.test."]; !ok {
		t.Error("the most recently fetched zone was evicted")
	}
}

// Refreshing a zone replaces the cached pointer and strands the previous heap
// node. The stale node must be skipped rather than evicting the refreshed zone,
// and it must not be able to outgrow the map.
func TestDNSKEYCacheStaleNodesFromRefreshAreSkipped(t *testing.T) {
	v := &Validator{keyCache: make(map[string]*dnskeyCache)}
	v.storeDNSKEY("a.test.", nil, nil, time.Hour)
	v.storeDNSKEY("b.test.", nil, nil, time.Hour)

	// Many refreshes of the same zone: one live node plus a pile of stale ones.
	for i := 0; i < 20; i++ {
		v.storeDNSKEY("a.test.", nil, nil, time.Hour)
	}
	if len(v.keyHeap) < 2 {
		t.Fatalf("setup: expected stale heap nodes after refreshes, heap holds %d", len(v.keyHeap))
	}
	if len(v.keyCache) != 2 {
		t.Fatalf("setup: refreshes grew the map to %d entries", len(v.keyCache))
	}

	v.mu.Lock()
	v.evictOldestDNSKEYLocked()
	heaped := len(v.keyHeap)
	v.mu.Unlock()

	// "b.test." is the least recently fetched live entry and must go; "a.test."
	// was refreshed most recently and must survive.
	if _, ok := v.keyCache["b.test."]; ok {
		t.Error("the least recently fetched zone survived eviction")
	}
	if _, ok := v.keyCache["a.test."]; !ok {
		t.Error("the refreshed zone was evicted via a stale heap node")
	}
	// Compaction bounds the heap against the map.
	if heaped > len(v.keyCache)*2+1 {
		t.Errorf("heap holds %d nodes for %d entries after eviction; stale nodes are accumulating",
			heaped, len(v.keyCache))
	}
}

// Eviction must drop exactly one entry so the cap still bounds the map.
func TestDNSKEYCacheEvictionDropsExactlyOneEntry(t *testing.T) {
	v := dnskeyEvictFilled(5_000)
	v.mu.Lock()
	before := len(v.keyCache)
	v.evictOldestDNSKEYLocked()
	after := len(v.keyCache)
	v.mu.Unlock()

	if before-1 != after {
		t.Errorf("eviction changed the entry count by %d, want exactly 1", after-before)
	}
}

// The cap must hold through the real insert path, and re-storing an existing
// zone must replace its entry rather than take a second slot.
func TestDNSKEYCacheCapHoldsAndRefreshReplaces(t *testing.T) {
	v := &Validator{keyCache: make(map[string]*dnskeyCache)}
	for i := 0; i < MaxDNSKEYCacheEntries+50; i++ {
		v.storeDNSKEY(dnskeyEvictZone(i), nil, nil, time.Hour)
	}
	if got := len(v.keyCache); got > MaxDNSKEYCacheEntries {
		t.Errorf("keyCache holds %d entries, cap is %d", got, MaxDNSKEYCacheEntries)
	}

	v.storeDNSKEY(dnskeyEvictZone(0), nil, nil, time.Hour)
	if got := len(v.keyCache); got > MaxDNSKEYCacheEntries {
		t.Errorf("re-storing an existing zone grew the map to %d, cap is %d", got, MaxDNSKEYCacheEntries)
	}
}

// Entries written straight into the map must still be evictable, so the cap
// cannot be bypassed by any caller that does not go through storeDNSKEY.
func TestDNSKEYCacheEvictionHandlesEntriesWithoutHeapNodes(t *testing.T) {
	v := &Validator{keyCache: make(map[string]*dnskeyCache)}
	now := time.Now()
	v.keyCache["a.test."] = &dnskeyCache{fetchedAt: now}
	v.keyCache["b.test."] = &dnskeyCache{fetchedAt: now.Add(-time.Hour)}
	if len(v.keyHeap) != 0 {
		t.Fatalf("setup: heap should be empty, holds %d", len(v.keyHeap))
	}

	v.mu.Lock()
	v.evictOldestDNSKEYLocked()
	v.mu.Unlock()

	if _, ok := v.keyCache["b.test."]; ok {
		t.Error("the oldest entry was not evicted when no heap node existed for it")
	}
}
