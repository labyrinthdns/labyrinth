package resolver

import (
	"fmt"
	"testing"
	"time"
)

// MaxInfraCacheEntries caps the entries map, but the eviction that enforces it
// used to walk the whole map to find the oldest LastUsed, while holding ic.mu
// in write mode, on the resolver's request path (RecordRTT / RecordFailure are
// called from resolveIterativeFromInner for every upstream contact).
//
// The cap's own docstring names the attacker who keeps the map full: "an
// attacker who controls an authoritative server ... can drive the resolver to
// contact thousands of distinct upstream NS addresses by serving each query
// with a fresh, unique IPv4/IPv6 NS set." Under exactly that pattern every
// query is an insert at the cap, so every query pays a full 100k-entry scan
// under the write lock that serialises all InfraCache users.
//
// security/rrl.go and security/ratelimit.go already carry an eviction heap for
// this reason, and security/rrl.go states the invariant outright: a
// cap-triggered eviction "never scans the attacker-controlled map while holding"
// its lock.
//
// Timing here is only a complexity assertion, never a correctness one: the
// same eviction is measured at two map sizes and the ratio compared, so an
// O(log n) eviction yields ~1 and an O(n) one yields the size ratio. The
// threshold sits far from both outcomes, so the result does not depend on
// machine speed.

const (
	evictSmallN  = 25_000
	evictLargeN  = 100_000
	evictReps    = 3
	evictTrials  = 3
	evictMaxRate = 3.0
)

// evictKey maps i to a unique nameserver address. Three octets are required:
// two wrap at 65536 and would silently under-fill the cache at the 100k cap.
func evictKey(i int) string {
	return fmt.Sprintf("198.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)
}

// evictFilled builds a cache holding exactly n entries, populated through the
// production RecordRTT entry point so the structure under test is the one a
// running resolver builds.
func evictFilled(t *testing.T, n int) *InfraCache {
	t.Helper()
	ic := NewInfraCache()
	for i := 0; i < n; i++ {
		ic.RecordRTT(evictKey(i), time.Millisecond)
	}
	return ic
}

// evictCost returns the best per-batch wall time of reps evictions, so one
// scheduling hiccup on a shared box cannot decide the result.
func evictCost(ic *InfraCache) time.Duration {
	best := time.Duration(1<<62 - 1)
	for t := 0; t < evictTrials; t++ {
		ic.mu.Lock()
		start := time.Now()
		for i := 0; i < evictReps; i++ {
			ic.evictOldestLocked()
		}
		elapsed := time.Since(start)
		ic.mu.Unlock()
		if elapsed < best {
			best = elapsed
		}
	}
	return best
}

// A capped eviction must not grow with the size of the map it protects.
func TestInfraCacheEvictionCostIsIndependentOfMapSize(t *testing.T) {
	small := evictFilled(t, evictSmallN)
	large := evictFilled(t, evictLargeN)

	if got := len(small.entries); got != evictSmallN {
		t.Fatalf("setup: small cache holds %d entries, want %d", got, evictSmallN)
	}
	if got := len(large.entries); got != evictLargeN {
		t.Fatalf("setup: large cache holds %d entries, want %d", got, evictLargeN)
	}

	smallCost := evictCost(small)
	largeCost := evictCost(large)
	ratio := float64(largeCost) / float64(smallCost)

	t.Logf("evicting %d entries: %v at N=%d, %v at N=%d (%.2fx for a %.1fx larger map)",
		evictReps, smallCost, evictSmallN, largeCost, evictLargeN,
		ratio, float64(evictLargeN)/float64(evictSmallN))

	if ratio >= evictMaxRate {
		t.Errorf("eviction cost grew %.2fx when the map grew %.1fx (%v at N=%d -> %v at N=%d); "+
			"evictOldestLocked must not scan the attacker-controlled map under ic.mu",
			ratio, float64(evictLargeN)/float64(evictSmallN),
			smallCost, evictSmallN, largeCost, evictLargeN)
	}
}

// The heap only preserves LRU if an entry that keeps being queried is not
// mistaken for an idle one. First-seen and least-recently-used order are made
// to disagree here.
func TestInfraCacheEvictionRemovesLeastRecentlyUsed(t *testing.T) {
	ic := NewInfraCache()
	ic.RecordRTT("198.18.0.1", time.Millisecond)
	ic.RecordRTT("198.18.0.2", time.Millisecond)
	if len(ic.entries) != 2 {
		t.Fatalf("setup: cache holds %d entries, want 2", len(ic.entries))
	}

	// Refresh the FIRST entry, making it the most recently used.
	ic.RecordRTT("198.18.0.1", time.Millisecond)

	ic.mu.Lock()
	ic.evictOldestLocked()
	ic.mu.Unlock()

	if _, ok := ic.entries["198.18.0.2"]; ok {
		t.Error("the least recently used entry survived eviction")
	}
	if _, ok := ic.entries["198.18.0.1"]; !ok {
		t.Error("the most recently used entry was evicted")
	}
}

// Eviction must drop exactly one entry so the cap still bounds the map.
func TestInfraCacheEvictionDropsExactlyOneEntry(t *testing.T) {
	ic := evictFilled(t, 5_000)
	ic.mu.Lock()
	before := len(ic.entries)
	ic.evictOldestLocked()
	after := len(ic.entries)
	ic.mu.Unlock()

	if before-1 != after {
		t.Errorf("eviction changed the entry count by %d, want exactly 1", after-before)
	}
}

// Every tracked entry must keep a reachable heap node, or the heap silently
// stops tracking the map and refreshInfraHeapLocked quietly stops working.
// Checked after the normal insert path and after CleanStale leaves stale nodes.
func TestInfraCacheHeapNodesTrackLiveEntries(t *testing.T) {
	ic := evictFilled(t, 500)
	for ip, e := range ic.entries {
		if e.key != ip {
			t.Errorf("%s: entry records key %q", ip, e.key)
		}
		idx := e.heapIndex
		if idx < 0 || idx >= ic.evictHeap.Len() || ic.evictHeap[idx] != e {
			t.Errorf("%s: heap index %d does not point at its own entry (len %d)",
				ip, idx, ic.evictHeap.Len())
		}
	}
	if ic.heapLive != len(ic.entries) {
		t.Errorf("heapLive = %d, want %d", ic.heapLive, len(ic.entries))
	}
}

// CleanStale deletes map entries out from under the heap, so eviction must stay
// correct afterwards: a newly seen nameserver is admitted, and the next
// eviction still drops the genuinely oldest entry. CleanStale also compacts
// the heap when it has outgrown the map, so this does not assume stale nodes
// survive it — only that the cache behaves correctly afterwards.
func TestInfraCacheEvictionCorrectAfterCleanStale(t *testing.T) {
	ic := NewInfraCache()
	ic.RecordRTT("198.18.0.1", time.Millisecond)
	ic.RecordRTT("198.18.0.2", time.Millisecond)

	// maxIdle of 0 makes every entry stale.
	ic.CleanStale(0)
	if len(ic.entries) != 0 {
		t.Fatalf("setup: cache still holds %d entries after CleanStale", len(ic.entries))
	}
	if ic.heapLive != 0 {
		t.Fatalf("setup: heapLive = %d after CleanStale emptied the map, want 0", ic.heapLive)
	}
	if len(ic.evictHeap) > len(ic.entries)*2+1 {
		t.Errorf("heap holds %d nodes for %d entries; it is not being compacted",
			len(ic.evictHeap), len(ic.entries))
	}

	// New nameservers must be admitted rather than tripping over stale nodes.
	ic.RecordRTT("198.18.0.3", time.Millisecond)
	ic.RecordRTT("198.18.0.4", time.Millisecond)
	for _, ip := range []string{"198.18.0.3", "198.18.0.4"} {
		if _, ok := ic.entries[ip]; !ok {
			t.Fatalf("%s was not tracked after CleanStale", ip)
		}
	}

	// Refresh .3 so first-seen and LRU order disagree, then evict.
	ic.RecordRTT("198.18.0.3", time.Millisecond)
	ic.mu.Lock()
	ic.evictOldestLocked()
	ic.mu.Unlock()

	if _, ok := ic.entries["198.18.0.4"]; ok {
		t.Error("the least recently used entry survived eviction after CleanStale")
	}
	if _, ok := ic.entries["198.18.0.3"]; !ok {
		t.Error("the most recently used entry was evicted after CleanStale")
	}
}

// Entries written straight into the map must still be evictable, so the cap
// cannot be bypassed by any caller that does not go through RecordRTT.
func TestInfraCacheEvictionHandlesEntriesWithoutHeapNodes(t *testing.T) {
	ic := NewInfraCache()
	now := time.Now()
	ic.entries["198.18.0.1"] = &NSInfo{LastUsed: now}
	ic.entries["198.18.0.2"] = &NSInfo{LastUsed: now.Add(-time.Hour)}
	if len(ic.evictHeap) != 0 {
		t.Fatalf("setup: heap should be empty, holds %d", len(ic.evictHeap))
	}

	ic.mu.Lock()
	ic.evictOldestLocked()
	ic.mu.Unlock()

	if _, ok := ic.entries["198.18.0.2"]; ok {
		t.Error("the oldest entry was not evicted when no heap node existed for it")
	}
}
