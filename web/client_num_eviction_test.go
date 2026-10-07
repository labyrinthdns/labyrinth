package web

import (
	"fmt"
	"testing"
	"time"
)

// MaxClientQueryNumEntries exists to bound clientQueryNum against a
// UDP-source-spoofing attacker who can plant an entry per spoofed source.
// The cap only holds if the eviction it triggers is cheap: the eviction runs
// on RecordQuery, the per-query counting path, while holding clientNumMu.
// An O(n) "find the oldest" scan therefore converts a bounded-memory defence
// into a CPU amplifier — the more entries the attacker plants, the more work
// every subsequent query does.
//
// security/rrl.go states the invariant this package must honour: a
// cap-triggered eviction "never scans the attacker-controlled map while
// holding" its lock. security/ratelimit.go's evictHeap was built for the same
// reason.
//
// Timing here is used only as a complexity assertion, never as a correctness
// one: the same eviction is measured at two map sizes and the ratio compared,
// so a constant-time implementation yields ~1 and a linear one yields ~8.
// Best-of-N sampling keeps one scheduling hiccup from deciding the result.

const (
	clientNumSmallN    = 50_000
	clientNumLargeN    = 400_000
	clientNumReps      = 5
	clientNumTrials    = 3
	clientNumMaxRatio  = 3.0
	clientNumPingDelay = 2 * time.Millisecond
)

// clientNumTestServer builds an AdminServer with the collaborators
// RecordQuery dereferences, and a cap high enough that populating n clients
// never itself triggers an eviction.
func clientNumTestServer(cap int) *AdminServer {
	return &AdminServer{
		clientQueryNum:            make(map[string]*clientQueryEntry),
		queryLog:                  NewQueryLog(64),
		timeSeries:                NewTimeSeriesAggregator(),
		topClients:                NewTopTracker(16),
		topDomains:                NewTopTracker(16),
		clientQueryNumCapOverride: cap,
	}
}

// clientNumPopulated returns a server holding n distinct clients inserted
// through the production RecordQuery path.
func clientNumPopulated(n int) *AdminServer {
	s := clientNumTestServer(n + 10)
	for i := 0; i < n; i++ {
		s.RecordQuery(fmt.Sprintf("203.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256),
			"example.com.", "A", "NOERROR", false, 1)
	}
	return s
}

func clientNumEvictCost(s *AdminServer) time.Duration {
	best := time.Duration(1<<62 - 1)
	for t := 0; t < clientNumTrials; t++ {
		s.clientNumMu.Lock()
		start := time.Now()
		for i := 0; i < clientNumReps; i++ {
			s.evictOldestClientLocked()
		}
		elapsed := time.Since(start)
		s.clientNumMu.Unlock()
		if elapsed < best {
			best = elapsed
		}
	}
	return best
}

// A capped eviction must not grow with the size of the map it is protecting.
func TestClientNumEvictionCostIsIndependentOfMapSize(t *testing.T) {
	small := clientNumPopulated(clientNumSmallN)
	large := clientNumPopulated(clientNumLargeN)

	if got := len(small.clientQueryNum); got != clientNumSmallN {
		t.Fatalf("setup: small map holds %d entries, want %d", got, clientNumSmallN)
	}
	if got := len(large.clientQueryNum); got != clientNumLargeN {
		t.Fatalf("setup: large map holds %d entries, want %d", got, clientNumLargeN)
	}

	smallCost := clientNumEvictCost(small)
	largeCost := clientNumEvictCost(large)
	ratio := float64(largeCost) / float64(smallCost)

	t.Logf("evicting %d entries: %v at N=%d, %v at N=%d (%.2fx for a %.1fx larger map)",
		clientNumReps, smallCost, clientNumSmallN, largeCost, clientNumLargeN,
		ratio, float64(clientNumLargeN)/float64(clientNumSmallN))

	if ratio >= clientNumMaxRatio {
		t.Errorf("eviction cost grew %.2fx when the map grew %.1fx (%v at N=%d -> %v at N=%d); "+
			"evictOldestClientLocked must not scan the attacker-controlled map under clientNumMu",
			ratio, float64(clientNumLargeN)/float64(clientNumSmallN),
			smallCost, clientNumSmallN, largeCost, clientNumLargeN)
	}
}

// The heap is only correct if a client that keeps querying is not mistaken for
// an idle one. First-seen order and least-recently-used order are made to
// disagree here, so an eviction that ignores lastAccess picks the wrong victim.
func TestClientNumEvictionRemovesLeastRecentlyUsed(t *testing.T) {
	s := clientNumTestServer(2)

	s.RecordQuery("198.51.100.1", "example.com.", "A", "NOERROR", false, 1)
	time.Sleep(clientNumPingDelay)
	s.RecordQuery("198.51.100.2", "example.com.", "A", "NOERROR", false, 1)
	time.Sleep(clientNumPingDelay)
	// Refresh the FIRST client, making it the most recently used.
	s.RecordQuery("198.51.100.1", "example.com.", "A", "NOERROR", false, 1)
	time.Sleep(clientNumPingDelay)
	// A new client pushes the map to the cap and forces the eviction.
	s.RecordQuery("198.51.100.3", "example.com.", "A", "NOERROR", false, 1)

	if _, ok := s.clientQueryNum["198.51.100.2"]; ok {
		t.Error("the least recently used client survived eviction")
	}
	if _, ok := s.clientQueryNum["198.51.100.1"]; !ok {
		t.Error("the most recently used client was evicted")
	}
	if _, ok := s.clientQueryNum["198.51.100.3"]; !ok {
		t.Error("the newly admitted client was not tracked")
	}
}

// TTL cleanup deletes map entries without touching the heap, so the heap must
// tolerate nodes whose entry is gone and still evict a live client next time.
func TestClientNumEvictionSkipsEntriesReapedByCleanup(t *testing.T) {
	s := clientNumTestServer(2)
	// cleanupStaleClients reaps entries idle for 2x this interval, so a
	// nanosecond interval makes everything written a moment ago stale.
	s.clientCleanupInterval = time.Nanosecond

	s.RecordQuery("198.51.100.1", "example.com.", "A", "NOERROR", false, 1)
	s.RecordQuery("198.51.100.2", "example.com.", "A", "NOERROR", false, 1)
	if len(s.clientQueryNum) != 2 {
		t.Fatalf("setup: map holds %d entries, want 2", len(s.clientQueryNum))
	}

	// Reap every map entry, leaving the heap full of stale nodes.
	s.cleanupStaleClients()
	if len(s.clientQueryNum) != 0 {
		t.Fatalf("setup: map still holds %d entries after cleanup", len(s.clientQueryNum))
	}
	if s.clientNumHeap.Len() == 0 {
		t.Fatal("setup: expected stale heap nodes to remain after cleanup")
	}

	// A new client must be admitted rather than tripping over the stale nodes.
	s.RecordQuery("198.51.100.3", "example.com.", "A", "NOERROR", false, 1)
	if _, ok := s.clientQueryNum["198.51.100.3"]; !ok {
		t.Error("the newly admitted client was not tracked after stale heap nodes")
	}
}

// Every live map entry must have a reachable heap node. If it does not, the
// heap silently stops tracking the map and refreshClientNumHeapLocked quietly
// stops working.
func TestClientNumHeapNodesTrackLiveEntries(t *testing.T) {
	s := clientNumPopulated(200)

	for ip, e := range s.clientQueryNum {
		idx := e.heapIndex
		if idx < 0 || idx >= s.clientNumHeap.Len() {
			t.Errorf("%s: heap index %d is outside the heap (len %d)", ip, idx, s.clientNumHeap.Len())
			continue
		}
		if s.clientNumHeap[idx] != e {
			t.Errorf("%s: heap index %d points at a different entry", ip, idx)
		}
		if e.key != ip {
			t.Errorf("%s: entry records key %q", ip, e.key)
		}
	}
}

// The heap is an accelerator, not a new source of truth: entries written
// straight into the map must still be evictable, so the cap cannot be
// bypassed by any caller that does not go through RecordQuery.
func TestClientNumEvictionHandlesEntriesWithoutHeapNodes(t *testing.T) {
	s := clientNumTestServer(3)
	now := time.Now()
	s.clientQueryNum["10.0.0.1"] = &clientQueryEntry{lastAccess: now}
	s.clientQueryNum["10.0.0.2"] = &clientQueryEntry{lastAccess: now.Add(-time.Hour)}
	if s.clientNumHeap.Len() != 0 {
		t.Fatalf("setup: heap should be empty, holds %d", s.clientNumHeap.Len())
	}

	s.RecordQuery("10.0.0.3", "example.com.", "A", "NOERROR", false, 1)
	s.RecordQuery("10.0.0.4", "example.com.", "A", "NOERROR", false, 1)

	if _, ok := s.clientQueryNum["10.0.0.2"]; ok {
		t.Error("the oldest entry was not evicted when no heap node existed for it")
	}
	if len(s.clientQueryNum) > 3 {
		t.Errorf("map holds %d entries, cap is 3", len(s.clientQueryNum))
	}
}

// The cap must still bound the map and counting must still accumulate.
func TestClientNumCapStillBoundsAndCounts(t *testing.T) {
	s := clientNumTestServer(10)

	for i := 0; i < 50; i++ {
		s.RecordQuery(fmt.Sprintf("203.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256),
			"example.com.", "A", "NOERROR", false, 1)
	}
	if n := len(s.clientQueryNum); n > 10 {
		t.Errorf("clientQueryNum holds %d entries, cap is 10", n)
	}

	s.RecordQuery("198.51.100.7", "example.com.", "A", "NOERROR", false, 1)
	if _, ok := s.clientQueryNum["198.51.100.7"]; !ok {
		t.Fatal("the most recently seen client is not tracked")
	}
	s.RecordQuery("198.51.100.7", "example.com.", "A", "NOERROR", false, 1)
	if got := s.clientQueryNum["198.51.100.7"].count.Load(); got != 2 {
		t.Errorf("per-client count is %d after two queries, want 2", got)
	}
}
