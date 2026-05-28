package metrics

import (
	"sync"
	"testing"
)

// TestEDECounters_IncrementsPerCode pins UI-M6.3 / M4.6 — the per-EDE
// emission counter MUST track each RFC 8914 §4 info code independently
// so an operator's "what's failing today?" pivot is meaningful. A
// regression that collapsed all codes into one bucket would still
// produce a non-zero count but lose the breakdown that makes the
// counter actionable.
func TestEDECounters_IncrementsPerCode(t *testing.T) {
	m := NewMetrics()

	// Emit a representative spread of codes.
	m.IncEDE(6)  // DNSSEC Bogus
	m.IncEDE(6)
	m.IncEDE(6)
	m.IncEDE(17) // Filtered
	m.IncEDE(17)
	m.IncEDE(18) // Prohibited
	m.IncEDE(25) // Signature Expired Before Valid (RFC 9606)

	got := m.EDECounts()

	want := map[uint16]int64{
		6:  3,
		17: 2,
		18: 1,
		25: 1,
	}
	for code, n := range want {
		if got[code] != n {
			t.Errorf("EDE %d: got %d, want %d", code, got[code], n)
		}
	}
	// Codes not emitted MUST be absent (zero-value is not "I saw it
	// zero times"). The UI uses absence to mean "never observed".
	if _, present := got[7]; present {
		t.Errorf("EDE 7 was not emitted but appears in the snapshot")
	}
}

// TestEDECounters_ConcurrentIncrements pins lock-free correctness
// under contention. The map ALLOCATION is mu-protected; per-code
// counters are atomic.Int64. Without the double-checked allocation
// (line 200-211 in metrics.go) two goroutines hitting an unseen code
// would race on map-write and panic.
func TestEDECounters_ConcurrentIncrements(t *testing.T) {
	m := NewMetrics()

	const goroutines = 32
	const perGoroutine = 1000

	// Mix of pre-known codes and a code never seen before so the
	// allocation path runs concurrently with the increment path.
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				code := uint16(j % 4) // 0,1,2,3 — small set, many collisions
				m.IncEDE(code)
			}
		}(i)
	}
	wg.Wait()

	got := m.EDECounts()
	total := int64(0)
	for _, n := range got {
		total += n
	}
	want := int64(goroutines * perGoroutine)
	if total != want {
		t.Errorf("concurrent inc total = %d, want %d (race lost increments)", total, want)
	}
}

// TestEDECounters_SnapshotIsCopy ensures EDECounts returns a snapshot
// the caller can iterate without holding any lock from the metrics
// package. A regression that returned the underlying map directly
// would create read/write races for any code that increments after
// the snapshot was taken.
func TestEDECounters_SnapshotIsCopy(t *testing.T) {
	m := NewMetrics()
	m.IncEDE(6)
	snap := m.EDECounts()
	if snap[6] != 1 {
		t.Fatalf("snapshot[6] = %d, want 1", snap[6])
	}

	// Mutating the snapshot must not affect the underlying counters.
	snap[6] = 999
	again := m.EDECounts()
	if again[6] != 1 {
		t.Errorf("internal counter mutated through snapshot: got %d, want 1", again[6])
	}
}
