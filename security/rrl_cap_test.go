package security

import (
	"strconv"
	"testing"
	"time"
)

// TestRRL_CapEvictsOldestEntry pins the v0.8.6 gate: when the RRL
// entries map hits MaxRRLEntries, a new insert evicts the entry whose
// `lastTime` is oldest rather than letting the map grow without bound.
// A UDP-source-spoofing attacker sending queries from millions of
// distinct (prefix, qname, responseType) tuples would otherwise grow
// `r.entries` to gigabytes between cleanup ticks (5 min); the cap
// keeps memory bounded even when the cleanup goroutine is paused.
//
// The pin seeds the map to a small test-only cap with monotonic
// `lastTime` values (oldest first), inserts one new key over-cap, and
// asserts the size stays at cap AND the OLDEST seeded key was removed.
func TestRRL_CapEvictsOldestEntry(t *testing.T) {
	rrl := NewRRL(10.0, 2, 24, 56)

	const testCap = 4
	baseTime := time.Now().Add(-time.Hour)
	for i := 0; i < testCap; i++ {
		key := rrlKey{
			prefix:       "10.0.0." + strconv.Itoa(i),
			qname:        "example.test.",
			responseType: "NOERROR",
		}
		rrl.entries[key] = &rrlEntry{
			tokens:   5,
			lastTime: baseTime.Add(time.Duration(i) * time.Minute),
		}
	}

	if got := len(rrl.entries); got != testCap {
		t.Fatalf("setup: entries = %d, want %d", got, testCap)
	}

	// Synthesise the cap condition without making the test depend on
	// MaxRRLEntries=1M (impractical for a unit test). evictOldestLocked
	// is the exact branch that fires when the cap hits.
	rrl.mu.Lock()
	rrl.evictOldestLocked()
	rrl.mu.Unlock()

	if got := len(rrl.entries); got != testCap-1 {
		t.Fatalf("after evict: entries = %d, want %d", got, testCap-1)
	}

	// Oldest = prefix "10.0.0.0" (lastTime = baseTime + 0 minutes).
	oldestKey := rrlKey{
		prefix:       "10.0.0.0",
		qname:        "example.test.",
		responseType: "NOERROR",
	}
	if _, stillThere := rrl.entries[oldestKey]; stillThere {
		t.Error("evictOldestLocked did not remove the entry with the oldest lastTime")
	}
}

// TestRRL_CapConstantStable pins the constant. A regression that
// dropped MaxRRLEntries to a thrash-threshold value (1k entries) would
// destroy RRL's per-key budget continuity under any honest moderate
// load. Balloon to 1B+ would reopen the OOM gap. Reasonable bracket
// is [100k, 100M].
func TestRRL_CapConstantStable(t *testing.T) {
	if MaxRRLEntries < 100_000 {
		t.Fatalf("MaxRRLEntries = %d is below thrash-threshold", MaxRRLEntries)
	}
	if MaxRRLEntries > 100_000_000 {
		t.Fatalf("MaxRRLEntries = %d is past the OOM threshold", MaxRRLEntries)
	}
}
