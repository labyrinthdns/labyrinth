package web

import (
	"fmt"
	"testing"
	"time"
)

// TestRecordQuery_ClientQueryNumCapWithLRU pins the v0.7.66 gate:
// AdminServer.clientQueryNum must cap and LRU-evict on insert so a
// UDP-source-spoofing flood (or a legitimate flash crowd of distinct
// clients) cannot bloat resolver RAM between cleanup ticks. Before
// v0.7.66 the map only shrank via the periodic TTL cleanup; an
// attacker sending packets from 1M distinct spoofed source IPs in
// the 10-minute window before the 2x cleanup TTL hit could pin
// ~100 MB+ of per-client counter state.
//
// The pin uses a small clientQueryNumCapOverride (4) so the cap is
// reachable in microseconds. It seeds the map to capacity with
// monotonically-increasing lastAccess, calls RecordQuery for a
// fresh client, and asserts:
//   (1) the map stayed at the cap,
//   (2) the new client is now tracked,
//   (3) the OLDEST seeded client was evicted.
func TestRecordQuery_ClientQueryNumCapWithLRU(t *testing.T) {
	srv := testAdminServer(t)
	srv.clientQueryNumCapOverride = 4

	base := time.Now().Add(-time.Hour)
	srv.clientNumMu.Lock()
	for i := 0; i < 4; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		srv.clientQueryNum[ip] = &clientQueryEntry{
			lastAccess: base.Add(time.Duration(i) * time.Millisecond),
		}
	}
	srv.clientNumMu.Unlock()
	if got := len(srv.clientQueryNum); got != 4 {
		t.Fatalf("seed: clientQueryNum size = %d, want 4", got)
	}

	oldestKey := "10.0.0.0"
	if _, present := srv.clientQueryNum[oldestKey]; !present {
		t.Fatalf("seed: oldest key %q missing", oldestKey)
	}

	srv.RecordQuery("203.0.113.42", "example.test", "A", "NOERROR", false, 1.0)

	srv.clientNumMu.Lock()
	defer srv.clientNumMu.Unlock()
	if got := len(srv.clientQueryNum); got != 4 {
		t.Errorf("clientQueryNum size after over-cap RecordQuery = %d, want 4 (LRU eviction did not maintain the cap)", got)
	}
	if _, present := srv.clientQueryNum["203.0.113.42"]; !present {
		t.Errorf("new client not present in clientQueryNum after RecordQuery")
	}
	if _, present := srv.clientQueryNum[oldestKey]; present {
		t.Errorf("oldest LRU entry %q was NOT evicted — eviction policy is broken", oldestKey)
	}
}

// TestRecordQuery_ExistingClientNotEvictedByCap pins that the cap
// only fires on NEW client insertion. A returning client at or
// past the cap must continue updating its bucket and incrementing
// its counter normally — the cap must not silently reset legitimate
// repeat callers.
func TestRecordQuery_ExistingClientNotEvictedByCap(t *testing.T) {
	srv := testAdminServer(t)
	srv.clientQueryNumCapOverride = 4

	const known = "198.51.100.5"
	srv.RecordQuery(known, "first.example", "A", "NOERROR", false, 1.0)

	// Fill the map with three more distinct clients to reach the cap.
	srv.RecordQuery("203.0.113.1", "q.example", "A", "NOERROR", false, 1.0)
	srv.RecordQuery("203.0.113.2", "q.example", "A", "NOERROR", false, 1.0)
	srv.RecordQuery("203.0.113.3", "q.example", "A", "NOERROR", false, 1.0)

	// Now the known client comes back. Its entry must NOT have been
	// evicted by its own update (cap only checks on NEW inserts).
	srv.RecordQuery(known, "second.example", "A", "NOERROR", false, 1.0)

	srv.clientNumMu.Lock()
	entry, present := srv.clientQueryNum[known]
	srv.clientNumMu.Unlock()
	if !present {
		t.Fatal("known client entry was evicted by its own RecordQuery — cap fires on existing-client updates, not just new inserts")
	}
	if got := entry.count.Load(); got != 2 {
		t.Errorf("known client count = %d, want 2 (cap must not reset counter for returning clients)", got)
	}
}
