package resolver

import (
	"fmt"
	"testing"
	"time"
)

// TestInfraCache_EntriesCapWithLRUEviction pins the v0.7.64 gate:
// InfraCache.entries must cap at MaxInfraCacheEntries via oldest-
// LastUsed eviction. Before v0.7.64 the map grew on every distinct
// nameserver IP we contacted; an attacker controlling an
// authoritative server could serve unique NS IPs per query and
// bloat resolver RAM between CleanStale ticks.
//
// The pin fills the cache to the cap with synthetic IPs at
// increasing LastUsed timestamps, then triggers one more insert
// and asserts (a) the cache size stays at the cap, (b) the
// inserted entry is present, and (c) the entry with the OLDEST
// LastUsed was the one that got evicted.
func TestInfraCache_EntriesCapWithLRUEviction(t *testing.T) {
	ic := NewInfraCache()

	// Seed the cache to capacity with monotonically-increasing
	// LastUsed so the eviction order is deterministic.
	base := time.Now().Add(-time.Hour)
	for i := 0; i < MaxInfraCacheEntries; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		ic.entries[ip] = &NSInfo{
			LameZones: make(map[string]struct{}),
			LastUsed:  base.Add(time.Duration(i) * time.Millisecond),
		}
	}
	if got := len(ic.entries); got != MaxInfraCacheEntries {
		t.Fatalf("seed: cache size = %d, want %d", got, MaxInfraCacheEntries)
	}

	// The oldest entry (i=0) is "10.0.0.0". Force an insert via the
	// public API; the cap must trigger eviction of "10.0.0.0".
	oldestKey := "10.0.0.0"
	if _, present := ic.entries[oldestKey]; !present {
		t.Fatalf("seed: oldest key %q missing", oldestKey)
	}
	ic.RecordRTT("new.tracked.ns", 42*time.Millisecond)

	if got := len(ic.entries); got != MaxInfraCacheEntries {
		t.Errorf("cache size after over-cap insert = %d, want %d (LRU eviction did not maintain the cap)", got, MaxInfraCacheEntries)
	}
	if _, present := ic.entries["new.tracked.ns"]; !present {
		t.Errorf("new entry not present in cache after over-cap insert")
	}
	if _, present := ic.entries[oldestKey]; present {
		t.Errorf("oldest LRU entry %q was NOT evicted — eviction policy is broken", oldestKey)
	}
}

// TestInfraCache_LameZonesCapPerNS pins the per-NSInfo LameZones cap.
// An attacker controlling one upstream NS can otherwise inflate that
// NSInfo's LameZones map without bound by serving lame referrals for
// crafted sub-zones. The cap stops the growth at MaxLameZonesPerNS
// without breaking the NSInfo's primary role (RTT / FailCount keep
// updating).
func TestInfraCache_LameZonesCapPerNS(t *testing.T) {
	ic := NewInfraCache()
	const nsIP = "192.0.2.1"

	for i := 0; i < MaxLameZonesPerNS; i++ {
		ic.RecordLame(nsIP, fmt.Sprintf("lame-%d.example", i))
	}
	ic.mu.RLock()
	got := len(ic.entries[nsIP].LameZones)
	ic.mu.RUnlock()
	if got != MaxLameZonesPerNS {
		t.Fatalf("LameZones size after filling to cap = %d, want %d", got, MaxLameZonesPerNS)
	}

	// One more distinct zone — must be silently dropped.
	ic.RecordLame(nsIP, "overflow.example")
	ic.mu.RLock()
	got = len(ic.entries[nsIP].LameZones)
	ic.mu.RUnlock()
	if got != MaxLameZonesPerNS {
		t.Errorf("LameZones size after over-cap RecordLame = %d, want %d (cap not enforced)", got, MaxLameZonesPerNS)
	}

	// Existing zones remain recordable (idempotent updates must not
	// be blocked by the cap).
	ic.RecordLame(nsIP, "lame-0.example")
	ic.mu.RLock()
	got = len(ic.entries[nsIP].LameZones)
	ic.mu.RUnlock()
	if got != MaxLameZonesPerNS {
		t.Errorf("LameZones size after idempotent re-record = %d, want %d", got, MaxLameZonesPerNS)
	}

	// The NSInfo still tracks RTT — the cap degrades lame-tracking
	// but must not break the primary cache function.
	ic.RecordRTT(nsIP, 100*time.Millisecond)
	if rtt := ic.GetRTT(nsIP); rtt == 0 {
		t.Error("RecordRTT not honoured after LameZones cap was hit — NSInfo function degraded beyond lame-tracking")
	}
}
