package cache

import (
	"fmt"
	"testing"
	"time"
)

// TestNSECIndex_ZoneCapEviction pins the v0.7.67 gate: when the
// per-zone NSEC interval map reaches MaxNSECZones, registering an
// interval for a NEW zone must evict the zone whose freshest
// interval has the OLDEST registeredAt timestamp. Before v0.7.67
// the byZone map grew without bound across distinct zones; an
// attacker controlling many DNSSEC-signed sibling zones could
// flood the resolver with Secure NXDOMAIN responses whose SOAs
// name distinct zones, pinning unbounded RAM (each entry holds
// SOA + NSEC + RRSIG bytes — a few KB each).
//
// The pin operates on the index helper directly (production path
// goes through RegisterNSECInterval which requires real NSEC RRs);
// we synthesise byZone entries with monotonically-increasing
// registeredAt and call evictOldestZoneLocked, asserting the
// zone with the OLDEST freshest-interval is the one dropped.
func TestNSECIndex_ZoneCapEviction(t *testing.T) {
	idx := newNSECIndex()

	const seed = 5
	base := time.Now().Add(-time.Hour)
	for i := 0; i < seed; i++ {
		zone := fmt.Sprintf("zone-%d.example", i)
		// One interval per zone, registeredAt increases with i.
		idx.byZone[zone] = []nsecInterval{{
			owner:        "a." + zone,
			next:         "z." + zone,
			expiresAt:    time.Now().Add(time.Hour),
			registeredAt: base.Add(time.Duration(i) * time.Millisecond),
		}}
	}
	if got := len(idx.byZone); got != seed {
		t.Fatalf("seed: zone count = %d, want %d", got, seed)
	}

	// The zone with the oldest freshest-interval is "zone-0.example"
	// (i=0). Evict and check.
	oldestZone := "zone-0.example"
	idx.evictOldestZoneLocked()

	if got := len(idx.byZone); got != seed-1 {
		t.Errorf("zone count after eviction = %d, want %d", got, seed-1)
	}
	if _, present := idx.byZone[oldestZone]; present {
		t.Errorf("oldest zone %q was NOT evicted — eviction policy is broken", oldestZone)
	}
	// Sanity: other zones still present.
	for i := 1; i < seed; i++ {
		zone := fmt.Sprintf("zone-%d.example", i)
		if _, present := idx.byZone[zone]; !present {
			t.Errorf("zone %q was evicted but should not have been", zone)
		}
	}
}

// TestNSECIndex_MaxZonesConstantIsSane is a tripwire on the cap
// constant: a future refactor that drops it to a tiny value
// (degrading aggressive-use cache hit rate) or balloons it to
// gigabytes (re-introducing the DoS) should be caught here.
func TestNSECIndex_MaxZonesConstantIsSane(t *testing.T) {
	if MaxNSECZones < 1000 {
		t.Errorf("MaxNSECZones = %d, too small — aggressive-use cache becomes useless below ~1k zones", MaxNSECZones)
	}
	if MaxNSECZones > 1_000_000 {
		t.Errorf("MaxNSECZones = %d, too large — defeats the DoS defence (per-entry footprint is multiple KB)", MaxNSECZones)
	}
}

// TestNSEC3Index_ZoneCapEviction is the NSEC3 counterpart.
func TestNSEC3Index_ZoneCapEviction(t *testing.T) {
	idx := newNSEC3Index()

	const seed = 5
	base := time.Now().Add(-time.Hour)
	for i := 0; i < seed; i++ {
		zone := fmt.Sprintf("zone3-%d.example", i)
		idx.byZone[zone] = []nsec3Interval{{
			ownerHash:    []byte{byte(i)},
			nextHash:     []byte{byte(i + 1)},
			expiresAt:    time.Now().Add(time.Hour),
			registeredAt: base.Add(time.Duration(i) * time.Millisecond),
		}}
	}
	oldestZone := "zone3-0.example"
	idx.evictOldestZoneLocked()
	if got := len(idx.byZone); got != seed-1 {
		t.Errorf("zone3 count after eviction = %d, want %d", got, seed-1)
	}
	if _, present := idx.byZone[oldestZone]; present {
		t.Errorf("oldest zone %q was NOT evicted — NSEC3 eviction policy broken", oldestZone)
	}
}
