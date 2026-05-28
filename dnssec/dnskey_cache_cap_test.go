package dnssec

import (
	"fmt"
	"testing"
	"time"
)

// TestDNSKEYCache_EvictionPicksOldest pins the v0.7.68 gate:
// evictOldestDNSKEYLocked must drop the entry with the OLDEST
// fetchedAt timestamp. Before v0.7.68 the keyCache grew without
// bound across distinct DNSSEC-signed zones; an attacker
// controlling many zones can pin gigabytes of cached DNSKEY RR
// bytes by driving the resolver to fetch keys for distinct zones
// at sustained rates.
//
// The pin directly populates keyCache with synthetic entries at
// monotonically-increasing fetchedAt timestamps and asserts the
// eviction helper drops the entry with the oldest timestamp.
func TestDNSKEYCache_EvictionPicksOldest(t *testing.T) {
	v := NewValidator(nil, nil)

	const seed = 5
	base := time.Now().Add(-time.Hour)
	for i := 0; i < seed; i++ {
		zone := fmt.Sprintf("zone-%d.example.", i)
		v.keyCache[zone] = &dnskeyCache{
			fetchedAt: base.Add(time.Duration(i) * time.Millisecond),
			ttl:       time.Hour,
		}
	}
	if got := len(v.keyCache); got != seed {
		t.Fatalf("seed: keyCache size = %d, want %d", got, seed)
	}

	oldestKey := "zone-0.example."
	v.evictOldestDNSKEYLocked()

	if got := len(v.keyCache); got != seed-1 {
		t.Errorf("keyCache size after eviction = %d, want %d", got, seed-1)
	}
	if _, present := v.keyCache[oldestKey]; present {
		t.Errorf("oldest key %q was NOT evicted — eviction policy is broken", oldestKey)
	}
}

// TestDNSKEYCache_MaxEntriesConstantIsSane is a tripwire on the cap
// constant. A refactor that pushed it below a few thousand would
// turn keyCache into a thrashing cache for any modestly-sized
// recursive resolver; one that ballooned it to gigabyte-scale
// would re-introduce the DoS.
func TestDNSKEYCache_MaxEntriesConstantIsSane(t *testing.T) {
	if MaxDNSKEYCacheEntries < 1000 {
		t.Errorf("MaxDNSKEYCacheEntries = %d, too small — keyCache thrashes below ~1k", MaxDNSKEYCacheEntries)
	}
	if MaxDNSKEYCacheEntries > 1_000_000 {
		t.Errorf("MaxDNSKEYCacheEntries = %d, too large — defeats DoS cap (per-entry ~1 KB)", MaxDNSKEYCacheEntries)
	}
}
