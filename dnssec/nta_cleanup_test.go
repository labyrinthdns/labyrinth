package dnssec

import (
	"testing"
	"time"
)

// TestNTAStore_CleanupPrunesExpiredEntries pins the v0.8.7 gate: NTAStore.Cleanup
// must remove entries whose Expiry has passed and leave still-active entries
// untouched. The store-side primitive existed since v0.6.x but was never wired
// up — expired entries sat in s.entries forever, consuming slots toward
// MaxNTAEntries=10000 even though Lookup ignored them.
//
// With the per-store cap, an attacker (or careless operator) who installs 10k
// NTAs with 1-minute expiry permanently fills the cap once the entries expire,
// blocking legitimate NTA installs until the resolver is restarted. The fix is
// to call Cleanup on a schedule from main; this pin guards the primitive.
func TestNTAStore_CleanupPrunesExpiredEntries(t *testing.T) {
	store := NewNTAStore()

	pastExpiry := time.Now().Add(-time.Hour)
	futureExpiry := time.Now().Add(time.Hour)

	// Bypass the public Add (which rejects past expiries) and seed
	// directly via the same code path Cleanup walks. Three expired
	// + two active.
	store.mu.Lock()
	store.entries["expired1.test."] = NegativeTrustAnchor{Zone: "expired1.test.", Expiry: pastExpiry, Reason: "test"}
	store.entries["expired2.test."] = NegativeTrustAnchor{Zone: "expired2.test.", Expiry: pastExpiry, Reason: "test"}
	store.entries["expired3.test."] = NegativeTrustAnchor{Zone: "expired3.test.", Expiry: pastExpiry, Reason: "test"}
	store.entries["active1.test."] = NegativeTrustAnchor{Zone: "active1.test.", Expiry: futureExpiry, Reason: "test"}
	store.entries["active2.test."] = NegativeTrustAnchor{Zone: "active2.test.", Expiry: futureExpiry, Reason: "test"}
	store.mu.Unlock()

	removed := store.Cleanup()
	if removed != 3 {
		t.Errorf("Cleanup removed %d entries, want 3", removed)
	}

	store.mu.Lock()
	got := len(store.entries)
	store.mu.Unlock()
	if got != 2 {
		t.Errorf("after Cleanup len(entries) = %d, want 2", got)
	}

	// Sanity: the two active entries survived.
	for _, zone := range []string{"active1.test.", "active2.test."} {
		store.mu.Lock()
		_, present := store.entries[zone]
		store.mu.Unlock()
		if !present {
			t.Errorf("active entry %s was wrongly removed", zone)
		}
	}
}

// TestNTAStore_CleanupOnEmptyStoreIsSafe pins that Cleanup on an empty store
// returns 0 and does not panic. The cleanup goroutine in main ticks every
// minute regardless of operator state, so this no-op path runs constantly.
func TestNTAStore_CleanupOnEmptyStoreIsSafe(t *testing.T) {
	store := NewNTAStore()
	if got := store.Cleanup(); got != 0 {
		t.Errorf("Cleanup on empty store returned %d, want 0", got)
	}
}
