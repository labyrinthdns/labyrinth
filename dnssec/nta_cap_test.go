package dnssec

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestNTAStore_AddCapEnforced pins the v0.7.63 gate: NTAStore.Add
// must refuse new entries past MaxNTAEntries. Before v0.7.63 the
// store grew without bound; an authenticated admin spamming
// /api/dnssec/nta — accidentally via a runaway script or maliciously
// — could grow the map without limit, and the map is consulted on
// EVERY DNSSEC-validated query through Match. The cap stops the
// growth at ~10k entries (real operator NTA lists are a handful).
//
// The pin fills the store to the cap, then asserts:
//   (1) the (cap+1)th distinct Add returns ErrNTAStoreFull,
//   (2) the store size did NOT grow past the cap,
//   (3) re-adding an EXISTING zone at the cap continues to succeed
//       (replacement is the documented "extend the window" path
//        and must not be broken by the cap).
func TestNTAStore_AddCapEnforced(t *testing.T) {
	store := NewNTAStore()
	expiry := time.Now().Add(24 * time.Hour)

	for i := 0; i < MaxNTAEntries; i++ {
		if err := store.Add(fmt.Sprintf("nta-cap-%d.example", i), expiry, "fill"); err != nil {
			t.Fatalf("Add %d returned unexpected error before cap: %v", i, err)
		}
	}
	if len(store.entries) != MaxNTAEntries {
		t.Fatalf("store size = %d, want %d after filling to cap", len(store.entries), MaxNTAEntries)
	}

	// (1) New entry must be rejected.
	err := store.Add("overflow.example", expiry, "overflow")
	if !errors.Is(err, ErrNTAStoreFull) {
		t.Errorf("Add past cap returned %v, want ErrNTAStoreFull", err)
	}
	// (2) Size did not grow.
	if len(store.entries) != MaxNTAEntries {
		t.Errorf("store size after rejected add = %d, want %d (map must not grow past cap)", len(store.entries), MaxNTAEntries)
	}

	// (3) Replacement of existing zone still succeeds at cap.
	extendedExpiry := time.Now().Add(48 * time.Hour)
	if err := store.Add("nta-cap-0.example", extendedExpiry, "extended"); err != nil {
		t.Errorf("replacement of existing zone at cap returned %v, want nil", err)
	}
	// And the replacement actually took effect (new expiry stored).
	store.mu.RLock()
	got := store.entries["nta-cap-0.example."]
	store.mu.RUnlock()
	if !got.Expiry.Equal(extendedExpiry) {
		t.Errorf("replacement at cap did not update expiry: got %v, want %v", got.Expiry, extendedExpiry)
	}
}
