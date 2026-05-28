package dnssec

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGetOrCreateNTAStore_RaceFree pins the v0.7.59 gate: concurrent
// callers to GetOrCreateNTAStore must all observe the SAME *NTAStore
// pointer. The handler /api/dnssec/nta lazily-inits the store on
// first POST; before v0.7.59 the sequence Load → if nil → New →
// Store was three separate operations, so two concurrent admin
// POSTs both saw nil, both created stores, and the loser's
// store.Add wrote to an orphaned store that the validator never
// consulted via NTAStore() — the NTA silently never took effect.
//
// The pin fires 100 concurrent GetOrCreateNTAStore calls on a fresh
// validator (ntaStore = nil) and asserts every returned pointer is
// identical to the validator's currently-wired NTAStore(). The CAS
// guarantees exactly one fresh store is published; the test confirms
// the loser branch returns the winner's store (Load after failed
// CAS) rather than a stale orphan.
func TestGetOrCreateNTAStore_RaceFree(t *testing.T) {
	v := NewValidator(nil, nil)

	const N = 100
	var (
		wg      sync.WaitGroup
		results [N]*NTAStore
	)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = v.GetOrCreateNTAStore()
		}(i)
	}
	close(start)
	wg.Wait()

	canonical := v.NTAStore()
	if canonical == nil {
		t.Fatal("validator.NTAStore() is nil after GetOrCreateNTAStore — CAS publish never happened")
	}
	for i, got := range results {
		if got != canonical {
			t.Errorf("goroutine %d returned a different *NTAStore than v.NTAStore() — lazy-init race not closed", i)
		}
	}

	// Smoke test: writes to the canonical store must be visible to
	// every previously-returned pointer (they should all be the same
	// pointer, so this is a redundancy check).
	canonical.Add("nta-race.test", time.Now().Add(time.Hour), "pin test")
	hits := atomic.Int32{}
	for _, got := range results {
		if _, matched := got.Match("nta-race.test"); matched {
			hits.Add(1)
		}
	}
	if hits.Load() != N {
		t.Errorf("only %d of %d returned stores see the canonical Add — orphaned stores still leaking", hits.Load(), N)
	}
}
