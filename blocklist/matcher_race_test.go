package blocklist

import (
	"sync"
	"testing"
)

// TestManager_MatcherSwapIsRaceFree pins the v0.8.17 gate: RefreshAll
// publishes new *Matcher and *RPZMatcher pointers; IsBlocked and
// RPZAction read those pointers on every DNS query (the hot path).
// Until v0.8.17 the field type was plain *Matcher; the writer took
// mgr.mu.Lock() but the readers took nothing. Go pointer stores are
// atomic in practice, but the memory model gives no happens-before
// edge without sync, so a reader on a weak-ordering CPU could keep
// observing the pre-refresh matcher indefinitely after a swap —
// effectively serving queries against the old blocklist until the
// reader's core happened to observe the new pointer.
//
// The fix migrates both fields to atomic.Pointer; this pin spawns
// N readers (IsBlocked — what the DNS handler calls) and one writer
// that swaps the matcher mid-flight, then asserts no read panicked
// and the final published pointer is non-nil.
func TestManager_MatcherSwapIsRaceFree(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newSilentLogger())
	mgr.matcher.Load().AddExact("ads.example.com")

	const (
		readers = 8
		ops     = 500
	)

	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				// Mirror the hot path. Whether the result is true or false
				// is irrelevant; what matters is that the call does not
				// nil-deref or read torn matcher state.
				_ = mgr.IsBlocked("ads.example.com")
				_ = mgr.RPZAction("malware.test")
			}
		}()
	}

	// Writer: swap matchers a handful of times mid-stream.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			fresh := NewMatcher()
			fresh.AddExact("ads.example.com")
			mgr.matcher.Store(fresh)
			mgr.rpzMatcher.Store(NewRPZMatcher())
		}
	}()

	wg.Wait()

	if mgr.matcher.Load() == nil {
		t.Fatal("after swap storm, matcher pointer is nil")
	}
	if mgr.rpzMatcher.Load() == nil {
		t.Fatal("after swap storm, rpzMatcher pointer is nil")
	}
}
