package blocklist

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRefreshAll_Singleflight pins the v0.7.53 gate: only one
// RefreshAll may be in flight at a time. A repeated admin POST to
// /api/blocklist/refresh — or the background tick racing with an
// operator click — would otherwise spawn N concurrent goroutines
// each pulling every upstream blocklist URL. The CAS leaves the
// gate untouched on collision so the in-flight refresh continues.
//
// The pin uses an upstream that signals when it is hit and holds
// until the test releases it. That makes the timing deterministic:
// (1) start the first refresh in a goroutine and wait until the
// upstream confirms it's running, (2) spawn 9 more refreshes that
// must hit the CAS gate and return immediately, (3) release the
// upstream and the first refresh completes. Total upstream hits = 1.
func TestRefreshAll_Singleflight(t *testing.T) {
	var hits atomic.Int32

	upstreamRunning := make(chan struct{})
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			close(upstreamRunning) // signal the test that we're inside the first refresh
		}
		<-release // hold until the test lets go
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("example.test\n"))
	}))
	defer srv.Close()

	mgr := NewManager(ManagerConfig{
		Lists: []ListEntry{{
			URL:    srv.URL,
			Format: "hosts",
		}},
	}, nil)

	// Start the first refresh — it will block inside the upstream.
	firstDone := make(chan struct{})
	go func() {
		mgr.RefreshAll()
		close(firstDone)
	}()
	<-upstreamRunning // first refresh is confirmed in flight

	// Now spawn 9 contending refreshes. The CAS gate is taken by the
	// first refresh, so all 9 must return immediately without touching
	// the upstream.
	var wg sync.WaitGroup
	for i := 0; i < 9; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.RefreshAll()
		}()
	}
	wg.Wait()

	// Release the held first refresh and let it finish.
	close(release)
	<-firstDone

	if got := hits.Load(); got != 1 {
		t.Errorf("upstream was hit %d times, want 1 — singleflight gate not effective", got)
	}
}
