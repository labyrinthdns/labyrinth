package web

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestApplyUpdate_Singleflight pins the v0.7.56 gate: concurrent
// POSTs to /api/system/update/apply must serialise on
// updateApplyRunning rather than each downloading the binary, racing
// for the Windows .old rename, and triggering parallel restart()
// invocations. A single misclick in the dashboard that fires the
// mutation twice (or a duplicated WebSocket-triggered click after
// the v0.7.53 blocklist refresh pattern) would otherwise hit the
// disk twice and corrupt the rename sequence.
//
// The pin parks the FIRST checkForUpdate call (via the mocked HTTP
// transport blocking on a channel until the test releases it) so the
// gate is held while the test fires N more contending POSTs. The
// contenders must all see 409 immediately; only the first call —
// which we release after the contenders complete — runs to a
// terminal status code. The test counts: contenders 409, first call
// non-409.
func TestApplyUpdate_Singleflight(t *testing.T) {
	srv := testAdminServer(t)

	prevVersion := Version
	Version = "v0.4.1"
	defer func() { Version = prevVersion }()

	// First call parks inside checkForUpdate until the test releases.
	// Subsequent calls under the gate never reach this transport
	// because the CAS gate short-circuits them before the upstream
	// fetch happens.
	firstHit := make(chan struct{}, 1)
	release := make(chan struct{})
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		select {
		case firstHit <- struct{}{}:
			// First request: hold here until release.
			<-release
		default:
			// Should not happen — gate must block contenders before
			// they call out. If we reach here, the gate is broken.
			t.Errorf("contender reached upstream transport — singleflight gate not effective")
		}
		// After release, return a benign already-up-to-date response
		// so the first POST terminates without touching the file
		// system.
		return jsonHTTP(http.StatusOK, `{
			"tag_name":"v0.4.1",
			"html_url":"https://example/release",
			"body":"notes",
			"assets":[]
		}`), nil
	})

	// Fire the first POST; it parks at the upstream transport.
	firstResult := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
		rec := httptest.NewRecorder()
		srv.handleApplyUpdate(rec, req)
		firstResult <- rec.Code
	}()

	// Wait until the first call is actually inside the gate.
	select {
	case <-firstHit:
	case <-time.After(5 * time.Second):
		t.Fatal("first update-apply POST never reached the upstream transport")
	}

	// Now fire 9 contending POSTs — all must CAS-fail and return 409.
	const N = 9
	var (
		got409 atomic.Int32
		other  atomic.Int32
	)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
			rec := httptest.NewRecorder()
			srv.handleApplyUpdate(rec, req)
			if rec.Code == http.StatusConflict {
				got409.Add(1)
			} else {
				other.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := got409.Load(); got != N {
		t.Errorf("contenders 409 = %d, want %d — singleflight gate not blocking concurrent applies", got, N)
	}
	if got := other.Load(); got != 0 {
		t.Errorf("contenders saw %d non-409 responses — gate leaked", got)
	}

	// Release the first POST and verify it ran to completion.
	close(release)
	select {
	case code := <-firstResult:
		if code == http.StatusConflict {
			t.Errorf("first POST returned 409 — gate self-rejected the very first caller")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first update-apply POST never returned after release")
	}
}
