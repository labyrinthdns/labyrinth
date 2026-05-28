package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestSetupComplete_Singleflight pins the v0.7.55 gate: concurrent
// POSTs to /api/setup/complete must not race past the setupDone check
// into writeConfigYAML, where os.Create's O_TRUNC semantics let the
// second writer blow away the first writer's bytes mid-flush and
// produce a corrupt config on disk. The endpoint is unauthenticated
// by design (it bootstraps the very first admin), so an attacker
// reaching it before a legitimate operator could fire dozens of
// concurrent POSTs to exploit the race.
//
// The pin fires 50 concurrent setup-complete requests with the same
// valid body and asserts exactly one succeeds with 200 — the others
// must see 409 (setup already in progress / completed). The CAS gate
// guarantees serialization; without it the race window between the
// setupDone read and the file-write would let multiple requests reach
// disk-write at once.
func TestSetupComplete_Singleflight(t *testing.T) {
	srv := testAdminServer(t)
	srv.setupDone.Store(false)
	srv.config.Web.Auth.Username = "" // pass-through auth
	// Point config at a temp file so the test does not litter cwd.
	cfgPath := t.TempDir() + "/labyrinth.yaml"
	srv.SetConfigPath(cfgPath)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"username":"admin","password":"validpwd123","listen_addr":":5353"}`

	var (
		ok409 atomic.Int32
		ok200 atomic.Int32
		other atomic.Int32
	)

	const N = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(body))
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			switch w.Code {
			case http.StatusOK:
				ok200.Add(1)
			case http.StatusConflict:
				ok409.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := ok200.Load(); got != 1 {
		t.Errorf("ok200 = %d, want exactly 1 — singleflight gate not serialising concurrent setup requests", got)
	}
	if got := ok409.Load(); got != N-1 {
		t.Errorf("ok409 = %d, want %d — losers must see 409 setup-in-progress / already-completed", got, N-1)
	}
	if got := other.Load(); got != 0 {
		t.Errorf("unexpected non-200/non-409 responses: %d", got)
	}
	if !srv.setupDone.Load() {
		t.Error("setupDone should be true after a successful setup")
	}
}
