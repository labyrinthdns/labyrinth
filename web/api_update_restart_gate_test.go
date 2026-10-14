package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// handleApplyUpdate returns 200 before the restart it schedules has run. The
// singleflight gate must stay held across that window: a second apply there
// would download and install again and schedule a second restart. If the
// restart itself fails, the gate has to open again so the operator can retry.

type restartGateEnv struct {
	srv       *AdminServer
	downloads atomic.Int32
	restarts  atomic.Int32
	inSleep   chan struct{}
	release   chan struct{}
	restarted chan struct{}
}

func newRestartGateEnv(t *testing.T, restartErr error) *restartGateEnv {
	t.Helper()
	withUpdateHooksReset(t)
	prevVersion := Version
	Version = "v0.4.1"
	t.Cleanup(func() { Version = prevVersion })

	e := &restartGateEnv{srv: testAdminServer(t), inSleep: make(chan struct{}, 4), release: make(chan struct{}), restarted: make(chan struct{}, 4)}
	assetName := fmt.Sprintf("labyrinth-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}
	body := []byte("new-binary-bytes")
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		switch classifyUpdateURL(r.URL.String()) {
		case "release":
			return jsonHTTP(http.StatusOK, releaseJSON(assetName)), nil
		case "checksums":
			return stringHTTP(http.StatusOK, checksumsBody(assetName, body)), nil
		default:
			e.downloads.Add(1)
			return stringHTTP(http.StatusOK, string(body)), nil
		}
	})
	exePath := filepath.Join(t.TempDir(), "labyrinth")
	if err := os.WriteFile(exePath, []byte("old"), 0o755); err != nil {
		t.Fatalf("os.WriteFile exe: %v", err)
	}
	updateExecutable = func() (string, error) { return exePath, nil }
	updateEvalSymlinks = func(p string) (string, error) { return p, nil }
	// The scheduled restart parks here until the test releases it.
	updateSleep = func(time.Duration) {
		e.inSleep <- struct{}{}
		<-e.release
	}
	updateRestartSelf = func() error {
		e.restarts.Add(1)
		e.restarted <- struct{}{}
		return restartErr
	}
	return e
}

func (e *restartGateEnv) apply() int {
	rec := httptest.NewRecorder()
	e.srv.handleApplyUpdate(rec, httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil))
	return rec.Code
}

func (e *restartGateEnv) waitRestartPending(t *testing.T) {
	t.Helper()
	select {
	case <-e.inSleep:
	case <-time.After(5 * time.Second):
		t.Fatal("restart goroutine never scheduled")
	}
}

// finishRestart releases the parked restart and waits until the restart hook
// ran, so the goroutine is done with the update hooks before cleanup restores
// them.
func (e *restartGateEnv) finishRestart(t *testing.T) {
	t.Helper()
	close(e.release)
	select {
	case <-e.restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("restart hook never ran")
	}
}

func TestApplyUpdate_GateHeldWhileRestartPending(t *testing.T) {
	e := newRestartGateEnv(t, nil)
	if code := e.apply(); code != http.StatusOK {
		t.Fatalf("first apply = %d, want 200", code)
	}
	e.waitRestartPending(t)

	if code := e.apply(); code != http.StatusConflict {
		t.Fatalf("apply while restart pending = %d, want 409", code)
	}
	if got := e.downloads.Load(); got != 1 {
		t.Fatalf("downloads = %d, want 1", got)
	}
	e.finishRestart(t)
}

func TestApplyUpdate_GateReopensWhenRestartFails(t *testing.T) {
	e := newRestartGateEnv(t, errors.New("exec failed"))
	if code := e.apply(); code != http.StatusOK {
		t.Fatalf("first apply = %d, want 200", code)
	}
	e.waitRestartPending(t)
	e.finishRestart(t)

	deadline := time.Now().Add(5 * time.Second)
	for e.srv.updateApplyRunning.Load() {
		if time.Now().After(deadline) {
			t.Fatal("gate still held after the restart failed")
		}
		runtime.Gosched()
	}
	if got := e.restarts.Load(); got != 1 {
		t.Fatalf("restarts = %d, want 1", got)
	}

	// The operator can retry: a new apply runs and schedules a new restart.
	e.release = make(chan struct{})
	if code := e.apply(); code != http.StatusOK {
		t.Fatalf("retry after failed restart = %d, want 200", code)
	}
	e.waitRestartPending(t)
	e.finishRestart(t)
	// The failed restart reopens the gate as its last step; wait for that so
	// the goroutine has finished before cleanup.
	for e.srv.updateApplyRunning.Load() {
		runtime.Gosched()
	}
}
