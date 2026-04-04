package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func withUpdateHooksReset(t *testing.T) {
	t.Helper()
	prevGet := updateHTTPGet
	prevExe := updateExecutable
	prevEval := updateEvalSymlinks
	prevCreateTemp := updateCreateTemp
	prevChmod := updateChmod
	prevRename := updateRename
	prevRemove := updateRemove
	prevSleep := updateSleep
	prevRestart := updateRestartSelf

	t.Cleanup(func() {
		updateHTTPGet = prevGet
		updateExecutable = prevExe
		updateEvalSymlinks = prevEval
		updateCreateTemp = prevCreateTemp
		updateChmod = prevChmod
		updateRename = prevRename
		updateRemove = prevRemove
		updateSleep = prevSleep
		updateRestartSelf = prevRestart
	})
}

func releaseJSON(assetName string) string {
	return `{
		"tag_name":"v0.4.2",
		"html_url":"https://example/release",
		"body":"notes",
		"assets":[{"name":"` + assetName + `","browser_download_url":"https://example/download"}]
	}`
}

func TestCheckForUpdate_HTTPAndDecodeErrors(t *testing.T) {
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonHTTP(http.StatusBadGateway, `{"error":"bad gateway"}`), nil
	})
	if _, err := checkForUpdate(); err == nil {
		t.Fatalf("expected checkForUpdate error for non-200 response")
	}

	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonHTTP(http.StatusOK, `{not-json}`), nil
	})
	if _, err := checkForUpdate(); err == nil {
		t.Fatalf("expected checkForUpdate decode error")
	}
}

func TestFindAssetURL_HTTPAndDecodeErrors(t *testing.T) {
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonHTTP(http.StatusInternalServerError, `{}`), nil
	})
	if _, err := findAssetURL("anything"); err == nil {
		t.Fatalf("expected findAssetURL error for non-200 response")
	}

	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonHTTP(http.StatusOK, `{not-json}`), nil
	})
	if _, err := findAssetURL("anything"); err == nil {
		t.Fatalf("expected findAssetURL decode error")
	}
}

func TestHandleApplyUpdate_AlreadyUpToDate(t *testing.T) {
	srv := testAdminServer(t)

	prevVersion := Version
	Version = "v0.4.2"
	defer func() { Version = prevVersion }()

	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonHTTP(http.StatusOK, `{
			"tag_name":"v0.4.2",
			"html_url":"https://example/release",
			"body":"notes",
			"assets":[]
		}`), nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec := httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := decodeJSON(t, rec)
	if body["status"] != "already up to date" {
		t.Fatalf("unexpected status response: %#v", body["status"])
	}
}

func TestHandleApplyUpdate_AssetNotFound(t *testing.T) {
	srv := testAdminServer(t)

	prevVersion := Version
	Version = "v0.4.1"
	defer func() { Version = prevVersion }()

	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonHTTP(http.StatusOK, `{
			"tag_name":"v0.4.2",
			"html_url":"https://example/release",
			"body":"notes",
			"assets":[
				{"name":"not-the-right-asset","browser_download_url":"https://example/asset"}
			]
		}`), nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec := httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
}

func TestHandleApplyUpdate_MethodAndFetchFailures(t *testing.T) {
	srv := testAdminServer(t)

	// Method not allowed branch.
	req := httptest.NewRequest(http.MethodGet, "/api/system/update/apply", nil)
	rec := httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}

	prevVersion := Version
	Version = "v0.4.1"
	defer func() { Version = prevVersion }()

	// Update check fetch failure branch.
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonHTTP(http.StatusBadGateway, `{"error":"upstream down"}`), nil
	})
	req = httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec = httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when checkForUpdate fails, got %d", rec.Code)
	}
}

func TestHandleApplyUpdate_DownloadFailures(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	prevVersion := Version
	Version = "v0.4.1"
	defer func() { Version = prevVersion }()

	assetName := "labyrinth-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}

	call := int32(0)
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		c := atomic.AddInt32(&call, 1)
		if c == 1 {
			// checkForUpdate
			return jsonHTTP(http.StatusOK, `{
				"tag_name":"v0.4.2",
				"html_url":"https://example/release",
				"body":"notes",
				"assets":[{"name":"`+assetName+`","browser_download_url":"https://example/download"}]
			}`), nil
		}
		if c == 2 {
			// findAssetURL
			return jsonHTTP(http.StatusOK, `{
				"tag_name":"v0.4.2",
				"html_url":"https://example/release",
				"body":"notes",
				"assets":[{"name":"`+assetName+`","browser_download_url":"https://example/download"}]
			}`), nil
		}
		// download URL status != 200
		return jsonHTTP(http.StatusBadGateway, `bad`), nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec := httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when download status is non-200, got %d", rec.Code)
	}
}

func TestHandleApplyUpdate_SuccessPathWithoutExit(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	prevVersion := Version
	Version = "v0.4.1"
	defer func() { Version = prevVersion }()

	assetName := "labyrinth-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}

	call := int32(0)
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		c := atomic.AddInt32(&call, 1)
		switch c {
		case 1, 2:
			return jsonHTTP(http.StatusOK, `{
				"tag_name":"v0.4.2",
				"html_url":"https://example/release",
				"body":"notes",
				"assets":[{"name":"`+assetName+`","browser_download_url":"https://example/download"}]
			}`), nil
		default:
			return jsonHTTP(http.StatusOK, "new-binary-bytes"), nil
		}
	})

	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "labyrinth.exe")
	if err := os.WriteFile(exePath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("os.WriteFile exe: %v", err)
	}

	updateExecutable = func() (string, error) { return exePath, nil }
	updateEvalSymlinks = func(path string) (string, error) { return path, nil }
	updateSleep = func(time.Duration) {}

	restartCalled := make(chan struct{}, 1)
	updateRestartSelf = func() error {
		select {
		case restartCalled <- struct{}{}:
		default:
		}
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec := httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for successful update, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeJSON(t, rec)
	if body["status"] != "updated" {
		t.Fatalf("unexpected status: %#v", body["status"])
	}

	select {
	case <-restartCalled:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected restart hook to be called")
	}

	updatedBytes, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatalf("os.ReadFile updated exe: %v", err)
	}
	if string(updatedBytes) != "new-binary-bytes" {
		t.Fatalf("unexpected exe contents: %q", string(updatedBytes))
	}
	if runtime.GOOS == "windows" {
		oldPath := exePath + ".old"
		if _, err := os.Stat(oldPath); err != nil {
			t.Fatalf("expected .old file on windows rename path: %v", err)
		}
	}
}

func TestHandleApplyUpdate_CreateTempError(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	prevVersion := Version
	Version = "v0.4.1"
	defer func() { Version = prevVersion }()

	assetName := "labyrinth-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}

	call := int32(0)
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		c := atomic.AddInt32(&call, 1)
		if c <= 2 {
			return jsonHTTP(http.StatusOK, `{
				"tag_name":"v0.4.2",
				"html_url":"https://example/release",
				"body":"notes",
				"assets":[{"name":"`+assetName+`","browser_download_url":"https://example/download"}]
			}`), nil
		}
		return jsonHTTP(http.StatusOK, "new-binary-bytes"), nil
	})

	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "labyrinth.exe")
	if err := os.WriteFile(exePath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("os.WriteFile exe: %v", err)
	}
	updateExecutable = func() (string, error) { return exePath, nil }
	updateEvalSymlinks = func(path string) (string, error) { return path, nil }
	updateCreateTemp = func(string, string) (*os.File, error) {
		return nil, fmt.Errorf("create temp failed")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec := httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for create temp failure, got %d", rec.Code)
	}
}

func TestHandleApplyUpdate_ExecutableAndEvalErrors(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	prevVersion := Version
	Version = "v0.4.1"
	defer func() { Version = prevVersion }()

	assetName := "labyrinth-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}

	call := int32(0)
	updateHTTPGet = func(url string) (*http.Response, error) {
		c := atomic.AddInt32(&call, 1)
		if c <= 2 {
			return jsonHTTP(http.StatusOK, releaseJSON(assetName)), nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("new-binary")),
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec := httptest.NewRecorder()

	updateExecutable = func() (string, error) { return "", errors.New("exe error") }
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for executable error, got %d", rec.Code)
	}

	call = 0
	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "labyrinth.exe")
	if err := os.WriteFile(exePath, []byte("old"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	updateExecutable = func() (string, error) { return exePath, nil }
	updateEvalSymlinks = func(string) (string, error) { return "", errors.New("symlink error") }

	req = httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec = httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for symlink resolution error, got %d", rec.Code)
	}
}

func TestHandleApplyUpdate_CopyAndRenameErrors(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	prevVersion := Version
	Version = "v0.4.1"
	defer func() { Version = prevVersion }()

	assetName := "labyrinth-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}

	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "labyrinth.exe")
	if err := os.WriteFile(exePath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	updateExecutable = func() (string, error) { return exePath, nil }
	updateEvalSymlinks = func(path string) (string, error) { return path, nil }

	call := int32(0)
	updateHTTPGet = func(string) (*http.Response, error) {
		c := atomic.AddInt32(&call, 1)
		if c <= 2 {
			return jsonHTTP(http.StatusOK, releaseJSON(assetName)), nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(errReader{}),
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec := httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for io.Copy error, got %d", rec.Code)
	}

	call = 0
	updateHTTPGet = func(string) (*http.Response, error) {
		c := atomic.AddInt32(&call, 1)
		if c <= 2 {
			return jsonHTTP(http.StatusOK, releaseJSON(assetName)), nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("new-binary")),
		}, nil
	}
	updateRename = func(oldpath, newpath string) error {
		if strings.Contains(newpath, ".old") || newpath == exePath {
			return errors.New("rename failed")
		}
		return os.Rename(oldpath, newpath)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	rec = httptest.NewRecorder()
	srv.handleApplyUpdate(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for rename failure, got %d", rec.Code)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read error")
}

func TestHandleCheckUpdate_MethodAndFreshCache(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	req := httptest.NewRequest(http.MethodPost, "/api/system/update/check", nil)
	rec := httptest.NewRecorder()
	srv.handleCheckUpdate(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for method not allowed, got %d", rec.Code)
	}

	srv.updateMu.Lock()
	srv.updateCache = &UpdateInfo{CurrentVersion: "v0.4.1", LatestVersion: "v0.4.2", UpdateAvailable: true}
	srv.updateCheckedAt = time.Now()
	srv.config.Web.UpdateCheckInterval = time.Hour
	srv.updateMu.Unlock()

	updateHTTPGet = func(string) (*http.Response, error) {
		t.Fatalf("fresh cache should avoid HTTP calls")
		return nil, nil
	}

	req = httptest.NewRequest(http.MethodGet, "/api/system/update/check", nil)
	rec = httptest.NewRecorder()
	srv.handleCheckUpdate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from fresh cache, got %d", rec.Code)
	}
}

func TestStartUpdateChecker_PeriodicPath(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.AutoUpdate = true
	srv.config.Web.UpdateCheckInterval = time.Minute

	var calls atomic.Int32
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return jsonHTTP(http.StatusOK, `{
			"tag_name":"v9.9.9",
			"html_url":"https://example/release",
			"body":"notes",
			"assets":[]
		}`), nil
	})

	prevDelay := updateInitialDelay
	prevTickerFactory := updateTickerFactory
	updateInitialDelay = 0
	updateTickerFactory = func(time.Duration) *time.Ticker {
		return time.NewTicker(5 * time.Millisecond)
	}
	defer func() {
		updateInitialDelay = prevDelay
		updateTickerFactory = prevTickerFactory
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.StartUpdateChecker(ctx)
	}()

	deadline := time.After(200 * time.Millisecond)
	for {
		if calls.Load() >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected at least 2 update checks, got %d", calls.Load())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("StartUpdateChecker did not stop after cancel")
	}

	srv.updateMu.RLock()
	defer srv.updateMu.RUnlock()
	if srv.updateCache == nil {
		t.Fatalf("expected update cache to be populated")
	}
}

func TestHandleCheckUpdate_StaleCacheFallbackDeterministic(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	srv.updateMu.Lock()
	srv.updateCache = &UpdateInfo{
		CurrentVersion:  "v0.4.1",
		LatestVersion:   "v0.4.2",
		UpdateAvailable: true,
	}
	srv.updateCheckedAt = time.Now().Add(-2 * time.Hour)
	srv.config.Web.UpdateCheckInterval = time.Minute
	srv.updateMu.Unlock()

	updateHTTPGet = func(string) (*http.Response, error) {
		return nil, errors.New("upstream unavailable")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/system/update/check", nil)
	rec := httptest.NewRecorder()
	srv.handleCheckUpdate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 stale cache fallback, got %d", rec.Code)
	}

	body := decodeJSON(t, rec)
	if body["latest_version"] != "v0.4.2" {
		t.Fatalf("expected stale latest_version v0.4.2, got %#v", body["latest_version"])
	}
}

func TestHandleCheckUpdate_NoCacheFetchErrorDeterministic(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	srv.config.Web.UpdateCheckInterval = time.Minute
	updateHTTPGet = func(string) (*http.Response, error) {
		return nil, errors.New("network down")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/system/update/check", nil)
	rec := httptest.NewRecorder()
	srv.handleCheckUpdate(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when no cache and fetch fails, got %d", rec.Code)
	}
}

func TestHandleCheckUpdate_RefreshesStaleCacheOnSuccess(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	prevVersion := Version
	Version = "v0.4.1"
	defer func() { Version = prevVersion }()

	srv.updateMu.Lock()
	srv.updateCache = &UpdateInfo{
		CurrentVersion:  "v0.4.1",
		LatestVersion:   "v0.4.1",
		UpdateAvailable: false,
	}
	srv.updateCheckedAt = time.Now().Add(-2 * time.Hour)
	srv.config.Web.UpdateCheckInterval = time.Minute
	srv.updateMu.Unlock()

	updateHTTPGet = func(string) (*http.Response, error) {
		return jsonHTTP(http.StatusOK, `{
			"tag_name":"v0.4.2",
			"html_url":"https://example/release",
			"body":"notes",
			"assets":[]
		}`), nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/system/update/check", nil)
	rec := httptest.NewRecorder()
	srv.handleCheckUpdate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for successful refresh, got %d", rec.Code)
	}

	body := decodeJSON(t, rec)
	if body["latest_version"] != "v0.4.2" {
		t.Fatalf("expected refreshed latest_version v0.4.2, got %#v", body["latest_version"])
	}
}

func TestStartUpdateChecker_IntervalClampToDaily(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	srv.config.Web.AutoUpdate = true
	srv.config.Web.UpdateCheckInterval = time.Second

	prevDelay := updateInitialDelay
	prevTickerFactory := updateTickerFactory
	defer func() {
		updateInitialDelay = prevDelay
		updateTickerFactory = prevTickerFactory
	}()

	updateInitialDelay = 0
	updateHTTPGet = func(string) (*http.Response, error) {
		return nil, errors.New("skip update fetch")
	}

	intervalCh := make(chan time.Duration, 1)
	updateTickerFactory = func(d time.Duration) *time.Ticker {
		select {
		case intervalCh <- d:
		default:
		}
		return time.NewTicker(time.Hour)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.StartUpdateChecker(ctx)
	}()

	var got time.Duration
	select {
	case got = <-intervalCh:
	case <-time.After(300 * time.Millisecond):
		cancel()
		<-done
		t.Fatalf("expected ticker interval to be captured")
	}

	if got != 24*time.Hour {
		cancel()
		<-done
		t.Fatalf("expected interval clamp to 24h, got %v", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatalf("StartUpdateChecker did not stop after cancel")
	}
}

func TestStartUpdateChecker_TickerErrorContinues(t *testing.T) {
	srv := testAdminServer(t)
	withUpdateHooksReset(t)

	srv.config.Web.AutoUpdate = true
	srv.config.Web.UpdateCheckInterval = time.Minute

	prevDelay := updateInitialDelay
	prevTickerFactory := updateTickerFactory
	defer func() {
		updateInitialDelay = prevDelay
		updateTickerFactory = prevTickerFactory
	}()

	updateInitialDelay = 0
	updateTickerFactory = func(time.Duration) *time.Ticker {
		return time.NewTicker(5 * time.Millisecond)
	}

	var calls atomic.Int32
	updateHTTPGet = func(string) (*http.Response, error) {
		c := calls.Add(1)
		if c == 1 {
			return jsonHTTP(http.StatusOK, `{
				"tag_name":"v9.9.9",
				"html_url":"https://example/release",
				"body":"notes",
				"assets":[]
			}`), nil
		}
		return nil, errors.New("ticker fetch failure")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.StartUpdateChecker(ctx)
	}()

	deadline := time.After(300 * time.Millisecond)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("expected at least one ticker fetch attempt")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatalf("StartUpdateChecker did not stop after cancel")
	}

	srv.updateMu.RLock()
	defer srv.updateMu.RUnlock()
	if srv.updateCache == nil {
		t.Fatalf("expected first successful check to populate cache")
	}
}
