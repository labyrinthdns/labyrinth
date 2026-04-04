package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func withMockTransport(t *testing.T, fn roundTripFunc) {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = fn
	t.Cleanup(func() {
		http.DefaultTransport = prev
	})
}

func jsonHTTP(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func TestCheckForUpdate_Success(t *testing.T) {
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != githubReleasesURL {
			t.Fatalf("unexpected URL: %s", r.URL.String())
		}
		return jsonHTTP(http.StatusOK, `{
			"tag_name":"v0.4.9",
			"html_url":"https://github.com/labyrinthdns/labyrinth/releases/tag/v0.4.9",
			"body":"notes",
			"assets":[
				{"name":"labyrinth-windows-amd64.exe","browser_download_url":"https://example/labyrinth.exe"}
			]
		}`), nil
	})

	prevVersion := Version
	Version = "v0.4.2"
	defer func() { Version = prevVersion }()

	info, err := checkForUpdate()
	if err != nil {
		t.Fatalf("checkForUpdate: %v", err)
	}
	if info.LatestVersion != "v0.4.9" {
		t.Fatalf("want latest v0.4.9, got %q", info.LatestVersion)
	}
	if !info.UpdateAvailable {
		t.Fatalf("expected update available")
	}
	if info.AssetName == "" {
		t.Fatalf("asset name should not be empty")
	}
}

func TestFindAssetURL(t *testing.T) {
	withMockTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonHTTP(http.StatusOK, `{
			"tag_name":"v0.4.9",
			"html_url":"https://example/release",
			"body":"notes",
			"assets":[
				{"name":"labyrinth-linux-amd64","browser_download_url":"https://example/linux-amd64"},
				{"name":"labyrinth-windows-amd64.exe","browser_download_url":"https://example/windows-amd64.exe"}
			]
		}`), nil
	})

	url, err := findAssetURL("labyrinth-windows-amd64.exe")
	if err != nil {
		t.Fatalf("findAssetURL: %v", err)
	}
	if url != "https://example/windows-amd64.exe" {
		t.Fatalf("unexpected asset url: %s", url)
	}

	if _, err := findAssetURL("missing-asset"); err == nil {
		t.Fatalf("expected error for missing asset")
	}
}

func TestStartUpdateChecker_EarlyExitPaths(t *testing.T) {
	srv := testAdminServer(t)

	// Branch: auto update disabled.
	srv.config.Web.AutoUpdate = false
	srv.StartUpdateChecker(context.Background())

	// Branch: context done before initial 30s wait.
	srv.config.Web.AutoUpdate = true
	srv.config.Web.UpdateCheckInterval = time.Second // exercise min interval clamp
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	srv.StartUpdateChecker(ctx)
}

