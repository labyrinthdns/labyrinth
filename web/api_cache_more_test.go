package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labyrinthdns/labyrinth/config"
)

func TestNormalizePeerBaseAndCacheFlushURL(t *testing.T) {
	if got := normalizePeerBase("  http://127.0.0.1:8080/  "); got != "http://127.0.0.1:8080" {
		t.Fatalf("normalizePeerBase mismatch: %q", got)
	}

	valid := config.ClusterPeerConfig{APIBase: "http://127.0.0.1:8080/"}
	if got := cacheFlushURL(valid); got != "http://127.0.0.1:8080/api/cache/flush" {
		t.Fatalf("cacheFlushURL valid mismatch: %q", got)
	}

	invalid := config.ClusterPeerConfig{APIBase: "://bad-url"}
	if got := cacheFlushURL(invalid); got != "" {
		t.Fatalf("cacheFlushURL should be empty for invalid base, got %q", got)
	}

	empty := config.ClusterPeerConfig{APIBase: "   "}
	if got := cacheFlushURL(empty); got != "" {
		t.Fatalf("cacheFlushURL should be empty for empty base, got %q", got)
	}
}

func TestFanoutCacheFlush_MixedOutcomes(t *testing.T) {
	srv := testAdminServer(t)

	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/cache/flush" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer okServer.Close()

	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failServer.Close()

	srv.config.Cluster.Peers = []config.ClusterPeerConfig{
		// skipped
		{Name: "disabled", Enabled: false, APIBase: okServer.URL},
		// invalid URL branch
		{Name: "invalid", Enabled: true, APIBase: "://bad-url"},
		// transport error branch
		{Name: "down", Enabled: true, APIBase: "http://127.0.0.1:1"},
		// non-2xx branch
		{Name: "non2xx", Enabled: true, APIBase: failServer.URL},
		// success branch
		{Name: "ok", Enabled: true, APIBase: okServer.URL, APIToken: "token"},
	}

	okCount, failCount := srv.fanoutCacheFlush()
	if okCount != 1 {
		t.Fatalf("expected okCount=1, got %d", okCount)
	}
	if failCount != 3 {
		t.Fatalf("expected failCount=3, got %d", failCount)
	}
}
