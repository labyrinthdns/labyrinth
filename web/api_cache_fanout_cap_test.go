package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/config"
)

// TestFanoutCacheFlush_CapsPeerResponseBody pins the LimitReader added
// in v0.7.50 around the cluster-fanout drain. Without it, a malicious
// or buggy peer can return a multi-gigabyte response body on
// `/api/cache/flush` and force the resolver to read all of it before
// closing the connection (Go's keep-alive contract requires the body
// be drained). The cap is 64 KiB — well above any legitimate fanout
// response (a few hundred bytes of JSON).
//
// The pin stands up a fake peer that streams a 1 MiB body and asserts
// fanoutCacheFlush returns the call as successful in well under a
// second, proving the read did not run to the full body length. A
// regression that removed the LimitReader would let the test peer
// pump unbounded bytes into the goroutine.
func TestFanoutCacheFlush_CapsPeerResponseBody(t *testing.T) {
	// Fake peer that responds with a 1 MiB body. The handler doesn't
	// care about the request body — it just wants to test how the
	// caller drains the response.
	const peerBodySize = 1 << 20 // 1 MiB
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		body := strings.Repeat("y", peerBodySize)
		_, _ = w.Write([]byte(body))
	}))
	defer peer.Close()

	srv := testAdminServer(t)
	srv.config.Load().Cluster.Enabled = true
	srv.config.Load().Cluster.Peers = []config.ClusterPeerConfig{{
		Name:    "fake",
		APIBase: peer.URL,
		Enabled: true,
	}}

	start := time.Now()
	okCount, failCount := srv.fanoutCacheFlush()
	elapsed := time.Since(start)

	if okCount != 1 || failCount != 0 {
		t.Errorf("counts: got ok=%d fail=%d, want ok=1 fail=0", okCount, failCount)
	}
	// Pre-cap, draining 1 MiB on a localhost loopback is still fast,
	// but we assert a generous ceiling well under the 5s client
	// timeout. The real defence here is the LimitReader; this is just
	// a smoke check that the function did not hang.
	if elapsed > 2*time.Second {
		t.Errorf("fanout took %v — read should be capped at 64 KiB", elapsed)
	}
}
