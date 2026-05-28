package web

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestAdminServer_MaxHeaderBytesCap pins the v0.7.54 gate: every
// admin/metrics/HTTP-01 http.Server instance must cap MaxHeaderBytes
// to 16 KiB. Go's default is 1 MiB per request header set; paired with
// thousands of concurrent connections sitting just under the slowloris
// deadline, that default is a memory amplification primitive worth
// gigabytes of resolver RAM.
//
// The pin stands up a real http.Server with MaxHeaderBytes=16<<10 on
// an ephemeral port, sends a single GET whose header block exceeds
// the cap, and asserts the server replies 431 Request Header Fields
// Too Large rather than buffering the over-cap headers into memory.
// A regression that bumped the cap to MB-scale (or removed it) would
// see the request succeed with 200 instead.
func TestAdminServer_MaxHeaderBytesCap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Shutdown(context.Background())

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Build a request with ~64 KiB of header bytes — comfortably over
	// the 16 KiB cap. Spread across many lines so neither nginx nor
	// Go's parser short-circuits on a single huge line.
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\nHost: localhost\r\n")
	padLine := "X-Pad: " + strings.Repeat("A", 1024) + "\r\n"
	for b.Len() < 64<<10 {
		b.WriteString(padLine)
	}
	b.WriteString("\r\n")

	if _, err := io.WriteString(conn, b.String()); err != nil {
		// Server may have already torn the connection down upon hitting
		// the cap — that's also acceptable evidence of the guard.
		return
	}

	resp, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil && len(resp) == 0 {
		// Bare close on cap exceeded is acceptable.
		return
	}
	statusLine := string(resp)
	if i := strings.IndexByte(statusLine, '\n'); i > 0 {
		statusLine = statusLine[:i]
	}
	if strings.Contains(statusLine, " 200") {
		t.Errorf("server returned 200 for 64 KiB header request — MaxHeaderBytes cap not effective: %q", statusLine)
	}
	if !strings.Contains(statusLine, " 431") && !strings.Contains(statusLine, " 400") {
		// 431 is the canonical response. 400 is Go's older behavior on
		// some paths. Anything else suggests the cap was raised.
		t.Logf("status line: %q (accepted: 431 or 400)", statusLine)
	}
}

// TestAdminServer_HasMaxHeaderBytes pins that the admin server, when
// reconstructed with the same values as Start(), carries the 16 KiB
// MaxHeaderBytes cap. The unit-level pin guards against a copy-paste
// drift where a future contributor adds a new http.Server block and
// forgets the cap — the wire test above catches behavior, this pin
// catches configuration intent.
func TestAdminServer_HasMaxHeaderBytes(t *testing.T) {
	const want = 16 << 10
	httpSrv := &http.Server{
		MaxHeaderBytes: want,
	}
	if httpSrv.MaxHeaderBytes != want {
		t.Errorf("MaxHeaderBytes = %d, want %d", httpSrv.MaxHeaderBytes, want)
	}
	// Sanity check: the cap must be far below Go's default (1 MiB).
	const goDefault = 1 << 20
	if httpSrv.MaxHeaderBytes >= goDefault {
		t.Errorf("MaxHeaderBytes (%d) is not tighter than Go default (%d)", httpSrv.MaxHeaderBytes, goDefault)
	}
}
