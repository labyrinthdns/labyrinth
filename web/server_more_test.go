package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func TestAdminServerStart_InvalidAddrReturnsServerError(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Addr = "127.0.0.1:bad"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := srv.Start(ctx)
	if err == nil {
		t.Fatalf("expected server start error for invalid addr")
	}
	if !strings.Contains(err.Error(), "admin server error") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAdminServerStart_DoH3WithoutTLSFailsFast(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.DoH3Enabled = true
	srv.config.Web.TLSEnabled = false
	srv.config.Web.TLSCertFile = ""
	srv.config.Web.TLSKeyFile = ""

	err := srv.Start(context.Background())
	if err == nil {
		t.Fatalf("expected configuration error when DoH3 is enabled without TLS")
	}
	if !strings.Contains(err.Error(), "doh3_enabled") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAdminServerStart_DoH3Enabled_MissingCertFails(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Addr = "127.0.0.1:0"
	srv.config.Web.DoH3Enabled = true
	srv.config.Web.TLSEnabled = true
	srv.config.Web.TLSCertFile = "missing-cert.pem"
	srv.config.Web.TLSKeyFile = "missing-key.pem"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := srv.Start(ctx)
	if err == nil {
		t.Fatalf("expected TLS startup failure with missing cert/key")
	}
}

func TestHandleQueryStreamWS_AcceptErrorPath(t *testing.T) {
	srv := testAdminServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/queries/stream", nil)
	w := httptest.NewRecorder()
	srv.handleQueryStreamWS(w, req)

	if w.Code < 400 {
		t.Fatalf("expected websocket upgrade failure status, got %d", w.Code)
	}
}

func TestHandleQueryStreamWS_ClosedSubscriptionChannelPath(t *testing.T) {
	srv := testAdminServer(t)
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/queries/stream"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer conn.Close(websocket.StatusGoingAway, "done")

	var subID uint64
	found := false
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		srv.queryLog.subMu.Lock()
		for id := range srv.queryLog.subs {
			subID = id
			found = true
			break
		}
		srv.queryLog.subMu.Unlock()
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatalf("expected websocket subscriber to be registered")
	}

	srv.queryLog.Unsubscribe(subID)

	readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
	defer readCancel()
	if _, _, err := conn.Read(readCtx); err == nil {
		t.Fatalf("expected websocket read error after server-side unsubscribe")
	}
}
