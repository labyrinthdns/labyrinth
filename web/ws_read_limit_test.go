package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestWSReadLimit_OverCapMessageClosesConnection pins the v0.8.0 gate:
// every WebSocket handler must call conn.SetReadLimit before its first
// read so a client that sends more than MaxWebSocketMessageBytes in a
// single message gets the connection closed with StatusMessageTooBig
// (1009). Without the explicit limit, the handler inherits the
// coder/websocket library default (32 KiB) and a regression that bumps
// the default — or future authenticated abuse — silently widens the
// memory-bloat surface on every live-stream endpoint.
//
// The pin sends a 64 KiB body, well above the 4 KiB cap and the 32 KiB
// library default, and asserts the server closes the connection rather
// than reading the whole payload.
func TestWSReadLimit_OverCapMessageClosesConnection(t *testing.T) {
	srv := testAdminServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats/timeseries/ws", srv.handleTimeSeriesWS)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	base := "ws" + ts.URL[4:]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, base+"/api/stats/timeseries/ws?mode=live", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Drain initial snapshot so we are not racing with the first push.
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read initial snapshot: %v", err)
	}

	// Send a 64 KiB JSON message — well over the 4 KiB SetReadLimit
	// cap and over the 32 KiB library default. The handler must close
	// the connection rather than buffer the whole payload.
	big := strings.Repeat("A", 64<<10)
	payload := []byte(`{"mode":"live","window":"1m","interval":"1s","pad":"` + big + `"}`)
	if err := conn.Write(ctx, websocket.MessageText, payload); err != nil {
		t.Fatalf("write over-cap payload: %v", err)
	}

	// The next read must error — the server will have closed with
	// StatusMessageTooBig. We don't pin the exact status because
	// gateway/proxy paths can mask 1009 as a transport close; the
	// important property is that the read does NOT succeed (which it
	// would, with another snapshot frame, if the limit were not in
	// effect).
	readCtx, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	defer cancelRead()
	if _, _, err := conn.Read(readCtx); err == nil {
		t.Fatal("expected read error after over-cap message — SetReadLimit not applied")
	}
}

// TestWSReadLimit_ConstantIsSmall pins that MaxWebSocketMessageBytes
// stays an explicit, small bound. If someone changes the constant to
// the library default or removes it, this test fails fast. The 4 KiB
// bound is well above the largest legitimate client message (a few
// hundred bytes of JSON: trace start, timeseries subscription update)
// and well below any plausible bloat vector.
func TestWSReadLimit_ConstantIsSmall(t *testing.T) {
	if MaxWebSocketMessageBytes <= 0 {
		t.Fatalf("MaxWebSocketMessageBytes must be positive, got %d", MaxWebSocketMessageBytes)
	}
	if MaxWebSocketMessageBytes > 16<<10 {
		t.Fatalf("MaxWebSocketMessageBytes = %d is larger than 16 KiB ceiling — accidental relaxation?", MaxWebSocketMessageBytes)
	}
}
