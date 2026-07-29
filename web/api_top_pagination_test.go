package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/metrics"
)

func newTopTestServer(t *testing.T) *AdminServer {
	t.Helper()
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled:         true,
			Addr:            "127.0.0.1:0",
			QueryLogBuffer:  100,
			TopClientsLimit: 10,
			TopDomainsLimit: 10,
		},
	}
	srv, err := NewAdminServer(cfg, c, m, nil, logger, nil)
	if err != nil {
		t.Fatalf("NewAdminServer failed: %v", err)
	}
	return srv
}

func parseJSONMap(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	return out
}

func TestTopTracker_TopPage(t *testing.T) {
	tracker := NewTopTracker(5)
	tracker.Inc("a")
	tracker.Inc("a")
	tracker.Inc("b")
	tracker.Inc("c")

	page, total := tracker.TopPage(2, 1)
	if total != 3 {
		t.Fatalf("want total=3, got %d", total)
	}
	if len(page) != 2 {
		t.Fatalf("want page len=2, got %d", len(page))
	}
	got := map[string]bool{
		page[0].Key: true,
		page[1].Key: true,
	}
	if !got["b"] || !got["c"] {
		t.Fatalf("unexpected page content: %+v", page)
	}
}

func TestHandleTopClients_WithOffsetAndMetadata(t *testing.T) {
	srv := newTopTestServer(t)
	srv.RecordQuery("10.0.0.1", "a.test.", "A", "NOERROR", false, 1.0)
	srv.RecordQuery("10.0.0.1", "a.test.", "A", "NOERROR", false, 1.0)
	srv.RecordQuery("10.0.0.2", "b.test.", "A", "NOERROR", false, 1.0)
	srv.RecordQuery("10.0.0.3", "c.test.", "A", "NOERROR", false, 1.0)

	req := httptest.NewRequest(http.MethodGet, "/api/stats/top-clients?limit=1&offset=1", nil)
	rr := httptest.NewRecorder()
	srv.handleTopClients(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := parseJSONMap(t, rr)
	if int(body["limit"].(float64)) != 1 {
		t.Fatalf("want limit=1, got %v", body["limit"])
	}
	if int(body["offset"].(float64)) != 1 {
		t.Fatalf("want offset=1, got %v", body["offset"])
	}
	if int(body["total"].(float64)) < 3 {
		t.Fatalf("want total>=3, got %v", body["total"])
	}
	entries, ok := body["entries"].([]interface{})
	if !ok || len(entries) != 1 {
		t.Fatalf("want 1 paged entry, got %v", body["entries"])
	}
}

func TestHandleTopDomains_LimitCap(t *testing.T) {
	srv := newTopTestServer(t)
	for i := 0; i < 5; i++ {
		srv.RecordQuery("10.0.0.1", "cap.test.", "A", "NOERROR", false, 1.0)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/stats/top-domains?limit=99999", nil)
	rr := httptest.NewRecorder()
	srv.handleTopDomains(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := parseJSONMap(t, rr)
	if int(body["limit"].(float64)) != maxTopPageLimit {
		t.Fatalf("want limit cap=%d, got %v", maxTopPageLimit, body["limit"])
	}
}
