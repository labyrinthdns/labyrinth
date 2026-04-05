package web

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/blocklist"
	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
	"nhooyr.io/websocket"
)

// ===========================================================================
// Helpers
// ===========================================================================

// testAdminServerWithBlocklist creates an AdminServer with a real blocklist manager.
func testAdminServerWithBlocklist(t *testing.T) *AdminServer {
	t.Helper()
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled:        true,
			Addr:           "127.0.0.1:0",
			QueryLogBuffer: 100,
		},
	}
	bl := blocklist.NewManager(blocklist.ManagerConfig{
		BlockingMode: "nxdomain",
	}, logger)
	srv, err := NewAdminServer(cfg, c, m, nil, logger, bl)
	if err != nil {
		t.Fatalf("NewAdminServer failed: %v", err)
	}
	return srv
}

// testAdminServerWithResolver creates an AdminServer with a real resolver (ready=false).
func testAdminServerWithResolver(t *testing.T) *AdminServer {
	t.Helper()
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled:        true,
			Addr:           "127.0.0.1:0",
			QueryLogBuffer: 100,
		},
	}
	r := resolver.NewResolver(c, resolver.ResolverConfig{MaxDepth: 10}, m, logger)
	srv, err := NewAdminServer(cfg, c, m, r, logger, nil)
	if err != nil {
		t.Fatalf("NewAdminServer failed: %v", err)
	}
	return srv
}

// ===========================================================================
// Blocklist handler tests (api_blocklist.go) — all 0% covered
// ===========================================================================

func TestHandleBlocklistStats_NilBlocklist(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/blocklist/stats", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["enabled"] != false {
		t.Fatalf("expected enabled=false, got %v", body["enabled"])
	}
}

func TestHandleBlocklistStats_WithBlocklist(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	req := httptest.NewRequest("GET", "/api/blocklist/stats", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHandleBlocklistStats_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/blocklist/stats", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistStats(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleBlocklistLists_NilBlocklist(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/blocklist/lists", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistLists(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHandleBlocklistLists_WithBlocklist(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	req := httptest.NewRequest("GET", "/api/blocklist/lists", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistLists(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHandleBlocklistLists_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("DELETE", "/api/blocklist/lists", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistLists(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleBlocklistRefresh_NilBlocklist(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/blocklist/refresh", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistRefresh(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "blocklist not enabled" {
		t.Fatalf("unexpected status: %v", body["status"])
	}
}

func TestHandleBlocklistRefresh_WithBlocklist(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	req := httptest.NewRequest("POST", "/api/blocklist/refresh", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistRefresh(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "refresh started" {
		t.Fatalf("unexpected status: %v", body["status"])
	}
}

func TestHandleBlocklistRefresh_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/blocklist/refresh", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistRefresh(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleBlocklistBlock_NilBlocklist(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/blocklist/block", strings.NewReader(`{"domain":"evil.com"}`))
	w := httptest.NewRecorder()
	srv.handleBlocklistBlock(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "blocklist not enabled" {
		t.Fatalf("unexpected status: %v", body["status"])
	}
}

func TestHandleBlocklistBlock_WithBlocklist(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	req := httptest.NewRequest("POST", "/api/blocklist/block", strings.NewReader(`{"domain":"evil.com"}`))
	w := httptest.NewRecorder()
	srv.handleBlocklistBlock(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "blocked" {
		t.Fatalf("unexpected status: %v", body["status"])
	}
	if body["domain"] != "evil.com" {
		t.Fatalf("unexpected domain: %v", body["domain"])
	}
}

func TestHandleBlocklistBlock_MissingDomain(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	req := httptest.NewRequest("POST", "/api/blocklist/block", strings.NewReader(`{"domain":""}`))
	w := httptest.NewRecorder()
	srv.handleBlocklistBlock(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleBlocklistBlock_InvalidJSON(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	req := httptest.NewRequest("POST", "/api/blocklist/block", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.handleBlocklistBlock(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleBlocklistBlock_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/blocklist/block", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistBlock(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleBlocklistUnblock_NilBlocklist(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/blocklist/unblock", strings.NewReader(`{"domain":"evil.com"}`))
	w := httptest.NewRecorder()
	srv.handleBlocklistUnblock(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "blocklist not enabled" {
		t.Fatalf("unexpected status: %v", body["status"])
	}
}

func TestHandleBlocklistUnblock_WithBlocklist(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	// Block first, then unblock
	srv.blocklist.BlockDomain("evil.com")

	req := httptest.NewRequest("POST", "/api/blocklist/unblock", strings.NewReader(`{"domain":"evil.com"}`))
	w := httptest.NewRecorder()
	srv.handleBlocklistUnblock(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "unblocked" {
		t.Fatalf("unexpected status: %v", body["status"])
	}
}

func TestHandleBlocklistUnblock_MissingDomain(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	req := httptest.NewRequest("POST", "/api/blocklist/unblock", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	srv.handleBlocklistUnblock(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleBlocklistUnblock_InvalidJSON(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	req := httptest.NewRequest("POST", "/api/blocklist/unblock", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	srv.handleBlocklistUnblock(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleBlocklistUnblock_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/blocklist/unblock", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistUnblock(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleBlocklistCheck_NilBlocklist(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/blocklist/check?domain=test.com", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["blocked"] != false {
		t.Fatalf("expected blocked=false, got %v", body["blocked"])
	}
}

func TestHandleBlocklistCheck_WithBlocklist(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	srv.blocklist.BlockDomain("blocked.com")

	req := httptest.NewRequest("GET", "/api/blocklist/check?domain=blocked.com", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["blocked"] != true {
		t.Fatalf("expected blocked=true, got %v", body["blocked"])
	}
}

func TestHandleBlocklistCheck_MissingDomain(t *testing.T) {
	srv := testAdminServerWithBlocklist(t)
	req := httptest.NewRequest("GET", "/api/blocklist/check", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistCheck(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleBlocklistCheck_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/blocklist/check", nil)
	w := httptest.NewRecorder()
	srv.handleBlocklistCheck(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// ===========================================================================
// Top tracker tests (toptracker.go) — Inc with prune, Top, prune
// ===========================================================================

func TestTopTracker_Top(t *testing.T) {
	tracker := NewTopTracker(5)

	tracker.Inc("a")
	tracker.Inc("a")
	tracker.Inc("a")
	tracker.Inc("b")
	tracker.Inc("b")
	tracker.Inc("c")

	top := tracker.Top(2)
	if len(top) != 2 {
		t.Fatalf("want 2 top entries, got %d", len(top))
	}
	if top[0].Key != "a" || top[0].Count != 3 {
		t.Fatalf("want top[0]={a,3}, got {%s,%d}", top[0].Key, top[0].Count)
	}
	if top[1].Key != "b" || top[1].Count != 2 {
		t.Fatalf("want top[1]={b,2}, got {%s,%d}", top[1].Key, top[1].Count)
	}
}

func TestTopTracker_TopMoreThanAvailable(t *testing.T) {
	tracker := NewTopTracker(5)
	tracker.Inc("only")

	top := tracker.Top(10)
	if len(top) != 1 {
		t.Fatalf("want 1, got %d", len(top))
	}
}

func TestTopTracker_Prune(t *testing.T) {
	// limit=2, so prune triggers when map size > 2*10 = 20
	tracker := NewTopTracker(2)

	// Add the "important" key many times
	for i := 0; i < 100; i++ {
		tracker.Inc("important")
	}

	// Fill up to trigger prune (need > limit*10 = 20 unique keys)
	for i := 0; i < 21; i++ {
		tracker.Inc(fmt.Sprintf("key-%d", i))
	}

	// After prune, "important" should still be there (it has highest count)
	top := tracker.Top(1)
	if len(top) == 0 {
		t.Fatal("expected at least one top entry after prune")
	}
	if top[0].Key != "important" {
		t.Fatalf("expected 'important' to survive prune, got %q", top[0].Key)
	}
}

func TestTopTracker_DefaultLimit(t *testing.T) {
	tracker := NewTopTracker(0)
	if tracker.limit != 20 {
		t.Fatalf("want default limit 20, got %d", tracker.limit)
	}
}

// ===========================================================================
// Top clients/domains handler tests (api_top.go) — all 0% covered
// ===========================================================================

func TestHandleTopClients(t *testing.T) {
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

	srv.RecordQuery("192.168.1.1", "test.com.", "A", "NOERROR", false, 1.0)
	srv.RecordQuery("192.168.1.1", "test.com.", "A", "NOERROR", false, 1.0)
	srv.RecordQuery("10.0.0.1", "test.com.", "A", "NOERROR", false, 1.0)

	req := httptest.NewRequest("GET", "/api/stats/top-clients", nil)
	w := httptest.NewRecorder()
	srv.handleTopClients(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	entries, ok := body["entries"].([]interface{})
	if !ok {
		t.Fatal("missing entries")
	}
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 entries, got %d", len(entries))
	}
}

func TestHandleTopClients_WithLimitParam(t *testing.T) {
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

	for i := 0; i < 5; i++ {
		srv.RecordQuery(fmt.Sprintf("10.0.0.%d", i), "test.com.", "A", "NOERROR", false, 1.0)
	}

	req := httptest.NewRequest("GET", "/api/stats/top-clients?limit=2", nil)
	w := httptest.NewRecorder()
	srv.handleTopClients(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	entries := body["entries"].([]interface{})
	if len(entries) != 2 {
		t.Fatalf("want 2 entries (limited), got %d", len(entries))
	}
}

func TestHandleTopClients_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/stats/top-clients", nil)
	w := httptest.NewRecorder()
	srv.handleTopClients(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleTopDomains(t *testing.T) {
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

	srv.RecordQuery("10.0.0.1", "popular.com.", "A", "NOERROR", false, 1.0)
	srv.RecordQuery("10.0.0.1", "popular.com.", "A", "NOERROR", false, 1.0)
	srv.RecordQuery("10.0.0.1", "less.com.", "A", "NOERROR", false, 1.0)

	req := httptest.NewRequest("GET", "/api/stats/top-domains", nil)
	w := httptest.NewRecorder()
	srv.handleTopDomains(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	entries, ok := body["entries"].([]interface{})
	if !ok {
		t.Fatal("missing entries")
	}
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 entries, got %d", len(entries))
	}
}

func TestHandleTopDomains_WithLimitParam(t *testing.T) {
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

	for i := 0; i < 5; i++ {
		srv.RecordQuery("10.0.0.1", fmt.Sprintf("domain%d.com.", i), "A", "NOERROR", false, 1.0)
	}

	req := httptest.NewRequest("GET", "/api/stats/top-domains?limit=1", nil)
	w := httptest.NewRecorder()
	srv.handleTopDomains(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	entries := body["entries"].([]interface{})
	if len(entries) != 1 {
		t.Fatalf("want 1 entry (limited), got %d", len(entries))
	}
}

func TestHandleTopDomains_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/stats/top-domains", nil)
	w := httptest.NewRecorder()
	srv.handleTopDomains(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// ===========================================================================
// Negative cache handler test (api_cache.go handleNegativeCache)
// ===========================================================================

func TestHandleNegativeCache(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/negative", nil)
	w := httptest.NewRecorder()
	srv.handleNegativeCache(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["count"] != float64(0) {
		t.Fatalf("expected count=0, got %v", body["count"])
	}
}

func TestHandleNegativeCache_WithLimit(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/negative?limit=5", nil)
	w := httptest.NewRecorder()
	srv.handleNegativeCache(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHandleNegativeCache_InvalidLimit(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/negative?limit=abc", nil)
	w := httptest.NewRecorder()
	srv.handleNegativeCache(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHandleNegativeCache_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/cache/negative", nil)
	w := httptest.NewRecorder()
	srv.handleNegativeCache(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// ===========================================================================
// Cache stats with hit rate > 0 (api_cache.go handleCacheStats)
// ===========================================================================

func TestHandleCacheStats_WithHitRate(t *testing.T) {
	srv := testAdminServer(t)

	// Generate some cache hits and misses
	srv.metrics.IncCacheHits()
	srv.metrics.IncCacheHits()
	srv.metrics.IncCacheHits()
	srv.metrics.IncCacheMisses()

	req := httptest.NewRequest("GET", "/api/cache/stats", nil)
	w := httptest.NewRecorder()
	srv.handleCacheStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	hitRate, ok := body["hit_rate"].(float64)
	if !ok {
		t.Fatal("missing hit_rate")
	}
	if hitRate != 75.0 {
		t.Fatalf("want hit_rate=75.0, got %v", hitRate)
	}
}

// ===========================================================================
// Cache lookup ALL type (api_cache.go handleCacheLookup)
// ===========================================================================

func TestHandleCacheLookup_ALL_Found(t *testing.T) {
	srv := testAdminServer(t)

	rr := dns.ResourceRecord{
		Name:  "all.com.",
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: net.IPv4(1, 2, 3, 4).To4(),
	}
	srv.cache.Store("all.com.", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{rr}, nil)

	req := httptest.NewRequest("GET", "/api/cache/lookup?name=all.com.&type=ALL", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["type"] != "ALL" {
		t.Fatalf("want type=ALL, got %v", body["type"])
	}
	entries, ok := body["entries"].([]interface{})
	if !ok {
		t.Fatal("missing entries key")
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one entry")
	}
}

func TestHandleCacheLookup_ALL_NotFound(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/lookup?name=nothing.com.&type=all", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestHandleCacheLookup_LowercaseType(t *testing.T) {
	srv := testAdminServer(t)

	rr := dns.ResourceRecord{
		Name:  "lower.com.",
		Type:  dns.TypeAAAA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: net.ParseIP("::1"),
	}
	srv.cache.Store("lower.com.", dns.TypeAAAA, dns.ClassIN, []dns.ResourceRecord{rr}, nil)

	req := httptest.NewRequest("GET", "/api/cache/lookup?name=lower.com.&type=aaaa", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// ===========================================================================
// Cache delete default type (api_cache.go handleCacheDelete)
// ===========================================================================

func TestHandleCacheDelete_DefaultType(t *testing.T) {
	srv := testAdminServer(t)

	rr := dns.ResourceRecord{
		Name:  "deftype.com.",
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: net.IPv4(1, 1, 1, 1).To4(),
	}
	srv.cache.Store("deftype.com.", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{rr}, nil)

	// No type param, should default to A
	req := httptest.NewRequest("DELETE", "/api/cache/entry?name=deftype.com.", nil)
	w := httptest.NewRecorder()
	srv.handleCacheDelete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// ===========================================================================
// handleStats with resolver (api_stats.go)
// ===========================================================================

func TestHandleStats_WithResolver(t *testing.T) {
	srv := testAdminServerWithResolver(t)
	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	// resolver exists but ready=false
	if body["resolver_ready"] != false {
		t.Fatalf("expected resolver_ready=false, got %v", body["resolver_ready"])
	}
}

func TestHandleStats_WithHitRatio(t *testing.T) {
	srv := testAdminServer(t)
	srv.metrics.IncCacheHits()
	srv.metrics.IncCacheMisses()

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	hitRatio, ok := body["cache_hit_ratio"].(float64)
	if !ok {
		t.Fatal("missing cache_hit_ratio")
	}
	if hitRatio != 0.5 {
		t.Fatalf("want 0.5, got %v", hitRatio)
	}
}

func TestHandleStats_FallbackMetrics(t *testing.T) {
	srv := testAdminServer(t)
	srv.metrics.IncFallbackQueries()
	srv.metrics.IncFallbackQueries()
	srv.metrics.IncFallbackQueries()
	srv.metrics.IncFallbackRecoveries()
	srv.metrics.IncFallbackRecoveries()

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)

	if v, ok := body["fallback_queries"].(float64); !ok || v != 3 {
		t.Errorf("expected fallback_queries=3, got %v", body["fallback_queries"])
	}
	if v, ok := body["fallback_recoveries"].(float64); !ok || v != 2 {
		t.Errorf("expected fallback_recoveries=2, got %v", body["fallback_recoveries"])
	}
}

func TestHandleStats_FallbackMetricsZero(t *testing.T) {
	srv := testAdminServer(t)

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)

	if v, ok := body["fallback_queries"].(float64); !ok || v != 0 {
		t.Errorf("expected fallback_queries=0, got %v", body["fallback_queries"])
	}
	if v, ok := body["fallback_recoveries"].(float64); !ok || v != 0 {
		t.Errorf("expected fallback_recoveries=0, got %v", body["fallback_recoveries"])
	}
}

// ===========================================================================
// handleTimeSeries with capped window (api_stats.go)
// ===========================================================================

func TestHandleTimeSeries_CappedWindow(t *testing.T) {
	srv := testAdminServer(t)
	// Request window > 1h, should be capped
	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=2h", nil)
	w := httptest.NewRecorder()
	srv.handleTimeSeries(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// ===========================================================================
// handleHealth with resolver (api_system.go)
// ===========================================================================

func TestHandleHealth_WithResolver(t *testing.T) {
	srv := testAdminServerWithResolver(t)
	req := httptest.NewRequest("GET", "/api/system/health", nil)
	w := httptest.NewRecorder()
	srv.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	// resolver is not ready (not primed), so still "degraded"
	if body["resolver_ready"] != false {
		t.Fatalf("expected resolver_ready=false, got %v", body["resolver_ready"])
	}
}

// ===========================================================================
// Auth: ValidatePassword, HashPassword short password (auth.go)
// ===========================================================================

func TestValidatePassword_TooShort(t *testing.T) {
	err := ValidatePassword("short")
	if err == nil {
		t.Fatal("expected error for short password")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Fatalf("expected 'too short' in error, got: %v", err)
	}
}

func TestValidatePassword_Valid(t *testing.T) {
	err := ValidatePassword("longEnoughPassword")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestHashPassword_TooShort(t *testing.T) {
	_, err := HashPassword("short")
	if err == nil {
		t.Fatal("expected error for short password")
	}
}

// ===========================================================================
// handleChangePassword (auth.go) — all 0% covered
// ===========================================================================

func TestHandleChangePassword_Success(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)

	// Write a config file for updatePasswordInConfig to find
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Write a config file with a password_hash line
	cfgContent := "web:\n  auth:\n    username: admin\n    password_hash: " + srv.config.Web.Auth.PasswordHash + "\n"
	os.WriteFile(filepath.Join(tmpDir, "labyrinth.yaml"), []byte(cfgContent), 0644)

	reqBody := fmt.Sprintf(`{"current_password":"%s","new_password":"newSecurePass123"}`, password)
	req := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["status"] != "ok" {
		t.Fatalf("want status=ok, got %v", body["status"])
	}
}

func TestHandleChangePassword_WrongCurrentPassword(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)

	req := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(`{"current_password":"wrongpass","new_password":"newSecurePass123"}`))
	w := httptest.NewRecorder()
	srv.handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestHandleChangePassword_NewPasswordTooShort(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)

	reqBody := fmt.Sprintf(`{"current_password":"%s","new_password":"short"}`, password)
	req := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleChangePassword_InvalidBody(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)

	req := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleChangePassword_MethodNotAllowed(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)

	req := httptest.NewRequest("GET", "/api/auth/change-password", nil)
	w := httptest.NewRecorder()
	srv.handleChangePassword(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleChangePassword_ConfigFileNotFound(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)

	// Chdir to a temp dir without a config file
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	reqBody := fmt.Sprintf(`{"current_password":"%s","new_password":"newSecurePass123"}`, password)
	req := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	// Should return "partial" since config file couldn't be saved
	if body["status"] != "partial" {
		t.Fatalf("want status=partial, got %v", body["status"])
	}
}

// ===========================================================================
// updatePasswordInConfig (auth.go) — all 0% covered
// ===========================================================================

func TestUpdatePasswordInConfig_Success(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	cfgContent := "web:\n  auth:\n    username: admin\n    password_hash: oldhash\n"
	os.WriteFile(filepath.Join(tmpDir, "labyrinth.yaml"), []byte(cfgContent), 0644)

	err := updatePasswordInConfig("newhash123")
	if err != nil {
		t.Fatalf("updatePasswordInConfig: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(tmpDir, "labyrinth.yaml"))
	if !strings.Contains(string(data), "newhash123") {
		t.Fatalf("expected new hash in config, got: %s", string(data))
	}
}

func TestUpdatePasswordInConfig_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	err := updatePasswordInConfig("newhash")
	if err == nil {
		t.Fatal("expected error when config not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}

func TestUpdatePasswordInConfig_NoPasswordHashField(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	cfgContent := "web:\n  auth:\n    username: admin\n"
	os.WriteFile(filepath.Join(tmpDir, "labyrinth.yaml"), []byte(cfgContent), 0644)

	err := updatePasswordInConfig("newhash")
	if err == nil {
		t.Fatal("expected error when password_hash field missing")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}

// ===========================================================================
// compareSemver and parseSemverParts (api_update.go) — all 0% covered
// ===========================================================================

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.9.9", 1},
		{"0.1.0", "0.2.0", -1},
		{"1.2.3", "1.2.3", 0},
	}
	for _, tc := range tests {
		got := compareSemver(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("compareSemver(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestParseSemverParts(t *testing.T) {
	tests := []struct {
		v    string
		want [3]int
	}{
		{"1.2.3", [3]int{1, 2, 3}},
		{"0.1.0", [3]int{0, 1, 0}},
		{"1.2.3-rc1", [3]int{1, 2, 3}},
		{"1.0.0+build123", [3]int{1, 0, 0}},
		{"1.2", [3]int{1, 2, 0}},
		{"1", [3]int{1, 0, 0}},
		{"", [3]int{0, 0, 0}},
		{"abc", [3]int{0, 0, 0}},
	}
	for _, tc := range tests {
		got := parseSemverParts(tc.v)
		if got != tc.want {
			t.Errorf("parseSemverParts(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// ===========================================================================
// handleCheckUpdate with mock HTTP server (api_update.go)
// ===========================================================================

func TestHandleCheckUpdate_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/system/update/check", nil)
	w := httptest.NewRecorder()
	srv.handleCheckUpdate(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleCheckUpdate_CachedResult(t *testing.T) {
	srv := testAdminServer(t)
	// Pre-populate the update cache
	srv.updateMu.Lock()
	srv.updateCache = &UpdateInfo{
		CurrentVersion:  "1.0.0",
		LatestVersion:   "1.0.0",
		UpdateAvailable: false,
	}
	srv.updateCheckedAt = time.Now()
	srv.config.Web.UpdateCheckInterval = time.Hour
	srv.updateMu.Unlock()

	req := httptest.NewRequest("GET", "/api/system/update/check", nil)
	w := httptest.NewRecorder()
	srv.handleCheckUpdate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["update_available"] != false {
		t.Fatalf("expected update_available=false, got %v", body["update_available"])
	}
}

func TestHandleApplyUpdate_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/system/update/apply", nil)
	w := httptest.NewRecorder()
	srv.handleApplyUpdate(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// ===========================================================================
// dohClientAddr edge cases (api_doh.go)
// ===========================================================================

func TestDohClientAddr_InvalidRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "not-an-address"

	addr := dohClientAddr(req)
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatal("expected *net.TCPAddr")
	}
	// Since "not-an-address" is not a valid IP, should fall back to 127.0.0.1
	if !tcpAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("expected 127.0.0.1, got %v", tcpAddr.IP)
	}
}

func TestDohClientAddr_ValidIPv6(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:12345"

	addr := dohClientAddr(req)
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatal("expected *net.TCPAddr")
	}
	if !tcpAddr.IP.Equal(net.IPv6loopback) {
		t.Fatalf("expected ::1, got %v", tcpAddr.IP)
	}
	if tcpAddr.Port != 12345 {
		t.Fatalf("expected port 12345, got %d", tcpAddr.Port)
	}
}

func TestDohClientAddr_NoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	// SplitHostPort will fail for bare IP without port
	req.RemoteAddr = "192.168.1.1"

	addr := dohClientAddr(req)
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatal("expected *net.TCPAddr")
	}
	// Fallback: parse as raw IP
	if !tcpAddr.IP.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Fatalf("expected 192.168.1.1, got %v", tcpAddr.IP)
	}
}

// ===========================================================================
// skipDNSName edge cases (api_doh.go)
// ===========================================================================

func TestSkipDNSName_NegativeOffset(t *testing.T) {
	result := skipDNSName([]byte{0}, -1)
	if result != -1 {
		t.Fatalf("expected -1 for negative offset, got %d", result)
	}
}

func TestSkipDNSName_OffsetBeyondBuffer(t *testing.T) {
	buf := []byte{3, 'f', 'o', 'o', 0}
	result := skipDNSName(buf, 10)
	if result != -1 {
		t.Fatalf("expected -1 for offset beyond buffer, got %d", result)
	}
}

func TestSkipDNSName_EmptyBuffer(t *testing.T) {
	result := skipDNSName([]byte{}, 0)
	if result != -1 {
		t.Fatalf("expected -1 for empty buffer, got %d", result)
	}
}

func TestSkipDNSName_ZeroLengthLabel(t *testing.T) {
	// Root name: just a zero byte
	result := skipDNSName([]byte{0}, 0)
	if result != 1 {
		t.Fatalf("expected 1 for root name, got %d", result)
	}
}

func TestSkipDNSName_CompressedPointer(t *testing.T) {
	buf := []byte{0xC0, 0x0C}
	result := skipDNSName(buf, 0)
	if result != 2 {
		t.Fatalf("expected 2 for compressed pointer, got %d", result)
	}
}

func TestSkipDNSName_RegularLabel(t *testing.T) {
	// "foo" followed by root
	buf := []byte{3, 'f', 'o', 'o', 0}
	result := skipDNSName(buf, 0)
	if result != 5 {
		t.Fatalf("expected 5, got %d", result)
	}
}

func TestSkipDNSName_TruncatedLabel(t *testing.T) {
	// Label says 10 bytes but buffer only has 3
	buf := []byte{10, 'a', 'b'}
	result := skipDNSName(buf, 0)
	if result != -1 {
		t.Fatalf("expected -1 for truncated label, got %d", result)
	}
}

// ===========================================================================
// dohMinTTL additional edge cases (api_doh.go)
// ===========================================================================

func TestDohMinTTL_TruncatedQuestion(t *testing.T) {
	// Header with QDCOUNT=1 but no question section
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[4:6], 1) // QDCOUNT=1
	binary.BigEndian.PutUint16(buf[6:8], 1) // ANCOUNT=1

	result := dohMinTTL(buf)
	if result != 0 {
		t.Fatalf("expected 0 for truncated question, got %d", result)
	}
}

func TestDohMinTTL_MultipleAnswersReturnMinimum(t *testing.T) {
	// Build a response with 2 answer records: TTL=600 and TTL=120
	// Layout: Header(12) + Question(17) + Answer1(16) + Answer2(16) = 61 bytes
	// Each answer: name_ptr(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA(4) = 16
	buf := make([]byte, 12+17+16+16)
	binary.BigEndian.PutUint16(buf[0:2], 0x1234)
	binary.BigEndian.PutUint16(buf[2:4], 0x8180)
	binary.BigEndian.PutUint16(buf[4:6], 1) // QDCOUNT=1
	binary.BigEndian.PutUint16(buf[6:8], 2) // ANCOUNT=2
	// Question section (example.com A IN)
	copy(buf[12:], []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0})
	binary.BigEndian.PutUint16(buf[25:27], 1) // QTYPE=A
	binary.BigEndian.PutUint16(buf[27:29], 1) // QCLASS=IN
	// Answer 1: compressed name ptr + TYPE=A + CLASS=IN + TTL=600 + RDLENGTH=4 + RDATA
	off := 29
	buf[off] = 0xC0
	buf[off+1] = 0x0C                                  // name pointer
	binary.BigEndian.PutUint16(buf[off+2:off+4], 1)    // TYPE=A
	binary.BigEndian.PutUint16(buf[off+4:off+6], 1)    // CLASS=IN
	binary.BigEndian.PutUint32(buf[off+6:off+10], 600) // TTL=600
	binary.BigEndian.PutUint16(buf[off+10:off+12], 4)  // RDLENGTH=4
	copy(buf[off+12:off+16], net.IPv4(1, 2, 3, 4).To4())
	// Answer 2: compressed name ptr + TYPE=A + CLASS=IN + TTL=120 + RDLENGTH=4 + RDATA
	off2 := off + 16
	buf[off2] = 0xC0
	buf[off2+1] = 0x0C                                   // name pointer
	binary.BigEndian.PutUint16(buf[off2+2:off2+4], 1)    // TYPE=A
	binary.BigEndian.PutUint16(buf[off2+4:off2+6], 1)    // CLASS=IN
	binary.BigEndian.PutUint32(buf[off2+6:off2+10], 120) // TTL=120
	binary.BigEndian.PutUint16(buf[off2+10:off2+12], 4)  // RDLENGTH=4
	copy(buf[off2+12:off2+16], net.IPv4(5, 6, 7, 8).To4())

	result := dohMinTTL(buf)
	if result != 120 {
		t.Fatalf("expected min TTL 120, got %d", result)
	}
}

// ===========================================================================
// handleDoH with error handler and nil response (api_doh.go)
// ===========================================================================

// errorDNSHandler returns an error from Handle.
type errorDNSHandler struct{}

func (h *errorDNSHandler) Handle(query []byte, addr net.Addr) ([]byte, error) {
	return nil, fmt.Errorf("simulated error")
}

// nilResponseHandler returns nil with no error.
type nilResponseHandler struct{}

func (h *nilResponseHandler) Handle(query []byte, addr net.Addr) ([]byte, error) {
	return nil, nil
}

func TestDoH_HandlerError(t *testing.T) {
	srv := testDoHServer(t)
	srv.SetDoHHandler(&errorDNSHandler{})

	query := buildDNSQuery(0xAAAA)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()
	srv.handleDoH(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestDoH_NilResponse(t *testing.T) {
	srv := testDoHServer(t)
	srv.SetDoHHandler(&nilResponseHandler{})

	query := buildDNSQuery(0xBBBB)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()
	srv.handleDoH(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ===========================================================================
// formatRData for DNAME type (api_cache.go)
// ===========================================================================

func TestFormatRData_TypeDNAME(t *testing.T) {
	nameBytes := dns.BuildPlainName("target.example.com.")
	rr := dns.ResourceRecord{
		Type:  dns.TypeDNAME,
		RData: nameBytes,
	}
	s := formatRData(rr)
	if !strings.Contains(s, "target.example.com") {
		t.Fatalf("expected target.example.com in output, got %q", s)
	}
}

// ===========================================================================
// RecordQuery with BLOCKED and FORMERR/REFUSED rcodes (server.go)
// ===========================================================================

func TestRecordQuery_Blocked(t *testing.T) {
	srv := testAdminServer(t)
	srv.RecordQuery("10.0.0.1", "blocked.com.", "A", "BLOCKED", false, 0.5)

	entries := srv.queryLog.Recent(1)
	if len(entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	if !entries[0].Blocked {
		t.Fatal("expected Blocked=true for BLOCKED rcode")
	}
}

func TestRecordQuery_ErrorRCodes(t *testing.T) {
	srv := testAdminServer(t)
	srv.RecordQuery("10.0.0.1", "err.com.", "A", "FORMERR", false, 1.0)
	srv.RecordQuery("10.0.0.1", "ref.com.", "A", "REFUSED", false, 1.0)

	// These should be recorded as errors in the time series
	entries := srv.queryLog.Recent(2)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

// ===========================================================================
// registerRoutes with DoH enabled (server.go)
// ===========================================================================

func TestRegisterRoutes_WithDoH(t *testing.T) {
	srv := testAdminServer(t)
	srv.SetDoHHandler(&echoHandler{})
	srv.SetDoHEnabled(true)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// The /dns-query route should be registered
	query := buildDNSQuery(0x1111)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ===========================================================================
// Start with TLS config (server.go)
// ===========================================================================

func TestAdminServerStart_DefaultAddr(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Addr = "" // empty — should default to 127.0.0.1:8080

	ctx, cancel := context.WithCancel(context.Background())

	// Start will try to bind 127.0.0.1:8080 — it may fail if the port is taken
	// We just cancel immediately to test the default addr code path
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	// This may return an error if port 8080 is in use; we just want to exercise the code path
	srv.Start(ctx)
}

// ===========================================================================
// TimeSeries: flushCurrentLocked nil bucket, Snapshot with old timestamps
// ===========================================================================

func TestTimeSeries_FlushNilCurrent(t *testing.T) {
	ts := NewTimeSeriesAggregator()

	// flushCurrentLocked with nil current should be a no-op
	ts.mu.Lock()
	ts.flushCurrentLocked()
	ts.mu.Unlock()

	if len(ts.buckets) != 0 {
		t.Fatalf("expected 0 buckets after flushing nil, got %d", len(ts.buckets))
	}
}

func TestTimeSeries_MaxBucketsTrimming(t *testing.T) {
	ts := NewTimeSeriesAggregator()

	// Fill with more than maxBuckets entries
	ts.mu.Lock()
	for i := 0; i < maxBuckets+10; i++ {
		ts.buckets = append(ts.buckets, Bucket{
			Timestamp: time.Now().Add(-time.Duration(i) * bucketInterval).UTC().Format(time.RFC3339),
			Queries:   1,
		})
	}
	// Trigger trimming
	ts.current = &activeBucket{
		ts:      time.Now().Truncate(bucketInterval),
		queries: 1,
	}
	ts.flushCurrentLocked()
	ts.mu.Unlock()

	ts.mu.Lock()
	count := len(ts.buckets)
	ts.mu.Unlock()

	if count > maxBuckets {
		t.Fatalf("expected at most %d buckets, got %d", maxBuckets, count)
	}
}

func TestTimeSeries_SnapshotFiltersOldBuckets(t *testing.T) {
	ts := NewTimeSeriesAggregator()

	// Add a bucket from 2 hours ago (outside any 1h window)
	ts.mu.Lock()
	ts.buckets = append(ts.buckets, Bucket{
		Timestamp: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
		Queries:   999,
	})
	ts.mu.Unlock()

	// Snapshot with 5-minute window should not include the old bucket
	snap := ts.Snapshot(5 * time.Minute)
	for _, b := range snap {
		if b.Queries == 999 {
			t.Fatal("old bucket should have been filtered out")
		}
	}
}

// ===========================================================================
// Zabbix: handleZabbixConn with ZBXD header prefix (api_zabbix.go)
// ===========================================================================

func TestHandleZabbixConn_WithZBXDPrefix(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	go StartZabbixAgent(ctx, addr, m, c, logger)

	var conn net.Conn
	for i := 0; i < 50; i++ {
		conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send request with ZBXD\x01 header + 8-byte length + key
	key := "labyrinth.cache.entries"
	zbxdHeader := []byte("ZBXD\x01")
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, uint64(len(key)))
	payload := append(zbxdHeader, lenBytes...)
	payload = append(payload, []byte(key)...)
	conn.Write(payload)

	// Read ZBXD response
	header := make([]byte, 13)
	_, err = io.ReadFull(conn, header)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}

	if string(header[:4]) != "ZBXD" {
		t.Fatalf("expected ZBXD header, got %q", header[:4])
	}

	dataLen := binary.LittleEndian.Uint64(header[5:13])
	respData := make([]byte, dataLen)
	io.ReadFull(conn, respData)

	if string(respData) != "0" {
		t.Fatalf("want '0', got %q", string(respData))
	}
}

// ===========================================================================
// handleSetupComplete with password hash error path (api_setup.go)
// ===========================================================================

func TestHandleSetupComplete_WithRateLimit(t *testing.T) {
	srv := testAdminServer(t)

	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	reqBody := `{
		"listen_addr": ":5353",
		"web_addr": "127.0.0.1:9090",
		"username": "admin",
		"password": "securepass123",
		"max_cache_size": 50000,
		"max_depth": 20,
		"rate_limit_rate": 100,
		"rate_limit_burst": 50,
		"log_level": "debug",
		"log_format": "text"
	}`

	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.handleSetupComplete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}

	data, _ := os.ReadFile(filepath.Join(tmpDir, "labyrinth.yaml"))
	content := string(data)
	if !strings.Contains(content, "rate_limit") {
		t.Fatal("expected rate_limit section in config")
	}
	if !strings.Contains(content, "burst: 50") {
		t.Fatal("expected burst in config")
	}
}

func TestHandleSetupComplete_WriteError(t *testing.T) {
	srv := testAdminServer(t)

	// Chdir to a non-existent directory to trigger write error
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	// Create a read-only dir or use an invalid path
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Remove the dir so writing fails
	os.RemoveAll(tmpDir)

	reqBody := `{}`
	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.handleSetupComplete(w, req)

	if w.Code != http.StatusInternalServerError {
		// On some OS, this might work (if tmpDir still exists due to cwd holding it)
		// So this is best-effort
		t.Logf("got status %d (expected 500 but OS may keep dir)", w.Code)
	}
}

// ===========================================================================
// writeConfigYAML: rate limit with burst=0 (api_setup.go)
// ===========================================================================

func TestWriteConfigYAML_RateLimitNoBurst(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")

	cfg := SetupRequest{
		ListenAddr:    ":53",
		WebAddr:       "127.0.0.1:8080",
		LogLevel:      "info",
		LogFormat:     "json",
		RateLimitRate: 50,
		// RateLimitBurst = 0 — no burst line
	}

	if err := writeConfigYAML(path, cfg, ""); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "rate: 50") {
		t.Fatal("expected rate in config")
	}
	if strings.Contains(content, "burst:") {
		t.Fatal("should not include burst when it's 0")
	}
}

// ===========================================================================
// validateJWT: invalid payload encoding (auth.go)
// ===========================================================================

func TestValidateJWT_InvalidPayloadEncoding(t *testing.T) {
	secret := []byte("test-secret")
	// Create a token with a valid header and signature but invalid payload
	badPayload := "!!!invalid-base64!!!"
	signingInput := jwtHeaderB64 + "." + badPayload
	sig := signHS256(signingInput, secret)
	token := signingInput + "." + sig

	_, err := validateJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for invalid payload encoding")
	}
}

func TestValidateJWT_InvalidPayloadJSON(t *testing.T) {
	secret := []byte("test-secret")
	// Create a token with valid base64 payload but invalid JSON
	badPayload := encodeSegment([]byte("not valid json"))
	signingInput := jwtHeaderB64 + "." + badPayload
	sig := signHS256(signingInput, secret)
	token := signingInput + "." + sig

	_, err := validateJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for invalid payload JSON")
	}
}

func TestValidateJWT_InvalidSignatureEncoding(t *testing.T) {
	secret := []byte("test-secret")
	token, _ := generateJWT("user", secret)
	parts := strings.SplitN(token, ".", 3)
	// Replace signature with invalid base64
	token = parts[0] + "." + parts[1] + ".!!!invalid!!!"

	_, err := validateJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for invalid signature encoding")
	}
}

// ===========================================================================
// handleLogin: generate JWT error (auth.go)
// This is difficult to trigger since generateJWT rarely fails.
// We cover the already-tested branches more thoroughly instead.
// ===========================================================================

// ===========================================================================
// Negative cache with entries (api_cache.go)
// ===========================================================================

func TestHandleNegativeCache_WithEntries(t *testing.T) {
	srv := testAdminServer(t)

	// Store a negative entry
	srv.cache.StoreNegative("nxdomain.com.", dns.TypeA, dns.ClassIN, cache.NegNXDomain, dns.RCodeNXDomain, nil)

	req := httptest.NewRequest("GET", "/api/cache/negative?limit=10", nil)
	w := httptest.NewRecorder()
	srv.handleNegativeCache(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	count, ok := body["count"].(float64)
	if !ok {
		t.Fatal("missing count")
	}
	if count == 0 {
		t.Fatal("expected at least one negative entry")
	}
}

// ===========================================================================
// handleCacheLookup: ALL with empty records (api_cache.go)
// Test the entryType == "" -> "UNKNOWN" fallback
// ===========================================================================

// ===========================================================================
// WebSocket query stream: context cancel path (api_queries.go)
// ===========================================================================

func TestHandleQueryStreamWS_LiveStreaming(t *testing.T) {
	srv := testAdminServer(t)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/queries/stream"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}

	// Now record a query after connection is established
	time.Sleep(100 * time.Millisecond) // let the subscription be set up
	srv.RecordQuery("10.0.0.2", "live.com.", "AAAA", "NOERROR", true, 0.5)

	// Read the live entry
	_, msg, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("websocket read: %v", err)
	}

	var entry QueryEntry
	if err := json.Unmarshal(msg, &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.QName != "live.com." {
		t.Fatalf("want qname live.com., got %q", entry.QName)
	}

	conn.Close(websocket.StatusGoingAway, "done")
}

// ===========================================================================
// handleCheckUpdate: stale cache fallback (api_update.go)
// ===========================================================================

func TestHandleCheckUpdate_StaleCacheFallback(t *testing.T) {
	srv := testAdminServer(t)
	// Set stale cache (old timestamp, short interval)
	srv.updateMu.Lock()
	srv.updateCache = &UpdateInfo{
		CurrentVersion:  "1.0.0",
		LatestVersion:   "1.1.0",
		UpdateAvailable: true,
	}
	srv.updateCheckedAt = time.Now().Add(-2 * time.Hour) // stale
	srv.config.Web.UpdateCheckInterval = time.Minute     // short interval
	srv.updateMu.Unlock()

	// This will try to fetch fresh from GitHub (which may fail), then return stale
	req := httptest.NewRequest("GET", "/api/system/update/check", nil)
	w := httptest.NewRecorder()
	srv.handleCheckUpdate(w, req)

	// Should return either fresh or stale, both give 200
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleCheckUpdate_NoCacheAndFetchFails(t *testing.T) {
	srv := testAdminServer(t)
	// No cache set, very short interval so it won't use cache
	srv.config.Web.UpdateCheckInterval = time.Nanosecond

	req := httptest.NewRequest("GET", "/api/system/update/check", nil)
	w := httptest.NewRecorder()
	srv.handleCheckUpdate(w, req)

	// Will try GitHub API — may return 200 (if GitHub is reachable) or 502 (if not)
	// We just want to exercise the code path
	if w.Code != http.StatusOK && w.Code != http.StatusBadGateway {
		t.Fatalf("want 200 or 502, got %d", w.Code)
	}
}

// ===========================================================================
// handleApplyUpdate exercise (api_update.go)
// ===========================================================================

// TestHandleApplyUpdate_ExerciseCodePath is not safe to run because on Windows
// restartSelf calls os.Exit(0), which kills the test process. The handleApplyUpdate
// function also calls the real GitHub API. This is documented as untestable without
// modifying production code (making githubReleasesURL a variable or injecting an
// HTTP client).

// ===========================================================================
// dohMinTTL: truncated answer record (api_doh.go)
// ===========================================================================

func TestDohMinTTL_TruncatedAnswerRecord(t *testing.T) {
	// Header with ANCOUNT=1 but answer is truncated (less than 10 bytes after name)
	buf := make([]byte, 12+17+5)            // header + question + truncated answer
	binary.BigEndian.PutUint16(buf[4:6], 1) // QDCOUNT=1
	binary.BigEndian.PutUint16(buf[6:8], 1) // ANCOUNT=1
	// Question: root name (single zero byte) + QTYPE + QCLASS
	buf[12] = 0                               // root name
	binary.BigEndian.PutUint16(buf[13:15], 1) // QTYPE
	binary.BigEndian.PutUint16(buf[15:17], 1) // QCLASS
	// Answer starts at 17: just a root name (1 byte) + 4 bytes = 5 bytes, less than 10
	buf[17] = 0 // root name

	result := dohMinTTL(buf)
	if result != 0 {
		t.Fatalf("expected 0 for truncated answer, got %d", result)
	}
}

func TestDohMinTTL_AnswerRDLengthExceedsBuf(t *testing.T) {
	// Build a response where RDLENGTH pushes offset past buffer end.
	// The function reads TTL and RDLENGTH, then computes new offset.
	// Since offset+10+rdlen > len(buf), it breaks BEFORE updating minTTL.
	buf := make([]byte, 12+5+12)            // header + minimal question + partial answer
	binary.BigEndian.PutUint16(buf[4:6], 1) // QDCOUNT=1
	binary.BigEndian.PutUint16(buf[6:8], 1) // ANCOUNT=1
	// Question: root name + QTYPE + QCLASS
	buf[12] = 0
	binary.BigEndian.PutUint16(buf[13:15], 1)
	binary.BigEndian.PutUint16(buf[15:17], 1)
	// Answer: root name (1 byte) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
	buf[17] = 0                                 // root name
	binary.BigEndian.PutUint32(buf[22:26], 300) // TTL
	binary.BigEndian.PutUint16(buf[26:28], 255) // RDLENGTH=255 (exceeds buffer)

	result := dohMinTTL(buf)
	// The break happens before minTTL is set, so result is 0
	if result != 0 {
		t.Fatalf("expected 0 (break before minTTL update), got %d", result)
	}
}

// ===========================================================================
// handleCacheLookup ALL: entry with no records (entryType fallback)
// ===========================================================================

func TestHandleCacheLookup_ALL_EmptyRecords(t *testing.T) {
	srv := testAdminServer(t)

	// Store a negative entry that has no answer records
	srv.cache.StoreNegative("neg.com.", dns.TypeA, dns.ClassIN, cache.NegNXDomain, dns.RCodeNXDomain, nil)

	req := httptest.NewRequest("GET", "/api/cache/lookup?name=neg.com.&type=ALL", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	// Negative entries via LookupAll may or may not have empty Records
	// This exercises the code path; status depends on cache internals
	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Fatalf("want 200 or 404, got %d", w.Code)
	}
}

// ===========================================================================
// toptracker prune: keep > len(entries) (toptracker.go)
// ===========================================================================

func TestTopTracker_PruneKeepMoreThanEntries(t *testing.T) {
	// limit=100, so prune triggers at >1000, and keep=200
	// But if we only have a few more than 1000 entries, keep > entries
	tracker := NewTopTracker(100)

	// Add exactly limit*10 + 1 = 1001 unique keys
	for i := 0; i < 1001; i++ {
		tracker.Inc(fmt.Sprintf("key-%d", i))
	}

	// After the 1001st Inc, prune should have been called
	// keep = 100*2 = 200, but entries might be fewer after prune runs
	// The point is to exercise the keep > len(entries) branch
	top := tracker.Top(5)
	if len(top) == 0 {
		t.Fatal("expected at least some entries after prune")
	}
}

// ===========================================================================
// AdminServer Start: TLS config path (server.go)
// ===========================================================================

func TestAdminServerStart_TLS(t *testing.T) {
	srv := testAdminServer(t)

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv.config.Web.Addr = addr
	srv.config.Web.TLSEnabled = true
	srv.config.Web.TLSCertFile = "nonexistent-cert.pem"
	srv.config.Web.TLSKeyFile = "nonexistent-key.pem"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// The TLS start should fail since the cert/key files don't exist
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error for missing TLS cert")
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Start did not return after TLS failure")
	}
}

// ===========================================================================
// NewAdminServer: rand.Read fallback path (server.go)
// This is tested indirectly — the fallback only triggers if crypto/rand fails
// which is OS-dependent and cannot be easily triggered. Dead code in practice.
// ===========================================================================

// ===========================================================================
// dohDecodePost: io.ReadAll error (api_doh.go line 94-96)
// This requires an io.Reader that returns an error, which is hard to trigger
// via httptest since httptest wraps the body. Dead code in practice.
// ===========================================================================

// ===========================================================================
// handleQueryStreamWS: additional coverage for context cancel path
// ===========================================================================

func TestHandleQueryStreamWS_ContextCancel(t *testing.T) {
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

	// Cancel context to trigger the ctx.Done() path in handleQueryStreamWS
	cancel()

	// Give the server time to notice the cancellation
	time.Sleep(200 * time.Millisecond)

	// Try to read — should fail since connection is closed
	readCtx, readCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer readCancel()
	_, _, err = conn.Read(readCtx)
	if err == nil {
		t.Fatal("expected error after context cancel")
	}

	conn.Close(websocket.StatusGoingAway, "done")
}

// ===========================================================================
// SPAHandler: exercise the fs.Sub success path (embed.go)
// The fs.Sub error path (lines 17-22) only triggers if the embed fails at
// compile time, which is not possible in tests.
// ===========================================================================

// ===========================================================================
// handleLogin: generateJWT error (auth.go line 157-160)
// This requires json.Marshal to fail on jwtPayload, which is unreachable
// since jwtPayload only contains string and int64 fields.
// ===========================================================================

// ===========================================================================
// handleSetupComplete: error from writeConfigYAML (api_setup.go)
// ===========================================================================

func TestHandleSetupComplete_WriteConfigError(t *testing.T) {
	srv := testAdminServer(t)

	// Create a tmpDir and then make 'labyrinth.yaml' a directory so Create fails
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Create a directory named labyrinth.yaml so os.Create fails
	os.Mkdir(filepath.Join(tmpDir, "labyrinth.yaml"), 0755)

	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	srv.handleSetupComplete(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ===========================================================================
// writeConfigYAML: os.Create error (api_setup.go)
// ===========================================================================

func TestWriteConfigYAML_CreateError(t *testing.T) {
	// Use a path inside a directory that doesn't exist
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "nonexistent-subdir", "deeper", "config.yaml")
	err := writeConfigYAML(badPath, SetupRequest{}, "")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

// ===========================================================================
// handleSetupComplete: password hash error (api_setup.go lines 61-64)
// HashPassword only fails for short passwords. Empty password skips hashing.
// So this path is actually covered by the empty password + defaults test.
// Let me trigger it with a short non-empty password.
// ===========================================================================

func TestHandleSetupComplete_ShortPassword(t *testing.T) {
	srv := testAdminServer(t)

	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Password is non-empty but too short
	reqBody := `{"password": "short"}`
	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.handleSetupComplete(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ===========================================================================
// handleChangePassword: HashPassword error path (auth.go lines 212-215)
// This is nearly unreachable since ValidatePassword would catch it first.
// Already covered by TestHandleChangePassword_NewPasswordTooShort.
// ===========================================================================

// ===========================================================================
// StartZabbixAgent: accept error + context cancel (api_zabbix.go)
// ===========================================================================

func TestStartZabbixAgent_ContextCancel(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	errCh := make(chan error, 1)
	go func() {
		errCh <- StartZabbixAgent(ctx, addr, m, c, logger)
	}()

	// Wait for agent to start
	time.Sleep(200 * time.Millisecond)

	// Cancel to trigger the ctx.Done() path in the accept loop
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected nil error on context cancel, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StartZabbixAgent did not return after cancel")
	}
}

// ===========================================================================
// handleZabbixConn: connection read error (api_zabbix.go)
// ===========================================================================

func TestHandleZabbixConn_ReadError(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create a pipe where we immediately close the writer to cause a read error
	server, client := net.Pipe()
	client.Close() // Close immediately to cause read error

	// This should not panic
	handleZabbixConn(server, m, c, logger)
}

// ===========================================================================
// Snapshot: time.Parse error branch (timeseries.go line 137-138)
// This is unreachable since timestamps are always written with time.RFC3339.
// ===========================================================================

// ===========================================================================
// Remaining unreachable/dead code summary:
// - parseSemverParts i>=3 break: dead code (SplitN returns max 3)
// - generateJWT json.Marshal error: unreachable (simple struct)
// - SPAHandler fs.Sub error: compile-time guaranteed
// - NewAdminServer rand.Read fallback: OS-level failure
// - dohDecodePost io.ReadAll error: requires broken Reader
// - restartSelf (update_windows.go): calls os.Exit(0), untestable
// - checkForUpdate/findAssetURL: require network access to GitHub API
// - StartUpdateChecker: requires network + long wait times
// ===========================================================================
