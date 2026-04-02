package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"nhooyr.io/websocket"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testAdminServer(t *testing.T) *AdminServer {
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
	return NewAdminServer(cfg, c, m, nil, logger)
}

func testAdminServerWithAuth(t *testing.T) (*AdminServer, string) {
	t.Helper()
	password := "s3cretPass!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled:        true,
			Addr:           "127.0.0.1:0",
			QueryLogBuffer: 100,
			Auth: config.WebAuthConfig{
				Username:     "admin",
				PasswordHash: hash,
			},
		},
	}
	return NewAdminServer(cfg, c, m, nil, logger), password
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode JSON: %v\nbody: %s", err, w.Body.String())
	}
	return m
}

// encodeSegment base64url-encodes data without padding.
func encodeSegment(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// signHS256 computes HMAC-SHA256 and returns the base64url-encoded result.
func signHS256(input string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// =========================================================================
// 1. QueryLog tests
// =========================================================================

func TestNewQueryLog(t *testing.T) {
	ql := NewQueryLog(10)
	if ql.capacity != 10 {
		t.Fatalf("want capacity 10, got %d", ql.capacity)
	}
}

func TestNewQueryLog_NegativeCapacity(t *testing.T) {
	ql := NewQueryLog(-1)
	if ql.capacity != 1000 {
		t.Fatalf("want default capacity 1000, got %d", ql.capacity)
	}
}

func TestQueryLog_RecordAndRecent(t *testing.T) {
	ql := NewQueryLog(5)

	for i := 0; i < 3; i++ {
		ql.Record(QueryEntry{ID: uint64(i + 1), QName: "example.com."})
	}

	recent := ql.Recent(10) // request more than available
	if len(recent) != 3 {
		t.Fatalf("want 3 recent entries, got %d", len(recent))
	}
	if recent[0].ID != 1 || recent[2].ID != 3 {
		t.Fatalf("entries not in chronological order")
	}
}

func TestQueryLog_RecentWraparound(t *testing.T) {
	ql := NewQueryLog(3)

	for i := 0; i < 5; i++ {
		ql.Record(QueryEntry{ID: uint64(i + 1), QName: "test."})
	}

	recent := ql.Recent(3)
	if len(recent) != 3 {
		t.Fatalf("want 3, got %d", len(recent))
	}
	if recent[0].ID != 3 || recent[1].ID != 4 || recent[2].ID != 5 {
		t.Fatalf("wrong wraparound IDs: %v %v %v", recent[0].ID, recent[1].ID, recent[2].ID)
	}
}

func TestQueryLog_RecentZero(t *testing.T) {
	ql := NewQueryLog(5)
	if r := ql.Recent(0); r != nil {
		t.Fatalf("expected nil for n=0, got %v", r)
	}
	if r := ql.Recent(5); r != nil {
		t.Fatalf("expected nil for empty log, got %v", r)
	}
}

func TestQueryLog_SubscribeUnsubscribe(t *testing.T) {
	ql := NewQueryLog(10)
	id, ch := ql.Subscribe()

	ql.Record(QueryEntry{ID: 42, QName: "sub.example."})

	select {
	case e := <-ch:
		if e.ID != 42 {
			t.Fatalf("want ID 42, got %d", e.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for subscriber")
	}

	ql.Unsubscribe(id)

	// Channel should be closed after unsubscribe.
	_, ok := <-ch
	if ok {
		t.Fatal("expected channel to be closed")
	}
}

func TestQueryLog_SubscribeSlowDrops(t *testing.T) {
	ql := NewQueryLog(10)
	_, ch := ql.Subscribe()

	// Overflow the 128-element channel buffer to trigger drops.
	for i := 0; i < 200; i++ {
		ql.Record(QueryEntry{ID: uint64(i)})
	}

	drained := 0
	for {
		select {
		case <-ch:
			drained++
		default:
			goto done
		}
	}
done:
	if drained == 0 {
		t.Fatal("expected at least some entries")
	}
	if drained > 128 {
		t.Fatalf("drained %d > channel buffer 128", drained)
	}
}

// =========================================================================
// 2. TimeSeries tests
// =========================================================================

func TestNewTimeSeriesAggregator(t *testing.T) {
	ts := NewTimeSeriesAggregator()
	if ts == nil {
		t.Fatal("nil aggregator")
	}
	if len(ts.buckets) != 0 {
		t.Fatalf("expected 0 initial buckets, got %d", len(ts.buckets))
	}
}

func TestTimeSeries_Record(t *testing.T) {
	ts := NewTimeSeriesAggregator()

	ts.Record(true, 1.5, false)
	ts.Record(false, 3.0, true)
	ts.Record(false, 2.0, false)

	ts.mu.Lock()
	cur := ts.current
	ts.mu.Unlock()

	if cur == nil {
		t.Fatal("current bucket is nil after recording")
	}
	if cur.queries != 3 {
		t.Fatalf("want 3 queries, got %d", cur.queries)
	}
	if cur.cacheHits != 1 {
		t.Fatalf("want 1 cache hit, got %d", cur.cacheHits)
	}
	if cur.cacheMisses != 2 {
		t.Fatalf("want 2 cache misses, got %d", cur.cacheMisses)
	}
	if cur.errors != 1 {
		t.Fatalf("want 1 error, got %d", cur.errors)
	}
}

func TestTimeSeries_Snapshot(t *testing.T) {
	ts := NewTimeSeriesAggregator()
	ts.Record(true, 2.0, false)

	snap := ts.Snapshot(time.Hour)
	if len(snap) == 0 {
		t.Fatal("expected at least 1 bucket in snapshot")
	}

	found := false
	for _, b := range snap {
		if b.Queries > 0 {
			found = true
			if b.CacheHits != 1 {
				t.Fatalf("want 1 cache hit, got %d", b.CacheHits)
			}
		}
	}
	if !found {
		t.Fatal("no bucket with queries > 0 found")
	}
}

// =========================================================================
// 3. Auth tests
// =========================================================================

func TestGenerateAndValidateJWT(t *testing.T) {
	secret := []byte("test-secret-key-0123456789abcdef")

	token, err := generateJWT("alice", secret)
	if err != nil {
		t.Fatalf("generateJWT: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}

	user, err := validateJWT(token, secret)
	if err != nil {
		t.Fatalf("validateJWT: %v", err)
	}
	if user != "alice" {
		t.Fatalf("want user alice, got %q", user)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	secret := []byte("test-secret-key-0123456789abcdef")

	expiredPayload, _ := json.Marshal(jwtPayload{
		Sub: "bob",
		Iat: time.Now().Add(-48 * time.Hour).Unix(),
		Exp: time.Now().Add(-24 * time.Hour).Unix(),
	})
	payloadB64 := encodeSegment(expiredPayload)
	signingInput := jwtHeaderB64 + "." + payloadB64
	sig := signHS256(signingInput, secret)
	expiredToken := signingInput + "." + sig

	_, err := validateJWT(expiredToken, secret)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected 'expired' in error, got: %v", err)
	}
}

func TestValidateJWT_InvalidFormat(t *testing.T) {
	_, err := validateJWT("not-a-jwt", []byte("secret"))
	if err == nil {
		t.Fatal("expected error for bad format")
	}
}

func TestValidateJWT_TamperedSignature(t *testing.T) {
	secret := []byte("test-secret")
	token, _ := generateJWT("carol", secret)

	// Flip a character in the middle of the signature to ensure actual tampering
	parts := strings.SplitN(token, ".", 3)
	sig := parts[2]
	// Toggle the first character of the signature
	var flipped byte
	if sig[0] == 'A' {
		flipped = 'B'
	} else {
		flipped = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(flipped) + sig[1:]
	_, err := validateJWT(tampered, secret)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	token, _ := generateJWT("dave", []byte("secret-A"))
	_, err := validateJWT(token, []byte("secret-B"))
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestValidateJWT_MissingSubject(t *testing.T) {
	secret := []byte("test-secret")
	payload, _ := json.Marshal(jwtPayload{
		Sub: "",
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(time.Hour).Unix(),
	})
	payloadB64 := encodeSegment(payload)
	signingInput := jwtHeaderB64 + "." + payloadB64
	sig := signHS256(signingInput, secret)
	token := signingInput + "." + sig

	_, err := validateJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for missing subject")
	}
}

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("password123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" || hash == "password123" {
		t.Fatal("hash looks wrong")
	}
}

func TestCheckPassword(t *testing.T) {
	hash, _ := HashPassword("hunter2pass")
	if !checkPassword("hunter2pass", hash) {
		t.Fatal("correct password should match")
	}
	if checkPassword("wrongpassword", hash) {
		t.Fatal("wrong password should not match")
	}
}

// =========================================================================
// 4. Middleware tests
// =========================================================================

func TestRequireAuth_NoAuthConfigured(t *testing.T) {
	srv := testAdminServer(t)

	called := false
	handler := srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler should be called when no auth configured")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestRequireAuth_MissingToken(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)

	handler := srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestRequireAuth_ValidBearerToken(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)

	token, err := generateJWT("admin", srv.jwtSecret)
	if err != nil {
		t.Fatal(err)
	}

	var gotUser string
	handler := srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		gotUser, _ = r.Context().Value(ctxKeyUser).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if gotUser != "admin" {
		t.Fatalf("want user admin, got %q", gotUser)
	}
}

func TestRequireAuth_ValidQueryToken(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)
	token, _ := generateJWT("admin", srv.jwtSecret)

	var gotUser string
	handler := srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		gotUser, _ = r.Context().Value(ctxKeyUser).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/test?token="+token, nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if gotUser != "admin" {
		t.Fatalf("want admin, got %q", gotUser)
	}
}

func TestRequireAuth_InvalidToken(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)

	handler := srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer garbage.token.here")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestJsonResponse(t *testing.T) {
	w := httptest.NewRecorder()
	jsonResponse(w, http.StatusCreated, map[string]string{"msg": "ok"})

	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("want application/json, got %q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["msg"] != "ok" {
		t.Fatalf("want ok, got %q", body["msg"])
	}
}

// =========================================================================
// 5. API handler tests
// =========================================================================

func TestHandleStats(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	for _, key := range []string{"cache_hits", "cache_misses", "cache_entries", "uptime_seconds", "goroutines"} {
		if _, ok := body[key]; !ok {
			t.Errorf("missing key %q in stats response", key)
		}
	}
}

func TestHandleStats_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleTimeSeries(t *testing.T) {
	srv := testAdminServer(t)
	srv.timeSeries.Record(true, 1.0, false)

	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=5m", nil)
	w := httptest.NewRecorder()
	srv.handleTimeSeries(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if _, ok := body["buckets"]; !ok {
		t.Fatal("missing 'buckets' key")
	}
}

func TestHandleTimeSeries_DefaultWindow(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/stats/timeseries", nil)
	w := httptest.NewRecorder()
	srv.handleTimeSeries(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["window"] != "5m" {
		t.Fatalf("want default window 5m, got %v", body["window"])
	}
}

func TestHandleTimeSeries_InvalidWindow(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=garbage", nil)
	w := httptest.NewRecorder()
	srv.handleTimeSeries(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleTimeSeries_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/stats/timeseries", nil)
	w := httptest.NewRecorder()
	srv.handleTimeSeries(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleCacheStats(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/stats", nil)
	w := httptest.NewRecorder()
	srv.handleCacheStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	for _, key := range []string{"entries", "hits", "misses", "evictions", "hit_rate"} {
		if _, ok := body[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
}

func TestHandleCacheStats_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("DELETE", "/api/cache/stats", nil)
	w := httptest.NewRecorder()
	srv.handleCacheStats(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleCacheLookup_Found(t *testing.T) {
	srv := testAdminServer(t)

	rr := dns.ResourceRecord{
		Name:  "test.com.",
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: net.IPv4(1, 2, 3, 4).To4(),
	}
	srv.cache.Store("test.com.", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{rr}, nil)

	req := httptest.NewRequest("GET", "/api/cache/lookup?name=test.com.&type=A", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["name"] != "test.com." {
		t.Fatalf("want name test.com., got %v", body["name"])
	}
}

func TestHandleCacheLookup_NotFound(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/lookup?name=nonexistent.com.&type=A", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestHandleCacheLookup_MissingName(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/lookup?type=A", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleCacheLookup_UnsupportedType(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/lookup?name=test.com.&type=XYZ", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleCacheLookup_DefaultType(t *testing.T) {
	srv := testAdminServer(t)

	rr := dns.ResourceRecord{
		Name:  "defaulttype.com.",
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: net.IPv4(5, 6, 7, 8).To4(),
	}
	srv.cache.Store("defaulttype.com.", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{rr}, nil)

	req := httptest.NewRequest("GET", "/api/cache/lookup?name=defaulttype.com.", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHandleCacheLookup_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/cache/lookup?name=x&type=A", nil)
	w := httptest.NewRecorder()
	srv.handleCacheLookup(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleCacheFlush(t *testing.T) {
	srv := testAdminServer(t)

	rr := dns.ResourceRecord{
		Name:  "flush.com.",
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: net.IPv4(1, 1, 1, 1).To4(),
	}
	srv.cache.Store("flush.com.", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{rr}, nil)

	req := httptest.NewRequest("POST", "/api/cache/flush", nil)
	w := httptest.NewRecorder()
	srv.handleCacheFlush(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "flushed" {
		t.Fatalf("want 'flushed', got %v", body["status"])
	}

	stats := srv.cache.Stats()
	if stats.Entries != 0 {
		t.Fatalf("cache should be empty after flush, got %d entries", stats.Entries)
	}
}

func TestHandleCacheFlush_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/flush", nil)
	w := httptest.NewRecorder()
	srv.handleCacheFlush(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleCacheDelete(t *testing.T) {
	srv := testAdminServer(t)

	rr := dns.ResourceRecord{
		Name:  "del.com.",
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: net.IPv4(2, 2, 2, 2).To4(),
	}
	srv.cache.Store("del.com.", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{rr}, nil)

	req := httptest.NewRequest("DELETE", "/api/cache/entry?name=del.com.&type=A", nil)
	w := httptest.NewRecorder()
	srv.handleCacheDelete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "deleted" {
		t.Fatalf("want 'deleted', got %v", body["status"])
	}
}

func TestHandleCacheDelete_NotFound(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("DELETE", "/api/cache/entry?name=nope.com.&type=A", nil)
	w := httptest.NewRecorder()
	srv.handleCacheDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestHandleCacheDelete_MissingName(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("DELETE", "/api/cache/entry?type=A", nil)
	w := httptest.NewRecorder()
	srv.handleCacheDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleCacheDelete_UnsupportedType(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("DELETE", "/api/cache/entry?name=x.com.&type=BOGUS", nil)
	w := httptest.NewRecorder()
	srv.handleCacheDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleCacheDelete_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/cache/entry?name=x.com.&type=A", nil)
	w := httptest.NewRecorder()
	srv.handleCacheDelete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleGetConfig(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/config", nil)
	w := httptest.NewRecorder()
	srv.handleGetConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	web, ok := body["web"].(map[string]interface{})
	if !ok {
		t.Fatal("missing 'web' key in config response")
	}
	auth, ok := web["auth"].(map[string]interface{})
	if !ok {
		t.Fatal("missing 'auth' in web config")
	}
	if auth["password_hash"] != "" {
		t.Fatalf("expected empty password_hash, got %v", auth["password_hash"])
	}
}

func TestHandleGetConfig_PasswordRedacted(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)

	req := httptest.NewRequest("GET", "/api/config", nil)
	w := httptest.NewRecorder()
	srv.handleGetConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	web := body["web"].(map[string]interface{})
	auth := web["auth"].(map[string]interface{})

	if auth["password_hash"] != "***REDACTED***" {
		t.Fatalf("expected ***REDACTED***, got %v", auth["password_hash"])
	}
}

func TestHandleGetConfig_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/config", nil)
	w := httptest.NewRecorder()
	srv.handleGetConfig(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleRecentQueries(t *testing.T) {
	srv := testAdminServer(t)

	for i := 0; i < 5; i++ {
		srv.RecordQuery("127.0.0.1", "test.com.", "A", "NOERROR", false, 1.0)
	}

	req := httptest.NewRequest("GET", "/api/queries/recent?limit=3", nil)
	w := httptest.NewRecorder()
	srv.handleRecentQueries(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	count, ok := body["count"].(float64)
	if !ok {
		t.Fatal("missing 'count'")
	}
	if int(count) != 3 {
		t.Fatalf("want count 3, got %v", count)
	}
}

func TestHandleRecentQueries_DefaultLimit(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/queries/recent", nil)
	w := httptest.NewRecorder()
	srv.handleRecentQueries(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHandleRecentQueries_LimitCapped(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/queries/recent?limit=9999", nil)
	w := httptest.NewRecorder()
	srv.handleRecentQueries(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHandleRecentQueries_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/queries/recent", nil)
	w := httptest.NewRecorder()
	srv.handleRecentQueries(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleSetupStatus(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/setup/status", nil)
	w := httptest.NewRecorder()
	srv.handleSetupStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["setup_required"] != true {
		t.Fatalf("expected setup_required=true, got %v", body["setup_required"])
	}
}

func TestHandleSetupStatus_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/setup/status", nil)
	w := httptest.NewRecorder()
	srv.handleSetupStatus(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleSetupComplete(t *testing.T) {
	srv := testAdminServer(t)

	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	reqBody := `{
		"listen_addr": ":5353",
		"web_addr": "127.0.0.1:9090",
		"username": "admin",
		"password": "testpass",
		"max_cache_size": 50000,
		"max_depth": 20,
		"log_level": "debug",
		"log_format": "text"
	}`

	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleSetupComplete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}
	resp := decodeJSON(t, w)
	if resp["status"] != "setup complete" {
		t.Fatalf("want 'setup complete', got %v", resp["status"])
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, "labyrinth.yaml"))
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, ":5353") {
		t.Fatal("config missing listen_addr")
	}
	if !strings.Contains(content, "admin") {
		t.Fatal("config missing username")
	}
	if !srv.setupDone {
		t.Fatal("setupDone should be true")
	}
}

func TestHandleSetupComplete_AlreadyDone(t *testing.T) {
	srv := testAdminServer(t)
	srv.setupDone = true

	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	srv.handleSetupComplete(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d", w.Code)
	}
}

func TestHandleSetupComplete_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/setup/complete", nil)
	w := httptest.NewRecorder()
	srv.handleSetupComplete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleSetupComplete_InvalidBody(t *testing.T) {
	srv := testAdminServer(t)

	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.handleSetupComplete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleSetupComplete_Defaults(t *testing.T) {
	srv := testAdminServer(t)

	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	srv.handleSetupComplete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}

	data, _ := os.ReadFile(filepath.Join(tmpDir, "labyrinth.yaml"))
	content := string(data)
	if !strings.Contains(content, ":53") {
		t.Fatal("expected default listen_addr :53")
	}
	if !strings.Contains(content, "127.0.0.1:8080") {
		t.Fatal("expected default web addr 127.0.0.1:8080")
	}
}

func TestHandleHealth(t *testing.T) {
	srv := testAdminServer(t) // resolver is nil

	req := httptest.NewRequest("GET", "/api/system/health", nil)
	w := httptest.NewRecorder()
	srv.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "degraded" {
		t.Fatalf("expected 'degraded' (nil resolver), got %v", body["status"])
	}
	if body["resolver_ready"] != false {
		t.Fatalf("expected resolver_ready=false, got %v", body["resolver_ready"])
	}
}

func TestHandleHealth_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("DELETE", "/api/system/health", nil)
	w := httptest.NewRecorder()
	srv.handleHealth(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleVersion(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/system/version", nil)
	w := httptest.NewRecorder()
	srv.handleVersion(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	for _, key := range []string{"version", "build_time", "go_version", "os", "arch"} {
		if _, ok := body[key]; !ok {
			t.Errorf("missing key %q in version response", key)
		}
	}
}

func TestHandleVersion_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/system/version", nil)
	w := httptest.NewRecorder()
	srv.handleVersion(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleLogin_Success(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)

	reqBody := `{"username":"admin","password":"` + password + `"}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}
	resp := decodeJSON(t, w)
	if resp["token"] == nil || resp["token"] == "" {
		t.Fatal("missing token in login response")
	}
	if resp["username"] != "admin" {
		t.Fatalf("want username admin, got %v", resp["username"])
	}
}

func TestHandleLogin_WrongPassword(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)

	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"wrongpass"}`))
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestHandleLogin_WrongUsername(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)

	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"nobody","password":"`+password+`"}`))
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestHandleLogin_MethodNotAllowed(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)
	req := httptest.NewRequest("GET", "/api/auth/login", nil)
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleLogin_InvalidBody(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleLogin_AuthNotConfigured(t *testing.T) {
	srv := testAdminServer(t)

	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"x"}`))
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleMe(t *testing.T) {
	srv := testAdminServer(t)

	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	ctx := context.WithValue(req.Context(), ctxKeyUser, "testuser")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	srv.handleMe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["username"] != "testuser" {
		t.Fatalf("want testuser, got %v", body["username"])
	}
}

func TestHandleMe_NotAuthenticated(t *testing.T) {
	srv := testAdminServer(t)

	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	w := httptest.NewRecorder()
	srv.handleMe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestHandleZabbixItems(t *testing.T) {
	srv := testAdminServer(t)

	req := httptest.NewRequest("GET", "/api/zabbix/items", nil)
	w := httptest.NewRecorder()
	srv.handleZabbixItems(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	items, ok := body["items"].([]interface{})
	if !ok {
		t.Fatal("missing or wrong type for 'items'")
	}
	if len(items) != len(zabbixKeys) {
		t.Fatalf("want %d items, got %d", len(zabbixKeys), len(items))
	}
}

func TestHandleZabbixItems_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/zabbix/items", nil)
	w := httptest.NewRecorder()
	srv.handleZabbixItems(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleZabbixItem_CacheEntries(t *testing.T) {
	srv := testAdminServer(t)

	req := httptest.NewRequest("GET", "/api/zabbix/item?key=labyrinth.cache.entries", nil)
	w := httptest.NewRecorder()
	srv.handleZabbixItem(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/plain" {
		t.Fatalf("want text/plain, got %q", ct)
	}
	if strings.TrimSpace(w.Body.String()) != "0" {
		t.Fatalf("want '0', got %q", w.Body.String())
	}
}

func TestHandleZabbixItem_MissingKey(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/zabbix/item", nil)
	w := httptest.NewRecorder()
	srv.handleZabbixItem(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleZabbixItem_UnknownKey(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/zabbix/item?key=labyrinth.fake.key", nil)
	w := httptest.NewRecorder()
	srv.handleZabbixItem(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestHandleZabbixItem_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/zabbix/item?key=labyrinth.cache.entries", nil)
	w := httptest.NewRecorder()
	srv.handleZabbixItem(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// =========================================================================
// 6. Server tests
// =========================================================================

func TestNewAdminServer(t *testing.T) {
	srv := testAdminServer(t)
	if srv == nil {
		t.Fatal("nil AdminServer")
	}
	if srv.queryLog == nil {
		t.Fatal("nil queryLog")
	}
	if srv.timeSeries == nil {
		t.Fatal("nil timeSeries")
	}
	if len(srv.jwtSecret) != 32 {
		t.Fatalf("expected 32-byte JWT secret, got %d", len(srv.jwtSecret))
	}
}

func TestNewAdminServer_DefaultQueryLogBuffer(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled:        true,
			QueryLogBuffer: 0,
		},
	}
	srv := NewAdminServer(cfg, c, m, nil, logger)
	if srv.queryLog.capacity != 1000 {
		t.Fatalf("want default capacity 1000, got %d", srv.queryLog.capacity)
	}
}

func TestRecordQuery(t *testing.T) {
	srv := testAdminServer(t)

	srv.RecordQuery("192.168.1.1", "example.com.", "A", "NOERROR", true, 2.5)
	srv.RecordQuery("192.168.1.2", "fail.com.", "A", "SERVFAIL", false, 10.0)

	entries := srv.queryLog.Recent(10)
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if entries[0].Client != "192.168.1.1" {
		t.Fatalf("want client 192.168.1.1, got %s", entries[0].Client)
	}
	if entries[0].Cached != true {
		t.Fatal("first entry should be cached")
	}
	if entries[1].RCode != "SERVFAIL" {
		t.Fatalf("want SERVFAIL, got %s", entries[1].RCode)
	}
	if entries[0].ID >= entries[1].ID {
		t.Fatal("IDs should be strictly increasing")
	}
}

func TestSPAHandler_NonAPIPath(t *testing.T) {
	handler := SPAHandler()

	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestSPAHandler_APIPath(t *testing.T) {
	handler := SPAHandler()

	req := httptest.NewRequest("GET", "/api/unknown", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown /api/ path, got %d", w.Code)
	}
}

func TestRegisterRoutes(t *testing.T) {
	srv := testAdminServer(t)
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/api/system/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 from registered route, got %d", w.Code)
	}
}

func TestRegisterRoutes_SpaFallback(t *testing.T) {
	srv := testAdminServer(t)
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Labyrinth") {
		t.Fatal("expected placeholder HTML from SPA handler")
	}
}

// =========================================================================
// 7. Embed tests
// =========================================================================

func TestSPAHandler_Placeholder(t *testing.T) {
	handler := SPAHandler()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Labyrinth") {
		t.Fatal("expected 'Labyrinth' in SPA/placeholder output")
	}
}

func TestSPAHandler_APIPathReturns404(t *testing.T) {
	handler := SPAHandler()

	req := httptest.NewRequest("GET", "/api/anything", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for /api/ path, got %d", w.Code)
	}
}

func TestSPAHandler_MetricsPathReturns404(t *testing.T) {
	handler := SPAHandler()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for /metrics path, got %d", w.Code)
	}
}

func TestSPAHandler_ClientSideRoute(t *testing.T) {
	handler := SPAHandler()

	req := httptest.NewRequest("GET", "/dashboard/settings", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 for SPA fallback, got %d", w.Code)
	}
}

// =========================================================================
// 8. Zabbix tests: resolveZabbixKey & formatRData
// =========================================================================

func TestResolveZabbixKey_AllKeys(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)

	for _, key := range zabbixKeys {
		val, err := resolveZabbixKey(key, m, c)
		if err != nil {
			t.Errorf("resolveZabbixKey(%q) error: %v", key, err)
		}
		if val == "" {
			t.Errorf("resolveZabbixKey(%q) returned empty string", key)
		}
	}
}

func TestResolveZabbixKey_Unknown(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)

	_, err := resolveZabbixKey("labyrinth.nonexistent", m, c)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestResolveZabbixKey_CacheHitRatio(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)

	val, _ := resolveZabbixKey("labyrinth.cache.hit_ratio", m, c)
	if val != "0.00" {
		t.Fatalf("want 0.00 with no queries, got %q", val)
	}

	m.IncCacheHits()
	m.IncCacheHits()
	m.IncCacheHits()
	m.IncCacheMisses()

	val, _ = resolveZabbixKey("labyrinth.cache.hit_ratio", m, c)
	if val != "75.00" {
		t.Fatalf("want 75.00, got %q", val)
	}
}

func TestResolveZabbixKey_QueriesTotal(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)

	m.IncQueries("A")
	m.IncQueries("A")
	m.IncQueries("AAAA")

	val, _ := resolveZabbixKey("labyrinth.queries.total", m, c)
	if val != "3" {
		t.Fatalf("want 3, got %q", val)
	}
}

func TestFormatRData_TypeA(t *testing.T) {
	rr := dns.ResourceRecord{
		Type:  dns.TypeA,
		RData: net.IPv4(10, 0, 0, 1).To4(),
	}
	s := formatRData(rr)
	if s != "10.0.0.1" {
		t.Fatalf("want 10.0.0.1, got %q", s)
	}
}

func TestFormatRData_TypeAAAA(t *testing.T) {
	rr := dns.ResourceRecord{
		Type:  dns.TypeAAAA,
		RData: net.ParseIP("::1"),
	}
	s := formatRData(rr)
	if s != "::1" {
		t.Fatalf("want ::1, got %q", s)
	}
}

func TestFormatRData_TypeNS(t *testing.T) {
	nameBytes := dns.BuildPlainName("ns1.example.com.")
	rr := dns.ResourceRecord{
		Type:  dns.TypeNS,
		RData: nameBytes,
	}
	s := formatRData(rr)
	if !strings.Contains(s, "ns1.example.com") {
		t.Fatalf("expected ns1.example.com in output, got %q", s)
	}
}

func TestFormatRData_TypeCNAME(t *testing.T) {
	nameBytes := dns.BuildPlainName("www.example.com.")
	rr := dns.ResourceRecord{
		Type:  dns.TypeCNAME,
		RData: nameBytes,
	}
	s := formatRData(rr)
	if !strings.Contains(s, "www.example.com") {
		t.Fatalf("expected www.example.com in output, got %q", s)
	}
}

func TestFormatRData_TypePTR(t *testing.T) {
	nameBytes := dns.BuildPlainName("host.example.com.")
	rr := dns.ResourceRecord{
		Type:  dns.TypePTR,
		RData: nameBytes,
	}
	s := formatRData(rr)
	if !strings.Contains(s, "host.example.com") {
		t.Fatalf("expected host.example.com in output, got %q", s)
	}
}

func TestFormatRData_TypeTXT(t *testing.T) {
	txt := "v=spf1 include:example.com ~all"
	rdata := append([]byte{byte(len(txt))}, []byte(txt)...)
	rr := dns.ResourceRecord{
		Type:  dns.TypeTXT,
		RData: rdata,
	}
	s := formatRData(rr)
	if s != txt {
		t.Fatalf("want %q, got %q", txt, s)
	}
}

func TestFormatRData_FallbackHex(t *testing.T) {
	rr := dns.ResourceRecord{
		Type:  999,
		RData: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	s := formatRData(rr)
	if s != "deadbeef" {
		t.Fatalf("want deadbeef, got %q", s)
	}
}

// =========================================================================
// 9. writeConfigYAML
// =========================================================================

func TestWriteConfigYAML(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")

	cfg := SetupRequest{
		ListenAddr:     ":53",
		WebAddr:        "0.0.0.0:8080",
		Username:       "admin",
		Password:       "ignored",
		MaxCacheSize:   100000,
		MaxDepth:       30,
		RateLimitRate:  100,
		RateLimitBurst: 200,
		LogLevel:       "info",
		LogFormat:      "json",
	}

	if err := writeConfigYAML(path, cfg, "$2a$10$fakehash"); err != nil {
		t.Fatalf("writeConfigYAML: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	checks := []string{
		`listen_addr: ":53"`,
		"max_depth: 30",
		"max_entries: 100000",
		"enabled: true",
		"rate: 100",
		"burst: 200",
		"level: info",
		"format: json",
		`addr: "0.0.0.0:8080"`,
		"username: admin",
	}
	for _, c := range checks {
		if !strings.Contains(content, c) {
			t.Errorf("config missing %q", c)
		}
	}
}

func TestWriteConfigYAML_NoRateLimit(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")

	cfg := SetupRequest{
		ListenAddr: ":53",
		WebAddr:    "127.0.0.1:8080",
		LogLevel:   "warn",
		LogFormat:  "text",
	}

	if err := writeConfigYAML(path, cfg, ""); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)

	if strings.Contains(content, "rate_limit") {
		t.Fatal("should not include rate_limit section when rate is 0")
	}
	if strings.Contains(content, "password_hash") {
		t.Fatal("should not include auth section when username is empty")
	}
}

func TestWriteConfigYAML_SpecialCharEscape(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")

	cfg := SetupRequest{
		ListenAddr: ":53",
		WebAddr:    "127.0.0.1:8080",
		Username:   "admin",
		LogLevel:   "info",
		LogFormat:  "json",
	}

	hash := "$2a$10$abc#def"
	if err := writeConfigYAML(path, cfg, hash); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, `"$2a$10$abc#def"`) {
		t.Fatalf("expected quoted password_hash, got content:\n%s", content)
	}
}

// =========================================================================
// 10. WebSocket query stream test
// =========================================================================

func TestHandleQueryStreamWS(t *testing.T) {
	srv := testAdminServer(t)

	// Pre-record a query so backfill has something to send
	srv.RecordQuery("10.0.0.1", "backfill.com.", "A", "NOERROR", false, 1.0)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect WebSocket
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/queries/stream"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}

	// Read the backfill message (the one we recorded before connecting)
	_, msg, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("websocket read: %v", err)
	}

	var entry QueryEntry
	if err := json.Unmarshal(msg, &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.QName != "backfill.com." {
		t.Fatalf("want qname backfill.com., got %q", entry.QName)
	}
	if entry.Client != "10.0.0.1" {
		t.Fatalf("want client 10.0.0.1, got %q", entry.Client)
	}

	// Force-close so we don't wait for the close handshake
	conn.Close(websocket.StatusGoingAway, "done")
}

// =========================================================================
// 11. Zabbix agent TCP protocol test
// =========================================================================

func TestStartZabbixAgent(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Find a free port
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

	// Wait for the agent to start listening
	var conn net.Conn
	for i := 0; i < 50; i++ {
		conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("could not connect to zabbix agent at %s: %v", addr, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send a Zabbix key
	_, err = conn.Write([]byte("labyrinth.cache.entries\n"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read ZBXD response header: "ZBXD\x01" (5 bytes) + 8-byte LE length
	header := make([]byte, 13)
	_, err = io.ReadFull(conn, header)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}

	if string(header[:4]) != "ZBXD" {
		t.Fatalf("expected ZBXD header, got %q", header[:4])
	}
	if header[4] != 0x01 {
		t.Fatalf("expected version 0x01, got 0x%02x", header[4])
	}

	dataLen := binary.LittleEndian.Uint64(header[5:13])
	if dataLen == 0 || dataLen > 1024 {
		t.Fatalf("unexpected data length: %d", dataLen)
	}

	// Read the data payload
	payload := make([]byte, dataLen)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}

	// Cache is empty, so entries should be "0"
	if string(payload) != "0" {
		t.Fatalf("want payload '0', got %q", string(payload))
	}

	// Cancel the context to stop the agent
	cancel()
}

func TestStartZabbixAgent_UnknownKey(t *testing.T) {
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

	// Wait for the agent to start
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
	conn.Write([]byte("labyrinth.bogus.key\n"))

	header := make([]byte, 13)
	_, err = io.ReadFull(conn, header)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}

	dataLen := binary.LittleEndian.Uint64(header[5:13])
	payload := make([]byte, dataLen)
	io.ReadFull(conn, payload)

	if !strings.HasPrefix(string(payload), "ZBX_NOTSUPPORTED") {
		t.Fatalf("expected ZBX_NOTSUPPORTED, got %q", string(payload))
	}
}

// =========================================================================
// 12. AdminServer.Start test
// =========================================================================

func TestAdminServerStart(t *testing.T) {
	srv := testAdminServer(t)

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv.config.Web.Addr = addr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for server to be ready
	var resp *http.Response
	client := &http.Client{Timeout: 2 * time.Second}
	for i := 0; i < 50; i++ {
		resp, err = client.Get("http://" + addr + "/api/system/health")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "status") {
		t.Fatalf("expected 'status' in health response, got %s", body)
	}

	// Cancel context to trigger graceful shutdown
	cancel()

	// Wait for Start to return
	select {
	case startErr := <-errCh:
		// Shutdown returns nil on clean exit
		if startErr != nil {
			t.Fatalf("Start returned error: %v", startErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}

// =========================================================================
// 13. TimeSeries flushCurrentLocked test
// =========================================================================

func TestTimeSeries_FlushCurrentLocked(t *testing.T) {
	ts := NewTimeSeriesAggregator()

	// Record some data into the current bucket
	ts.Record(true, 2.0, false)
	ts.Record(false, 4.0, true)
	ts.Record(true, 6.0, false)

	// Manually trigger a flush by calling Snapshot with a large window.
	// Snapshot calls rotateLocked which triggers flushCurrentLocked when
	// the bucket boundary changes. Since we just recorded, the current
	// bucket is active. We can force a flush by manipulating the bucket
	// timestamp.
	ts.mu.Lock()
	if ts.current == nil {
		ts.mu.Unlock()
		t.Fatal("current bucket should not be nil")
	}
	// Move the current bucket timestamp back so the next rotation flushes it
	ts.current.ts = ts.current.ts.Add(-bucketInterval)
	ts.mu.Unlock()

	// Now record again, which will trigger rotation and flush the old bucket
	ts.Record(false, 1.0, false)

	// Snapshot with a large window to get all buckets
	snap := ts.Snapshot(time.Hour)

	// We should see the flushed bucket with our original data
	var foundFlushed bool
	for _, b := range snap {
		if b.Queries == 3 && b.CacheHits == 2 && b.CacheMisses == 1 && b.Errors == 1 {
			foundFlushed = true
			expectedAvg := (2.0 + 4.0 + 6.0) / 3.0
			if b.AvgLatencyMs != expectedAvg {
				t.Fatalf("want avg latency %.2f, got %.2f", expectedAvg, b.AvgLatencyMs)
			}
		}
	}
	if !foundFlushed {
		t.Fatalf("did not find flushed bucket with expected data; got %d buckets", len(snap))
	}
}

func TestTimeSeries_FlushEmptyBucket(t *testing.T) {
	ts := NewTimeSeriesAggregator()

	// Create a current bucket without recording anything
	ts.mu.Lock()
	ts.current = &activeBucket{ts: time.Now().Truncate(bucketInterval).Add(-bucketInterval)}
	ts.mu.Unlock()

	// Record triggers rotation, flushing the empty bucket
	ts.Record(true, 1.0, false)

	snap := ts.Snapshot(time.Hour)

	// The empty bucket should still be recorded for continuity
	var foundEmpty bool
	for _, b := range snap {
		if b.Queries == 0 {
			foundEmpty = true
		}
	}
	if !foundEmpty {
		t.Fatal("expected empty bucket to be recorded for continuity")
	}
}

// =========================================================================
// 14. HashPassword valid password test
// =========================================================================

func TestHashPassword_ValidPassword(t *testing.T) {
	password := "correcthorsebatterystaple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	if hash == password {
		t.Fatal("hash should differ from plaintext")
	}
	// Verify the hash works with checkPassword
	if !checkPassword(password, hash) {
		t.Fatal("checkPassword should return true for correct password")
	}
	if checkPassword("wrongpassword", hash) {
		t.Fatal("checkPassword should return false for wrong password")
	}
}

// =========================================================================
// 15. SPAHandler embedded file serving test
// =========================================================================

func TestSPAHandler_ServesEmbeddedFile(t *testing.T) {
	handler := SPAHandler()

	// favicon.svg exists in web/ui/dist/
	req := httptest.NewRequest("GET", "/favicon.svg", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 for embedded file, got %d", w.Code)
	}
	// favicon.svg should be served as SVG or at least not as text/html fallback
	body := w.Body.String()
	if strings.Contains(body, "Dashboard is not built yet") {
		t.Fatal("should serve actual file, not placeholder")
	}
}

func TestSPAHandler_FallbackToIndex(t *testing.T) {
	handler := SPAHandler()

	// A path that does not match any file should fall back to index.html
	req := httptest.NewRequest("GET", "/some/deep/route", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 for SPA fallback, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<!doctype html>") && !strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatalf("expected index.html content in fallback, got: %.200s", body)
	}
}

func TestSPAHandler_RootServesIndex(t *testing.T) {
	handler := SPAHandler()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// =========================================================================
// 16. formatRData with MX, SOA, SRV record types
// =========================================================================

func TestFormatRData_TypeMX(t *testing.T) {
	// Build MX RDATA: 2-byte preference (big-endian) + encoded exchange name
	exchangeBytes := dns.BuildPlainName("mail.example.com.")
	rdata := make([]byte, 2+len(exchangeBytes))
	binary.BigEndian.PutUint16(rdata, 10) // preference = 10
	copy(rdata[2:], exchangeBytes)

	rr := dns.ResourceRecord{
		Type:  dns.TypeMX,
		RData: rdata,
	}
	s := formatRData(rr)
	if !strings.Contains(s, "10") {
		t.Fatalf("expected preference 10 in output, got %q", s)
	}
	if !strings.Contains(s, "mail.example.com") {
		t.Fatalf("expected mail.example.com in output, got %q", s)
	}
}

func TestFormatRData_TypeSOA(t *testing.T) {
	// Build SOA RDATA: mname + rname + 5x uint32 (serial, refresh, retry, expire, minimum)
	mnameBytes := dns.BuildPlainName("ns1.example.com.")
	rnameBytes := dns.BuildPlainName("admin.example.com.")
	serials := make([]byte, 20)
	binary.BigEndian.PutUint32(serials[0:4], 2024010101) // serial
	binary.BigEndian.PutUint32(serials[4:8], 3600)       // refresh
	binary.BigEndian.PutUint32(serials[8:12], 900)       // retry
	binary.BigEndian.PutUint32(serials[12:16], 1209600)  // expire
	binary.BigEndian.PutUint32(serials[16:20], 86400)    // minimum

	rdata := make([]byte, 0, len(mnameBytes)+len(rnameBytes)+20)
	rdata = append(rdata, mnameBytes...)
	rdata = append(rdata, rnameBytes...)
	rdata = append(rdata, serials...)

	rr := dns.ResourceRecord{
		Type:  dns.TypeSOA,
		RData: rdata,
	}
	s := formatRData(rr)
	if !strings.Contains(s, "ns1.example.com") {
		t.Fatalf("expected ns1.example.com in output, got %q", s)
	}
	if !strings.Contains(s, "admin.example.com") {
		t.Fatalf("expected admin.example.com in output, got %q", s)
	}
	if !strings.Contains(s, "2024010101") {
		t.Fatalf("expected serial 2024010101 in output, got %q", s)
	}
	if !strings.Contains(s, "3600") {
		t.Fatalf("expected refresh 3600 in output, got %q", s)
	}
}

func TestFormatRData_TypeSRV(t *testing.T) {
	// Build SRV RDATA: priority(2) + weight(2) + port(2) + target name
	targetBytes := dns.BuildPlainName("sip.example.com.")
	rdata := make([]byte, 6+len(targetBytes))
	binary.BigEndian.PutUint16(rdata[0:2], 10)   // priority
	binary.BigEndian.PutUint16(rdata[2:4], 60)   // weight
	binary.BigEndian.PutUint16(rdata[4:6], 5060) // port
	copy(rdata[6:], targetBytes)

	rr := dns.ResourceRecord{
		Type:  dns.TypeSRV,
		RData: rdata,
	}
	s := formatRData(rr)
	if !strings.Contains(s, "10") {
		t.Fatalf("expected priority 10 in output, got %q", s)
	}
	if !strings.Contains(s, "60") {
		t.Fatalf("expected weight 60 in output, got %q", s)
	}
	if !strings.Contains(s, "5060") {
		t.Fatalf("expected port 5060 in output, got %q", s)
	}
	if !strings.Contains(s, "sip.example.com") {
		t.Fatalf("expected sip.example.com in output, got %q", s)
	}
	// Verify the exact format: "priority weight port target"
	// DecodeName may or may not include the trailing dot depending on implementation
	if s != "10 60 5060 sip.example.com." && s != "10 60 5060 sip.example.com" {
		t.Fatalf("want '10 60 5060 sip.example.com[.]', got %q", s)
	}
}
