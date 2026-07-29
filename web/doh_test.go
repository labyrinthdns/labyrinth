package web

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// echoHandler is a simple DNS handler that echoes the query back as the response.
type echoHandler struct{}

func (h *echoHandler) Handle(query []byte, addr net.Addr) ([]byte, error) {
	return query, nil
}

// buildDNSQuery creates a minimal DNS query in wire format for testing.
func buildDNSQuery(id uint16) []byte {
	// Header (12 bytes) + Question for "example.com" A
	buf := make([]byte, 29)
	binary.BigEndian.PutUint16(buf[0:2], id)     // ID
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // Flags: RD=1
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT=1
	// QNAME: \x07example\x03com\x00
	copy(buf[12:], []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0})
	binary.BigEndian.PutUint16(buf[25:27], 1) // QTYPE=A
	binary.BigEndian.PutUint16(buf[27:29], 1) // QCLASS=IN
	return buf
}

// buildDNSResponseWithTTL creates a minimal DNS response with one A answer record.
func buildDNSResponseWithTTL(id uint16, ttl uint32) []byte {
	// Header (12 bytes) + Question (17 bytes) + Answer A record
	buf := make([]byte, 29+16) // header + question + answer
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x8180) // QR=1, RD=1, RA=1
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT=1
	binary.BigEndian.PutUint16(buf[6:8], 1)      // ANCOUNT=1
	// Question section
	copy(buf[12:], []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0})
	binary.BigEndian.PutUint16(buf[25:27], 1) // QTYPE=A
	binary.BigEndian.PutUint16(buf[27:29], 1) // QCLASS=IN
	// Answer: compressed name pointer to offset 12
	buf[29] = 0xC0
	buf[30] = 0x0C
	binary.BigEndian.PutUint16(buf[31:33], 1) // TYPE=A
	binary.BigEndian.PutUint16(buf[33:35], 1) // CLASS=IN
	binary.BigEndian.PutUint32(buf[35:39], ttl)
	binary.BigEndian.PutUint16(buf[39:41], 4) // RDLENGTH=4
	buf[41] = 93
	buf[42] = 184
	buf[43] = 216
	buf[44] = 34
	return buf
}

// testDoHServer creates an AdminServer configured for DoH testing.
func testDoHServer(t *testing.T) *AdminServer {
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
	srv, err := NewAdminServer(cfg, c, m, nil, logger, nil)
	if err != nil {
		t.Fatalf("NewAdminServer failed: %v", err)
	}
	srv.SetDoHHandler(&echoHandler{})
	srv.SetDoHEnabled(true)
	return srv
}

// TestDoHPost verifies that a POST request with application/dns-message Content-Type
// is handled correctly.
func TestDoHPost(t *testing.T) {
	srv := testDoHServer(t)

	query := buildDNSQuery(0x1234)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	srv.handleDoH(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		t.Errorf("expected Content-Type 'application/dns-message', got %q", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// EchoHandler returns the query verbatim
	if len(body) != len(query) {
		t.Errorf("expected body length %d, got %d", len(query), len(body))
	}

	respID := binary.BigEndian.Uint16(body[0:2])
	if respID != 0x1234 {
		t.Errorf("expected ID 0x1234, got 0x%04X", respID)
	}
}

// TestDoHGet verifies that a GET request with a base64url-encoded "dns" parameter
// is handled correctly.
func TestDoHGet(t *testing.T) {
	srv := testDoHServer(t)

	query := buildDNSQuery(0x5678)
	encoded := base64.RawURLEncoding.EncodeToString(query)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	w := httptest.NewRecorder()

	srv.handleDoH(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", resp.StatusCode, w.Body.String())
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		t.Errorf("expected Content-Type 'application/dns-message', got %q", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	respID := binary.BigEndian.Uint16(body[0:2])
	if respID != 0x5678 {
		t.Errorf("expected ID 0x5678, got 0x%04X", respID)
	}
}

// TestDoHBadRequest verifies error handling for invalid requests.
func TestDoHBadRequest(t *testing.T) {
	srv := testDoHServer(t)

	tests := []struct {
		name       string
		method     string
		path       string
		body       []byte
		ct         string
		wantStatus int
	}{
		{
			name:       "GET missing dns param",
			method:     http.MethodGet,
			path:       "/dns-query",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "GET invalid base64",
			method:     http.MethodGet,
			path:       "/dns-query?dns=!!!invalid!!!",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "GET message too short",
			method:     http.MethodGet,
			path:       "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "POST wrong content type",
			method:     http.MethodPost,
			path:       "/dns-query",
			body:       buildDNSQuery(0x1111),
			ct:         "application/json",
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "POST message too short",
			method:     http.MethodPost,
			path:       "/dns-query",
			body:       []byte{1, 2, 3},
			ct:         "application/dns-message",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "PUT method not allowed",
			method:     http.MethodPut,
			path:       "/dns-query",
			body:       buildDNSQuery(0x2222),
			ct:         "application/dns-message",
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.body != nil {
				req = httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			} else {
				req = httptest.NewRequest(tc.method, tc.path, nil)
			}
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}

			w := httptest.NewRecorder()
			srv.handleDoH(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("expected status %d, got %d; body: %s", tc.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestDoHCacheControl verifies the Cache-Control header is set based on answer TTL.
func TestDoHCacheControl(t *testing.T) {
	// Use a handler that returns a response with a known TTL
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
	srv, err := NewAdminServer(cfg, c, m, nil, logger, nil)
	if err != nil {
		t.Fatalf("NewAdminServer failed: %v", err)
	}

	// Custom handler that returns a response with TTL=300
	handler := &ttlHandler{ttl: 300}
	srv.SetDoHHandler(handler)
	srv.SetDoHEnabled(true)

	query := buildDNSQuery(0x9999)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	srv.handleDoH(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	cc := resp.Header.Get("Cache-Control")
	if cc != "max-age=300" {
		t.Errorf("expected Cache-Control 'max-age=300', got %q", cc)
	}
}

// TestDoHNotEnabled verifies that DoH returns 404 when not enabled.
func TestDoHNotEnabled(t *testing.T) {
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
	srv, err := NewAdminServer(cfg, c, m, nil, logger, nil)
	if err != nil {
		t.Fatalf("NewAdminServer failed: %v", err)
	}
	// dohHandler is nil — DoH is not enabled

	query := buildDNSQuery(0x4444)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	srv.handleDoH(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

// TestDohMinTTL verifies the dohMinTTL helper function.
func TestDohMinTTL(t *testing.T) {
	tests := []struct {
		name    string
		resp    []byte
		wantTTL uint32
	}{
		{
			name:    "response with TTL 300",
			resp:    buildDNSResponseWithTTL(0x1111, 300),
			wantTTL: 300,
		},
		{
			name:    "response with TTL 0",
			resp:    buildDNSResponseWithTTL(0x2222, 0),
			wantTTL: 0,
		},
		{
			name:    "short response",
			resp:    []byte{1, 2, 3},
			wantTTL: 0,
		},
		{
			name:    "no answers",
			resp:    buildDNSQuery(0x3333), // query has ANCOUNT=0
			wantTTL: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dohMinTTL(tc.resp)
			if got != tc.wantTTL {
				t.Errorf("dohMinTTL: expected %d, got %d", tc.wantTTL, got)
			}
		})
	}
}

// ttlHandler is a DNS handler that returns a response with a configurable TTL.
type ttlHandler struct {
	ttl uint32
}

func (h *ttlHandler) Handle(query []byte, addr net.Addr) ([]byte, error) {
	if len(query) < 12 {
		return query, nil
	}
	id := binary.BigEndian.Uint16(query[0:2])
	return buildDNSResponseWithTTL(id, h.ttl), nil
}
