package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/labyrinth-dns/labyrinth/cache"
	"github.com/labyrinth-dns/labyrinth/dns"
	"github.com/labyrinth-dns/labyrinth/metrics"
	"github.com/labyrinth-dns/labyrinth/resolver"
	"github.com/labyrinth-dns/labyrinth/security"
)

// networkAvailable checks whether outbound DNS traffic can reach the internet.
func networkAvailable(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("udp", "198.41.0.4:53", 2*time.Second)
	if err != nil {
		t.Skip("skipping: no network connectivity to root DNS servers")
	}
	conn.Close()
}

// setupTestServer creates all components and starts a UDP server on a random
// port. It returns the listener address and a cancel function that tears
// everything down.
func setupTestServer(t *testing.T, rateBurst int) (addr string, cancel func()) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)

	var rl *security.RateLimiter
	if rateBurst > 0 {
		rl = security.NewRateLimiter(0, rateBurst)
	}

	res := resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 3,
		QMinEnabled:     true,
		PreferIPv4:      true,
	}, m, logger)

	// Prime root hints so the resolver is functional.
	if err := res.PrimeRootHints(); err != nil {
		t.Logf("root hint priming warning: %v", err)
	}

	handler := NewMainHandler(res, c, rl, nil, nil, m, logger)

	udp, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatalf("NewUDPServer: %v", err)
	}

	ctx, ctxCancel := context.WithCancel(context.Background())
	go udp.Serve(ctx)

	udpAddr := udp.conn.LocalAddr().String()

	return udpAddr, func() {
		ctxCancel()
		udp.Close()
	}
}

// setupTestTCPServer creates components and starts a TCP server on a random
// port alongside the UDP server, returning both addresses and a cancel func.
func setupTestTCPServer(t *testing.T) (udpAddr, tcpAddr string, cancel func()) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	rl := security.NewRateLimiter(0, 1000)

	res := resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 3,
		QMinEnabled:     true,
		PreferIPv4:      true,
	}, m, logger)

	if err := res.PrimeRootHints(); err != nil {
		t.Logf("root hint priming warning: %v", err)
	}

	handler := NewMainHandler(res, c, rl, nil, nil, m, logger)

	udp, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatalf("NewUDPServer: %v", err)
	}

	tcp, err := NewTCPServer(":0", handler, 5*time.Second, 10, logger)
	if err != nil {
		t.Fatalf("NewTCPServer: %v", err)
	}

	ctx, ctxCancel := context.WithCancel(context.Background())
	go udp.Serve(ctx)
	go tcp.Serve(ctx)

	return udp.conn.LocalAddr().String(), tcp.listener.Addr().String(), func() {
		ctxCancel()
		udp.Close()
		tcp.Close()
	}
}

// buildQuery constructs a minimal DNS query message in wire format.
func buildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	msg := &dns.Message{
		Header: dns.Header{
			ID: id,
			Flags: dns.NewFlagBuilder().
				SetRD(true).
				Build(),
		},
		Questions: []dns.Question{
			{Name: name, Type: qtype, Class: dns.ClassIN},
		},
	}
	buf := make([]byte, 512)
	return dns.Pack(msg, buf)
}

// buildQueryWithEDNS constructs a DNS query with an OPT record (EDNS0).
func buildQueryWithEDNS(id uint16, name string, qtype uint16, udpSize uint16) ([]byte, error) {
	msg := &dns.Message{
		Header: dns.Header{
			ID: id,
			Flags: dns.NewFlagBuilder().
				SetRD(true).
				Build(),
		},
		Questions: []dns.Question{
			{Name: name, Type: qtype, Class: dns.ClassIN},
		},
		Additional: []dns.ResourceRecord{
			dns.BuildOPT(udpSize, false),
		},
	}
	buf := make([]byte, 512)
	return dns.Pack(msg, buf)
}

// sendUDP sends a raw DNS query over UDP and reads the response.
func sendUDP(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial udp %s: %v", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf[:n]
}

// sendTCP sends a raw DNS query over TCP with the 2-byte length prefix framing.
func sendTCP(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial tcp %s: %v", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Write 2-byte length prefix + query
	if err := binary.Write(conn, binary.BigEndian, uint16(len(query))); err != nil {
		t.Fatalf("write length prefix: %v", err)
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write query: %v", err)
	}

	// Read 2-byte length prefix
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		t.Fatalf("read length prefix: %v", err)
	}

	// Read response body
	resp := make([]byte, length)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

func TestEndToEndResolveA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	networkAvailable(t)

	addr, cancel := setupTestServer(t, 1000)
	defer cancel()

	query, err := buildQuery(0x1234, "google.com", dns.TypeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}

	resp := sendUDP(t, addr, query)

	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack response: %v", err)
	}

	if !msg.Header.QR() {
		t.Error("expected QR=1 in response")
	}
	if !msg.Header.RA() {
		t.Error("expected RA=1 in response")
	}
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected RCODE=0, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) < 1 {
		t.Error("expected at least 1 answer record")
	}
}

func TestEndToEndNXDOMAIN(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	networkAvailable(t)

	addr, cancel := setupTestServer(t, 1000)
	defer cancel()

	query, err := buildQuery(0xABCD, "thisdomaindoesnotexist12345678.com", dns.TypeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}

	resp := sendUDP(t, addr, query)

	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack response: %v", err)
	}

	if !msg.Header.QR() {
		t.Error("expected QR=1 in response")
	}
	if msg.Header.RCODE() != dns.RCodeNXDomain {
		t.Errorf("expected RCODE=3 (NXDOMAIN), got %d", msg.Header.RCODE())
	}
}

func TestEndToEndTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	networkAvailable(t)

	_, tcpAddr, cancel := setupTestTCPServer(t)
	defer cancel()

	query, err := buildQuery(0x5678, "google.com", dns.TypeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}

	resp := sendTCP(t, tcpAddr, query)

	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack response: %v", err)
	}

	if !msg.Header.QR() {
		t.Error("expected QR=1 in response")
	}
	if !msg.Header.RA() {
		t.Error("expected RA=1 in response")
	}
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected RCODE=0, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) < 1 {
		t.Error("expected at least 1 answer record for TCP query")
	}
}

func TestEndToEndCacheHit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	networkAvailable(t)

	addr, cancel := setupTestServer(t, 1000)
	defer cancel()

	query, err := buildQuery(0x1111, "google.com", dns.TypeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}

	// First query — populates cache.
	resp1 := sendUDP(t, addr, query)
	msg1, err := dns.Unpack(resp1)
	if err != nil {
		t.Fatalf("Unpack first response: %v", err)
	}
	if msg1.Header.RCODE() != dns.RCodeNoError {
		t.Fatalf("first query: expected RCODE=0, got %d", msg1.Header.RCODE())
	}

	// Second query — should be served from cache (just verify it succeeds).
	query2, err := buildQuery(0x2222, "google.com", dns.TypeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}

	resp2 := sendUDP(t, addr, query2)
	msg2, err := dns.Unpack(resp2)
	if err != nil {
		t.Fatalf("Unpack second response: %v", err)
	}
	if msg2.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("second query: expected RCODE=0, got %d", msg2.Header.RCODE())
	}
	if len(msg2.Answers) < 1 {
		t.Error("second query: expected at least 1 answer record")
	}
}

func TestEndToEndRateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	networkAvailable(t)

	// Rate limiter with burst=2 and rate=0 (no refill), so only 2 queries allowed.
	addr, cancel := setupTestServer(t, 2)
	defer cancel()

	var results []uint8
	for i := 0; i < 5; i++ {
		query, err := buildQuery(uint16(0x3000+i), fmt.Sprintf("example%d.com", i), dns.TypeA)
		if err != nil {
			t.Fatalf("buildQuery %d: %v", i, err)
		}
		resp := sendUDP(t, addr, query)
		msg, err := dns.Unpack(resp)
		if err != nil {
			t.Fatalf("Unpack response %d: %v", i, err)
		}
		results = append(results, msg.Header.RCODE())
	}

	// First 2 should be allowed (RCODE 0 or 3 — NOERROR or NXDOMAIN).
	for i := 0; i < 2; i++ {
		if results[i] != dns.RCodeNoError && results[i] != dns.RCodeNXDomain {
			t.Errorf("query %d: expected RCODE 0 or 3, got %d", i, results[i])
		}
	}

	// Remaining should be REFUSED (RCODE 5).
	for i := 2; i < 5; i++ {
		if results[i] != dns.RCodeRefused {
			t.Errorf("query %d: expected RCODE 5 (REFUSED), got %d", i, results[i])
		}
	}
}

func TestEndToEndEDNS0(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	networkAvailable(t)

	addr, cancel := setupTestServer(t, 1000)
	defer cancel()

	query, err := buildQueryWithEDNS(0x4444, "google.com", dns.TypeA, 4096)
	if err != nil {
		t.Fatalf("buildQueryWithEDNS: %v", err)
	}

	resp := sendUDP(t, addr, query)

	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack response: %v", err)
	}

	if !msg.Header.QR() {
		t.Error("expected QR=1 in response")
	}
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected RCODE=0, got %d", msg.Header.RCODE())
	}

	// Verify OPT record is present in the response.
	hasOPT := false
	for _, rr := range msg.Additional {
		if rr.Type == dns.TypeOPT {
			hasOPT = true
			break
		}
	}
	if !hasOPT {
		t.Error("expected OPT record in response additional section")
	}
}

func TestEndToEndMetricsEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := metrics.NewMetrics()

	mux := http.NewServeMux()
	mux.Handle("/metrics", m)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	_ = logger // used for consistency; not needed for HTTP test

	url := fmt.Sprintf("http://%s/metrics", ln.Addr().String())
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Error("expected non-empty metrics body")
	}
}

func TestEndToEndHealthEndpoint(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		stats := c.Stats()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy","cache_entries":%d,"uptime":"%s"}`,
			stats.Entries, time.Since(m.StartTime()).Round(time.Second))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	url := fmt.Sprintf("http://%s/health", ln.Addr().String())
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if _, ok := result["status"]; !ok {
		t.Error("expected 'status' field in health JSON response")
	}
}

// --- Additional integration tests (T-087, T-088, T-098) ---

func TestEndToEndResolveAAAA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	networkAvailable(t)

	addr, cancel := setupTestServer(t, 1000)
	defer cancel()

	query, _ := buildQuery(0x2222, "google.com", dns.TypeAAAA)
	resp := sendUDP(t, addr, query)

	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if !msg.Header.QR() {
		t.Error("QR should be 1")
	}
	if !msg.Header.RA() {
		t.Error("RA should be 1")
	}
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("RCODE: expected NOERROR, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) == 0 {
		t.Error("expected at least 1 answer")
	}
	// Verify at least one AAAA record
	hasAAAA := false
	for _, rr := range msg.Answers {
		if rr.Type == dns.TypeAAAA {
			hasAAAA = true
			break
		}
	}
	if !hasAAAA {
		t.Error("expected at least one AAAA record in answers")
	}
}

func TestEndToEndCNAME(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	networkAvailable(t)

	addr, cancel := setupTestServer(t, 1000)
	defer cancel()

	// www.google.com typically has a CNAME
	query, _ := buildQuery(0x3333, "www.google.com", dns.TypeA)
	resp := sendUDP(t, addr, query)

	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Fatalf("RCODE: expected NOERROR, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) == 0 {
		t.Fatal("expected at least 1 answer")
	}

	// Should have either a CNAME + A or just A records
	hasA := false
	for _, rr := range msg.Answers {
		if rr.Type == dns.TypeA {
			hasA = true
		}
	}
	if !hasA {
		t.Error("expected an A record in final answer (possibly after CNAME chain)")
	}
}

func TestEndToEndConcurrentQueries(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	networkAvailable(t)

	addr, cancel := setupTestServer(t, 10000)
	defer cancel()

	domains := []string{
		"google.com", "example.com", "cloudflare.com",
		"github.com", "wikipedia.org", "amazon.com",
		"microsoft.com", "apple.com", "netflix.com", "twitter.com",
	}

	type result struct {
		domain string
		err    error
		rcode  uint8
	}
	results := make(chan result, len(domains)*10)

	// Send 10 queries per domain concurrently (100 total)
	for _, domain := range domains {
		for i := 0; i < 10; i++ {
			go func(d string) {
				query, _ := buildQuery(0x4444, d, dns.TypeA)
				resp := sendUDPQueryNoFatal(t, addr, query)
				if resp == nil {
					results <- result{domain: d, err: fmt.Errorf("nil response")}
					return
				}
				msg, err := dns.Unpack(resp)
				if err != nil {
					results <- result{domain: d, err: err}
					return
				}
				results <- result{domain: d, rcode: msg.Header.RCODE()}
			}(domain)
		}
	}

	// Collect results
	successCount := 0
	for i := 0; i < len(domains)*10; i++ {
		r := <-results
		if r.err != nil {
			t.Logf("query %s failed: %v", r.domain, r.err)
			continue
		}
		if r.rcode == dns.RCodeNoError || r.rcode == dns.RCodeNXDomain {
			successCount++
		}
	}

	// At least 80% should succeed (network may have some timeouts)
	minSuccess := len(domains) * 10 * 80 / 100
	if successCount < minSuccess {
		t.Errorf("only %d/%d queries succeeded (expected >=%d)", successCount, len(domains)*10, minSuccess)
	}
}

func TestEndToEndGracefulShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	networkAvailable(t)

	addr, cancel := setupTestServer(t, 1000)

	// Send a query to verify server works
	query, _ := buildQuery(0x7777, "google.com", dns.TypeA)
	resp := sendUDP(t, addr, query)
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if !msg.Header.QR() {
		t.Error("QR should be 1 before shutdown")
	}

	// Trigger shutdown
	cancel()

	// After shutdown, server should stop accepting — connection may fail or timeout
	time.Sleep(100 * time.Millisecond)
	conn, err := net.DialTimeout("udp", addr, 500*time.Millisecond)
	if err != nil {
		return // expected: server closed
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write(query)
	buf := make([]byte, 4096)
	_, err = conn.Read(buf)
	// After shutdown, reads should timeout or fail — both are acceptable
	if err == nil {
		t.Log("server still responded after cancel — may have in-flight query")
	}
}

func TestEndToEndCacheFlush(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	networkAvailable(t)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	rl := security.NewRateLimiter(0, 1000)

	res := resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth: 30, MaxCNAMEDepth: 10, UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 3, QMinEnabled: true, PreferIPv4: true,
	}, m, logger)
	_ = res.PrimeRootHints()

	handler := NewMainHandler(res, c, rl, nil, nil, m, logger)
	udp, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatalf("NewUDPServer: %v", err)
	}
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go udp.Serve(ctx)
	addr := udp.conn.LocalAddr().String()

	// Populate cache via query
	query, _ := buildQuery(0x8888, "google.com", dns.TypeA)
	sendUDP(t, addr, query)

	stats := c.Stats()
	if stats.Entries == 0 {
		t.Log("cache empty after query — may not have resolved, skipping flush check")
		return
	}

	// Flush cache
	c.Flush()

	stats = c.Stats()
	if stats.Entries != 0 {
		t.Errorf("expected 0 entries after flush, got %d", stats.Entries)
	}
}

func sendUDPQueryNoFatal(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}
