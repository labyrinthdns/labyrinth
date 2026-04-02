package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/labyrinth-dns/labyrinth/cache"
	"github.com/labyrinth-dns/labyrinth/dns"
	"github.com/labyrinth-dns/labyrinth/metrics"
	"github.com/labyrinth-dns/labyrinth/resolver"
	"github.com/labyrinth-dns/labyrinth/security"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestResolver(c *cache.Cache, m *metrics.Metrics) *resolver.Resolver {
	return resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth:        2,
		MaxCNAMEDepth:   2,
		UpstreamTimeout: 100 * time.Millisecond,
		UpstreamRetries: 1,
		PreferIPv4:      true,
	}, m, discardLogger())
}

// newFailFastResolver returns a resolver that fails immediately (unreachable
// upstream, one iteration only). Resolve returns (*ResolveResult, nil) with
// RCODE=SERVFAIL.
func newFailFastResolver(c *cache.Cache, m *metrics.Metrics) *resolver.Resolver {
	return resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth:        1,
		MaxCNAMEDepth:   1,
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamRetries: 1,
		PreferIPv4:      true,
		UpstreamPort:    "1", // unreachable
	}, m, discardLogger())
}

// newPanickingResolver returns a resolver whose metrics are nil. The first
// upstream query will panic (nil pointer on r.metrics.IncUpstreamQueries()).
// The inflight.do recovery turns the panic into an error return, which lets
// callers exercise error-handling paths.
func newPanickingResolver(c *cache.Cache) *resolver.Resolver {
	return resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth:        2,
		MaxCNAMEDepth:   2,
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamRetries: 1,
		PreferIPv4:      true,
	}, nil, discardLogger()) // nil metrics → panics in queryUpstream
}

func buildTestQueryWithEDNS(name string, qtype uint16, udpSize uint16) []byte {
	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x1234,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPT(udpSize, false),
		},
	}
	buf := make([]byte, 512)
	packed, err := dns.Pack(msg, buf)
	if err != nil {
		panic("buildTestQueryWithEDNS: " + err.Error())
	}
	result := make([]byte, len(packed))
	copy(result, packed)
	return result
}

type nilHandler struct{}

func (h *nilHandler) Handle([]byte, net.Addr) ([]byte, error) { return nil, nil }

type errHandler struct{}

func (h *errHandler) Handle([]byte, net.Addr) ([]byte, error) {
	return nil, errors.New("synthetic error")
}

// buildSOARData constructs SOA RDATA in uncompressed wire format.
func buildSOARData(mname, rname string, serial, refresh, retry, expire, minimum uint32) []byte {
	mn := dns.BuildPlainName(mname)
	rn := dns.BuildPlainName(rname)
	buf := make([]byte, len(mn)+len(rn)+20)
	copy(buf, mn)
	copy(buf[len(mn):], rn)
	off := len(mn) + len(rn)
	binary.BigEndian.PutUint32(buf[off:], serial)
	binary.BigEndian.PutUint32(buf[off+4:], refresh)
	binary.BigEndian.PutUint32(buf[off+8:], retry)
	binary.BigEndian.PutUint32(buf[off+12:], expire)
	binary.BigEndian.PutUint32(buf[off+16:], minimum)
	return buf
}

// ---------------------------------------------------------------------------
// 1. handler.go Handle – ACL check branch
// ---------------------------------------------------------------------------

func TestHandleACLBlocked(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	acl, err := security.NewACL([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewMainHandler(res, c, nil, nil, acl, m, discardLogger())

	query := buildTestQuery("example.com", dns.TypeA)
	addr := &mockAddr{network: "udp", addr: "192.168.1.1:12345"}
	resp, err := handler.Handle(query, addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected REFUSED response")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeRefused {
		t.Errorf("expected REFUSED(5), got %d", rcode)
	}
}

func TestHandleACLAllowed(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.Store("example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{93, 184, 216, 34},
	}}, nil)
	res := newTestResolver(c, m)
	acl, _ := security.NewACL([]string{"10.0.0.0/8"}, nil)
	handler := NewMainHandler(res, c, nil, nil, acl, m, discardLogger())

	query := buildTestQuery("example.com", dns.TypeA)
	addr := &mockAddr{network: "udp", addr: "10.0.0.1:12345"}
	resp, err := handler.Handle(query, addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeNoError {
		t.Errorf("expected NOERROR(0), got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// 2. handler.go Handle – RRL Drop and Slip
//
// The RRL check only fires on the cache-miss → resolve → buildResponse path.
// We use a fail-fast resolver (UpstreamPort="1", MaxDepth=1) so resolution
// fails quickly with SERVFAIL. The handler still calls buildResponse + RRL.
// ---------------------------------------------------------------------------

func TestHandleRRLDrop(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newFailFastResolver(c, m)

	// responsesPerSecond=1, slipRatio=0 → always Drop when rate exceeded.
	rrl := security.NewRRL(1, 0, 24, 56)
	handler := NewMainHandler(res, c, nil, rrl, nil, m, discardLogger())
	addr := &mockAddr{network: "udp", addr: "192.168.1.1:1234"}

	// First query — RRL allows the first response (even though SERVFAIL).
	// Use the SAME qname for all queries so they share the same RRL bucket.
	// SERVFAIL results are not cached, so each call is a cache miss.
	query := buildTestQuery("rrl-drop.example.com", dns.TypeA)
	resp, err := handler.Handle(query, addr)
	if err != nil {
		t.Fatalf("first query error: %v", err)
	}
	if resp == nil {
		t.Fatal("first query should return a response")
	}

	// Exhaust the rate by sending more queries with the same name.
	var dropped bool
	for i := 0; i < 20; i++ {
		resp, err = handler.Handle(query, addr)
		if err == nil && resp == nil {
			dropped = true
			break
		}
	}
	if !dropped {
		t.Error("expected a dropped (nil, nil) response from RRL")
	}
}

func TestHandleRRLSlip(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newFailFastResolver(c, m)

	// slipRatio=1 → every rate-exceeded response is a Slip (truncated).
	rrl := security.NewRRL(1, 1, 24, 56)
	handler := NewMainHandler(res, c, nil, rrl, nil, m, discardLogger())
	addr := &mockAddr{network: "udp", addr: "172.16.0.1:1234"}

	// First query — allowed. Same qname to share RRL bucket.
	query := buildTestQuery("rrl-slip.example.com", dns.TypeA)
	handler.Handle(query, addr)

	// Continue with same name until we see a slip response.
	var slipped bool
	for i := 0; i < 20; i++ {
		resp, err := handler.Handle(query, addr)
		if err == nil && resp != nil {
			msg, parseErr := dns.Unpack(resp)
			// A slipped response is buildError(query, RCodeNoError) → short,
			// QR=1, 0 answers. Distinguish from normal SERVFAIL response
			// by checking that it's not a full buildResponse output.
			if parseErr == nil && msg.Header.QR() && msg.Header.RCODE() == dns.RCodeNoError {
				slipped = true
				break
			}
		}
	}
	if !slipped {
		t.Error("expected a slipped (TC=1) response from RRL")
	}
}

// ---------------------------------------------------------------------------
// 3. handler.go Handle – serve-stale branch
//
// The serve-stale branch requires resolver.Resolve to return an error (not
// just SERVFAIL result). We trigger this by using a resolver with nil metrics;
// queryUpstream panics on r.metrics.IncUpstreamQueries(), and inflight.do's
// recover converts the panic into an error.
// ---------------------------------------------------------------------------

func TestHandleServeStale(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	// Use separate metrics for the cache (non-nil) and nil for the resolver.
	cacheMetrics := metrics.NewMetrics()
	c := cache.NewCacheWithStale(1000, 1, 86400, 3600, true, 30, cacheMetrics)

	// Pre-populate cache with an entry that will expire after ~1 second.
	c.Store("stale.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "stale.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 0, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}, nil)

	// Wait for the entry to expire (minTTL clamped to 1).
	time.Sleep(1500 * time.Millisecond)

	// Panicking resolver: metrics=nil causes panic in queryUpstream.
	// inflight.do recovers the panic and returns (nil, error).
	res := newPanickingResolver(c)
	handler := NewMainHandler(res, c, nil, nil, nil, handlerMetrics, discardLogger())

	query := buildTestQuery("stale.example.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected stale response, got nil")
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack error: %v", err)
	}
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR from stale cache, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) == 0 {
		t.Error("expected stale answer records")
	}
}

// ---------------------------------------------------------------------------
// 4. handler.go Handle – negative cache store (NXDOMAIN and NODATA)
//    Tested via integration tests (need real network) and via mock below.
// ---------------------------------------------------------------------------

func TestHandleNegativeCacheNXDOMAIN(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: requires network")
	}
	networkAvailable(t)

	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth: 30, MaxCNAMEDepth: 10, UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 3, QMinEnabled: true, PreferIPv4: true,
	}, m, discardLogger())
	if err := res.PrimeRootHints(); err != nil {
		t.Logf("root priming warning: %v", err)
	}
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	query := buildTestQuery("definitelynotexist999.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNXDomain {
		t.Errorf("expected NXDOMAIN(3), got %d", msg.Header.RCODE())
	}

	// Second query should come from negative cache.
	resp2, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error on second query: %v", err)
	}
	if resp2 == nil {
		t.Fatal("expected cached negative response")
	}
	msg2, _ := dns.Unpack(resp2)
	if msg2.Header.RCODE() != dns.RCodeNXDomain {
		t.Errorf("expected NXDOMAIN from negative cache, got %d", msg2.Header.RCODE())
	}
}

// ---------------------------------------------------------------------------
// 5. handler.go buildCacheResponse – negative cache entry (RCODE set)
// ---------------------------------------------------------------------------

func TestBuildCacheResponseNegative(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.StoreNegative("neg.example.com", dns.TypeA, dns.ClassIN,
		cache.NegNXDomain, dns.RCodeNXDomain, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	query := buildTestQuery("neg.example.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNXDomain {
		t.Errorf("expected NXDOMAIN, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) != 0 {
		t.Errorf("expected 0 answers, got %d", len(msg.Answers))
	}
}

// ---------------------------------------------------------------------------
// 6. handler.go buildCacheResponse / buildResponse – EDNS0 branch
// ---------------------------------------------------------------------------

func TestBuildCacheResponseWithEDNS0(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.Store("edns.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "edns.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	query := buildTestQueryWithEDNS("edns.example.com", dns.TypeA, 4096)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	msg, _ := dns.Unpack(resp)
	if msg.EDNS0 == nil {
		t.Error("expected OPT record (EDNS0 echo)")
	}
}

// ---------------------------------------------------------------------------
// 7. handler.go buildResponse – truncation path (response > maxSize)
// ---------------------------------------------------------------------------

func TestBuildResponseTruncation(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x5678,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "big.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
	}

	// 50 A records, each ~16 bytes compressed → well over 512 bytes.
	var answers []dns.ResourceRecord
	for i := 0; i < 50; i++ {
		answers = append(answers, dns.ResourceRecord{
			Name: "big.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 0, 0, 1},
		})
	}

	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}
	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp) > 512 {
		t.Errorf("expected truncated response <= 512 bytes, got %d", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 1 {
		t.Error("expected TC bit to be set")
	}
}

func TestBuildResponseNoTruncationWithEDNS(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x5679,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "big.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		EDNS0: &dns.EDNS0{UDPSize: 4096},
	}

	result := &resolver.ResolveResult{
		Answers: []dns.ResourceRecord{{
			Name: "big.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
		RCODE: dns.RCodeNoError,
	}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 == 1 {
		t.Error("TC bit should not be set with large EDNS0 buffer")
	}
}

// ---------------------------------------------------------------------------
// 8. handler.go buildError – question parse fails (returns header-only)
// ---------------------------------------------------------------------------

func TestBuildErrorBadQuestion(t *testing.T) {
	h := testHandler()
	query := make([]byte, 20)
	binary.BigEndian.PutUint16(query[0:2], 0x1234)
	binary.BigEndian.PutUint16(query[4:6], 1)
	query[12] = 0x40 // label-length 64 > max 63

	resp, err := h.buildError(query, dns.RCodeFormErr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp) != 12 {
		t.Errorf("expected 12-byte header-only, got %d", len(resp))
	}
}

// ---------------------------------------------------------------------------
// 9. handler.go extractIP – TrimRight fallback path
// ---------------------------------------------------------------------------

func TestExtractIPTrimRightFallback(t *testing.T) {
	addr := &mockAddr{network: "udp", addr: "192.168.1.1"}
	ip := extractIP(addr)
	if ip != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got %q", ip)
	}
}

func TestExtractIPTrimRightColonSuffix(t *testing.T) {
	addr := &mockAddr{network: "udp", addr: "10.0.0.1:::"}
	ip := extractIP(addr)
	if ip != "10.0.0.1" {
		t.Errorf("expected '10.0.0.1', got %q", ip)
	}
}

// ---------------------------------------------------------------------------
// 10. tcp.go handleTCP – length < 12 rejection
// ---------------------------------------------------------------------------

func TestTCPHandleTooShortMessage(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	binary.Write(conn, binary.BigEndian, uint16(4))
	conn.Write([]byte{0, 1, 2, 3})

	var respLen uint16
	if binary.Read(conn, binary.BigEndian, &respLen) == nil {
		t.Error("expected error/EOF for too-short query")
	}
}

// ---------------------------------------------------------------------------
// 11. tcp.go handleTCP – handler returns nil response
// ---------------------------------------------------------------------------

func TestTCPHandleNilResponse(t *testing.T) {
	logger := discardLogger()
	handler := &nilHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	query := buildTestQuery("example.com", dns.TypeA)
	binary.Write(conn, binary.BigEndian, uint16(len(query)))
	conn.Write(query)

	var respLen uint16
	if binary.Read(conn, binary.BigEndian, &respLen) == nil {
		t.Error("expected error/EOF for nil handler response")
	}
}

// ---------------------------------------------------------------------------
// 12. tcp.go handleTCP – handler returns error
// ---------------------------------------------------------------------------

func TestTCPHandleError(t *testing.T) {
	logger := discardLogger()
	handler := &errHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	query := buildTestQuery("example.com", dns.TypeA)
	binary.Write(conn, binary.BigEndian, uint16(len(query)))
	conn.Write(query)

	var respLen uint16
	if binary.Read(conn, binary.BigEndian, &respLen) == nil {
		t.Error("expected error/EOF for handler error")
	}
}

// ---------------------------------------------------------------------------
// 13. tcp.go Serve – ctx.Err shutdown path + accept timeout continue
// ---------------------------------------------------------------------------

func TestTCPServeShutdown(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil on shutdown, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// ---------------------------------------------------------------------------
// 14. udp.go handleUDP – nil response path
// ---------------------------------------------------------------------------

func TestUDPHandleNilResponse(t *testing.T) {
	logger := discardLogger()
	handler := &nilHandler{}
	srv, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("udp", srv.conn.LocalAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(1 * time.Second))
	conn.Write(buildTestQuery("example.com", dns.TypeA))

	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected timeout for nil handler response")
	}
}

// ---------------------------------------------------------------------------
// 15. udp.go handleUDP – handler error path
// ---------------------------------------------------------------------------

func TestUDPHandleError(t *testing.T) {
	logger := discardLogger()
	handler := &errHandler{}
	srv, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("udp", srv.conn.LocalAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(1 * time.Second))
	conn.Write(buildTestQuery("example.com", dns.TypeA))

	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected timeout for handler error")
	}
}

// ---------------------------------------------------------------------------
// 16. udp.go Serve – non-timeout read error path
// ---------------------------------------------------------------------------

func TestUDPServeReadError(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	srv.conn.Close() // force non-timeout read error
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// ---------------------------------------------------------------------------
// 17. handler.go – NODATA negative cache (RCODE=NOERROR, 0 answers)
// ---------------------------------------------------------------------------

func TestBuildCacheResponseNODATA(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.StoreNegative("nodata.example.com", dns.TypeAAAA, dns.ClassIN,
		cache.NegNoData, dns.RCodeNoError, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	query := buildTestQuery("nodata.example.com", dns.TypeAAAA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) != 0 {
		t.Errorf("expected 0 answers, got %d", len(msg.Answers))
	}
}

// ---------------------------------------------------------------------------
// 18. Multiple-question query
// ---------------------------------------------------------------------------

func TestHandleMultipleQuestions(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x9999,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{
			{Name: "a.com", Type: dns.TypeA, Class: dns.ClassIN},
			{Name: "b.com", Type: dns.TypeA, Class: dns.ClassIN},
		},
	}
	buf := make([]byte, 512)
	query, err := dns.Pack(msg, buf)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected FORMERR")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeFormErr {
		t.Errorf("expected FORMERR(1), got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// 19. Resolution fails, no stale → SERVFAIL
// ---------------------------------------------------------------------------

func TestHandleResolutionFailsNoStale(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	query := buildTestQuery("fail.example.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected SERVFAIL")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL(2), got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// 20-21. tcp.go handleTCP – read length fails / incomplete body
// ---------------------------------------------------------------------------

func TestTCPHandleReadLengthFails(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

func TestTCPHandleIncompleteBody(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	binary.Write(conn, binary.BigEndian, uint16(100))
	conn.Write([]byte{1, 2, 3, 4, 5})
	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// 22. Unknown qtype string → "OTHER"
// ---------------------------------------------------------------------------

func TestHandleUnknownQType(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.Store("other.example.com", 65534, dns.ClassIN, []dns.ResourceRecord{{
		Name: "other.example.com", Type: 65534, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x7777,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "other.example.com", Type: 65534, Class: dns.ClassIN}},
	}
	buf := make([]byte, 512)
	query, err := dns.Pack(msg, buf)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
}

// ---------------------------------------------------------------------------
// 23. UDP graceful shutdown
// ---------------------------------------------------------------------------

func TestUDPServeShutdown(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// ---------------------------------------------------------------------------
// 24. buildResponse – EDNS0 OPT appended
// ---------------------------------------------------------------------------

func TestBuildResponseWithEDNS0(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x1111,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "edns.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		EDNS0: &dns.EDNS0{UDPSize: 4096, DOFlag: true},
	}

	result := &resolver.ResolveResult{
		Answers: []dns.ResourceRecord{{
			Name: "edns.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
		RCODE: dns.RCodeNoError,
	}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	msg, _ := dns.Unpack(resp)
	hasOPT := false
	for _, rr := range msg.Additional {
		if rr.Type == dns.TypeOPT {
			hasOPT = true
		}
	}
	if !hasOPT {
		t.Error("expected OPT in Additional")
	}
}

// ---------------------------------------------------------------------------
// 25. TCP normal response (write path)
// ---------------------------------------------------------------------------

func TestTCPNormalResponse(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	resp := sendTCP(t, srv.listener.Addr().String(), buildTestQuery("example.com", dns.TypeA))
	if len(resp) == 0 {
		t.Error("expected non-empty response")
	}
}

// ---------------------------------------------------------------------------
// 26. zero-length query
// ---------------------------------------------------------------------------

func TestHandleZeroLengthQuery(t *testing.T) {
	h := testHandler()
	resp, err := h.Handle([]byte{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected FORMERR")
	}
	if len(resp) != 12 {
		t.Errorf("expected 12-byte header, got %d", len(resp))
	}
}

// ---------------------------------------------------------------------------
// 27. ACL + RateLimiter together
// ---------------------------------------------------------------------------

func TestHandleACLAndRateLimit(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.Store("both.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "both.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}, nil)
	res := newTestResolver(c, m)
	acl, _ := security.NewACL([]string{"192.168.0.0/16"}, nil)
	rl := security.NewRateLimiter(0, 1)
	handler := NewMainHandler(res, c, rl, nil, acl, m, discardLogger())
	addr := &mockAddr{network: "udp", addr: "192.168.1.1:1234"}
	query := buildTestQuery("both.example.com", dns.TypeA)

	resp, _ := handler.Handle(query, addr)
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeNoError {
		t.Errorf("first query: expected NOERROR, got %d", rcode)
	}

	resp, _ = handler.Handle(query, addr)
	rcode = uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeRefused {
		t.Errorf("second query: expected REFUSED(5), got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// 28. UDP accept timeout continue (server stays alive after idle)
// ---------------------------------------------------------------------------

func TestUDPServeTimeoutContinue(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	time.Sleep(2500 * time.Millisecond)

	conn, err := net.DialTimeout("udp", srv.conn.LocalAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(buildTestQuery("alive.example.com", dns.TypeA))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected echo response: %v", err)
	}
	if n == 0 {
		t.Error("expected non-empty response")
	}
}

// ---------------------------------------------------------------------------
// 29. buildError – exact 12 bytes, QDCount=0
// ---------------------------------------------------------------------------

func TestBuildErrorExact12Bytes(t *testing.T) {
	h := testHandler()
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0xBEEF)
	resp, err := h.buildError(query, dns.RCodeRefused)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 12 {
		t.Errorf("expected 12 bytes, got %d", len(resp))
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeRefused {
		t.Errorf("expected REFUSED(5), got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// 30. buildError – offset > len(query) clamp
// ---------------------------------------------------------------------------

func TestBuildErrorOffsetClamp(t *testing.T) {
	h := testHandler()
	query := make([]byte, 16)
	binary.BigEndian.PutUint16(query[0:2], 0x1234)
	binary.BigEndian.PutUint16(query[4:6], 1)
	query[12] = 1
	query[13] = 'a'
	query[14] = 0x00

	resp, err := h.buildError(query, dns.RCodeServFail)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) > len(query) {
		t.Errorf("response (%d) exceeds query (%d)", len(resp), len(query))
	}
}

// ---------------------------------------------------------------------------
// 31. TCP accept-timeout-continue
// ---------------------------------------------------------------------------

func TestTCPServeAcceptTimeoutContinue(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	time.Sleep(2500 * time.Millisecond)

	resp := sendTCP(t, srv.listener.Addr().String(), buildTestQuery("alive.example.com", dns.TypeA))
	if len(resp) == 0 {
		t.Error("expected response after accept timeout cycles")
	}
}

// ---------------------------------------------------------------------------
// 32. serve-stale no stale entry → SERVFAIL
// ---------------------------------------------------------------------------

func TestHandleServeStaleBuildsFailFallsToSERVFAIL(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCacheWithStale(1000, 1, 86400, 3600, true, 30, m)
	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	query := buildTestQuery("nostale.example.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected SERVFAIL")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL(2), got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// 33. buildError NOTIMP / REFUSED
// ---------------------------------------------------------------------------

func TestBuildErrorNOTIMP(t *testing.T) {
	h := testHandler()
	resp, _ := h.buildError(buildTestQuery("x.com", dns.TypeA), dns.RCodeNotImp)
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeNotImp {
		t.Errorf("expected NOTIMP(4), got %d", rcode)
	}
}

func TestBuildErrorREFUSED(t *testing.T) {
	h := testHandler()
	resp, _ := h.buildError(buildTestQuery("x.com", dns.TypeA), dns.RCodeRefused)
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeRefused {
		t.Errorf("expected REFUSED(5), got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// 34. TCP large length / incomplete
// ---------------------------------------------------------------------------

func TestTCPHandleLargeLength(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	binary.Write(conn, binary.BigEndian, uint16(65535))
	conn.Write([]byte{1, 2, 3})
	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// 35. UDP write error (best effort, no panic)
// ---------------------------------------------------------------------------

func TestUDPWriteErrorHandled(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("udp", srv.conn.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(buildTestQuery("panic.example.com", dns.TypeA))
	conn.Close()
	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// 36. handler.go Handle – resolver error with no stale → SERVFAIL (line 130-131)
//     The panicking resolver returns (nil, error). GetStale fails (no entry).
// ---------------------------------------------------------------------------

func TestHandleResolverErrorNoStale(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, handlerMetrics)
	// Don't store anything stale — GetStale will return false.
	res := newPanickingResolver(c)
	handler := NewMainHandler(res, c, nil, nil, nil, handlerMetrics, discardLogger())

	query := buildTestQuery("resolver-err.example.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected SERVFAIL response")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL(2), got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// 37. handler.go Handle – UNKNOWN rcodeStr (line 136-138)
//     Need resolver to return a result with an RCODE not in RCodeToString.
// ---------------------------------------------------------------------------

// We can't easily make the resolver return an unusual RCODE without network,
// but the fail-fast resolver returns SERVFAIL which IS in the map. This is
// already covered by the RRL tests above. The "UNKNOWN" branch would require
// an RCODE like 6-15. We'll skip this as it's unreachable with the current
// resolver implementation.

// ---------------------------------------------------------------------------
// 38. handler.go Handle – cache stores for NXDOMAIN and NODATA (lines 140-146)
//     These require successful resolution that returns NXDOMAIN or NODATA.
//     Already covered by TestHandleNegativeCacheNXDOMAIN (network test).
//     Adding a non-network test using the panicking resolver approach is not
//     feasible since these require successful resolution. The fail-fast
//     resolver returns SERVFAIL which doesn't match any branch.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 39. handler.go buildResponse – Pack error (line 274-276)
//     Pack fails when the buffer is too small. We pass 4096 which is enough.
//     Covering this would require a response > 4096 bytes, which would need
//     very large answer sections. This is an edge case.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 40. tcp.go Serve – non-timeout accept error (lines 61-62)
//     Close the listener while Serve is running (not via context cancel).
// ---------------------------------------------------------------------------

func TestTCPServeAcceptError(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	time.Sleep(100 * time.Millisecond)
	// Close the listener directly — causes a non-timeout accept error.
	srv.listener.Close()
	time.Sleep(200 * time.Millisecond)
	// Cancel context to let Serve exit.
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// ---------------------------------------------------------------------------
// 41. tcp.go Serve – ctx.Done() select branch (lines 43-44)
//     To hit this, cancel the context before the Accept call returns.
//     If we cancel and the loop restarts, the select picks up ctx.Done().
// ---------------------------------------------------------------------------

func TestTCPServeCtxDoneSelectBranch(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	// Let it start, then cancel + close listener so the Accept unblocks
	// and the next loop iteration hits the select case.
	time.Sleep(100 * time.Millisecond)
	cancel()
	srv.listener.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// ---------------------------------------------------------------------------
// 42. udp.go handleUDP – WriteTo error (line 86-88)
// ---------------------------------------------------------------------------

func TestUDPHandleWriteToError(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewUDPServer(":0", handler, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	// Use a raw UDP socket so we can control the source address.
	// Send a query from a valid address. The echo handler replies,
	// but if we close the server's conn before the reply, WriteTo fails.
	// This is best-effort; no panic is the goal.
	addr := srv.conn.LocalAddr().String()
	conn, err := net.DialTimeout("udp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(buildTestQuery("write-err.example.com", dns.TypeA))
	// Close the server conn immediately so WriteTo fails.
	srv.conn.Close()
	time.Sleep(200 * time.Millisecond)
	conn.Close()
}

// ---------------------------------------------------------------------------
// 43. NewTCPServer / NewUDPServer error paths (Listen/ListenPacket fails)
//     These fail when the address is invalid.
// ---------------------------------------------------------------------------

func TestNewTCPServerError(t *testing.T) {
	_, err := NewTCPServer("invalid-addr-no-port", &EchoHandler{}, time.Second, 10, discardLogger())
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestNewUDPServerError(t *testing.T) {
	_, err := NewUDPServer("invalid-addr-no-port", &EchoHandler{}, 10, discardLogger())
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

// ---------------------------------------------------------------------------
// 44. handler.go buildResponse – dns.Pack error (lines 274-276, 164-166)
//     Pack fails when the response exceeds the 4096-byte internal buffer.
// ---------------------------------------------------------------------------

func TestBuildResponsePackError(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xAAAA,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "overflow.example.com", Type: dns.TypeTXT, Class: dns.ClassIN,
		}},
	}

	// Create records that exceed 4096 bytes total. Each TXT record with
	// unique long name + 200-byte RDATA. Name + overhead ~ 30 bytes + 200.
	// Need about 18 records: 18 * 230 = 4140 > 4096.
	var answers []dns.ResourceRecord
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("very-long-subdomain-%d.overflow.example.com", i)
		txt := strings.Repeat("x", 200)
		rdata := make([]byte, len(txt)+1)
		rdata[0] = byte(len(txt))
		copy(rdata[1:], txt)
		answers = append(answers, dns.ResourceRecord{
			Name: name, Type: dns.TypeTXT, Class: dns.ClassIN,
			TTL: 300, RDLength: uint16(len(rdata)), RData: rdata,
		})
	}

	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}
	_, err := handler.buildResponse(queryMsg, result)
	if err == nil {
		t.Error("expected error from dns.Pack (buffer overflow)")
	}
}

// ---------------------------------------------------------------------------
// 45. handler.go Handle – buildResponse error path (line 164-166)
//     When buildResponse returns error, Handle returns (nil, err).
//     We need a cache miss → resolver returns → buildResponse fails.
//     Use fail-fast resolver (returns SERVFAIL) and enough records.
// ---------------------------------------------------------------------------

// The fail-fast resolver returns SERVFAIL with no answers/authority/additional.
// That builds a small response. To make buildResponse fail, we'd need the
// resolver to return a huge result. This is impractical without a mock.
// The buildResponse error path is covered by TestBuildResponsePackError above
// which tests the function directly.

// ---------------------------------------------------------------------------
// Compile guard
// ---------------------------------------------------------------------------

var _ = fmt.Sprintf("coverage tests loaded")
var _ = strings.TrimSpace("")
