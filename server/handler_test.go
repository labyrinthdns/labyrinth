package server

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// testHandler creates a MainHandler with only metrics (for unit tests that don't need full resolver).
func testHandler() *MainHandler {
	return &MainHandler{
		metrics: metrics.NewMetrics(),
	}
}

// EchoHandler returns the query as-is (for testing).
type EchoHandler struct{}

func (h *EchoHandler) Handle(query []byte, addr net.Addr) ([]byte, error) {
	return query, nil
}

func TestEchoHandler(t *testing.T) {
	h := &EchoHandler{}
	input := []byte{1, 2, 3, 4, 5}
	output, err := h.Handle(input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output) != len(input) {
		t.Fatalf("expected %d bytes, got %d", len(input), len(output))
	}
	for i := range input {
		if output[i] != input[i] {
			t.Errorf("byte %d: expected %d, got %d", i, input[i], output[i])
		}
	}
}

func TestBuildErrorSERVFAIL(t *testing.T) {
	h := testHandler()

	// Build a valid query
	query := buildTestQuery("example.com", dns.TypeA)

	resp, err := h.buildError(query, dns.RCodeServFail)
	if err != nil {
		t.Fatalf("buildError error: %v", err)
	}
	if len(resp) < 12 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	// Check QR=1
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>15&1 != 1 {
		t.Error("QR should be 1")
	}
	// Check RA=1
	if flags>>7&1 != 1 {
		t.Error("RA should be 1")
	}
	// Check RCODE=2 (SERVFAIL)
	if uint8(flags&0xF) != dns.RCodeServFail {
		t.Errorf("RCODE: expected SERVFAIL(2), got %d", flags&0xF)
	}
	// Check ANCount=0
	if binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Error("ANCount should be 0")
	}
}

func TestBuildErrorFORMERR(t *testing.T) {
	h := testHandler()
	query := buildTestQuery("test.com", dns.TypeA)

	resp, err := h.buildError(query, dns.RCodeFormErr)
	if err != nil {
		t.Fatalf("buildError error: %v", err)
	}

	flags := binary.BigEndian.Uint16(resp[2:4])
	if uint8(flags&0xF) != dns.RCodeFormErr {
		t.Errorf("RCODE: expected FORMERR(1), got %d", flags&0xF)
	}
}

func TestBuildErrorTruncatedQuery(t *testing.T) {
	h := testHandler()
	// Query < 12 bytes
	resp, err := h.buildError([]byte{0x00, 0x01}, dns.RCodeServFail)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp) != 12 {
		t.Errorf("expected 12-byte header-only response, got %d", len(resp))
	}
}

func TestBuildErrorPreservesID(t *testing.T) {
	h := testHandler()
	query := buildTestQuery("example.com", dns.TypeA)
	// Set a specific ID
	binary.BigEndian.PutUint16(query[0:2], 0xABCD)

	resp, err := h.buildError(query, dns.RCodeServFail)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	respID := binary.BigEndian.Uint16(resp[0:2])
	if respID != 0xABCD {
		t.Errorf("ID not preserved: expected 0xABCD, got 0x%04X", respID)
	}
}

func TestInputValidationQR1Dropped(t *testing.T) {
	h := testHandler()

	// Build a query but set QR=1 (it's a response, not a query)
	query := buildTestQuery("test.com", dns.TypeA)
	flags := binary.BigEndian.Uint16(query[2:4])
	flags |= 1 << 15 // QR=1
	binary.BigEndian.PutUint16(query[2:4], flags)

	resp, err := h.Handle(query, nil)
	if resp != nil {
		t.Error("QR=1 query should be dropped (nil response)")
	}
	if err == nil {
		t.Error("QR=1 query should return error")
	}
}

func TestInputValidationOPCODE(t *testing.T) {
	h := testHandler()

	// Build a query with OPCODE=2 (STATUS)
	query := buildTestQuery("test.com", dns.TypeA)
	flags := binary.BigEndian.Uint16(query[2:4])
	flags |= uint16(dns.OpcodeStatus) << 11
	binary.BigEndian.PutUint16(query[2:4], flags)

	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected NOTIMP response, got nil")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeNotImp {
		t.Errorf("expected NOTIMP(4), got %d", rcode)
	}
}

func TestInputValidationTooShort(t *testing.T) {
	h := testHandler()

	resp, err := h.Handle([]byte{0, 1, 2}, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected FORMERR response")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeFormErr {
		t.Errorf("expected FORMERR(1), got %d", rcode)
	}
}

func BenchmarkResolveCached(b *testing.B) {
	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Pre-populate cache
	c.Store("bench.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "bench.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{93, 184, 216, 34},
	}}, nil)

	handler := &MainHandler{
		cache:   c,
		metrics: m,
		logger:  logger,
	}

	query := buildTestQuery("bench.example.com", dns.TypeA)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			handler.Handle(query, nil)
		}
	})
}

func TestAddEDEToResponse(t *testing.T) {
	resp := &dns.Message{
		Header: dns.Header{
			ID: 0x1234,
			Flags: dns.NewFlagBuilder().
				SetQR(true).
				SetRA(true).
				SetRCODE(dns.RCodeServFail).
				Build(),
		},
		Questions: []dns.Question{{
			Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
	}

	// Add OPT first
	resp.Additional = append(resp.Additional, dns.BuildOPT(4096, false))

	addEDEToResponse(resp, dns.EDECodeDNSSECBogus, "DNSSEC validation failure")

	// Check that the OPT record now has EDE data
	if len(resp.Additional) != 1 {
		t.Fatalf("expected 1 additional record, got %d", len(resp.Additional))
	}
	opt := resp.Additional[0]
	if opt.Type != dns.TypeOPT {
		t.Fatalf("expected OPT type, got %d", opt.Type)
	}
	if len(opt.RData) == 0 {
		t.Fatal("expected non-empty OPT RDATA after adding EDE")
	}

	// Parse the OPT to verify
	edns, err := dns.ParseOPT(&opt)
	if err != nil {
		t.Fatalf("ParseOPT error: %v", err)
	}
	if len(edns.Options) == 0 {
		t.Fatal("expected at least one EDNS option")
	}
	if edns.Options[0].Code != dns.EDNSOptionCodeEDE {
		t.Errorf("expected EDE option code %d, got %d", dns.EDNSOptionCodeEDE, edns.Options[0].Code)
	}
	code, text, err := dns.ParseEDEOption(edns.Options[0].Data)
	if err != nil {
		t.Fatalf("ParseEDEOption error: %v", err)
	}
	if code != dns.EDECodeDNSSECBogus {
		t.Errorf("EDE code: expected %d, got %d", dns.EDECodeDNSSECBogus, code)
	}
	if text != "DNSSEC validation failure" {
		t.Errorf("EDE text: expected 'DNSSEC validation failure', got %q", text)
	}
}

func TestAddEDEToResponse_NoOPT(t *testing.T) {
	resp := &dns.Message{
		Header: dns.Header{
			ID: 0x1234,
			Flags: dns.NewFlagBuilder().
				SetQR(true).
				SetRCODE(dns.RCodeServFail).
				Build(),
		},
	}

	addEDEToResponse(resp, dns.EDECodeStaleAnswer, "serve-stale")

	// Should create an OPT record
	if len(resp.Additional) != 1 {
		t.Fatalf("expected 1 additional record, got %d", len(resp.Additional))
	}
	if resp.Additional[0].Type != dns.TypeOPT {
		t.Fatal("expected OPT record to be created")
	}
}

func TestGenerateServerCookie(t *testing.T) {
	h := testHandler()
	h.cookiesEnabled = true
	h.cookieSecret = []byte("test-secret-1234")

	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	cookie1 := h.generateServerCookie(clientCookie, "192.168.1.1")
	// RFC 9018: server cookie = Version(1) + Reserved(3) + Timestamp(4) + Hash(8) = 16 bytes
	if len(cookie1) != 16 {
		t.Fatalf("expected 16-byte server cookie (RFC 9018), got %d", len(cookie1))
	}
	if cookie1[0] != 1 {
		t.Errorf("expected Version=1, got %d", cookie1[0])
	}

	// Same inputs with same timestamp produce same cookie
	ts := binary.BigEndian.Uint32(cookie1[4:8])
	cookie2 := h.generateServerCookieAt(clientCookie, "192.168.1.1", ts)
	for i := range cookie1 {
		if cookie1[i] != cookie2[i] {
			t.Fatal("same inputs should produce same cookie")
		}
	}

	// Different client IP produces different cookie
	cookie3 := h.generateServerCookieAt(clientCookie, "10.0.0.1", ts)
	same := true
	for i := range cookie1 {
		if cookie1[i] != cookie3[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different client IPs should produce different cookies")
	}
}

func TestValidateServerCookie(t *testing.T) {
	h := testHandler()
	h.cookiesEnabled = true
	h.cookieSecret = []byte("test-secret-1234")

	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	serverCookie := h.generateServerCookie(clientCookie, "10.0.0.1")

	if !h.validateServerCookie(clientCookie, serverCookie, "10.0.0.1") {
		t.Error("should validate freshly generated cookie")
	}

	// Wrong IP
	if h.validateServerCookie(clientCookie, serverCookie, "10.0.0.2") {
		t.Error("should reject cookie for different IP")
	}

	// Wrong version
	bad := make([]byte, 16)
	copy(bad, serverCookie)
	bad[0] = 2
	if h.validateServerCookie(clientCookie, bad, "10.0.0.1") {
		t.Error("should reject wrong version")
	}

	// Too short
	if h.validateServerCookie(clientCookie, serverCookie[:8], "10.0.0.1") {
		t.Error("should reject short cookie")
	}
}

func TestBuildErrorWithEDE(t *testing.T) {
	h := testHandler()
	query := buildTestQuery("example.com", dns.TypeA)

	resp, err := h.buildErrorWithEDE(query, dns.RCodeServFail, dns.EDECodeDNSSECBogus, "bogus")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp) < 12 {
		t.Fatal("response too short")
	}

	// Check RCODE is SERVFAIL
	flags := binary.BigEndian.Uint16(resp[2:4])
	if uint8(flags&0xF) != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL, got %d", flags&0xF)
	}

	// Parse and check EDE
	msg, parseErr := dns.Unpack(resp)
	if parseErr != nil {
		t.Fatalf("unpack error: %v", parseErr)
	}
	if msg.EDNS0 == nil {
		t.Fatal("expected EDNS0 in response")
	}
	found := false
	for _, opt := range msg.EDNS0.Options {
		if opt.Code == dns.EDNSOptionCodeEDE {
			code, _, _ := dns.ParseEDEOption(opt.Data)
			if code == dns.EDECodeDNSSECBogus {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected EDE option with DNSSEC Bogus code in response")
	}
}

func buildTestQuery(name string, qtype uint16) []byte {
	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x1234,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name:  name,
			Type:  qtype,
			Class: dns.ClassIN,
		}},
	}
	buf := make([]byte, 512)
	packed, err := dns.Pack(msg, buf)
	if err != nil {
		panic("failed to build test query: " + err.Error())
	}
	result := make([]byte, len(packed))
	copy(result, packed)
	return result
}
