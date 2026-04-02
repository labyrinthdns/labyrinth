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
