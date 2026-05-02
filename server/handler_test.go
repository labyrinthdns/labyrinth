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
	"github.com/labyrinthdns/labyrinth/resolver"
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

// --- EDNS0 advertised UDP buffer size (DNS Flag Day 2020 / RFC 9018) ---

func TestAdvertisedDownstreamUDPBufferSize_DefaultsTo1232WhenZero(t *testing.T) {
	h := testHandler()
	if got := h.advertisedUDPBufferSize(); got != 1232 {
		t.Errorf("zero/unset config must fall back to 1232, got %d", got)
	}
}

func TestAdvertisedDownstreamUDPBufferSize_HonorsConfiguredValue(t *testing.T) {
	cases := []struct {
		configured int
		want       uint16
	}{
		{512, 512},     // RFC 6891 mandated minimum
		{1232, 1232},   // DNS Flag Day 2020 default
		{4096, 4096},   // legacy default — operator may still want it
		{65535, 65535}, // max valid uint16
	}
	for _, c := range cases {
		h := testHandler()
		h.SetDownstreamUDPBufferSize(c.configured)
		if got := h.advertisedUDPBufferSize(); got != c.want {
			t.Errorf("downstreamUDPBufferSize=%d: got %d, want %d", c.configured, got, c.want)
		}
	}
}

func TestAdvertisedDownstreamUDPBufferSize_RejectsOutOfRange(t *testing.T) {
	// Pathological values must fall back to the safe 1232 default rather
	// than be propagated into outgoing OPT records.
	cases := []int{-1, 0, 1, 511, 65536, 1 << 30}
	for _, v := range cases {
		h := testHandler()
		h.SetDownstreamUDPBufferSize(v)
		if got := h.advertisedUDPBufferSize(); got != 1232 {
			t.Errorf("downstreamUDPBufferSize=%d should fall back to 1232, got %d", v, got)
		}
	}
}

// TestResponseAdvertisesDefaultDownstreamBufferWhenUnset verifies that an
// unconfigured handler still emits the safe 1232-byte buffer in the OPT
// of its responses, rather than the legacy 4096 default. End-to-end
// regression guard against silently re-introducing 4096 across all five
// BuildOPT call sites in the response builders.
func TestResponseAdvertisesDefaultDownstreamBufferWhenUnset(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.Store("default-buf.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "default-buf.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	// Note: deliberately NOT calling SetDownstreamUDPBufferSize here.

	query := buildTestQueryWithEDNS("default-buf.example.com", dns.TypeA, 4096)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if msg.EDNS0 == nil {
		t.Fatal("expected EDNS0/OPT in response")
	}
	if msg.EDNS0.UDPSize != 1232 {
		t.Errorf("OPT.UDPSize: got %d, want 1232 (DNS Flag Day default)", msg.EDNS0.UDPSize)
	}
}

// TestResponseAdvertisesConfiguredDownstreamBuffer verifies that an
// explicit operator override is honoured on the wire, end-to-end.
func TestResponseAdvertisesConfiguredDownstreamBuffer(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.Store("configured-buf.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "configured-buf.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetDownstreamUDPBufferSize(4096)

	query := buildTestQueryWithEDNS("configured-buf.example.com", dns.TypeA, 4096)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if msg.EDNS0 == nil {
		t.Fatal("expected EDNS0/OPT in response")
	}
	if msg.EDNS0.UDPSize != 4096 {
		t.Errorf("OPT.UDPSize: got %d, want 4096 (operator override)", msg.EDNS0.UDPSize)
	}
}

// --- Outgoing UDP response size cap (RFC 9018 / fragment-injection mitigation) ---
//
// These three tests guard the truncation logic in buildResponse, which caps
// the on-wire UDP response at min(client-advertised, configured-ceiling). The
// configured ceiling is the same value advertised in our outgoing OPT, so a
// well-behaved client that honours our advertisement will never see TC=1 from
// us; a client that ignores the advertisement and asks for more (e.g. 4096)
// is forced down to our ceiling, denying off-path attackers the predictable
// large-fragment surface (Brandt et al, USENIX Security 2018) on responses.

// TestBuildResponse_CapsAtServerConfiguredCeiling verifies that a client
// advertising 4096 cannot induce us to emit a response larger than our
// 1232-byte default ceiling. The truncated response must have TC=1 and
// ANCount=0 per RFC 1035 §4.1.1.
func TestBuildResponse_CapsAtServerConfiguredCeiling(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	// Note: deliberately NOT calling SetDownstreamUDPBufferSize here.
	// Default behaviour must cap at 1232.

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xC001,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "cap.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		EDNS0: &dns.EDNS0{UDPSize: 4096},
	}

	// 200 A records, ~16 bytes wire each → ~3200 bytes uncompressed,
	// guaranteed to exceed the 1232-byte ceiling.
	var answers []dns.ResourceRecord
	for i := 0; i < 200; i++ {
		answers = append(answers, dns.ResourceRecord{
			Name: "cap.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{10, byte(i >> 8), byte(i), 1},
		})
	}
	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("buildResponse error: %v", err)
	}
	if len(resp) > 1232 {
		t.Errorf("response not capped: got %d bytes, want <= 1232 (server ceiling)", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 1 {
		t.Error("TC bit must be set on truncated response (RFC 1035 §4.1.1)")
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Errorf("ANCount must be 0 on truncated response, got %d", ancount)
	}
}

// TestBuildResponse_HonorsClientWhenSmallerThanCap verifies that a client
// advertising a buffer smaller than our ceiling still wins — we never emit
// more than the client said it could receive, even if our ceiling would
// allow it.
func TestBuildResponse_HonorsClientWhenSmallerThanCap(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	// Default ceiling = 1232. Client advertises 600.

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xC002,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "small-client.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		EDNS0: &dns.EDNS0{UDPSize: 600},
	}

	// 50 A records, ~30 bytes wire each (full FQDN) → comfortably above 600B.
	var answers []dns.ResourceRecord
	for i := 0; i < 50; i++ {
		answers = append(answers, dns.ResourceRecord{
			Name: "small-client.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{10, 0, byte(i), 1},
		})
	}
	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("buildResponse error: %v", err)
	}
	if len(resp) > 600 {
		t.Errorf("response exceeded client-advertised buffer: got %d bytes, want <= 600", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 1 {
		t.Error("TC bit must be set when truncating to client buffer")
	}
}

// TestBuildResponse_AllowsLargeResponseWithOperatorOverride verifies that an
// operator who has explicitly raised the ceiling to 4096 is honoured — a
// 1.5KB response goes out untruncated. Without the operator override, the
// 1232-byte default would have forced TC=1.
func TestBuildResponse_AllowsLargeResponseWithOperatorOverride(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetDownstreamUDPBufferSize(4096) // raise ceiling

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xC003,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "override.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		EDNS0: &dns.EDNS0{UDPSize: 4096},
	}

	// ~100 A records: enough to exceed the default 1232 ceiling but well
	// under 4096, so without the override this would truncate.
	var answers []dns.ResourceRecord
	for i := 0; i < 100; i++ {
		answers = append(answers, dns.ResourceRecord{
			Name: "override.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{10, 0, byte(i), 1},
		})
	}
	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("buildResponse error: %v", err)
	}
	if len(resp) <= 1232 {
		t.Fatalf("test setup invariant: response %d bytes is not > 1232; the test cannot prove the override matters", len(resp))
	}
	if len(resp) > 4096 {
		t.Errorf("response exceeded operator override: got %d bytes, want <= 4096", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 0 {
		t.Error("TC bit must NOT be set when response fits within operator-configured ceiling")
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount == 0 {
		t.Error("ANCount must be > 0 when response is not truncated")
	}
}

// TestBuildCacheResponse_CapsAtServerCeiling proves the cache-hit path now
// goes through maybeTruncateUDP after the helper-extraction refactor. Before
// the refactor, buildCacheResponse emitted unbounded UDP regardless of cap
// — a pathological cache entry could induce 1232 < N bytes responses.
func TestBuildCacheResponse_CapsAtServerCeiling(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	// Default ceiling = 1232. Client claims 4096.

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xCAC1,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "cached.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		EDNS0: &dns.EDNS0{UDPSize: 4096},
	}

	// Construct a pathological cache entry: 200 A records, ~3.2KB
	// uncompressed. Real-world cache entries are typically 1-2 RRs, but
	// nothing in the cache layer prevents an entry of this size.
	var records []dns.ResourceRecord
	for i := 0; i < 200; i++ {
		records = append(records, dns.ResourceRecord{
			Name: "cached.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{10, byte(i >> 8), byte(i), 1},
		})
	}
	entry := &cache.Entry{Records: records, RCODE: dns.RCodeNoError}

	resp, err := handler.buildCacheResponse(queryMsg, entry)
	if err != nil {
		t.Fatalf("buildCacheResponse error: %v", err)
	}
	if len(resp) > 1232 {
		t.Errorf("cache-hit response not capped: got %d bytes, want <= 1232", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 1 {
		t.Error("TC bit must be set on truncated cache-hit response")
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Errorf("ANCount must be 0 on truncated response, got %d", ancount)
	}
}

// TestBuildMinimalANYResponse_FloorsClientUDPSize proves the RFC 6891 §6.2.5
// floor is wired through the ANY-collapse path. Client advertises an
// illegally-small UDPSize=30, but the resolver MUST treat that as 512
// (the protocol minimum) — meaning the ~57-byte synthetic HINFO response
// goes out untruncated, with TC=0 and ANCount>0. Without the floor, this
// path would have set TC=1 and dropped the answer (regression in a5b351c
// before the floor was introduced).
func TestBuildMinimalANYResponse_FloorsClientUDPSize(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	q := dns.Question{Name: "any.example.com", Type: dns.TypeANY, Class: dns.ClassIN}
	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xA001,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{q},
		// UDPSize=30 is illegal per RFC 6891 §6.2.5 (minimum 512).
		// The floor logic in maybeTruncateUDP must ignore this and use 512.
		EDNS0: &dns.EDNS0{UDPSize: 30},
	}

	resp, err := handler.buildMinimalANYResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("buildMinimalANYResponse error: %v", err)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 0 {
		t.Errorf("TC bit must NOT be set: client UDPSize<512 should be floored, got TC=1 (resp=%d bytes)", len(resp))
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount == 0 {
		t.Error("ANCount must be > 0: synthetic HINFO answer should be preserved when floored")
	}
	if len(resp) <= 12 {
		t.Errorf("response too small (header-only?): got %d bytes", len(resp))
	}
}

// TestMaybeTruncateUDP_NoEDNSCapsAt512 verifies the RFC 1035 default: a
// query without EDNS0 caps the response at 512 bytes regardless of how
// generous the server-configured ceiling is. Defensive guard against
// regressions that would forget to floor at 512 for legacy clients.
func TestMaybeTruncateUDP_NoEDNSCapsAt512(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetDownstreamUDPBufferSize(4096) // generous server cap

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xC512,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "legacy.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		// No EDNS0: this is a legacy RFC 1035 client.
	}

	// 50 A records → ~800 bytes uncompressed, well over 512.
	var answers []dns.ResourceRecord
	for i := 0; i < 50; i++ {
		answers = append(answers, dns.ResourceRecord{
			Name: "legacy.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{10, 0, byte(i), 1},
		})
	}
	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("buildResponse error: %v", err)
	}
	if len(resp) > 512 {
		t.Errorf("non-EDNS response exceeded 512: got %d bytes (RFC 1035 §4.2.1)", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 1 {
		t.Error("TC bit must be set when truncating to 512-byte default")
	}
}

// TestMaybeTruncateUDP_FloorsClientBelowRFCMinimum proves that a client
// advertising EDNS0 UDPSize < 512 (RFC 6891 §6.2.5 minimum) is not
// honoured: we use 512 as the floor and emit a full RFC-compliant
// response. Without the floor, a misconfigured or malicious client
// could induce TC=1 + TCP retransmit on every response by advertising
// UDPSize=0, opening a low-effort amplification-via-TCP-fallback DoS.
func TestMaybeTruncateUDP_FloorsClientBelowRFCMinimum(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xF100,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "broken-client.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		// Illegal per RFC 6891 §6.2.5 (minimum 512). Floor must ignore.
		EDNS0: &dns.EDNS0{UDPSize: 30},
	}

	// 20 A records → ~370 bytes packed. Comfortably under the 512-byte
	// floor, so a correctly-floored handler must NOT truncate. Without
	// the floor, a 30-byte cap would force TC=1.
	var answers []dns.ResourceRecord
	for i := 0; i < 20; i++ {
		answers = append(answers, dns.ResourceRecord{
			Name: "broken-client.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{10, 0, byte(i), 1},
		})
	}
	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("buildResponse error: %v", err)
	}
	if len(resp) >= 512 {
		t.Fatalf("test setup invariant: response %d bytes is not < 512; cannot prove the floor matters", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 0 {
		t.Errorf("TC bit must NOT be set: client UDPSize<512 should be floored to 512 (resp=%d bytes)", len(resp))
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount == 0 {
		t.Error("ANCount must be > 0: response should be preserved when floored")
	}
}

// TestMaybeTruncateUDP_FloorsZeroUDPSize is the minimal pathological case
// of the floor: a client advertising UDPSize=0 (or omitting it but sending
// an OPT). RFC 6891 §6.2.5 says zero is invalid; we treat it as 512.
func TestMaybeTruncateUDP_FloorsZeroUDPSize(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xF000,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "zero-udpsize.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		EDNS0: &dns.EDNS0{UDPSize: 0},
	}
	answers := []dns.ResourceRecord{{
		Name: "zero-udpsize.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}
	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("buildResponse error: %v", err)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 0 {
		t.Error("TC bit must NOT be set when client UDPSize=0 is floored to 512")
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount == 0 {
		t.Error("ANCount must be > 0: response should be preserved when floored from 0")
	}
}
