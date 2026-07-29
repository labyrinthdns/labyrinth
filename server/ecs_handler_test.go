package server

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// buildTestQueryWithECS constructs a DNS query carrying an ECS option in
// its OPT record. ScopePrefixLen is 0 per RFC 7871 section 6.
func buildTestQueryWithECS(name string, qtype uint16, ecs *dns.ECSOption) []byte {
	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x1234,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{dns.BuildECS(ecs)}),
		},
	}
	buf := make([]byte, 1024)
	packed, err := dns.Pack(msg, buf)
	if err != nil {
		panic("buildTestQueryWithECS: " + err.Error())
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out
}

func extractECSFromWire(t *testing.T, resp []byte) *dns.ECSOption {
	t.Helper()
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	for i := range msg.Additional {
		rr := &msg.Additional[i]
		if rr.Type != dns.TypeOPT {
			continue
		}
		opt, err := dns.ParseOPT(rr)
		if err != nil {
			return nil
		}
		ecs, _ := dns.ExtractECSFromOPT(opt)
		return ecs
	}
	return nil
}

// TestHandle_ECS_ScopedCacheIsolation verifies that a cache entry stored
// against an ECS scope is NOT served to a client whose subnet falls outside
// that scope. RFC 7871 section 7.3 correctness property: a CDN's
// geo-tailored answer to subnet X must not leak to clients in subnet Y.
func TestHandle_ECS_ScopedCacheIsolation(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)

	scopedAnswer := []dns.ResourceRecord{{
		Name: "cdn.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 99},
	}}
	c.StoreWithECSStatus("cdn.example.com", dns.TypeA, dns.ClassIN,
		"1.2.3.0/24", 24, scopedAnswer, nil, "")

	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetECS(true, 24)

	ecsA := &dns.ECSOption{
		Family: 1, SourcePrefixLen: 24, Address: net.ParseIP("1.2.3.5").To4(),
	}
	q := buildTestQueryWithECS("cdn.example.com", dns.TypeA, ecsA)
	resp, err := handler.Handle(q, &mockAddr{network: "udp", addr: "1.2.3.5:12345"})
	if err != nil || resp == nil {
		t.Fatalf("client A: err=%v resp=%v", err, resp)
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeNoError {
		t.Errorf("client A: expected NOERROR from scoped cache, got rcode=%d", rcode)
	}

	ecsB := &dns.ECSOption{
		Family: 1, SourcePrefixLen: 24, Address: net.ParseIP("8.8.8.7").To4(),
	}
	q2 := buildTestQueryWithECS("cdn.example.com", dns.TypeA, ecsB)
	resp2, err := handler.Handle(q2, &mockAddr{network: "udp", addr: "8.8.8.7:12345"})
	if err != nil || resp2 == nil {
		t.Fatalf("client B: err=%v resp=%v", err, resp2)
	}
	rcode2 := uint8(binary.BigEndian.Uint16(resp2[2:4]) & 0xF)
	if rcode2 == dns.RCodeNoError {
		t.Errorf("client B in 8.8.8.0/24 received the 1.2.3.0/24-scoped answer (cache leak)")
	}
}

// TestHandle_ECS_EchoesScopeInResponse verifies that when the client sends
// ECS in its query, the response carries an ECS option echoing the client's
// source prefix back with the authoritative scope (RFC 7871 section 7.2.1).
func TestHandle_ECS_EchoesScopeInResponse(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)

	c.StoreWithECSStatus("geo.example.com", dns.TypeA, dns.ClassIN,
		"1.2.3.0/24", 24, []dns.ResourceRecord{{
			Name: "geo.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}}, nil, "")

	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetECS(true, 24)

	clientECS := &dns.ECSOption{
		Family: 1, SourcePrefixLen: 24, Address: net.ParseIP("1.2.3.45").To4(),
	}
	q := buildTestQueryWithECS("geo.example.com", dns.TypeA, clientECS)
	resp, err := handler.Handle(q, &mockAddr{network: "udp", addr: "1.2.3.45:12345"})
	if err != nil || resp == nil {
		t.Fatalf("Handle: err=%v resp=%v", err, resp)
	}
	echo := extractECSFromWire(t, resp)
	if echo == nil {
		t.Fatal("response carried no ECS echo")
	}
	if echo.SourcePrefixLen != 24 {
		t.Errorf("echoed source prefix: want 24, got %d", echo.SourcePrefixLen)
	}
	if echo.ScopePrefixLen != 24 {
		t.Errorf("echoed scope: want 24 (matching cached scope), got %d", echo.ScopePrefixLen)
	}
}

// TestHandle_ECS_DisabledNoEcho verifies that with ECS forwarding disabled,
// no ECS option is echoed back even if the client sent one.
func TestHandle_ECS_DisabledNoEcho(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.Store("plain.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "plain.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{8, 8, 8, 8},
	}}, nil)

	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	clientECS := &dns.ECSOption{
		Family: 1, SourcePrefixLen: 24, Address: net.ParseIP("1.2.3.5").To4(),
	}
	q := buildTestQueryWithECS("plain.example.com", dns.TypeA, clientECS)
	resp, err := handler.Handle(q, &mockAddr{network: "udp", addr: "1.2.3.5:12345"})
	if err != nil || resp == nil {
		t.Fatalf("Handle: err=%v resp=%v", err, resp)
	}
	if echo := extractECSFromWire(t, resp); echo != nil {
		t.Errorf("expected no ECS echo when forwarding disabled, got %+v", echo)
	}
}

// TestHandle_ECS_ReservedSrcStripped verifies that an ECS option whose
// source address is in a reserved range (RFC 1918, CGNAT, loopback, etc.)
// is NOT forwarded. RFC 7871 section 11.1 / 7.1.2 privacy hazard.
func TestHandle_ECS_ReservedSrcStripped(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)

	c.Store("strip.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "strip.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{8, 8, 8, 8},
	}}, nil)
	c.StoreWithECSStatus("strip.example.com", dns.TypeA, dns.ClassIN,
		"192.168.1.0/24", 24, []dns.ResourceRecord{{
			Name: "strip.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{4, 4, 4, 4},
		}}, nil, "")

	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetECS(true, 24)

	privateECS := &dns.ECSOption{
		Family: 1, SourcePrefixLen: 24, Address: net.ParseIP("192.168.1.5").To4(),
	}
	q := buildTestQueryWithECS("strip.example.com", dns.TypeA, privateECS)
	resp, err := handler.Handle(q, &mockAddr{network: "udp", addr: "192.168.1.5:12345"})
	if err != nil || resp == nil {
		t.Fatalf("Handle: err=%v resp=%v", err, resp)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if len(msg.Answers) != 1 || len(msg.Answers[0].RData) != 4 {
		t.Fatalf("unexpected answers: %+v", msg.Answers)
	}
	if msg.Answers[0].RData[0] != 8 {
		t.Errorf("expected global 8.8.8.8 (private ECS stripped), got %v", msg.Answers[0].RData)
	}
}
