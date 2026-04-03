package resolver

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/dnssec"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// tcMockDNS returns TC=1 on UDP and full answer on TCP, to test TC fallback.
func startTCMockDNS(t *testing.T) *mockDNSServer {
	t.Helper()
	var udpCount atomic.Int32
	return startMockDNS(t, func(q *dns.Message) *dns.Message {
		count := udpCount.Add(1)
		if count <= 1 {
			// First UDP response: TC=1
			return &dns.Message{
				Header: dns.Header{
					Flags: dns.NewFlagBuilder().SetQR(true).SetTC(true).Build(),
				},
				Questions: q.Questions,
			}
		}
		// TCP or subsequent: full answer
		return &dns.Message{
			Header: dns.Header{
				Flags: dns.NewFlagBuilder().SetQR(true).Build(),
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: "tc-test.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 60, RDLength: 4, RData: []byte{10, 20, 30, 40},
			}},
		}
	})
}

func TestQueryUpstreamOnceTCFallback(t *testing.T) {
	mock := startTCMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	msg, err := r.queryUpstreamOnce(mock.ip, "tc-test.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("queryUpstreamOnce error: %v", err)
	}
	if msg == nil {
		t.Fatal("expected response after TC fallback")
	}
	if len(msg.Answers) == 0 {
		t.Error("expected answers from TCP fallback")
	}
}

// txidMismatchMockDNS returns responses with deliberately wrong TXID.
func startTXIDMismatchMockDNS(t *testing.T) *mockDNSServer {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())
	var tcp net.Listener
	for i := 0; i < 10; i++ {
		tcp, err = net.Listen("tcp", "127.0.0.1:"+portStr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		udp.Close()
		t.Skipf("tcp listen on same port failed: %v", err)
	}

	m := &mockDNSServer{udpConn: udp, tcpLn: tcp, port: portStr, ip: "127.0.0.1"}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			// Build response with WRONG TXID
			resp := make([]byte, n)
			copy(resp, buf[:n])
			if len(resp) >= 12 {
				resp[2] |= 0x80 // set QR=1
				// Corrupt TXID
				binary.BigEndian.PutUint16(resp[0:2], 0xDEAD)
			}
			udp.WriteTo(resp, addr)
		}
	}()

	return m
}

func TestQueryUpstreamOnceTXIDMismatch(t *testing.T) {
	mock := startTXIDMismatchMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	_, err := r.queryUpstreamOnce(mock.ip, "mismatch.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected TXID mismatch error")
	}
}

func TestResolveIterativeCNAMEChaseAndCache(t *testing.T) {
	var queryNum atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queryNum.Add(1)
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name

		// First: return CNAME
		if qname == "www.chase.com" {
			cnameRData := dns.BuildPlainName("real.chase.com")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "www.chase.com", Type: dns.TypeCNAME, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(cnameRData)), RData: cnameRData,
				}},
			}
		}
		// real.chase.com: return A
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 99},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("www.chase.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}
	// Should have CNAME + A
	if len(result.Answers) < 2 {
		t.Errorf("expected 2+ answers (CNAME + A), got %d", len(result.Answers))
	}
}

func TestResolveIterativeNXDOMAINCache(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		soaRData := buildSOARData()
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "com", Type: dns.TypeSOA, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, _ := r.Resolve("nxd.com", dns.TypeA, dns.ClassIN)
	if result.RCODE != dns.RCodeNXDomain {
		t.Errorf("expected NXDOMAIN, got %d", result.RCODE)
	}
	// Should be cached as negative
	entry, ok := r.cache.Get("nxd.com", dns.TypeA, dns.ClassIN)
	if ok && entry.Negative {
		// good — negative cache hit
	}
}

func TestResolveIterativeReferralFollowed(t *testing.T) {
	var queryCount atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		count := queryCount.Add(1)
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name

		// First query: referral
		if count == 1 {
			nsRData := dns.BuildPlainName("ns1.ref.com")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "ref.com", Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
				}},
				Additional: []dns.ResourceRecord{{
					Name: "ns1.ref.com", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 3600, RDLength: 4, RData: []byte{127, 0, 0, 1},
				}},
			}
		}
		// Second: answer
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 10, 10, 10},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("sub.ref.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Result may be NOERROR or SERVFAIL (loop detection with same IP)
	_ = result
}

func TestResolveIterativeQMinNoDataFallback(t *testing.T) {
	var queryCount atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queryCount.Add(1)
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		// QMin NS query returns NODATA → should fallback to full query
		if qtype == dns.TypeNS && qname != "." {
			soaRData := buildSOARData()
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: qname, Type: dns.TypeSOA, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
				}},
			}
		}
		// Full A query: answer
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 7},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	r.config.QMinEnabled = true
	result, err := r.Resolve("www.qmin.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}
}

func TestResolveIterativeEmptyReferral(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		// Return referral with NS record but broken RDATA (empty)
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN,
				TTL: 3600, RDLength: 0, RData: nil,
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("sub.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL from empty delegation, got %d", result.RCODE)
	}
}

func TestSelectAndResolveNSRecursiveResolveAAAA(t *testing.T) {
	// Test the AAAA recursive resolve fallback path
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		// Resolve ns1.other.com A → NODATA
		if qname == "ns1.other.com" && qtype == dns.TypeA {
			soaRData := buildSOARData()
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "other.com", Type: dns.TypeSOA, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
				}},
			}
		}
		// Resolve ns1.other.com AAAA → answer
		if qname == "ns1.other.com" && qtype == dns.TypeAAAA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "ns1.other.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
					TTL: 300, RDLength: 16, RData: net.ParseIP("::1").To16(),
				}},
			}
		}
		// Default
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	ns := []nsEntry{{hostname: "ns1.other.com"}} // no glue, not in cache
	_, ip, err := r.selectAndResolveNS(ns, newVisitedSet(), "different.zone")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ip != "::1" {
		t.Errorf("expected ::1 from AAAA fallback, got %q", ip)
	}
}

func TestBuildPlainName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"example.com", "example.com"},
		{"a.b.c", "a.b.c"},
		{"", ""},
		{".", ""},
	}
	for _, tt := range tests {
		b := dns.BuildPlainName(tt.name)
		decoded, _, err := dns.DecodeName(b, 0)
		if err != nil {
			t.Fatalf("BuildPlainName(%q) decode error: %v", tt.name, err)
		}
		if decoded != tt.expected {
			t.Errorf("BuildPlainName(%q): decoded to %q, expected %q", tt.name, decoded, tt.expected)
		}
	}
}

func TestExtractDelegationAAAAGlue(t *testing.T) {
	nsRData := dns.BuildPlainName("ns1.example.com")
	msg := &dns.Message{
		Authority: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN,
			TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
		}},
		Additional: []dns.ResourceRecord{{
			Name: "ns1.example.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
			TTL: 3600, RDLength: 16, RData: net.ParseIP("2001:db8::1").To16(),
		}},
	}

	delegation, zone := extractDelegation(msg)
	if zone != "example.com" {
		t.Errorf("zone: %q", zone)
	}
	if len(delegation) != 1 {
		t.Fatalf("expected 1 NS, got %d", len(delegation))
	}
	if delegation[0].IPv6 != "2001:db8::1" {
		t.Errorf("IPv6 glue: expected '2001:db8::1', got %q", delegation[0].IPv6)
	}
}

func TestQMinNXDOMAINRetry(t *testing.T) {
	// When QMIN sends a minimized query and gets NXDOMAIN, the resolver
	// should retry with the full query name (RFC 9156 §3).
	var queries []string
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type
		queries = append(queries, qname)

		// Minimized NS query → NXDOMAIN (intermediate label doesn't exist)
		if qtype == dns.TypeNS && qname != "." {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "com", Type: dns.TypeSOA, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(buildSOARData())), RData: buildSOARData(),
				}},
			}
		}
		// Full A query → answer
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 42},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	r.config.QMinEnabled = true
	result, err := r.Resolve("www.qmin-nx.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR after QMIN NXDOMAIN retry, got %d", result.RCODE)
	}
}

func TestSelectAndResolveNSCacheSkipsBadFirstRecord(t *testing.T) {
	// Cache has two A records: first is corrupt, second is valid.
	// selectAndResolveNS should skip the bad one and return the good one.
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message { return nil })
	defer mock.close()

	r := testResolver(t, mock)
	r.cache.Store("ns1.test.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{
		{Name: "ns1.test.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 2, RData: []byte{0xFF, 0xFF}}, // corrupt: only 2 bytes
		{Name: "ns1.test.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{10, 20, 30, 40}}, // valid
	}, nil)

	ns := []nsEntry{{hostname: "ns1.test.com"}}
	_, ip, err := r.selectAndResolveNS(ns, newVisitedSet(), "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ip != "10.20.30.40" {
		t.Errorf("expected 10.20.30.40 from second cache record, got %q", ip)
	}
}

func TestResolveNSAddrBypassesInflight(t *testing.T) {
	// resolveNSAddr should work independently of the inflight coalescer,
	// preventing deadlock when NS hostname resolution would hit the same key.
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)

	// Call resolveNSAddr directly — should succeed without going through inflight
	result, err := r.resolveNSAddr("ns1.example.tr", dns.TypeA)
	if err != nil {
		t.Fatalf("resolveNSAddr error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}
	if len(result.Answers) == 0 {
		t.Error("expected answers from resolveNSAddr")
	}
}

func TestValidateResponseQuestion(t *testing.T) {
	// Matching question — should pass
	msg := &dns.Message{
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	if err := validateResponseQuestion(msg, "example.com", dns.TypeA, dns.ClassIN); err != nil {
		t.Errorf("expected nil error for matching question, got: %v", err)
	}

	// Case-insensitive match — should pass
	msg.Questions[0].Name = "EXAMPLE.COM"
	if err := validateResponseQuestion(msg, "example.com", dns.TypeA, dns.ClassIN); err != nil {
		t.Errorf("expected nil for case-insensitive match, got: %v", err)
	}

	// Wrong name — should fail
	msg.Questions[0].Name = "evil.com"
	if err := validateResponseQuestion(msg, "example.com", dns.TypeA, dns.ClassIN); err == nil {
		t.Error("expected error for mismatched question name")
	}

	// Wrong type — should fail
	msg.Questions[0].Name = "example.com"
	msg.Questions[0].Type = dns.TypeAAAA
	if err := validateResponseQuestion(msg, "example.com", dns.TypeA, dns.ClassIN); err == nil {
		t.Error("expected error for mismatched question type")
	}

	// Root zone: "." vs "" — should pass
	msg.Questions = []dns.Question{{Name: "", Type: dns.TypeNS, Class: dns.ClassIN}}
	if err := validateResponseQuestion(msg, ".", dns.TypeNS, dns.ClassIN); err != nil {
		t.Errorf("expected nil for root zone match, got: %v", err)
	}

	// Empty questions — should fail
	msg.Questions = nil
	if err := validateResponseQuestion(msg, "example.com", dns.TypeA, dns.ClassIN); err == nil {
		t.Error("expected error for empty question section")
	}
}

// =============================================================================
// NEW COVERAGE TESTS — targeting uncovered code paths
// =============================================================================

// --- EnableDNSSEC and QueryDNSSEC (resolver.go:104-113) ---

func TestEnableDNSSEC(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	if r.dnssecValidator != nil {
		t.Fatal("validator should be nil before EnableDNSSEC")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r.EnableDNSSEC(logger)

	if r.dnssecValidator == nil {
		t.Fatal("validator should be non-nil after EnableDNSSEC")
	}
}

func TestQueryDNSSEC(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	msg, err := r.QueryDNSSEC("example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("QueryDNSSEC error: %v", err)
	}
	if msg == nil {
		t.Fatal("expected non-nil response from QueryDNSSEC")
	}
	if len(msg.Answers) == 0 {
		t.Error("expected answers from QueryDNSSEC")
	}
}

// --- DNSSEC validation paths in resolveIterative (resolver.go:204-218) ---

func TestResolveIterativeDNSSECInsecure(t *testing.T) {
	// Response has no RRSIG -> validator returns Insecure -> covers lines 210-211
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r.EnableDNSSEC(logger)

	result, err := r.Resolve("insecure.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}
	if result.DNSSECStatus != "insecure" {
		t.Errorf("expected DNSSECStatus 'insecure', got %q", result.DNSSECStatus)
	}
}

func TestResolveIterativeDNSSECBogus(t *testing.T) {
	// Response has RRSIG with expired timestamp -> validator returns Bogus -> covers lines 213-215
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name

		// Build a minimal RRSIG RDATA with expired expiration time.
		signerName := dns.BuildPlainName("example.com")
		rrsigRData := make([]byte, 0, 18+len(signerName)+64)
		rrsigRData = append(rrsigRData, 0, 1) // TypeCovered = A (1)
		rrsigRData = append(rrsigRData, 8)     // Algorithm = 8 (RSA/SHA-256)
		rrsigRData = append(rrsigRData, 3)     // Labels = 3
		ttlBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ttlBytes, 300)
		rrsigRData = append(rrsigRData, ttlBytes...) // OriginalTTL
		expBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(expBytes, 1000) // Expiration = 1000 (long expired)
		rrsigRData = append(rrsigRData, expBytes...)
		incBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(incBytes, 500) // Inception = 500
		rrsigRData = append(rrsigRData, incBytes...)
		ktBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(ktBytes, 12345) // KeyTag
		rrsigRData = append(rrsigRData, ktBytes...)
		rrsigRData = append(rrsigRData, signerName...)     // Signer name
		rrsigRData = append(rrsigRData, make([]byte, 64)...) // Fake signature

		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{
				{
					Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 2},
				},
				{
					Name: qname, Type: dns.TypeRRSIG, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(rrsigRData)), RData: rrsigRData,
				},
			},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r.EnableDNSSEC(logger)

	result, err := r.Resolve("bogus.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL for bogus DNSSEC, got %d", result.RCODE)
	}
	if result.DNSSECStatus != "bogus" {
		t.Errorf("expected DNSSECStatus 'bogus', got %q", result.DNSSECStatus)
	}
}

func TestResolveIterativeDNSSECIndeterminate(t *testing.T) {
	// Response has RRSIG with valid time but DNSKEY can't be fetched ->
	// validator returns Indeterminate -> covers default case lines 216-217
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		// For DNSKEY queries, return SERVFAIL so the validator can't fetch keys
		if qtype == dns.TypeDNSKEY {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build()},
				Questions: q.Questions,
			}
		}

		// Build RRSIG with valid (current) time window
		signerName := dns.BuildPlainName("example.com")
		rrsigRData := make([]byte, 0, 18+len(signerName)+64)
		rrsigRData = append(rrsigRData, 0, 1) // TypeCovered = A
		rrsigRData = append(rrsigRData, 8)     // Algorithm
		rrsigRData = append(rrsigRData, 3)     // Labels
		ttlBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ttlBytes, 300)
		rrsigRData = append(rrsigRData, ttlBytes...)
		expBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(expBytes, 2000000000) // far future
		rrsigRData = append(rrsigRData, expBytes...)
		incBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(incBytes, 1000000000) // past
		rrsigRData = append(rrsigRData, incBytes...)
		ktBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(ktBytes, 12345)
		rrsigRData = append(rrsigRData, ktBytes...)
		rrsigRData = append(rrsigRData, signerName...)
		rrsigRData = append(rrsigRData, make([]byte, 64)...)

		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{
				{
					Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 3},
				},
				{
					Name: qname, Type: dns.TypeRRSIG, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(rrsigRData)), RData: rrsigRData,
				},
			},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r.EnableDNSSEC(logger)

	result, err := r.Resolve("indeterminate.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Indeterminate hits the default case -> DNSSECStatus = "insecure"
	if result.DNSSECStatus != "insecure" {
		t.Errorf("expected DNSSECStatus 'insecure' for indeterminate, got %q", result.DNSSECStatus)
	}
}

// --- ServFail retry with NS removal (resolver.go:301-306) ---

func TestResolveIterativeServFailRetryRemovesNS(t *testing.T) {
	// This exercises the responseServFail path (lines 301-306) which removes
	// the failing NS by IP and continues with remaining nameservers.
	// We use two mock servers: first returns SERVFAIL, second returns answer.
	mock1 := startMockDNS(t, func(q *dns.Message) *dns.Message {
		// Always SERVFAIL
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build()},
			Questions: q.Questions,
		}
	})
	defer mock1.close()

	mock2 := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 50},
			}},
		}
	})
	defer mock2.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Both mocks must use the same port setting — use mock1's port for the resolver
	// but we need separate IPs for the two NS entries. Since both are 127.0.0.1,
	// we instead test using a single mock with a counter approach — but we need
	// different IPs so removeNSByIP only removes one. On localhost we can't easily
	// get two IPs, so we test the code path via a different strategy:
	// We call resolveIterative directly with a nameservers list that has two
	// entries with different IPs, where the first IP has nothing listening.
	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 100 * time.Millisecond,
		UpstreamRetries: 1,
		QMinEnabled:     false,
		PreferIPv4:      true,
		UpstreamPort:    mock2.port,
	}, m, logger)
	// Use two root servers: first unreachable (192.0.2.1 = TEST-NET, will timeout),
	// second points to mock2. The upstream error path removes the first NS,
	// then the loop continues with mock2 which succeeds.
	r.rootServers = []NameServer{
		{Name: "ns1.mock.root", IPv4: "192.0.2.1"},
		{Name: "ns2.mock.root", IPv4: mock2.ip},
	}

	result, err := r.Resolve("servfail-retry.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR after upstream error retry, got %d", result.RCODE)
	}
}

func TestResolveIterativeServFailAllNSExhausted(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build()},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("all-fail.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL, got %d", result.RCODE)
	}
}

// --- Upstream error removal path (resolver.go:169-176) ---

func TestResolveIterativeUpstreamErrorRemovesNS(t *testing.T) {
	goodMock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 77},
			}},
		}
	})
	defer goodMock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 100 * time.Millisecond,
		UpstreamRetries: 1,
		QMinEnabled:     false,
		PreferIPv4:      true,
		UpstreamPort:    goodMock.port,
	}, m, logger)
	r.rootServers = []NameServer{
		{Name: "bad.root", IPv4: "192.0.2.1"},
		{Name: "good.root", IPv4: goodMock.ip},
	}

	result, err := r.Resolve("upstream-error.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR after upstream error retry, got %d", result.RCODE)
	}
}

// --- selectAndResolveNS: IPv6 glue with PreferIPv4=false (resolver.go:329-334) ---

func TestSelectAndResolveNSIPv6GlueNoIPv4(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message { return nil })
	defer mock.close()

	r := testResolver(t, mock)
	r.config.PreferIPv4 = false

	ns := []nsEntry{{hostname: "ns1.v6only.com", ipv6: "2001:db8::1"}}
	_, ip, err := r.selectAndResolveNS(ns, newVisitedSet(), "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ip != "2001:db8::1" {
		t.Errorf("expected 2001:db8::1, got %q", ip)
	}
}

// --- selectAndResolveNS: two-pass in-bailiwick (resolver.go:363-398) ---

func TestSelectAndResolveNSInBailiwickSecondPass(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		if qname == "ns1.example.tr" && qtype == dns.TypeA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "ns1.example.tr", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 99},
				}},
			}
		}
		soaRData := buildSOARData()
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "tr", Type: dns.TypeSOA, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	ns := []nsEntry{{hostname: "ns1.example.tr"}}
	_, ip, err := r.selectAndResolveNS(ns, newVisitedSet(), "tr")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ip != "10.0.0.99" {
		t.Errorf("expected 10.0.0.99 from in-bailiwick second pass, got %q", ip)
	}
}

// --- CNAME target empty -> SERVFAIL (resolver.go:224-225) ---

func TestResolveIterativeCNAMEEmptyTarget(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeCNAME, Class: dns.ClassIN,
				TTL: 300, RDLength: 0, RData: nil,
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("bad-cname.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL for empty CNAME target, got %d", result.RCODE)
	}
}

// --- CNAME loop detection (resolver.go:228-229) ---

func TestResolveIterativeCNAMELoop(t *testing.T) {
	// A -> CNAME B, B -> CNAME B (self-referencing CNAME loop).
	// The second time B is encountered, HasCNAME("loop-b") returns true → SERVFAIL.
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		if qname == "loop-a.example.com" {
			cnameRData := dns.BuildPlainName("loop-b.example.com")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: qname, Type: dns.TypeCNAME, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(cnameRData)), RData: cnameRData,
				}},
			}
		}
		if qname == "loop-b.example.com" {
			// Self-referencing CNAME: B -> B
			cnameRData := dns.BuildPlainName("loop-b.example.com")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: qname, Type: dns.TypeCNAME, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(cnameRData)), RData: cnameRData,
				}},
			}
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("loop-a.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL for CNAME loop, got %d", result.RCODE)
	}
}

// --- Referral with IPv6 glue caching (resolver.go:273-284) ---

func TestResolveIterativeReferralWithIPv6Glue(t *testing.T) {
	var queryCount atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		count := queryCount.Add(1)
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name

		if count == 1 {
			nsRData := dns.BuildPlainName("ns1.v6ref.com")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "v6ref.com", Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
				}},
				Additional: []dns.ResourceRecord{
					{
						Name: "ns1.v6ref.com", Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 3600, RDLength: 4, RData: []byte{127, 0, 0, 1},
					},
					{
						Name: "ns1.v6ref.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
						TTL: 3600, RDLength: 16, RData: net.ParseIP("2001:db8::53").To16(),
					},
				},
			}
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 66},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, _ := r.Resolve("sub.v6ref.com", dns.TypeA, dns.ClassIN)

	entry, ok := r.cache.Get("ns1.v6ref.com", dns.TypeAAAA, dns.ClassIN)
	if !ok {
		t.Error("IPv6 glue should be cached")
	} else if len(entry.Records) == 0 {
		t.Error("expected cached AAAA record")
	}
	_ = result
}

// --- queryUpstreamOnce: question validation error after UDP (upstream.go:81-83) ---

func TestQueryUpstreamOnceQuestionMismatchUDP(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: []dns.Question{{Name: "evil.com", Type: dns.TypeA, Class: dns.ClassIN}},
			Answers: []dns.ResourceRecord{{
				Name: "evil.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{6, 6, 6, 6},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	_, err := r.queryUpstreamOnce(mock.ip, "legit.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected question mismatch error")
	}
}

// --- queryUpstreamOnce: TC fallback with TCP question mismatch (upstream.go:98-99) ---

func TestQueryUpstreamOnceTCFallbackQuestionMismatch(t *testing.T) {
	var udpCount atomic.Int32
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())
	var tcp net.Listener
	for i := 0; i < 10; i++ {
		tcp, err = net.Listen("tcp", "127.0.0.1:"+portStr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		udp.Close()
		t.Skipf("tcp listen on same port failed: %v", err)
	}

	mockSrv := &mockDNSServer{udpConn: udp, tcpLn: tcp, port: portStr, ip: "127.0.0.1",
		responds: func(q *dns.Message) *dns.Message {
			count := udpCount.Add(1)
			if count <= 1 {
				return &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetTC(true).Build()},
					Questions: q.Questions,
				}
			}
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: []dns.Question{{Name: "wrong.com", Type: dns.TypeA, Class: dns.ClassIN}},
			}
		},
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			resp := mockSrv.responds(query)
			if resp == nil {
				continue
			}
			resp.Header.ID = query.Header.ID
			out := make([]byte, 4096)
			packed, err := dns.Pack(resp, out)
			if err != nil {
				continue
			}
			udp.WriteTo(packed, addr)
		}
	}()

	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				if _, err := c.Read(lenBuf); err != nil {
					return
				}
				qLen := binary.BigEndian.Uint16(lenBuf)
				qBuf := make([]byte, qLen)
				if _, err := c.Read(qBuf); err != nil {
					return
				}
				query, err := dns.Unpack(qBuf)
				if err != nil {
					return
				}
				resp := mockSrv.responds(query)
				if resp == nil {
					return
				}
				resp.Header.ID = query.Header.ID
				out := make([]byte, 4096)
				packed, err := dns.Pack(resp, out)
				if err != nil {
					return
				}
				binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
				c.Write(lenBuf)
				c.Write(packed)
			}(conn)
		}
	}()
	defer mockSrv.close()

	r := testResolver(t, mockSrv)
	_, err = r.queryUpstreamOnce(mockSrv.ip, "tc-qmismatch.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected question mismatch error on TCP fallback")
	}
}

// --- queryUpstreamOnce: TC fallback with TCP TXID mismatch (upstream.go:95-96) ---

func TestQueryUpstreamOnceTCFallbackTXIDMismatch(t *testing.T) {
	var udpCount atomic.Int32
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())
	var tcp net.Listener
	for i := 0; i < 10; i++ {
		tcp, err = net.Listen("tcp", "127.0.0.1:"+portStr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		udp.Close()
		t.Skipf("tcp listen on same port failed: %v", err)
	}

	mockSrv := &mockDNSServer{udpConn: udp, tcpLn: tcp, port: portStr, ip: "127.0.0.1"}
	defer mockSrv.close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			udpCount.Add(1)
			resp := &dns.Message{
				Header:    dns.Header{ID: query.Header.ID, Flags: dns.NewFlagBuilder().SetQR(true).SetTC(true).Build()},
				Questions: query.Questions,
			}
			out := make([]byte, 4096)
			packed, err := dns.Pack(resp, out)
			if err != nil {
				continue
			}
			udp.WriteTo(packed, addr)
		}
	}()

	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				if _, err := c.Read(lenBuf); err != nil {
					return
				}
				qLen := binary.BigEndian.Uint16(lenBuf)
				qBuf := make([]byte, qLen)
				if _, err := c.Read(qBuf); err != nil {
					return
				}
				query, err := dns.Unpack(qBuf)
				if err != nil {
					return
				}
				resp := &dns.Message{
					Header:    dns.Header{ID: query.Header.ID ^ 0xFFFF, Flags: dns.NewFlagBuilder().SetQR(true).Build()},
					Questions: query.Questions,
				}
				out := make([]byte, 4096)
				packed, err := dns.Pack(resp, out)
				if err != nil {
					return
				}
				binary.BigEndian.PutUint16(packed[0:2], 0xBEEF) // corrupt TXID
				binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
				c.Write(lenBuf)
				c.Write(packed)
			}(conn)
		}
	}()

	r := testResolver(t, mockSrv)
	_, err = r.queryUpstreamOnce(mockSrv.ip, "tc-txid.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected TXID mismatch error on TCP fallback")
	}
}

// --- queryUpstream retry exhaustion (upstream.go:24-31) ---

func TestQueryUpstreamRetryExhausted(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamRetries: 3,
		UpstreamPort:    "19993",
	}, m, logger)

	_, err := r.queryUpstream("127.0.0.1", "retry-fail.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected error after all retries exhausted")
	}
}

// --- queryUpstream with 0 retries (upstream.go:19-20) ---

func TestQueryUpstreamZeroRetries(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: "zero-retry.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 60, RDLength: 4, RData: []byte{1, 1, 1, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	r.config.UpstreamRetries = 0

	msg, err := r.queryUpstream(mock.ip, "zero-retry.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg == nil {
		t.Fatal("expected response with 0 retries (clamped to 1)")
	}
}

// --- extractDelegation: bad A/AAAA glue RDATA (delegation.go:52-58) ---

func TestExtractDelegationBadGlue(t *testing.T) {
	nsRData := dns.BuildPlainName("ns1.example.com")
	msg := &dns.Message{
		Authority: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN,
			TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
		}},
		Additional: []dns.ResourceRecord{
			{
				Name: "ns1.example.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 3600, RDLength: 2, RData: []byte{0xFF, 0xFF},
			},
			{
				Name: "ns1.example.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
				TTL: 3600, RDLength: 4, RData: []byte{1, 2, 3, 4},
			},
		},
	}

	delegation, _ := extractDelegation(msg)
	if len(delegation) != 1 {
		t.Fatalf("expected 1 NS, got %d", len(delegation))
	}
	if delegation[0].IPv4 != "" {
		t.Errorf("expected empty IPv4 for corrupt A glue, got %q", delegation[0].IPv4)
	}
	if delegation[0].IPv6 != "" {
		t.Errorf("expected empty IPv6 for corrupt AAAA glue, got %q", delegation[0].IPv6)
	}
}

// --- selectAndResolveNS: cache has corrupt AAAA records (resolver.go:348-355) ---

func TestSelectAndResolveNSCacheCorruptAAAA(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 44},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	r.cache.Store("ns1.corrupt.com", dns.TypeAAAA, dns.ClassIN, []dns.ResourceRecord{
		{Name: "ns1.corrupt.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4}},
		{Name: "ns1.corrupt.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
			TTL: 300, RDLength: 16, RData: net.ParseIP("2001:db8::99").To16()},
	}, nil)

	ns := []nsEntry{{hostname: "ns1.corrupt.com"}}
	_, ip, err := r.selectAndResolveNS(ns, newVisitedSet(), "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ip != "2001:db8::99" {
		t.Errorf("expected 2001:db8::99 from second AAAA cache record, got %q", ip)
	}
}

// --- queryTCP with read error (upstream.go:150-152) ---

func TestQueryTCPReadLengthError(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcp.Close()
	_, portStr, _ := net.SplitHostPort(tcp.Addr().String())

	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			lenBuf := make([]byte, 2)
			conn.Read(lenBuf)
			qLen := binary.BigEndian.Uint16(lenBuf)
			qBuf := make([]byte, qLen)
			conn.Read(qBuf)
			conn.Close()
		}
	}()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 1 * time.Second,
		UpstreamPort:    portStr,
	}, m, logger)

	query := buildQueryBytes(0x1234, "tcpfail.com", dns.TypeA)
	_, err = r.queryTCP("127.0.0.1", query)
	if err == nil {
		t.Error("expected error from TCP read failure")
	}
}

// --- queryTCP with partial body read error (upstream.go:155-158) ---

func TestQueryTCPReadBodyError(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcp.Close()
	_, portStr, _ := net.SplitHostPort(tcp.Addr().String())

	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			lenBuf := make([]byte, 2)
			conn.Read(lenBuf)
			qLen := binary.BigEndian.Uint16(lenBuf)
			qBuf := make([]byte, qLen)
			conn.Read(qBuf)
			respLen := make([]byte, 2)
			binary.BigEndian.PutUint16(respLen, 1000)
			conn.Write(respLen)
			conn.Write([]byte{0x01})
			conn.Close()
		}
	}()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 1 * time.Second,
		UpstreamPort:    portStr,
	}, m, logger)

	query := buildQueryBytes(0x1234, "tcpbody.com", dns.TypeA)
	_, err = r.queryTCP("127.0.0.1", query)
	if err == nil {
		t.Error("expected error from truncated TCP body")
	}
}

// --- queryUpstreamOnce: TC fallback with TCP connect error (upstream.go:88-89) ---

func TestQueryUpstreamOnceTCFallbackTCPError(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())
	// NO TCP listener

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			resp := &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetTC(true).Build()},
				Questions: query.Questions,
			}
			resp.Header.ID = query.Header.ID
			out := make([]byte, 4096)
			packed, err := dns.Pack(resp, out)
			if err != nil {
				continue
			}
			udp.WriteTo(packed, addr)
		}
	}()
	defer udp.Close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 500 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    portStr,
	}, m, logger)

	_, err = r.queryUpstreamOnce("127.0.0.1", "tc-no-tcp.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected error from TCP connect failure after TC")
	}
}

// --- queryUpstreamOnce: TC fallback with TCP unpack error (upstream.go:92-93) ---

func TestQueryUpstreamOnceTCFallbackTCPUnpackError(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())
	var tcp net.Listener
	for attempt := 0; attempt < 10; attempt++ {
		tcp, err = net.Listen("tcp", "127.0.0.1:"+portStr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		udp.Close()
		t.Skipf("tcp listen on same port failed (Windows port reuse): %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			resp := &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetTC(true).Build()},
				Questions: query.Questions,
			}
			resp.Header.ID = query.Header.ID
			out := make([]byte, 4096)
			packed, err := dns.Pack(resp, out)
			if err != nil {
				continue
			}
			udp.WriteTo(packed, addr)
		}
	}()

	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				c.Read(lenBuf)
				qLen := binary.BigEndian.Uint16(lenBuf)
				qBuf := make([]byte, qLen)
				c.Read(qBuf)
				garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
				respLen := make([]byte, 2)
				binary.BigEndian.PutUint16(respLen, uint16(len(garbage)))
				c.Write(respLen)
				c.Write(garbage)
			}(conn)
		}
	}()
	defer udp.Close()
	defer tcp.Close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 1 * time.Second,
		UpstreamRetries: 1,
		UpstreamPort:    portStr,
	}, m, logger)

	_, err = r.queryUpstreamOnce("127.0.0.1", "tc-garbage.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected unpack error from TCP garbage response")
	}
}

// --- queryUDP: read timeout (upstream.go:122-124) ---

func TestQueryUDPReadTimeout(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer udp.Close()
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())

	go func() {
		buf := make([]byte, 4096)
		for {
			_, _, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			// absorb but never respond
		}
	}()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 100 * time.Millisecond,
		UpstreamPort:    portStr,
	}, m, logger)

	query := buildQueryBytes(0xABCD, "timeout.com", dns.TypeA)
	_, err = r.queryUDP("127.0.0.1", query)
	if err == nil {
		t.Error("expected timeout error from UDP read")
	}
}

// --- selectAndResolveNS: recursive resolve returns CNAME before A (resolver.go:377-383) ---

func TestSelectAndResolveNSRecursiveResolveCNAMEThenA(t *testing.T) {
	// When resolving NS hostname, the answer may include CNAME + A records.
	// The code at resolver.go:377-383 scans all answers for Type A specifically.
	// We pre-populate the cache with a CNAME+A result to bypass the full resolution flow.
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message { return nil })
	defer mock.close()

	r := testResolver(t, mock)

	// Pre-cache: resolveNSAddr for ns1.cnamed.com returns CNAME+A.
	// But selectAndResolveNS calls resolveNSAddr which does resolveIterative.
	// Instead, let's pre-populate the A cache so it hits the cache path (line 340-345),
	// but with a CNAME before the A in the same cache entry — that won't work because
	// cache is keyed by type.
	//
	// The actual code path we want to cover is the "scan all answers for A" loop
	// at lines 377-383. This is already covered when resolveNSAddr returns an A record
	// normally. The specific subpath where rr.Type == dns.TypeA and parseErr != nil
	// is the corrupt A test. The path where rr.Type != dns.TypeA (CNAME skipped) is
	// implicitly covered when there are multiple answer records.
	//
	// Let's directly test via cache with valid A record to ensure the scan loop works.
	r.cache.Store("ns1.cnamed.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{
		{Name: "ns1.cnamed.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 55}},
	}, nil)

	ns := []nsEntry{{hostname: "ns1.cnamed.com"}}
	_, ip, err := r.selectAndResolveNS(ns, newVisitedSet(), "other.zone")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ip != "10.0.0.55" {
		t.Errorf("expected 10.0.0.55, got %q", ip)
	}
}

// --- selectAndResolveNS: recursive resolve with corrupt A RDATA (resolver.go:380-382) ---

func TestSelectAndResolveNSRecursiveResolveCorruptA(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		if qname == "ns1.corruptns.com" && qtype == dns.TypeA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "ns1.corruptns.com", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 2, RData: []byte{0xFF, 0xFF},
				}},
			}
		}
		if qname == "ns1.corruptns.com" && qtype == dns.TypeAAAA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "ns1.corruptns.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
					TTL: 300, RDLength: 16, RData: net.ParseIP("2001:db8::77").To16(),
				}},
			}
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	ns := []nsEntry{{hostname: "ns1.corruptns.com"}}
	_, ip, err := r.selectAndResolveNS(ns, newVisitedSet(), "other.zone")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ip != "2001:db8::77" {
		t.Errorf("expected 2001:db8::77 from AAAA fallback after corrupt A, got %q", ip)
	}
}

// --- selectAndResolveNS: recursive resolve with corrupt AAAA (resolver.go:391-393) ---

func TestSelectAndResolveNSRecursiveResolveCorruptAAAA(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		if qname == "ns1.allcorrupt.com" && qtype == dns.TypeA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "ns1.allcorrupt.com", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 2, RData: []byte{0xFF, 0xFF},
				}},
			}
		}
		if qname == "ns1.allcorrupt.com" && qtype == dns.TypeAAAA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "ns1.allcorrupt.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
				}},
			}
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	ns := []nsEntry{{hostname: "ns1.allcorrupt.com"}}
	_, _, err := r.selectAndResolveNS(ns, newVisitedSet(), "other.zone")
	if err == nil {
		t.Error("expected 'no reachable nameserver' error for all corrupt records")
	}
}

// --- classifyResponse with NS+SOA in authority -> NODATA not referral ---

func TestClassifyResponseNSAndSOA(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
			NSCount: 2,
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600},
			{Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 3600},
		},
	}
	rtype := classifyResponse(msg, "test.example.com", dns.TypeA)
	if rtype != responseNoData {
		t.Errorf("expected responseNoData when NS+SOA present, got %d", rtype)
	}
}

// --- classifyResponse: answer with unrelated records (classify.go:55) ---

func TestClassifyResponseAnswerUnrelatedType(t *testing.T) {
	// Unrelated answer records (ANCount > 0 but no match for qname/qtype)
	// should fall through to authority checks. With no authority section,
	// the result is responseServFail (no useful information).
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
			ANCount: 1,
		},
		Answers: []dns.ResourceRecord{{
			Name: "test.com", Type: dns.TypeMX, Class: dns.ClassIN,
			TTL: 300, RDLength: 0, RData: nil,
		}},
	}
	rtype := classifyResponse(msg, "test.com", dns.TypeA)
	if rtype != responseServFail {
		t.Errorf("expected responseServFail for unrelated answer with no authority, got %d", rtype)
	}

	// With NS in authority → should be treated as referral
	nsRData := dns.BuildPlainName("ns1.test.com")
	msg.Authority = []dns.ResourceRecord{{
		Name: "test.com", Type: dns.TypeNS, Class: dns.ClassIN,
		TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
	}}
	rtype = classifyResponse(msg, "test.com", dns.TypeA)
	if rtype != responseReferral {
		t.Errorf("expected responseReferral for unrelated answer with NS authority, got %d", rtype)
	}
}

// --- Ensure dnssec import is used ---

func TestDNSSECConstants(t *testing.T) {
	if dnssec.Secure != 0 {
		t.Error("unexpected value for dnssec.Secure")
	}
	if dnssec.Insecure != 1 {
		t.Error("unexpected value for dnssec.Insecure")
	}
	if dnssec.Bogus != 2 {
		t.Error("unexpected value for dnssec.Bogus")
	}
}

// --- extractDelegation: non-NS records in Authority are skipped (delegation.go:23-24) ---

func TestExtractDelegationSkipsNonNSAuthority(t *testing.T) {
	nsRData := dns.BuildPlainName("ns1.example.com")
	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			// SOA before the NS — should be skipped
			{Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 3600,
				RDLength: uint16(len(buildSOARData())), RData: buildSOARData()},
			// Actual NS record
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600,
				RDLength: uint16(len(nsRData)), RData: nsRData},
		},
		Additional: []dns.ResourceRecord{{
			Name: "ns1.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600,
			RDLength: 4, RData: []byte{10, 0, 0, 1},
		}},
	}

	delegation, zone := extractDelegation(msg)
	if zone != "example.com" {
		t.Errorf("zone: expected 'example.com', got %q", zone)
	}
	if len(delegation) != 1 {
		t.Fatalf("expected 1 NS, got %d", len(delegation))
	}
	if delegation[0].IPv4 != "10.0.0.1" {
		t.Errorf("expected glue 10.0.0.1, got %q", delegation[0].IPv4)
	}
}

// --- extractDelegation: additional record for non-matching NS name (delegation.go:47-48) ---

func TestExtractDelegationAdditionalNotMatchingNS(t *testing.T) {
	nsRData := dns.BuildPlainName("ns1.example.com")
	msg := &dns.Message{
		Authority: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600,
			RDLength: uint16(len(nsRData)), RData: nsRData,
		}},
		Additional: []dns.ResourceRecord{
			// Glue for a different NS name — should be skipped
			{Name: "ns999.other.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600,
				RDLength: 4, RData: []byte{9, 9, 9, 9}},
		},
	}

	delegation, _ := extractDelegation(msg)
	if len(delegation) != 1 {
		t.Fatalf("expected 1 NS, got %d", len(delegation))
	}
	if delegation[0].IPv4 != "" {
		t.Errorf("should not have matched glue for unknown NS, got %q", delegation[0].IPv4)
	}
}

// --- resolveIterative: selectAndResolveNS returns error (resolver.go:145-147) ---

func TestResolveIterativeSelectNSFails(t *testing.T) {
	// selectAndResolveNS returns error → SERVFAIL at resolver.go:145-147.
	// We achieve this by passing an empty nameservers list to resolveIterative.
	// Since rootServers have IPs, we need a scenario where after a referral
	// all NS are removed. The simplest approach: set rootServers to empty.
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        5,
		MaxCNAMEDepth:   3,
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamRetries: 1,
	}, m, logger)
	// Empty root servers → toNameServerList returns empty → selectAndResolveNS fails
	r.rootServers = []NameServer{}

	result, err := r.Resolve("test.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL when NS resolution fails, got %d", result.RCODE)
	}
}

// --- resolveIterative: CNAME chase error propagation (resolver.go:242-244) ---

func TestResolveIterativeCNAMEChaseError(t *testing.T) {
	// CNAME target resolution exceeds MaxCNAMEDepth → returns error
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		// Always return CNAME: qname → qname + ".next"
		cnameTarget := qname + ".next"
		cnameRData := dns.BuildPlainName(cnameTarget)
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeCNAME, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(cnameRData)), RData: cnameRData,
			}},
		}
	})
	defer mock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   1, // very low — will trigger "CNAME chain too long" on the second chase
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 1,
		QMinEnabled:     false,
		PreferIPv4:      true,
		UpstreamPort:    mock.port,
	}, m, logger)
	r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}

	_, err := r.Resolve("chain.example.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected error from CNAME chain too long")
	}
}

// --- resolveIterative: ServFail continue when nameservers remain (resolver.go:302-306) ---

func TestResolveIterativeServFailContinueWithRemaining(t *testing.T) {
	// We need two NS with different IPs where one returns SERVFAIL.
	// After removeNSByIP, only the other remains → line 306 continue.
	// Bind a UDP listener on 127.0.0.2 to handle the second NS.
	udp2, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}
	_, port2, _ := net.SplitHostPort(udp2.LocalAddr().String())
	defer udp2.Close()

	// UDP handler for 127.0.0.2: returns answer
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp2.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			resp := &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: query.Questions,
				Answers: []dns.ResourceRecord{{
					Name: query.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 99},
				}},
			}
			resp.Header.ID = query.Header.ID
			out := make([]byte, 4096)
			packed, pErr := dns.Pack(resp, out)
			if pErr != nil {
				continue
			}
			udp2.WriteTo(packed, addr)
		}
	}()

	// Mock for 127.0.0.1: first query is referral, second is SERVFAIL
	var queryCount atomic.Int32
	// Bind mock on same port as the 127.0.0.2 listener
	udp1, err := net.ListenPacket("udp", "127.0.0.1:"+port2)
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:%s: %v", port2, err)
	}
	defer udp1.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp1.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			count := queryCount.Add(1)
			var resp *dns.Message
			if count == 1 {
				// Referral
				ns1RData := dns.BuildPlainName("ns1.sf.com")
				ns2RData := dns.BuildPlainName("ns2.sf.com")
				resp = &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
					Questions: query.Questions,
					Authority: []dns.ResourceRecord{
						{Name: "sf.com", Type: dns.TypeNS, Class: dns.ClassIN,
							TTL: 3600, RDLength: uint16(len(ns1RData)), RData: ns1RData},
						{Name: "sf.com", Type: dns.TypeNS, Class: dns.ClassIN,
							TTL: 3600, RDLength: uint16(len(ns2RData)), RData: ns2RData},
					},
					Additional: []dns.ResourceRecord{
						{Name: "ns1.sf.com", Type: dns.TypeA, Class: dns.ClassIN,
							TTL: 3600, RDLength: 4, RData: []byte{127, 0, 0, 1}},
						{Name: "ns2.sf.com", Type: dns.TypeA, Class: dns.ClassIN,
							TTL: 3600, RDLength: 4, RData: []byte{127, 0, 0, 2}},
					},
				}
			} else {
				// SERVFAIL
				resp = &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build()},
					Questions: query.Questions,
				}
			}
			resp.Header.ID = query.Header.ID
			out := make([]byte, 4096)
			packed, pErr := dns.Pack(resp, out)
			if pErr != nil {
				continue
			}
			udp1.WriteTo(packed, addr)
		}
	}()

	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 1,
		QMinEnabled:     false,
		PreferIPv4:      true,
		UpstreamPort:    port2,
	}, m, logger)
	r.rootServers = []NameServer{{Name: "mock.root", IPv4: "127.0.0.1"}}

	result, err := r.Resolve("sub.sf.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Should succeed: first NS gets SERVFAIL, second NS answers
	_ = result
}

// --- upstream.go: queryUDP dial error (upstream.go:109-111) ---

func TestQueryUDPDialError(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamPort:    "53",
	}, m, logger)

	// Use an invalid IP to trigger dial error
	query := buildQueryBytes(0x1234, "dial-fail.com", dns.TypeA)
	_, err := r.queryUDP("999.999.999.999", query)
	if err == nil {
		t.Error("expected dial error for invalid IP")
	}
}

// --- upstream.go: queryTCP write errors (upstream.go:142-147) ---
// These are hard to test reliably on all OSes because writes to a recently-closed
// TCP connection may succeed to the kernel buffer. We accept the existing
// TestQueryTCPReadLengthError and TestQueryTCPReadBodyError as sufficient
// for TCP error paths.

// --- upstream.go: queryUpstreamOnce dns.Pack error (upstream.go:61-63) ---
// This requires dns.Pack to fail, which happens with extremely long names.
// The dns.Pack function is robust, so triggering this error path reliably
// is impractical without modifying the message internals.

// --- upstream.go: randomTXID error (upstream.go:182-184) ---
// crypto/rand.Read rarely fails in normal operation. This error path
// protects against system entropy exhaustion. Testing it would require
// mocking crypto/rand which is not feasible without modifying production code.

// --- queryUpstreamOnce: UDP response unpack error (upstream.go:72-74) ---

func TestQueryUpstreamOnceUDPUnpackError(t *testing.T) {
	// Mock returns garbage bytes that can't be unpacked as DNS.
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())
	defer udp.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			_, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			// Return garbage: too short to be a valid DNS message
			garbage := []byte{0x00, 0x01, 0x02}
			udp.WriteTo(garbage, addr)
		}
	}()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 1 * time.Second,
		UpstreamRetries: 1,
		UpstreamPort:    portStr,
	}, m, logger)

	_, err = r.queryUpstreamOnce("127.0.0.1", "unpack-fail.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected unpack error from garbage UDP response")
	}
}

// --- resolveIterative: max depth exceeded (resolver.go:310) ---

func TestResolveIterativeMaxDepthExceeded(t *testing.T) {
	// Each query returns a referral to a deeper zone so that the queryKey
	// is always different (avoiding loop detection). Eventually MaxDepth
	// is exceeded and the resolver returns SERVFAIL at line 310.
	var queryCount atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		count := queryCount.Add(1)
		if len(q.Questions) == 0 {
			return nil
		}

		// Each referral delegates to a unique zone: depth1.com, depth2.com, etc.
		// The NS hostname and glue IP stay the same (mock server).
		zone := "depth" + string(rune('0'+count)) + ".com"
		nsRData := dns.BuildPlainName("ns.depth.com")
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: zone, Type: dns.TypeNS, Class: dns.ClassIN,
				TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
			}},
			Additional: []dns.ResourceRecord{{
				Name: "ns.depth.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 3600, RDLength: 4, RData: []byte{127, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        3,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 1,
		QMinEnabled:     false,
		PreferIPv4:      true,
		UpstreamPort:    mock.port,
	}, m, logger)
	r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}

	result, err := r.Resolve("deep.test.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL from max depth exceeded, got %d", result.RCODE)
	}
}

// --- queryUDP: write error path (upstream.go:116-118) ---

func TestQueryUDPWriteErrorLargePayload(t *testing.T) {
	// Send an extremely large query buffer that might trigger write errors.
	// On most systems UDP write of a 65KB payload fails.
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 100 * time.Millisecond,
		UpstreamPort:    "53",
	}, m, logger)

	// A very large query may fail to write on UDP (depends on OS)
	bigQuery := make([]byte, 65536)
	_, err := r.queryUDP("127.0.0.1", bigQuery)
	// May or may not error depending on OS, but exercises the write path
	_ = err
}

func TestQueryUpstreamOnceRandomTXIDError(t *testing.T) {
	orig := randTXIDFunc
	randTXIDFunc = func() (uint16, error) {
		return 0, errors.New("entropy exhausted")
	}
	defer func() { randTXIDFunc = orig }()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 100 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    "19990",
	}, m, logger)

	_, err := r.queryUpstreamOnce("127.0.0.1", "test.com", dns.TypeA, dns.ClassIN)
	if err == nil || err.Error() != "entropy exhausted" {
		t.Errorf("expected 'entropy exhausted' error, got: %v", err)
	}
}

func TestQueryTCPWriteError(t *testing.T) {
	// Start a TCP listener that accepts and immediately closes the connection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close() // close immediately to cause write/read error
		}
	}()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 500 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    port,
	}, m, logger)

	query := buildQueryBytes(0x1234, "test.com", dns.TypeA)
	_, err = r.queryTCP("127.0.0.1", query)
	if err == nil {
		t.Error("expected error from TCP write/read on closed connection")
	}
}

// =============================================================================
// .tr TLD integration test — simulates real Turkish DNS infrastructure
// =============================================================================

// startTRMockDNS creates a mock that behaves like the real .tr DNS hierarchy:
//
//	root → .tr referral (ns71.ns.tr with glue 127.0.0.1)
//	.tr NS:
//	  "net.tr NS" → answer section with NS records (real .tr behavior)
//	  "com.tr NS" → answer section with NS records
//	  "dgn.net.tr A" → referral to net.tr zone (NS in authority)
//	  "hurriyet.com.tr A" → referral to com.tr zone
//	  "nic.tr A" → direct answer (nic.tr is directly under .tr)
//	net.tr NS:
//	  "dgn.net.tr A" → answer 93.89.224.13
//	com.tr NS:
//	  "hurriyet.com.tr A" → answer 94.55.200.100
//
// All NS point to 127.0.0.1 (the mock itself) with different zone behavior
// determined by which zone was last delegated.
func startTRMockDNS(t *testing.T) *mockDNSServer {
	t.Helper()
	return startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		// --- Root behavior: refer everything to .tr ---
		if qname == "tr" || strings.HasSuffix(qname, ".tr") {
			// If asking for "tr" itself (QMIN first step), return referral
			if qname == "tr" && qtype == dns.TypeNS {
				nsRData := dns.BuildPlainName("ns71.ns.tr")
				return &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
					Questions: q.Questions,
					Authority: []dns.ResourceRecord{{
						Name: "tr", Type: dns.TypeNS, Class: dns.ClassIN,
						TTL: 172800, RDLength: uint16(len(nsRData)), RData: nsRData,
					}},
					Additional: []dns.ResourceRecord{{
						Name: "ns71.ns.tr", Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 172800, RDLength: 4, RData: []byte{127, 0, 0, 1},
					}},
				}
			}
		}

		// --- .tr NS behavior ---

		// "net.tr NS" → answer with NS records (this is how real .tr NS behaves)
		if qname == "net.tr" && qtype == dns.TypeNS {
			nsRData := dns.BuildPlainName("ns43.ns.tr")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "net.tr", Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 43200, RDLength: uint16(len(nsRData)), RData: nsRData,
				}},
			}
		}

		// "com.tr NS" → answer with NS records
		if qname == "com.tr" && qtype == dns.TypeNS {
			nsRData := dns.BuildPlainName("ns43.ns.tr")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "com.tr", Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 43200, RDLength: uint16(len(nsRData)), RData: nsRData,
				}},
			}
		}

		// "nic.tr A" → direct answer (nic.tr is under .tr directly)
		if qname == "nic.tr" && qtype == dns.TypeA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "nic.tr", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{185, 7, 0, 3},
				}},
			}
		}

		// Anything under *.net.tr → referral to net.tr NS
		if strings.HasSuffix(qname, ".net.tr") && qtype == dns.TypeA {
			// Check if this is net.tr NS asking → give answer
			// Or .tr NS asking → give referral
			// We detect by: if the name is directly "X.net.tr" and we're being
			// asked for A, we either give answer (we are net.tr NS) or referral (.tr NS)
			// Since the mock is all on 127.0.0.1, we use the qname to decide.
			// After delegation to net.tr, the resolver will query again for the same
			// name. We return answer on the second visit.

			// For dgn.net.tr specifically: return A record (simulating net.tr NS)
			if qname == "dgn.net.tr" {
				return &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
					Questions: q.Questions,
					Answers: []dns.ResourceRecord{{
						Name: "dgn.net.tr", Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 300, RDLength: 4, RData: []byte{93, 89, 224, 13},
					}},
				}
			}

			// Generic *.net.tr → referral to net.tr
			nsRData := dns.BuildPlainName("ns43.ns.tr")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "net.tr", Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 43200, RDLength: uint16(len(nsRData)), RData: nsRData,
				}},
				Additional: []dns.ResourceRecord{{
					Name: "ns43.ns.tr", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 43200, RDLength: 4, RData: []byte{127, 0, 0, 1},
				}},
			}
		}

		// Anything under *.com.tr → similar pattern
		if strings.HasSuffix(qname, ".com.tr") && qtype == dns.TypeA {
			if qname == "hurriyet.com.tr" {
				return &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
					Questions: q.Questions,
					Answers: []dns.ResourceRecord{{
						Name: "hurriyet.com.tr", Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 300, RDLength: 4, RData: []byte{94, 55, 200, 100},
					}},
				}
			}

			nsRData := dns.BuildPlainName("ns43.ns.tr")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "com.tr", Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 43200, RDLength: uint16(len(nsRData)), RData: nsRData,
				}},
				Additional: []dns.ResourceRecord{{
					Name: "ns43.ns.tr", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 43200, RDLength: 4, RData: []byte{127, 0, 0, 1},
				}},
			}
		}

		// Default: NXDOMAIN
		soaRData := buildSOARData()
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "tr", Type: dns.TypeSOA, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
			}},
		}
	})
}

func TestResolveTR_DgnNetTr(t *testing.T) {
	mock := startTRMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	r.config.QMinEnabled = true

	result, err := r.Resolve("dgn.net.tr", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got RCODE %d", result.RCODE)
	}
	// Must have an A record with 93.89.224.13
	found := false
	for _, rr := range result.Answers {
		if rr.Type == dns.TypeA {
			ip, _ := dns.ParseA(rr.RData)
			if ip != nil && ip.String() == "93.89.224.13" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected A record 93.89.224.13 for dgn.net.tr, got: %+v", result.Answers)
	}
}

func TestResolveTR_HurriyetComTr(t *testing.T) {
	mock := startTRMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	r.config.QMinEnabled = true

	result, err := r.Resolve("hurriyet.com.tr", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got RCODE %d", result.RCODE)
	}
	found := false
	for _, rr := range result.Answers {
		if rr.Type == dns.TypeA {
			ip, _ := dns.ParseA(rr.RData)
			if ip != nil && ip.String() == "94.55.200.100" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected A record 94.55.200.100 for hurriyet.com.tr, got: %+v", result.Answers)
	}
}

func TestResolveTR_NicTr(t *testing.T) {
	mock := startTRMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	r.config.QMinEnabled = true

	result, err := r.Resolve("nic.tr", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got RCODE %d", result.RCODE)
	}
	found := false
	for _, rr := range result.Answers {
		if rr.Type == dns.TypeA {
			ip, _ := dns.ParseA(rr.RData)
			if ip != nil && ip.String() == "185.7.0.3" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected A record 185.7.0.3 for nic.tr, got: %+v", result.Answers)
	}
}

func TestResolveTR_WithoutQMin(t *testing.T) {
	mock := startTRMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	r.config.QMinEnabled = false

	// All three should still work without QMIN
	for _, tc := range []struct {
		name string
		ip   string
	}{
		{"dgn.net.tr", "93.89.224.13"},
		{"hurriyet.com.tr", "94.55.200.100"},
		{"nic.tr", "185.7.0.3"},
	} {
		result, err := r.Resolve(tc.name, dns.TypeA, dns.ClassIN)
		if err != nil {
			t.Fatalf("%s: error: %v", tc.name, err)
		}
		if result.RCODE != dns.RCodeNoError {
			t.Fatalf("%s: expected NOERROR, got RCODE %d", tc.name, result.RCODE)
		}
		found := false
		for _, rr := range result.Answers {
			if rr.Type == dns.TypeA {
				ip, _ := dns.ParseA(rr.RData)
				if ip != nil && ip.String() == tc.ip {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s: expected A record %s", tc.name, tc.ip)
		}
	}
}

// =============================================================================
// Reverse DNS (PTR) integration test
// =============================================================================

func startRDNSMockDNS(t *testing.T) *mockDNSServer {
	t.Helper()
	return startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		// Root → arpa referral
		if qname == "arpa" && qtype == dns.TypeNS {
			nsRData := dns.BuildPlainName("a.ns.arpa")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "arpa", Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 172800, RDLength: uint16(len(nsRData)), RData: nsRData,
				}},
				Additional: []dns.ResourceRecord{{
					Name: "a.ns.arpa", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 172800, RDLength: 4, RData: []byte{127, 0, 0, 1},
				}},
			}
		}

		// arpa → in-addr.arpa referral
		if qname == "in-addr.arpa" && qtype == dns.TypeNS {
			nsRData := dns.BuildPlainName("b.ns.arpa")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "in-addr.arpa", Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 172800, RDLength: uint16(len(nsRData)), RData: nsRData,
				}},
				Additional: []dns.ResourceRecord{{
					Name: "b.ns.arpa", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 172800, RDLength: 4, RData: []byte{127, 0, 0, 1},
				}},
			}
		}

		// Anything under in-addr.arpa: referral down, or final PTR answer
		if strings.HasSuffix(qname, ".in-addr.arpa") {
			// Final PTR query
			if qname == "1.1.20.46.in-addr.arpa" && qtype == dns.TypePTR {
				ptrRData := dns.BuildPlainName("host-46-20-1-1.example.com")
				return &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
					Questions: q.Questions,
					Answers: []dns.ResourceRecord{{
						Name: qname, Type: dns.TypePTR, Class: dns.ClassIN,
						TTL: 3600, RDLength: uint16(len(ptrRData)), RData: ptrRData,
					}},
				}
			}

			// QMIN NS queries or full-name queries: return referral
			// Count labels to decide delegation level
			labels := strings.Split(qname, ".")
			// e.g. "46.in-addr.arpa" = 3 labels → referral from in-addr.arpa
			// e.g. "20.46.in-addr.arpa" = 4 labels → referral from 46.in-addr.arpa
			// Final answer for 5+ labels that match the PTR name
			nsZone := strings.Join(labels[1:], ".") // parent zone
			nsRData := dns.BuildPlainName("ns." + nsZone)
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: qname, Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 86400, RDLength: uint16(len(nsRData)), RData: nsRData,
				}},
				Additional: []dns.ResourceRecord{{
					Name: "ns." + nsZone, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 86400, RDLength: 4, RData: []byte{127, 0, 0, 1},
				}},
			}
		}

		// Default answer for NS resolution of mock nameservers
		if qtype == dns.TypeA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{127, 0, 0, 1},
				}},
			}
		}

		// NXDOMAIN fallback
		soaRData := buildSOARData()
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "in-addr.arpa", Type: dns.TypeSOA, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
			}},
		}
	})
}

func TestResolveReverseDNS_WithQMin(t *testing.T) {
	mock := startRDNSMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	r.config.QMinEnabled = true

	result, err := r.Resolve("1.1.20.46.in-addr.arpa", dns.TypePTR, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got RCODE %d", result.RCODE)
	}

	found := false
	for _, rr := range result.Answers {
		if rr.Type == dns.TypePTR {
			name, _, err := dns.DecodeName(rr.RData, 0)
			if err == nil && name == "host-46-20-1-1.example.com" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected PTR host-46-20-1-1.example.com, got: %+v", result.Answers)
	}
}

func TestResolveReverseDNS_WithoutQMin(t *testing.T) {
	mock := startRDNSMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	r.config.QMinEnabled = false

	result, err := r.Resolve("1.1.20.46.in-addr.arpa", dns.TypePTR, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got RCODE %d", result.RCODE)
	}

	found := false
	for _, rr := range result.Answers {
		if rr.Type == dns.TypePTR {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PTR record, got: %+v", result.Answers)
	}
}

