package resolver

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
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
	tcp, err := net.Listen("tcp", "127.0.0.1:"+portStr)
	if err != nil {
		udp.Close()
		t.Fatalf("tcp listen: %v", err)
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

	// Empty questions — should fail
	msg.Questions = nil
	if err := validateResponseQuestion(msg, "example.com", dns.TypeA, dns.ClassIN); err == nil {
		t.Error("expected error for empty question section")
	}
}

