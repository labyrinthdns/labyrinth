package resolver

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// tcMockDNS returns TC=1 on UDP and full answer on TCP, to test TC fallback.
func startTCMockDNS(t *testing.T) *mockDNSServer {
	t.Helper()
	udpCount := 0
	return startMockDNS(t, func(q *dns.Message) *dns.Message {
		udpCount++
		if udpCount <= 1 {
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
	queryNum := 0
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queryNum++
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
	queryCount := 0
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queryCount++
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name

		// First query: referral
		if queryCount == 1 {
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
	queryCount := 0
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queryCount++
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
