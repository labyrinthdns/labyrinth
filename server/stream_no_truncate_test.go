package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/security"
)

// TestStreamTransport_NoTruncation pins the fix for the TCP/DoT/DoH truncation
// bug. A response larger than 512 bytes must be truncated (TC=1) for a UDP
// datagram client, but delivered intact over a stream transport (RFC 7766 §5).
// Before the fix, MainHandler.Handle truncated unconditionally, so the forced
// "retry over TCP" returned a header-only TC=1 answer that the client could
// never resolve.
func TestStreamTransport_NoTruncation(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	name := "big.example.com."
	queryMsg := &dns.Message{
		Header:    dns.Header{ID: 0xABCD, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
		Questions: []dns.Question{{Name: name, Type: dns.TypeA, Class: dns.ClassIN}},
		// No EDNS0 → UDP cap is 512.
	}

	// Enough A records to push the packed response well past 512 bytes.
	var answers []dns.ResourceRecord
	for i := 0; i < 60; i++ {
		answers = append(answers, dns.ResourceRecord{
			Name: name, Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{10, 0, byte(i >> 8), byte(i)},
		})
	}
	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}

	tc := func(resp []byte) bool { return binary.BigEndian.Uint16(resp[2:4])>>9&1 == 1 }
	anCount := func(resp []byte) uint16 { return binary.BigEndian.Uint16(resp[6:8]) }

	// UDP path (default / nil-addr semantics): MUST truncate.
	udpResp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("buildResponse udp: %v", err)
	}
	if !tc(udpResp) {
		t.Error("UDP response: expected TC=1 (truncated) for >512-byte answer")
	}
	if anCount(udpResp) != 0 {
		t.Errorf("UDP truncated response: expected ANCOUNT=0, got %d", anCount(udpResp))
	}

	// Stream path (TCP/DoT/DoH): MUST NOT truncate.
	streamResp, err := handler.buildResponse(queryMsg, result, true)
	if err != nil {
		t.Fatalf("buildResponse stream: %v", err)
	}
	if tc(streamResp) {
		t.Error("stream response: TC bit must not be set on TCP/DoT/DoH (RFC 7766 §5)")
	}
	if int(anCount(streamResp)) != len(answers) {
		t.Errorf("stream response: expected all %d answers, got ANCOUNT=%d", len(answers), anCount(streamResp))
	}
	if len(streamResp) <= 512 {
		t.Errorf("stream response unexpectedly small (%d bytes) — test no longer exercises >512 path", len(streamResp))
	}
}

// TestRRLSlip_StreamDeliversRealAnswer pins that RRL slip (TC=1, "retry over
// TCP") is suppressed on stream transports: a TCP/DoT/DoH client is already on
// TCP and cannot retry, so it must get the real answer, never a TC=1 stub. The
// same load over UDP must still slip, proving RRL actually engaged.
func TestRRLSlip_StreamDeliversRealAnswer(t *testing.T) {
	mk := func() *MainHandler {
		m := metrics.NewMetrics()
		c := cache.NewCache(1000, 5, 86400, 3600, m)
		res := newFailFastResolver(c, m)
		rrl := security.NewRRL(1, 1, 24, 56) // 1 rps, slipRatio 1 → slip every limited response
		return NewMainHandler(res, c, nil, rrl, nil, m, discardLogger())
	}
	query := buildTestQuery("rrl-stream.example.com", dns.TypeA)
	isTC := func(resp []byte) bool {
		return len(resp) >= 4 && binary.BigEndian.Uint16(resp[2:4])>>9&1 == 1
	}

	// UDP control: the same flood must produce at least one TC=1 slip.
	udp := mk()
	udpAddr := &mockAddr{network: "udp", addr: "172.16.5.1:1234"}
	udpSlipped := false
	for i := 0; i < 25; i++ {
		if resp, _ := udp.Handle(query, udpAddr); isTC(resp) {
			udpSlipped = true
			break
		}
	}
	if !udpSlipped {
		t.Fatal("UDP control did not slip — RRL not engaging, test is inconclusive")
	}

	// Stream: never a TC=1 slip stub, regardless of how hard we hit it.
	stream := mk()
	tcpAddr := &mockAddr{network: "tcp", addr: "172.16.5.2:1234"}
	for i := 0; i < 25; i++ {
		resp, _ := stream.Handle(query, tcpAddr)
		if isTC(resp) {
			t.Fatalf("stream transport returned a TC=1 RRL slip on query %d — RFC 7766 §4 dead-end", i)
		}
	}
}

// TestIsStreamTransport pins the transport inference used by Handle.
func TestIsStreamTransport(t *testing.T) {
	cases := []struct {
		network string
		nilAddr bool
		want    bool
	}{
		{network: "tcp", want: true},
		{network: "tcp4", want: true},
		{network: "tcp6", want: true},
		{network: "udp", want: false},
		{network: "udp4", want: false},
		{nilAddr: true, want: false},
	}
	for _, tcse := range cases {
		var addr interface {
			Network() string
			String() string
		}
		if !tcse.nilAddr {
			addr = &mockAddr{network: tcse.network, addr: "192.0.2.1:53"}
		}
		var got bool
		if addr == nil {
			got = isStreamTransport(nil)
		} else {
			got = isStreamTransport(addr)
		}
		if got != tcse.want {
			t.Errorf("isStreamTransport(network=%q nil=%v) = %v, want %v",
				tcse.network, tcse.nilAddr, got, tcse.want)
		}
	}
}
