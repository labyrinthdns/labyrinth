package resolver

import (
	"sync/atomic"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// portBoundCookieMock behaves like the stabletransit.com / hostingmatrix.net
// NS live: they bind the server cookie to the client's source port. Every
// query here leaves from a new socket, so from the resolver's side the server
// rejects each server cookie it handed out (BADCOOKIE with a fresh one) and
// answers a client-cookie-only query normally.
func portBoundCookieMock(t *testing.T, queries, withServerCookie *atomic.Int32) *mockDNSServer {
	serverCookie := []byte{1, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8}
	return startMockDNS(t, func(q *dns.Message) *dns.Message {
		queries.Add(1)
		cc := clientCookieOf(q)
		cookie := append(append([]byte(nil), cc...), serverCookie...)
		opt := dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{{Code: dns.EDNSOptionCodeCookie, Data: cookie}})
		resp := &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(), QDCount: 1},
			Questions: q.Questions,
		}
		hasSC := false
		for _, o := range q.EDNS0.Options {
			if o.Code == dns.EDNSOptionCodeCookie && len(o.Data) > 8 {
				hasSC = true
			}
		}
		if hasSC {
			withServerCookie.Add(1)
			// BADCOOKIE (23): low nibble 7 in the header, high bits 1 in
			// the OPT TTL's top byte.
			resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeBadCookie & 0x0f).Build()
			opt.TTL |= uint32(dns.RCodeBadCookie>>4) << 24
			resp.Additional = []dns.ResourceRecord{opt}
			return resp
		}
		resp.Header.ANCount = 1
		resp.Answers = []dns.ResourceRecord{{
			Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RDLength: 4, RData: []byte{192, 0, 2, 1},
		}}
		resp.Additional = []dns.ResourceRecord{opt}
		return resp
	})
}

// TestQueryUpstream_PortBoundServerCookie pins the live failure: with the
// server cookie cached from an earlier exchange, every query was answered
// BADCOOKIE, the one §5.4 retry was too, and both NS were treated as dead
// (holycowdude.com, redcrm.com.tr fell back to 1.1.1.1/8.8.8.8). The query
// is now asked once more with the client cookie only, and the server is
// remembered so later queries go out that way first.
func TestQueryUpstream_PortBoundServerCookie(t *testing.T) {
	var queries, withSC atomic.Int32
	mock := portBoundCookieMock(t, &queries, &withSC)
	defer mock.close()
	r := testResolver(t, mock)
	if len(r.outboundClientCookie) != 8 {
		t.Fatal("test resolver has no outbound cookie")
	}

	// First exchange: client cookie only, answered, server cookie cached.
	msg, err := r.queryUpstreamOnceECS(mock.ip, "holycowdude.com", dns.TypeA, dns.ClassIN, nil)
	if err != nil || msg.Header.RCODE() != dns.RCodeNoError || len(msg.Answers) != 1 {
		t.Fatalf("first query: msg=%v err=%v, want the answer", msg, err)
	}
	if len(r.serverCookieCache.Get(mock.ip)) == 0 {
		t.Fatal("server cookie from a good answer was not cached")
	}

	// Second: cached cookie → BADCOOKIE, §5.4 retry → BADCOOKIE, then the
	// client-cookie-only query answers.
	msg, err = r.queryUpstreamOnceECS(mock.ip, "www.holycowdude.com", dns.TypeA, dns.ClassIN, nil)
	if err != nil || extendedRCODE(msg) != dns.RCodeNoError || len(msg.Answers) != 1 {
		t.Fatalf("second query: rcode=%d err=%v, want the answer from the client-cookie-only retry", extendedRCODE(msg), err)
	}
	if !r.noServerCookieServers.Has(mock.ip) {
		t.Fatal("server that rejects its own cookie was not remembered")
	}

	// Third: no server cookie sent at all, one query.
	before, beforeSC := queries.Load(), withSC.Load()
	msg, err = r.queryUpstreamOnceECS(mock.ip, "holycowdude.com", dns.TypeA, dns.ClassIN, nil)
	if err != nil || len(msg.Answers) != 1 {
		t.Fatalf("third query: msg=%v err=%v", msg, err)
	}
	if n := queries.Load() - before; n != 1 {
		t.Errorf("third query took %d upstream queries, want 1", n)
	}
	if withSC.Load() != beforeSC {
		t.Error("a server cookie was sent to a server remembered as rejecting it")
	}
}
