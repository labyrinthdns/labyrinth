package resolver

import (
	"sync/atomic"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func hasCookieOption(q *dns.Message) bool {
	return clientCookieOf(q) != nil
}

// clientCookieOf returns the 8-byte client cookie of q, or nil.
func clientCookieOf(q *dns.Message) []byte {
	if q.EDNS0 == nil {
		return nil
	}
	for _, opt := range q.EDNS0.Options {
		if opt.Code == dns.EDNSOptionCodeCookie && len(opt.Data) >= 8 {
			return append([]byte(nil), opt.Data[:8]...)
		}
	}
	return nil
}

// cookieIntolerantMock answers FORMERR to every query carrying a COOKIE
// option and a normal answer otherwise, like ns1/ns2.jettsms.com live: the
// FORMERR carries an OPT record that echoes the 8-byte client cookie with
// no server cookie. It records whether each query had OPT and DO.
func cookieIntolerantMock(t *testing.T, queries, withCookie, withoutDO *atomic.Int32) *mockDNSServer {
	return startMockDNS(t, func(q *dns.Message) *dns.Message {
		queries.Add(1)
		if q.EDNS0 == nil || !q.EDNS0.DOFlag {
			withoutDO.Add(1)
		}
		resp := &dns.Message{
			Header:     dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(), QDCount: 1},
			Questions:  q.Questions,
			Additional: []dns.ResourceRecord{dns.BuildOPT(1232, false)},
		}
		if hasCookieOption(q) {
			withCookie.Add(1)
			resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeFormErr).Build()
			resp.Additional = []dns.ResourceRecord{dns.BuildOPTWithOptions(1232, true, []dns.EDNSOption{{
				Code: dns.EDNSOptionCodeCookie, Data: clientCookieOf(q),
			}})}
			return resp
		}
		resp.Header.ANCount = 1
		resp.Answers = []dns.ResourceRecord{{
			Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RDLength: 4, RData: []byte{192, 0, 2, 1},
		}}
		return resp
	})
}

// TestQueryUpstream_CookieFormErrRetriedWithoutCookie pins the RFC 7873
// cookie fallback. Live, ns1/ns2.jettsms.com answer FORMERR (with OPT) to
// any query carrying a COOKIE option, so mail.jettsms.com was SERVFAIL and
// the request burned its whole query budget re-resolving the in-zone NS
// names. The query is now asked once more without the cookie, still with
// EDNS and DO, and the server is remembered so later queries skip the
// cookie straight away.
func TestQueryUpstream_CookieFormErrRetriedWithoutCookie(t *testing.T) {
	var queries, withCookie, withoutDO atomic.Int32
	mock := cookieIntolerantMock(t, &queries, &withCookie, &withoutDO)
	defer mock.close()
	r := testResolver(t, mock)
	r.config.DNSSECEnabled = true
	if len(r.outboundClientCookie) != 8 {
		t.Fatal("test resolver has no outbound cookie")
	}

	msg, err := r.queryUpstreamOnceECS(mock.ip, "mail.example.com", dns.TypeA, dns.ClassIN, nil)
	if err != nil || msg == nil || msg.Header.RCODE() != dns.RCodeNoError || len(msg.Answers) != 1 {
		t.Fatalf("msg=%v err=%v, want the answer from the cookie-less retry", msg, err)
	}
	if !r.noCookieServers.Has(mock.ip) {
		t.Fatal("cookie-intolerant server was not remembered")
	}
	if r.noEDNSServers.Has(mock.ip) {
		t.Error("server downgraded to no-EDNS; only the cookie should be dropped")
	}

	before, cookiesBefore := queries.Load(), withCookie.Load()
	if _, err := r.queryUpstreamOnceECS(mock.ip, "www.example.com", dns.TypeA, dns.ClassIN, nil); err != nil {
		t.Fatalf("second query: %v", err)
	}
	if n := queries.Load() - before; n != 1 {
		t.Errorf("second query sent %d packets, want 1", n)
	}
	if withCookie.Load() != cookiesBefore {
		t.Error("second query still carried a COOKIE option")
	}
	if withoutDO.Load() != 0 {
		t.Errorf("%d queries went out without EDNS DO; DNSSEC must not be downgraded", withoutDO.Load())
	}
}

// TestQueryUpstream_PersistentFormErrNotMarkedCookieIntolerant: when the
// cookie-less retry draws FORMERR too, the cookie was not the problem. The
// FORMERR is surfaced as before and the server is not marked.
func TestQueryUpstream_PersistentFormErrNotMarkedCookieIntolerant(t *testing.T) {
	var queries atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queries.Add(1)
		return &dns.Message{
			Header:     dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeFormErr).Build(), QDCount: 1},
			Questions:  q.Questions,
			Additional: []dns.ResourceRecord{dns.BuildOPT(1232, false)},
		}
	})
	defer mock.close()
	r := testResolver(t, mock)

	msg, err := r.queryUpstreamOnceECS(mock.ip, "mail.example.com", dns.TypeA, dns.ClassIN, nil)
	if err != nil || msg == nil || msg.Header.RCODE() != dns.RCodeFormErr {
		t.Fatalf("msg=%v err=%v, want the FORMERR surfaced", msg, err)
	}
	if n := queries.Load(); n != 2 {
		t.Errorf("sent %d packets, want 2 (one cookie-less retry)", n)
	}
	if r.noCookieServers.Has(mock.ip) {
		t.Error("server marked cookie-intolerant although the retry failed too")
	}
}

// TestQueryUpstream_FormErrWithServerCookieNotRetried: a FORMERR that
// carries a server cookie comes from a server that implements RFC 7873, so
// the cookie is not dropped.
func TestQueryUpstream_FormErrWithServerCookieNotRetried(t *testing.T) {
	var queries atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queries.Add(1)
		opt := dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{{
			Code: dns.EDNSOptionCodeCookie,
			Data: append(clientCookieOf(q), 1, 2, 3, 4, 5, 6, 7, 8),
		}})
		return &dns.Message{
			Header:     dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeFormErr).Build(), QDCount: 1},
			Questions:  q.Questions,
			Additional: []dns.ResourceRecord{opt},
		}
	})
	defer mock.close()
	r := testResolver(t, mock)

	if _, err := r.queryUpstreamOnceECS(mock.ip, "mail.example.com", dns.TypeA, dns.ClassIN, nil); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n := queries.Load(); n != 1 {
		t.Errorf("sent %d packets, want 1 (no cookie-less retry)", n)
	}
	if r.noCookieServers.Has(mock.ip) {
		t.Error("server marked cookie-intolerant although it returned a server cookie")
	}
}
