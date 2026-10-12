package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestUpstreamQuery_NoRFC6975Options pins that outbound queries carry no
// DAU/DHU/N3U options. RFC 6975 makes them optional and measurement-only
// (§5: they MUST NOT change the response), and some authoritatives drop
// any query with an EDNS option they do not know. Live, both NS of
// toksan.com.tr (78.135.65.70) answer DO+COOKIE but never a query with
// DAU, so the name was SERVFAIL while public resolvers resolved it. The
// query must still carry DO and the client cookie.
func TestUpstreamQuery_NoRFC6975Options(t *testing.T) {
	seen := make(chan *dns.Message, 1)
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		select {
		case seen <- q:
		default:
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(), QDCount: 1},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RDLength: 4, RData: []byte{192, 0, 2, 1},
			}},
		}
	})
	defer mock.close()
	r := testResolver(t, mock)
	r.config.DNSSECEnabled = true

	if _, err := r.queryUpstreamOnce(mock.ip, "host.example.com", dns.TypeA, dns.ClassIN); err != nil {
		t.Fatalf("query: %v", err)
	}
	q := <-seen
	if q.EDNS0 == nil {
		t.Fatal("query has no OPT record")
	}
	if !q.EDNS0.DOFlag {
		t.Error("DO bit not set on a DNSSEC-enabled query")
	}
	cookie := false
	for _, o := range q.EDNS0.Options {
		switch o.Code {
		case dns.EDNSOptionCodeDAU, dns.EDNSOptionCodeDHU, dns.EDNSOptionCodeN3U:
			t.Errorf("query carries RFC 6975 option %d", o.Code)
		case dns.EDNSOptionCodeCookie:
			cookie = true
		}
	}
	if !cookie {
		t.Error("query lost its client cookie")
	}
}
