package resolver

import (
	"strings"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestResolveIterative_AllNSRefused_TagsNoReachableAuthority pins the
// Fix B behaviour for v0.6.17: when every authoritative nameserver in
// the final delegation returns REFUSED (the broken-reverse-zone shape
// the user observed on 153.133.185.147.in-addr.arpa — parent publishes
// NS for a /24 whose actual operators never set up real auth), the
// ResolveResult must carry FailureReason="no-reachable-authority" so
// the server can map it to RFC 8914 §4.22 EDE info code 22. Without
// the tag the SERVFAIL is indistinguishable from a generic resolver
// failure and clients lose the "upstream is broken, retry won't help"
// signal.
func TestResolveIterative_AllNSRefused_TagsNoReachableAuthority(t *testing.T) {
	// Mock: any query gets REFUSED. The mock plays the role of every
	// auth in the chain, so the resolver exhausts the delegation list
	// and bottoms out on FailureReason="no-reachable-authority".
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				ID:    q.Header.ID,
				Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeRefused).Build(),
			},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, _ := r.Resolve("203.0.113.55.in-addr.arpa", dns.TypePTR, dns.ClassIN)
	if result == nil {
		t.Fatal("expected SERVFAIL ResolveResult, got nil")
	}
	if result.RCODE != dns.RCodeServFail {
		t.Fatalf("rcode: want SERVFAIL, got %d", result.RCODE)
	}
	if result.FailureReason != "no-reachable-authority" {
		t.Errorf("FailureReason: want %q (so server emits EDE 22 per RFC 8914 §4.22), got %q",
			"no-reachable-authority", result.FailureReason)
	}
}

// TestResolveResult_FailureReasonOnly_NotSetForSuccess sanity-checks the
// negative: a NOERROR resolution must NOT carry FailureReason. Otherwise
// a downstream consumer keying on the field gets false positives.
func TestResolveResult_FailureReasonOnly_NotSetForSuccess(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		return &dns.Message{
			Header:    dns.Header{ID: q.Header.ID, Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("rcode: want NOERROR, got %d", result.RCODE)
	}
	if result.FailureReason != "" {
		t.Errorf("FailureReason on successful resolve should be empty, got %q", result.FailureReason)
	}
	// Defence in depth: the success path must not falsely advertise the
	// token through any substring confusion at the consumer end.
	if strings.Contains(result.FailureReason, "no-reachable") {
		t.Errorf("FailureReason contains failure token on success: %q", result.FailureReason)
	}
}
