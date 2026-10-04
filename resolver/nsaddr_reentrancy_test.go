package resolver

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestResolveIterativeServFailAllNSExhausted_NoReentrancyStorm pins the
// Happy Eyeballs × resolveNSAddr bug: after the only glue IP SERVFAILs,
// excludeNSIP keeps the hostname and selectAndResolveNS used to
// recursively resolve that same root hostname forever (7 GiB RSS under
// -race). With the nsAddrName guard the query must finish quickly as
// SERVFAIL.
func TestResolveIterativeServFailAllNSExhausted_NoReentrancyStorm(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build()},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	done := make(chan struct{})
	var result *ResolveResult
	var err error
	go func() {
		result, err = r.Resolve("all-fail-storm.com", dns.TypeA, dns.ClassIN)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Resolve hung/stormed after all-NS SERVFAIL; nsAddr re-entrancy guard missing")
	}
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result == nil || result.RCODE != dns.RCodeServFail {
		t.Fatalf("expected SERVFAIL, got %+v", result)
	}
}
