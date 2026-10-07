package resolver

import (
	"github.com/labyrinthdns/labyrinth/dns"
	"testing"
)

func TestQueryFallback_AcceptsOnlySuccessfulRcodes(t *testing.T) {
	codes := []uint8{dns.RCodeNoError, dns.RCodeNXDomain, dns.RCodeRefused, dns.RCodeNotImp, dns.RCodeServFail}
	failed := false
	for _, code := range codes {
		mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
			return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(code).Build(), QDCount: 1}, Questions: q.Questions}
		})
		r := testResolver(t, mock)
		r.config.FallbackResolvers = []string{mock.ip}
		result := r.queryFallback("example.com", dns.TypeA, dns.ClassIN, "audit")
		mock.close()
		want := code == dns.RCodeNoError || code == dns.RCodeNXDomain
		got := result != nil
		t.Logf("RCODE %d EXPECTED: recovered=%v ACTUAL: recovered=%v", code, want, got)
		if got != want {
			failed = true
		}
		recoveries := r.metrics.Snapshot().FallbackRecoveries
		if (recoveries == 1) != want {
			failed = true
		}
	}
	if failed {
		t.Fatal("PROBLEM CONFIRMED")
	}
	t.Log("FIX VERIFIED")
}
