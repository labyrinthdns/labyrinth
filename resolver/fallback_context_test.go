package resolver

import (
	"github.com/labyrinthdns/labyrinth/dns"
	"net"
	"sync/atomic"
	"testing"
)

func TestResolve_FallbackPreservesClientContext(t *testing.T) {
	failed := false
	for _, tc := range []struct{ cd, ecs bool }{{false, false}, {true, false}, {false, true}, {true, true}, {false, false}} {
		var calls atomic.Int32
		observed := make(chan *dns.Message, 2)
		mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
			observed <- q
			code := dns.RCodeNoError
			if calls.Add(1) == 1 {
				code = dns.RCodeServFail
			}
			return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(code).Build(), QDCount: 1}, Questions: q.Questions, Additional: q.Additional}
		})
		r := testResolver(t, mock)
		r.config.ECSEnabled = true
		r.config.FallbackResolvers = []string{mock.ip}
		r.SetForwardTable(NewForwardTable([]ForwardZone{{Name: "example.com", Addrs: []string{mock.ip}}}))
		var ecs *dns.ECSOption
		if tc.ecs {
			ecs = &dns.ECSOption{Family: 1, SourcePrefixLen: 24, Address: net.IP{198, 51, 100, 0}}
		}
		result, err := r.ResolveWithECSAndCD("host.example.com", dns.TypeA, dns.ClassIN, ecs, tc.cd)
		mock.close()
		if err != nil || result == nil || calls.Load() != 2 {
			t.Fatalf("invalid environment: calls=%d result=%v err=%v", calls.Load(), result, err)
		}
		primary, backup := <-observed, <-observed
		if primary.Header.CD() != tc.cd || (extractResponseECS(primary) != nil) != tc.ecs {
			t.Fatal("primary control failed")
		}
		gotECS := extractResponseECS(backup) != nil
		gotScope := result.UpstreamECS != nil
		t.Logf("EXPECTED: fallback CD=%v ECS=%v response ECS=%v ACTUAL: CD=%v ECS=%v response ECS=%v", tc.cd, tc.ecs, tc.ecs, backup.Header.CD(), gotECS, gotScope)
		if backup.Header.CD() != tc.cd || gotECS != tc.ecs || gotScope != tc.ecs {
			failed = true
		}
	}
	if failed {
		t.Fatal("PROBLEM CONFIRMED")
	}
	t.Log("FIX VERIFIED")
}

// TestQueryFallback_CDKeepsBogusVerdict pins RFC 4035 §3.2.2: under CD=1 the
// backup does not validate, so its NOERROR answer is the very data our
// validator ruled Bogus. The verdict must survive; laundered to "" the
// answer was cached and served to every later CD=0 client.
func TestQueryFallback_CDKeepsBogusVerdict(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNoError).Build(), QDCount: 1}, Questions: q.Questions}
	})
	defer mock.close()
	r := testResolver(t, mock)
	r.config.DNSSECEnabled = true
	r.config.FallbackResolvers = []string{mock.ip}
	primary := &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}

	for _, tc := range []struct {
		cd   bool
		want string
	}{{true, "bogus"}, {false, ""}} {
		got := r.queryFallbackWithContext("host.example.com", dns.TypeA, dns.ClassIN, "DNSSEC bogus", primary, nil, tc.cd)
		if got == nil {
			t.Fatalf("CD=%v: fallback did not recover", tc.cd)
		}
		if got.DNSSECStatus != tc.want {
			t.Errorf("CD=%v: DNSSECStatus=%q, want %q", tc.cd, got.DNSSECStatus, tc.want)
		}
	}
}
