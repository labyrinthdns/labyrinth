package resolver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestTrace_FallbackPreservesClientContext: Trace must forward CD and ECS
// on the public-resolver fallback the same way ResolveWithECSAndCD does,
// otherwise dashboard diagnostics disagree with production answers.
func TestTrace_FallbackPreservesClientContext(t *testing.T) {
	for _, tc := range []struct {
		cd  bool
		ecs bool
	}{
		{false, false},
		{true, false},
		{false, true},
		{true, true},
	} {
		t.Run("", func(t *testing.T) {
			var calls atomic.Int32
			observed := make(chan *dns.Message, 4)
			mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
				observed <- q
				code := dns.RCodeNoError
				if calls.Add(1) == 1 {
					code = dns.RCodeServFail
				}
				return &dns.Message{
					Header:     dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(code).Build(), QDCount: 1},
					Questions:  q.Questions,
					Additional: q.Additional,
				}
			})
			defer mock.close()

			r := testResolver(t, mock)
			r.config.ECSEnabled = true
			r.config.UpstreamRetries = 1
			r.config.FallbackResolvers = []string{mock.ip}
			r.SetForwardTable(NewForwardTable([]ForwardZone{
				{Name: "example.com", Addrs: []string{mock.ip}},
			}))

			var ecs *dns.ECSOption
			if tc.ecs {
				ecs = &dns.ECSOption{Family: 1, SourcePrefixLen: 24, Address: net.IP{198, 51, 100, 0}}
			}

			events := make(chan TraceEvent, 64)
			result, err := r.Trace(context.Background(), "host.example.com", dns.TypeA, dns.ClassIN, TraceOptions{
				BypassCache:      true,
				ClientECS:        ecs,
				CheckingDisabled: tc.cd,
			}, events)
			for range events {
			}
			if err != nil || result == nil || result.RCODE != dns.RCodeNoError {
				t.Fatalf("trace: result=%v err=%v calls=%d", result, err, calls.Load())
			}
			if calls.Load() < 2 {
				t.Fatalf("expected forward + fallback queries, got %d", calls.Load())
			}

			var backup *dns.Message
			for {
				select {
				case q := <-observed:
					// Fallback is recursive (RD=1); take the last RD=1 query.
					if q.Header.RD() {
						backup = q
					}
				default:
					goto check
				}
			}
		check:
			if backup == nil {
				t.Fatal("no recursive fallback query observed")
			}
			gotECS := extractResponseECS(backup) != nil
			if backup.Header.CD() != tc.cd {
				t.Errorf("fallback CD=%v, want %v", backup.Header.CD(), tc.cd)
			}
			if gotECS != tc.ecs {
				t.Errorf("fallback ECS present=%v, want %v", gotECS, tc.ecs)
			}
		})
	}
}
