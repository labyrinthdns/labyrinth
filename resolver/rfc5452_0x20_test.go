package resolver

import (
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestOutboundQuery_0x20CaseRandomizationFollowsConfig pins Y48: the
// resolver's RFC 5452 §6 "DNS 0x20" anti-forgery defence must actually
// engage when `Caps0x20Enabled=true` and STAY OFF when false. A bug in
// either direction is operational: lost randomization halves the
// entropy stack against off-path forgery (back to TXID + source port);
// randomization-when-disabled would surprise legacy auths that compare
// QNAME byte-for-byte and fail to echo it.
//
// We capture the actual outbound QNAME at the mock server's UDP socket
// and check whether case is mixed. With a 24-letter qname the chance
// that randomizeCase happens to produce an all-lowercase string by
// pure unfortunate RNG is (1/2)^24 ≈ 6×10⁻⁸ — flake-proof.
func TestOutboundQuery_0x20CaseRandomizationFollowsConfig(t *testing.T) {
	const qname = "verylongnametestforypin.example.com"

	for _, c := range []struct {
		name      string
		caps0x20  bool
		wantMixed bool
	}{
		{"Caps0x20Enabled=true => mixed case", true, true},
		{"Caps0x20Enabled=false => lowercase preserved", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var capturedName atomic.Value
			var captured atomic.Bool

			mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
				if captured.CompareAndSwap(false, true) && len(q.Questions) > 0 {
					capturedName.Store(q.Questions[0].Name)
				}
				if len(q.Questions) == 0 {
					return nil
				}
				return &dns.Message{
					Header: dns.Header{
						Flags: dns.NewFlagBuilder().SetQR(true).Build(),
					},
					Questions: q.Questions,
					Answers: []dns.ResourceRecord{{
						Name:     q.Questions[0].Name,
						Type:     dns.TypeA,
						Class:    dns.ClassIN,
						TTL:      300,
						RDLength: 4,
						RData:    []byte{10, 0, 0, 2},
					}},
				}
			})
			defer mock.close()

			m := metrics.NewMetrics()
			ca := cache.NewCache(100, 5, 86400, 3600, m)
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
			r := NewResolver(ca, ResolverConfig{
				MaxDepth:        10,
				MaxCNAMEDepth:   5,
				UpstreamTimeout: 2 * time.Second,
				UpstreamRetries: 1,
				QMinEnabled:     false,
				PreferIPv4:      true,
				UpstreamPort:    mock.port,
				Caps0x20Enabled: c.caps0x20,
			}, m, logger)
			r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}

			if _, err := r.Resolve(qname, dns.TypeA, dns.ClassIN); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if !captured.Load() {
				t.Fatalf("mock did not capture an upstream query")
			}

			got, ok := capturedName.Load().(string)
			if !ok {
				t.Fatalf("captured name was not a string")
			}

			hasMixedCase := got != strings.ToLower(got)
			if hasMixedCase != c.wantMixed {
				t.Errorf("0x20 randomization mismatch: captured QNAME = %q, hasMixedCase=%v, want %v (Caps0x20Enabled=%v)",
					got, hasMixedCase, c.wantMixed, c.caps0x20)
			}

			// In both modes the letters must match case-insensitively —
			// 0x20 randomization MUST NOT change which letters appear,
			// only their case. A regression that mangled the QNAME
			// would surface here.
			if !strings.EqualFold(got, qname) {
				t.Errorf("QNAME letters changed: got %q, want %q (case-insensitive)", got, qname)
			}
		})
	}
}
