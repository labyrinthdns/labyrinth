package resolver

import (
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestOutboundQuery_DOBitMatchesDNSSECEnabled pins Y43: RFC 4035 §4.7
// requires a validating resolver to set the DNSSEC OK (DO) bit in the
// OPT pseudo-record of every outbound query so the authoritative server
// includes RRSIG records. A resolver that loses DO=1 silently degrades
// to insecure: the validator gets no signatures to verify and every
// answer becomes Insecure or Bogus.
//
// The inverse is also pinned: when DNSSECEnabled=false the DO bit MUST
// be clear so unnecessary RRSIG bytes don't flow back over the wire.
//
// We capture the actual outbound query at the mock server's UDP socket
// and inspect the packed OPT TTL high word. The bit semantics come from
// RFC 6891 §6.1.4: DO is bit 15 of the TTL field (the high byte).
func TestOutboundQuery_DOBitMatchesDNSSECEnabled(t *testing.T) {
	for _, c := range []struct {
		name   string
		dnssec bool
		wantDO bool
	}{
		{"DNSSEC enabled => DO=1", true, true},
		{"DNSSEC disabled => DO=0", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var capturedDO atomic.Bool
			var captured atomic.Bool

			mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
				if captured.CompareAndSwap(false, true) {
					for _, rr := range q.Additional {
						if rr.Type == dns.TypeOPT {
							// DO is bit 15 of the OPT TTL field per RFC 6891 §6.1.4.
							doSet := (rr.TTL>>15)&1 == 1
							capturedDO.Store(doSet)
							break
						}
					}
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
						RData:    []byte{10, 0, 0, 1},
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
				DNSSECEnabled:   c.dnssec,
			}, m, logger)
			r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}

			_, err := r.Resolve("y43.test.example.com", dns.TypeA, dns.ClassIN)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if !captured.Load() {
				t.Fatalf("mock never received an upstream query")
			}
			if got := capturedDO.Load(); got != c.wantDO {
				t.Errorf("DO bit on outbound query = %v, want %v (DNSSECEnabled=%v)", got, c.wantDO, c.dnssec)
			}
		})
	}
}
