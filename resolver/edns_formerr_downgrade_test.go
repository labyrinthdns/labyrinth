package resolver

import (
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// ednsHostileAuth is a mock UDP authoritative. Its first `reject` EDNS
// queries (all of them when reject < 0) get the reply observed from the
// Microsoft 365 mail.protection.outlook.com auths: FORMERR with no question
// and no OPT. Everything else gets a normal A answer.
type ednsHostileAuth struct {
	port           string
	reject         int32
	ednsQueries    atomic.Int32
	nonEDNSQueries atomic.Int32
}

func startEDNSHostileAuth(t *testing.T, reject int32) *ednsHostileAuth {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { udp.Close() })
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	a := &ednsHostileAuth{port: port, reject: reject}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			resp := &dns.Message{Header: dns.Header{ID: q.Header.ID}}
			hostile := false
			if q.EDNS0 != nil {
				seen := a.ednsQueries.Add(1)
				hostile = a.reject < 0 || seen <= a.reject
			} else {
				a.nonEDNSQueries.Add(1)
			}
			if hostile {
				resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeFormErr).Build()
			} else {
				resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()
				resp.Questions = q.Questions
				resp.Answers = []dns.ResourceRecord{
					{Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 10, RData: []byte{52, 101, 170, 1}},
				}
			}
			packed, err := dns.Pack(resp, make([]byte, 4096))
			if err != nil {
				continue
			}
			udp.WriteTo(packed, addr)
		}
	}()
	return a
}

func newEDNSTestResolver(port string) *Resolver {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewResolver(c, ResolverConfig{
		MaxDepth:        10,
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 1,
		UpstreamPort:    port,
		Caps0x20Enabled: true,
		DNSSECEnabled:   true,
	}, m, logger)
}

// TestQueryUpstream_EDNSFormErrConfirmedDowngrades: an auth that rejects
// every EDNS query with a question-less FORMERR must still be resolvable,
// and once confirmed it is queried directly without EDNS.
func TestQueryUpstream_EDNSFormErrConfirmedDowngrades(t *testing.T) {
	a := startEDNSHostileAuth(t, -1)
	r := newEDNSTestResolver(a.port)
	const name = "franksa-de.mail.protection.outlook.com."

	msg, err := r.queryUpstreamOnce("127.0.0.1", name, dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("queryUpstreamOnce: %v", err)
	}
	if msg.Header.RCODE() != dns.RCodeNoError || len(msg.Answers) != 1 {
		t.Fatalf("want NOERROR with 1 answer, got rcode=%d answers=%d", msg.Header.RCODE(), len(msg.Answers))
	}
	if a.ednsQueries.Load() != 2 || a.nonEDNSQueries.Load() != 1 {
		t.Fatalf("want 2 EDNS queries (original + confirmation) and 1 plain, got %d + %d",
			a.ednsQueries.Load(), a.nonEDNSQueries.Load())
	}
	if !r.noEDNSServers.Has("127.0.0.1") {
		t.Fatal("confirmed EDNS-intolerant server not remembered")
	}

	if _, err := r.queryUpstreamOnce("127.0.0.1", name, dns.TypeA, dns.ClassIN); err != nil {
		t.Fatalf("second query: %v", err)
	}
	if a.ednsQueries.Load() != 2 || a.nonEDNSQueries.Load() != 2 {
		t.Fatalf("remembered server should get only a plain query (edns=%d plain=%d)",
			a.ednsQueries.Load(), a.nonEDNSQueries.Load())
	}
}

// TestQueryUpstream_SingleFormErrDoesNotDowngrade pins the RFC 5452 §6.1
// protection: one FORMERR (as a single spoofed packet would be) must not
// strip EDNS. The confirming EDNS answer is used and nothing is cached.
func TestQueryUpstream_SingleFormErrDoesNotDowngrade(t *testing.T) {
	a := startEDNSHostileAuth(t, 1)
	r := newEDNSTestResolver(a.port)

	msg, err := r.queryUpstreamOnce("127.0.0.1", "x.example.", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("queryUpstreamOnce: %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("want EDNS answer from the confirmation query, got %d answers", len(msg.Answers))
	}
	if a.nonEDNSQueries.Load() != 0 {
		t.Fatalf("single FORMERR triggered %d non-EDNS queries", a.nonEDNSQueries.Load())
	}
	if r.noEDNSServers.Has("127.0.0.1") {
		t.Fatal("unconfirmed FORMERR must not mark the server EDNS-intolerant")
	}
}
