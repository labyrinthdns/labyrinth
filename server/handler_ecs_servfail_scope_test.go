package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// ecsFailUpstream answers SERVFAIL to queries carrying ECS and an A record to
// queries without it.
type ecsFailUpstream struct {
	queries atomic.Int64
	port    string
}

func startECSFailUpstream(t *testing.T) *ecsFailUpstream {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	s := &ecsFailUpstream{port: port}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			s.queries.Add(1)
			q, err := dns.Unpack(buf[:n])
			if err != nil || len(q.Questions) == 0 {
				continue
			}
			hasECS := false
			for i := range q.Additional {
				if q.Additional[i].Type != dns.TypeOPT {
					continue
				}
				if opt, perr := dns.ParseOPT(&q.Additional[i]); perr == nil && opt != nil {
					if e, eerr := dns.ExtractECSFromOPT(opt); eerr == nil && e != nil && e.SourcePrefixLen > 0 {
						hasECS = true
					}
				}
			}
			resp := &dns.Message{
				Header:    dns.Header{ID: q.Header.ID, QDCount: uint16(len(q.Questions))},
				Questions: q.Questions,
			}
			failAll := len(q.Questions[0].Name) >= 4 && q.Questions[0].Name[:4] == "bad."
			fb := dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true)
			if hasECS || failAll {
				resp.Header.Flags = fb.SetRCODE(dns.RCodeServFail).Build()
			} else {
				resp.Header.Flags = fb.Build()
				resp.Header.ANCount = 1
				resp.Answers = []dns.ResourceRecord{{Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{93, 184, 216, 34}}}
			}
			if packed, perr := dns.Pack(resp, make([]byte, 4096)); perr == nil {
				_, _ = conn.WriteTo(packed, addr)
			}
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return s
}

func newECSFailHandler(t *testing.T) (*MainHandler, *ecsFailUpstream) {
	up := startECSFailUpstream(t)
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 1, 86400, 3600, m)
	logger := discardLogger()
	res := resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth: 5, MaxCNAMEDepth: 2, UpstreamTimeout: 500 * time.Millisecond,
		UpstreamRetries: 1, UpstreamPort: up.port, ECSEnabled: true,
	}, m, logger)
	res.SetForwardTable(resolver.NewForwardTable([]resolver.ForwardZone{{Name: "forward.example.org", Addrs: []string{"127.0.0.1"}}}))
	h := NewMainHandler(res, c, nil, nil, nil, m, logger)
	h.SetECS(true, 24)
	return h, up
}

// TestHandle_ECS_ServfailNotCachedGlobally pins that a SERVFAIL learned while a
// client-subnet option was in flight is not written to the global failure
// cache (it is not portable across subnets, as resolver.go already assumes),
// while an ordinary client's failure is still cached (RFC 9520).
func TestHandle_ECS_ServfailNotCachedGlobally(t *testing.T) {
	rcode := func(h *MainHandler, q []byte, addr string) uint8 {
		t.Helper()
		resp, err := h.Handle(q, &mockAddr{network: "udp", addr: addr})
		rc, rerr := ecsScopeRcodeOf(resp, err)
		if rerr != nil {
			t.Fatal(rerr)
		}
		return rc
	}

	t.Run("control: unscoped client resolves", func(t *testing.T) {
		h, _ := newECSFailHandler(t)
		if rc := rcode(h, unscopedQuery(t, "ctl.forward.example.org", dns.TypeA), "198.51.100.9:1111"); rc != dns.RCodeNoError {
			t.Fatalf("rcode=%d", rc)
		}
	})

	t.Run("ECS SERVFAIL does not leak to unscoped clients", func(t *testing.T) {
		h, _ := newECSFailHandler(t)
		const qname = "geo.forward.example.org"
		if rc := rcode(h, ecsScopedQuery(t, qname, dns.TypeA, "1.2.3.4"), "203.0.113.4:2222"); rc != dns.RCodeServFail {
			t.Fatalf("precondition: ECS client rcode=%d, want SERVFAIL", rc)
		}
		if rc := rcode(h, unscopedQuery(t, qname, dns.TypeA), "198.51.100.77:3333"); rc != dns.RCodeNoError {
			t.Fatalf("unscoped client got rcode=%d, want NOERROR", rc)
		}
	})

	t.Run("repeated ECS SERVFAIL re-asks the upstream", func(t *testing.T) {
		h, up := newECSFailHandler(t)
		const qname = "geo2.forward.example.org"
		rcode(h, ecsScopedQuery(t, qname, dns.TypeA, "1.2.3.4"), "203.0.113.4:2222")
		before := up.queries.Load()
		rcode(h, ecsScopedQuery(t, qname, dns.TypeA, "1.2.3.4"), "203.0.113.4:2222")
		if up.queries.Load() == before {
			t.Fatal("second ECS query was answered from a cached failure")
		}
	})

	t.Run("unscoped failures are still cached (RFC 9520)", func(t *testing.T) {
		h, up := newECSFailHandler(t)
		const qname = "bad.forward.example.org"
		if rc := rcode(h, unscopedQuery(t, qname, dns.TypeA), "198.51.100.1:1"); rc != dns.RCodeServFail {
			t.Fatalf("rcode=%d, want SERVFAIL", rc)
		}
		before := up.queries.Load()
		if rc := rcode(h, unscopedQuery(t, qname, dns.TypeA), "198.51.100.2:2"); rc != dns.RCodeServFail {
			t.Fatalf("rcode=%d, want SERVFAIL", rc)
		}
		if up.queries.Load() != before {
			t.Fatal("unscoped failure was not served from the failure cache")
		}
	})
}
