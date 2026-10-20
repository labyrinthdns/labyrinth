package server

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// scopedNXForward is a loopback authoritative that answers NXDOMAIN (with an
// SOA so the denial is well-formed) to any query carrying a client-subnet
// (ECS) option, and a positive A answer to any query without one. That
// asymmetry is what makes the leak observable: a globally cached
// ECS-scoped NXDOMAIN denies a name that this same upstream would otherwise
// answer for an unscoped client.
type scopedNXForward struct {
	conn    net.PacketConn
	port    string
	queries atomic.Int64
	ecsSeen atomic.Int64
}

// noECSEcho makes startScopedNXForwardScope reply without an ECS option.
const noECSEcho = -1

// startScopedNXForward is an ECS-aware upstream: NXDOMAIN for a client
// subnet, echoed with SCOPE /24 as RFC 7871 §7.2.1 requires of a server
// whose answer depends on the subnet.
func startScopedNXForward(t *testing.T) *scopedNXForward {
	t.Helper()
	return startScopedNXForwardScope(t, 24)
}

// startScopedNXForwardScope answers queries carrying ECS with NXDOMAIN,
// echoing ECS with the given SCOPE PREFIX-LENGTH (noECSEcho: no ECS in
// the reply), and queries without ECS with an address.
func startScopedNXForwardScope(t *testing.T, scope int) *scopedNXForward {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	fw := &scopedNXForward{conn: conn, port: port}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			fw.queries.Add(1)
			q, err := dns.Unpack(buf[:n])
			if err != nil || len(q.Questions) == 0 {
				continue
			}

			hasECS := false
			var queryECS *dns.ECSOption
			for i := range q.Additional {
				if q.Additional[i].Type != dns.TypeOPT {
					continue
				}
				opt, perr := dns.ParseOPT(&q.Additional[i])
				if perr != nil || opt == nil {
					continue
				}
				if ecs, eerr := dns.ExtractECSFromOPT(opt); eerr == nil && ecs != nil && ecs.SourcePrefixLen > 0 {
					hasECS = true
					queryECS = ecs
				}
			}
			if hasECS {
				fw.ecsSeen.Add(1)
			}

			resp := &dns.Message{
				Header: dns.Header{
					ID:      q.Header.ID,
					Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(),
					QDCount: uint16(len(q.Questions)),
				},
				Questions: q.Questions,
			}
			if hasECS {
				// ECS-scoped view: this name does not exist for the
				// subnet the resolver asked about.
				resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).
					SetRCODE(dns.RCodeNXDomain).Build()
				soaRD := dns.BuildPlainName("ns.forward.example.org.")
				soaRD = append(soaRD, dns.BuildPlainName("hostmaster.forward.example.org.")...)
				soaRD = append(soaRD,
					0, 0, 0, 1, // SERIAL
					0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 1, 0, // REFRESH RETRY EXPIRE
					0, 0, 1, 0, // MINIMUM (60)
				)
				resp.Header.NSCount = 1
				resp.Authority = []dns.ResourceRecord{{
					Name: "forward.example.org", Type: dns.TypeSOA, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(soaRD)), RData: soaRD,
				}}
				if scope != noECSEcho {
					echo := *queryECS
					echo.ScopePrefixLen = uint8(scope)
					resp.Additional = []dns.ResourceRecord{
						dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{dns.BuildECS(&echo)}),
					}
					resp.Header.ARCount = 1
				}
			} else {
				// Unscoped view: the name exists.
				resp.Header.ANCount = 1
				resp.Answers = []dns.ResourceRecord{{
					Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{93, 184, 216, 34},
				}}
			}
			out := make([]byte, 4096)
			packed, perr := dns.Pack(resp, out)
			if perr != nil {
				continue
			}
			_, _ = conn.WriteTo(packed[:], addr)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return fw
}

func ecsScopedQuery(t *testing.T, name string, qtype uint16, addr string) []byte {
	t.Helper()
	ecs := &dns.ECSOption{Family: 1, SourcePrefixLen: 24, ScopePrefixLen: 0, Address: net.ParseIP(addr).To4()}
	msg := &dns.Message{
		Header:    dns.Header{ID: 0x1111, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
		Questions: []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{dns.BuildECS(ecs)}),
		},
	}
	buf := make([]byte, 1024)
	packed, err := dns.Pack(msg, buf)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out
}

func unscopedQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	msg := &dns.Message{
		Header:    dns.Header{ID: 0x2222, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
		Questions: []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}},
	}
	buf := make([]byte, 1024)
	packed, err := dns.Pack(msg, buf)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out
}

func ecsScopeRcodeOf(resp []byte, err error) (uint8, error) {
	if err != nil {
		return 0, err
	}
	if len(resp) < 4 {
		return 0, nil
	}
	return uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF), nil
}

// TestHandle_ECS_NegativeNotCachedGlobally pins RFC 7871 §7.3: a negative
// answer learned while a client-subnet (ECS) option was in flight belongs to
// that subnet alone and MUST NOT be written to, or served from, the global
// (name, type, class) cache.
//
// The resolver already enforces this — resolver.go refuses to store a scoped
// NXDOMAIN under the global key when clientECS != nil. MainHandler.Handle
// then re-caches the very same denial globally via StoreNegativeWithStatus,
// which both reintroduces the leak the resolver avoided and lets one subnet's
// NXDOMAIN deny a name to every other client, including clients that never
// sent ECS at all.
//
// The upstream is a forward zone, which keeps the resolver on the simple
// queryForward path: whatever this upstream answers is returned verbatim, so
// the cache layer is the only thing under test. (A root-seeded harness
// cannot work here: RFC 6761 short-circuits reserved TLDs before the forward
// table is consulted.)
func TestHandle_ECS_NegativeNotCachedGlobally(t *testing.T) {
	fw := startScopedNXForward(t)

	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 1, 86400, 3600, m)
	logger := discardLogger()
	res := resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth:        5,
		MaxCNAMEDepth:   2,
		UpstreamTimeout: 500 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    fw.port,
		// ECS must be enabled or sendQueryWithRDECSCDT strips the option
		// before it reaches the wire (resolver/forward.go:269).
		ECSEnabled: true,
	}, m, logger)
	res.SetForwardTable(resolver.NewForwardTable([]resolver.ForwardZone{
		{Name: "forward.example.org", Addrs: []string{"127.0.0.1"}},
	}))

	handler := NewMainHandler(res, c, nil, nil, nil, m, logger)
	handler.SetECS(true, 24)

	const qname = "geo.forward.example.org"
	const ctlName = "ctl.forward.example.org"

	// CONTROL (a different name, so it cannot pollute qname's cache slot):
	// an unscoped client is answered positively by the upstream. This proves
	// the harness reaches the upstream and reads back a real NOERROR.
	rc, errc := handler.Handle(unscopedQuery(t, ctlName, dns.TypeA),
		&mockAddr{network: "udp", addr: "198.51.100.9:1111"})
	controlRcode, cerr := ecsScopeRcodeOf(rc, errc)
	if cerr != nil || controlRcode != dns.RCodeNoError {
		t.Fatalf("control FAILED: unscoped client rcode=%d err=%v (upstream queries=%d); harness is wrong",
			controlRcode, cerr, fw.queries.Load())
	}
	t.Logf("control: unscoped client rcode=%d (NOERROR), upstream queries=%d", controlRcode, fw.queries.Load())

	// STEP 1: an ECS-scoped client (1.2.3.0/24) gets NXDOMAIN. That denial
	// belongs to that subnet alone.
	r1, err1 := handler.Handle(ecsScopedQuery(t, qname, dns.TypeA, "1.2.3.4"),
		&mockAddr{network: "udp", addr: "203.0.113.4:2222"})
	ecsRcode, eerr := ecsScopeRcodeOf(r1, err1)
	t.Logf("step1: ECS client (1.2.3.0/24) rcode=%d (expect %d NXDOMAIN), upstream saw ECS %d time(s)",
		ecsRcode, dns.RCodeNXDomain, fw.ecsSeen.Load())
	if eerr != nil || ecsRcode != dns.RCodeNXDomain {
		t.Fatalf("step1 precondition FAILED: ECS client rcode=%d err=%v, want NXDOMAIN; harness is wrong",
			ecsRcode, eerr)
	}

	// STEP 2 (the impact): an unscoped client from a different subnet, which
	// never sent ECS, must still get the positive answer this same upstream
	// would give it. If the scoped NXDOMAIN was written to the global key, it
	// is served instead and the upstream is never consulted.
	before := fw.queries.Load()
	r2, err2 := handler.Handle(unscopedQuery(t, qname, dns.TypeA),
		&mockAddr{network: "udp", addr: "198.51.100.77:3333"})
	impactRcode, ierr := ecsScopeRcodeOf(r2, err2)
	consulted := fw.queries.Load() > before
	t.Logf("step2: second unscoped client rcode=%d, upstream consulted=%v", impactRcode, consulted)

	if ierr != nil {
		t.Fatalf("impact Handle: %v", ierr)
	}
	if impactRcode == dns.RCodeNXDomain {
		t.Errorf("ECS leak: a scoped NXDOMAIN (1.2.3.0/24) was served to an unrelated unscoped client; upstream consulted=%v", consulted)
	}
}

// TestHandle_ECS_GlobalScopeNegativeCachedGlobally: RFC 7871 §7.3.1 — a
// reply without ECS, or with SCOPE 0, "is an answer suitable for all
// client addresses", so a negative learned for an ECS client is cached
// under the global key like any other (Unbound's subnet module does the
// same). Live: NXDOMAINs for clients that send ECS were never cached, so
// every repeat re-resolved and re-asked the public fallback.
func TestHandle_ECS_GlobalScopeNegativeCachedGlobally(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope int
	}{{"no ECS in reply", noECSEcho}, {"scope 0", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			fw := startScopedNXForwardScope(t, tc.scope)
			m := metrics.NewMetrics()
			c := cache.NewCache(1000, 1, 86400, 3600, m)
			logger := discardLogger()
			res := resolver.NewResolver(c, resolver.ResolverConfig{
				MaxDepth: 5, MaxCNAMEDepth: 2, UpstreamTimeout: 500 * time.Millisecond,
				UpstreamRetries: 1, UpstreamPort: fw.port, ECSEnabled: true,
			}, m, logger)
			res.SetForwardTable(resolver.NewForwardTable([]resolver.ForwardZone{
				{Name: "forward.example.org", Addrs: []string{"127.0.0.1"}},
			}))
			handler := NewMainHandler(res, c, nil, nil, nil, m, logger)
			handler.SetECS(true, 24)

			const qname = "gone.forward.example.org"
			for i := 0; i < 2; i++ {
				resp, err := handler.Handle(ecsScopedQuery(t, qname, dns.TypeA, "1.2.3.4"),
					&mockAddr{network: "udp", addr: "203.0.113.4:2222"})
				if rc, rerr := ecsScopeRcodeOf(resp, err); rerr != nil || rc != dns.RCodeNXDomain {
					t.Fatalf("query %d: rcode=%d err=%v, want NXDOMAIN", i+1, rc, rerr)
				}
			}
			if n := fw.queries.Load(); n != 1 {
				t.Errorf("upstream asked %d times, want 1 (second answer from the global negative cache)", n)
			}
		})
	}
}
