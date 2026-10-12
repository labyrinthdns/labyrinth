package web

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// countingMockRoot is a loopback UDP DNS server that answers every query
// with NXDOMAIN + SOA (a well-formed negative answer, so resolution
// terminates in one hop) and counts the queries it receives.
type countingMockRoot struct {
	conn    net.PacketConn
	port    string
	queries atomic.Int64
}

func startCountingMockRoot(t *testing.T) *countingMockRoot {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	m := &countingMockRoot{conn: conn, port: port}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			m.queries.Add(1)
			q, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			soa := dns.BuildPlainName("mock.")
			soa = append(soa, dns.BuildPlainName("hostmaster.mock.")...)
			soa = append(soa, 0, 0, 0, 1, 0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 0, 60)
			resp := &dns.Message{
				Header: dns.Header{
					ID:      q.Header.ID,
					Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).SetRCODE(dns.RCodeNXDomain).Build(),
					QDCount: 1, NSCount: 1,
				},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "mock", Type: dns.TypeSOA, Class: dns.ClassIN,
					TTL: 60, RDLength: uint16(len(soa)), RData: soa,
				}},
			}
			out := make([]byte, 4096)
			packed, err := dns.Pack(resp, out)
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(packed[:], addr)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return m
}

// trustChainServer wires an AdminServer to a resolver whose only upstream is
// the counting mock, so every QueryDNSSEC call is observable.
func trustChainServer(t *testing.T, mock *countingMockRoot) *AdminServer {
	t.Helper()

	orig := resolver.RootServers
	resolver.RootServers = []resolver.NameServer{{Name: "mock", IPv4: "127.0.0.1"}}
	t.Cleanup(func() { resolver.RootServers = orig })

	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	res := resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   5,
		UpstreamTimeout: 200 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    mock.port,
	}, m, logger)

	cfg := &config.Config{
		Web: config.WebConfig{Enabled: true, Addr: "127.0.0.1:0", QueryLogBuffer: 100},
	}
	srv, err := NewAdminServer(cfg, c, m, res, logger, nil)
	if err != nil {
		t.Fatalf("NewAdminServer: %v", err)
	}
	return srv
}

func doTrustChain(srv *AdminServer, name string) int {
	req := httptest.NewRequest("GET", "/api/dnssec/trustchain?name="+name, nil)
	w := httptest.NewRecorder()
	srv.handleTrustChain(w, req)
	return w.Code
}

// TestHandleTrustChain_RejectsOverCapName pins the RFC 1035 §2.3.4 name cap on
// /api/dnssec/trustchain. It drives the
// real production handler (handleTrustChain -> buildTrustChain ->
// resolver.QueryDNSSEC) and counts the upstream queries one request causes.
//
// Contract, established by the sibling admin handlers in this same package —
// web/api_cache.go:123, web/api_dnssec.go:152 and web/api_blocklist.go:68 all
// refuse a domain name longer than 255 octets, citing RFC 1035 §2.3.4:
// handleTrustChain must apply the same cap. Without it the per-label loop in
// buildTrustChain (1 DNSKEY query per zone + 1 DS query per non-root zone)
// scales upstream work with an attacker-chosen label count, so a single
// authenticated GET drives an arbitrary number of upstream resolutions.
//
// The cap must be applied before any resolver work, so an over-long name
// costs zero upstream queries.
func TestHandleTrustChain_RejectsOverCapName(t *testing.T) {
	mock := startCountingMockRoot(t)
	srv := trustChainServer(t, mock)

	// Control: an ordinary name inside the cap must be accepted and must
	// cost the small, expected number of queries.
	mock.queries.Store(0)
	if code := doTrustChain(srv, "example.com"); code != 200 {
		t.Fatalf("control: status = %d, want 200", code)
	}
	control := mock.queries.Load()
	t.Logf("control  name=%q status=200 upstream queries=%d", "example.com", control)
	if control == 0 {
		t.Fatal("control FAILED: a normal name issued no upstream queries; harness is wrong, not the code")
	}

	// A name over the 255-octet RFC 1035 §2.3.4 maximum. Every sibling
	// handler in this package rejects this with 400 before doing any work.
	const labels = 200
	overCap := strings.TrimSuffix(strings.Repeat("a.", labels), ".")
	if len(overCap) != 2*labels-1 {
		t.Fatalf("fixture is %d octets, want %d", len(overCap), 2*labels-1)
	}

	mock.queries.Store(0)
	code := doTrustChain(srv, overCap)
	got := mock.queries.Load()

	fmt.Printf("EXPECTED: 400 Bad Request, 0 upstream queries (RFC 1035 §2.3.4 cap, as in web/api_dnssec.go:152)\n")
	fmt.Printf("ACTUAL:   status=%d, %d upstream queries for one request (%d labels)\n", code, got, labels)
	fmt.Printf("CONTROL:  \"example.com\" -> status 200, %d queries\n", control)

	if code == 200 {
		fmt.Printf("FAIL: over-cap name accepted; one request drove %d upstream queries\n", got)
		t.Errorf("amplification: over-cap name (%d octets, %d labels) accepted, cost %d upstream queries",
			len(overCap), labels, got)
		return
	}
	fmt.Println("PASS: over-cap name rejected before any upstream work")
}
