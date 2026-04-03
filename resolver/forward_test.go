package resolver

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// ---------------------------------------------------------------------------
// ForwardTable.Match tests
// ---------------------------------------------------------------------------

func TestForwardTableMatchExact(t *testing.T) {
	ft := NewForwardTable([]ForwardZone{
		{Name: "example.com", Addrs: []string{"1.1.1.1"}},
	})
	fz := ft.Match("example.com")
	if fz == nil {
		t.Fatal("expected match for exact zone name")
	}
	if fz.Name != "example.com" {
		t.Errorf("expected zone 'example.com', got %q", fz.Name)
	}
}

func TestForwardTableMatchSuffix(t *testing.T) {
	ft := NewForwardTable([]ForwardZone{
		{Name: "example.com", Addrs: []string{"1.1.1.1"}},
	})
	fz := ft.Match("www.example.com")
	if fz == nil {
		t.Fatal("expected match for suffix")
	}
	if fz.Name != "example.com" {
		t.Errorf("expected zone 'example.com', got %q", fz.Name)
	}
}

func TestForwardTableMatchNoMatch(t *testing.T) {
	ft := NewForwardTable([]ForwardZone{
		{Name: "example.com", Addrs: []string{"1.1.1.1"}},
	})
	if fz := ft.Match("other.net"); fz != nil {
		t.Errorf("expected no match, got %q", fz.Name)
	}
}

func TestForwardTableMatchLongest(t *testing.T) {
	ft := NewForwardTable([]ForwardZone{
		{Name: "com", Addrs: []string{"1.1.1.1"}},
		{Name: "example.com", Addrs: []string{"2.2.2.2"}},
		{Name: "sub.example.com", Addrs: []string{"3.3.3.3"}},
	})

	// "host.sub.example.com" should match "sub.example.com" (longest)
	fz := ft.Match("host.sub.example.com")
	if fz == nil {
		t.Fatal("expected match")
	}
	if fz.Name != "sub.example.com" {
		t.Errorf("expected longest match 'sub.example.com', got %q", fz.Name)
	}

	// "other.example.com" should match "example.com"
	fz = ft.Match("other.example.com")
	if fz == nil {
		t.Fatal("expected match")
	}
	if fz.Name != "example.com" {
		t.Errorf("expected match 'example.com', got %q", fz.Name)
	}

	// "random.com" should match "com"
	fz = ft.Match("random.com")
	if fz == nil {
		t.Fatal("expected match")
	}
	if fz.Name != "com" {
		t.Errorf("expected match 'com', got %q", fz.Name)
	}
}

func TestForwardTableMatchNilTable(t *testing.T) {
	var ft *ForwardTable
	if fz := ft.Match("example.com"); fz != nil {
		t.Error("nil table should return nil")
	}
}

func TestForwardTableMatchEmptyZones(t *testing.T) {
	ft := NewForwardTable(nil)
	if fz := ft.Match("example.com"); fz != nil {
		t.Error("empty table should return nil")
	}
}

func TestForwardTableMatchCaseInsensitive(t *testing.T) {
	ft := NewForwardTable([]ForwardZone{
		{Name: "Example.COM", Addrs: []string{"1.1.1.1"}},
	})
	fz := ft.Match("WWW.EXAMPLE.COM")
	if fz == nil {
		t.Fatal("expected case-insensitive match")
	}
}

func TestForwardTableMatchTrailingDot(t *testing.T) {
	ft := NewForwardTable([]ForwardZone{
		{Name: "example.com.", Addrs: []string{"1.1.1.1"}},
	})
	fz := ft.Match("www.example.com.")
	if fz == nil {
		t.Fatal("expected match with trailing dot normalization")
	}
}

func TestForwardTableMatchNoPartialLabel(t *testing.T) {
	ft := NewForwardTable([]ForwardZone{
		{Name: "ample.com", Addrs: []string{"1.1.1.1"}},
	})
	// "example.com" ends with "ample.com" as a string, but not as a label suffix
	if fz := ft.Match("example.com"); fz != nil {
		t.Error("should not match partial label suffix")
	}
}

// ---------------------------------------------------------------------------
// Forward zone resolve test (RD=1 forwarding)
// ---------------------------------------------------------------------------

func TestForwardZoneResolve(t *testing.T) {
	// Start a mock DNS server that responds to any query with a canned A record.
	// It verifies that RD=1 is set in the query.
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		// Verify RD=1 was set by the forward query
		if !q.Header.RD() {
			t.Error("forward query should have RD=1")
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRA(true).SetRD(true).Build(),
				ANCount: 1,
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 20, 30, 40},
			}},
		}
	})
	defer mock.close()

	r := testResolverWithForward(t, mock)

	result, err := r.Resolve("forwarded.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got RCODE %d", result.RCODE)
	}
	if len(result.Answers) == 0 {
		t.Fatal("expected answers")
	}
	if result.Answers[0].Type != dns.TypeA {
		t.Errorf("expected A record, got type %d", result.Answers[0].Type)
	}
	ip, err := dns.ParseA(result.Answers[0].RData)
	if err != nil {
		t.Fatalf("parse A: %v", err)
	}
	if ip.String() != "10.20.30.40" {
		t.Errorf("expected 10.20.30.40, got %s", ip.String())
	}
}

// ---------------------------------------------------------------------------
// Stub zone resolve test (RD=0, iterative from stub NS)
// ---------------------------------------------------------------------------

func TestStubZoneResolve(t *testing.T) {
	// The mock DNS server acts as a stub zone authoritative server.
	// First query: return a referral to a child NS.
	// Second query (to the same mock, since we only have one): return the answer.
	var queryCount int
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		// Verify RD=0 (iterative mode)
		if q.Header.RD() {
			t.Error("stub zone query should have RD=0")
		}
		queryCount++
		name := q.Questions[0].Name

		// For the initial query for "host.internal.corp", the stub NS
		// can just return a direct answer (simulating authoritative data).
		if name == "host.internal.corp" && q.Questions[0].Type == dns.TypeA {
			return &dns.Message{
				Header: dns.Header{
					Flags:   dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(),
					ANCount: 1,
				},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "host.internal.corp", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 60, RDLength: 4, RData: []byte{192, 168, 1, 100},
				}},
			}
		}

		// For QMIN or NS queries, return a referral with glue
		nsRData := buildPlainNameRData("ns.internal.corp")
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
				NSCount: 1,
			},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "internal.corp", Type: dns.TypeNS, Class: dns.ClassIN,
				TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
			}},
			Additional: []dns.ResourceRecord{{
				Name: "ns.internal.corp", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 3600, RDLength: 4, RData: []byte{127, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolverWithStub(t, mock)

	result, err := r.Resolve("host.internal.corp", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got RCODE %d", result.RCODE)
	}
	if len(result.Answers) == 0 {
		t.Fatal("expected answers from stub zone")
	}
	ip, err := dns.ParseA(result.Answers[0].RData)
	if err != nil {
		t.Fatalf("parse A: %v", err)
	}
	if ip.String() != "192.168.1.100" {
		t.Errorf("expected 192.168.1.100, got %s", ip.String())
	}
}

// ---------------------------------------------------------------------------
// Test forward zone with all addrs failing returns error
// ---------------------------------------------------------------------------

func TestForwardZoneAllAddrsFail(t *testing.T) {
	ft := NewForwardTable([]ForwardZone{
		{Name: "fail.example.com", Addrs: []string{"192.0.2.1", "192.0.2.2"}, IsStub: false},
	})

	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 200 * time.Millisecond,
		UpstreamRetries: 1,
		QMinEnabled:     false,
		PreferIPv4:      true,
	}, m, logger)
	r.SetForwardTable(ft)
	r.ready = true

	_, err := r.Resolve("test.fail.example.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Fatal("expected error when all forward addrs are unreachable")
	}
}

// ---------------------------------------------------------------------------
// Test that non-matching queries still use normal iterative resolution
// ---------------------------------------------------------------------------

func TestNonMatchingQueryUsesIterative(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
				ANCount: 1,
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	// Set a forward table that does NOT match the query domain
	r.SetForwardTable(NewForwardTable([]ForwardZone{
		{Name: "other.zone", Addrs: []string{"9.9.9.9"}},
	}))

	result, err := r.Resolve("normal.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got RCODE %d", result.RCODE)
	}
	if len(result.Answers) == 0 {
		t.Fatal("expected answers from iterative resolution")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testResolverWithForward(t *testing.T, mock *mockDNSServer) *Resolver {
	t.Helper()
	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 2,
		QMinEnabled:     false,
		PreferIPv4:      true,
		UpstreamPort:    mock.port,
	}, m, logger)
	r.ready = true

	// Configure forward zone pointing at the mock server
	r.SetForwardTable(NewForwardTable([]ForwardZone{
		{Name: "example.com", Addrs: []string{mock.ip}, IsStub: false},
	}))

	return r
}

func testResolverWithStub(t *testing.T, mock *mockDNSServer) *Resolver {
	t.Helper()
	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 2,
		QMinEnabled:     false,
		PreferIPv4:      true,
		UpstreamPort:    mock.port,
	}, m, logger)
	r.ready = true

	// Configure stub zone pointing at the mock server
	r.SetForwardTable(NewForwardTable([]ForwardZone{
		{Name: "internal.corp", Addrs: []string{mock.ip}, IsStub: true},
	}))

	return r
}
