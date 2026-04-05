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

func TestShouldFallback_ServFail(t *testing.T) {
	result := &ResolveResult{RCODE: dns.RCodeServFail}
	if !shouldFallback(result, nil) {
		t.Error("expected shouldFallback=true for SERVFAIL")
	}
}

func TestShouldFallback_Error(t *testing.T) {
	if !shouldFallback(nil, errTXIDMismatch) {
		t.Error("expected shouldFallback=true for non-nil error")
	}
}

func TestShouldFallback_NilResult(t *testing.T) {
	if !shouldFallback(nil, nil) {
		t.Error("expected shouldFallback=true for nil result")
	}
}

func TestShouldFallback_NoError(t *testing.T) {
	result := &ResolveResult{RCODE: dns.RCodeNoError}
	if shouldFallback(result, nil) {
		t.Error("expected shouldFallback=false for NOERROR")
	}
}

func TestShouldFallback_NXDOMAIN(t *testing.T) {
	result := &ResolveResult{RCODE: dns.RCodeNXDomain}
	if shouldFallback(result, nil) {
		t.Error("expected shouldFallback=false for NXDOMAIN")
	}
}

func TestShouldFallback_DNSSECBogus(t *testing.T) {
	result := &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}
	if shouldFallback(result, nil) {
		t.Error("expected shouldFallback=false for DNSSEC bogus")
	}
}

func TestQueryFallback_NotConfigured(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		UpstreamTimeout: 1 * time.Second,
		UpstreamRetries: 1,
	}, m, logger)

	result := r.queryFallback("example.com", dns.TypeA, dns.ClassIN)
	if result != nil {
		t.Error("expected nil when no fallback resolvers configured")
	}
	snap := m.Snapshot()
	if snap.FallbackQueries != 0 {
		t.Errorf("expected 0 fallback queries, got %d", snap.FallbackQueries)
	}
}

func TestQueryFallback_Success(t *testing.T) {
	// Start a mock DNS server that always returns a successful A record.
	fallbackMock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(),
				QDCount: 1,
				ANCount: 1,
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{93, 184, 216, 34},
			}},
		}
	})
	defer fallbackMock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		UpstreamPort:      fallbackMock.port,
		FallbackResolvers: []string{fallbackMock.ip},
	}, m, logger)

	result := r.queryFallback("example.com", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected non-nil result from fallback")
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}
	if len(result.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(result.Answers))
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 1 {
		t.Errorf("expected 1 fallback query, got %d", snap.FallbackQueries)
	}
	if snap.FallbackRecoveries != 1 {
		t.Errorf("expected 1 fallback recovery, got %d", snap.FallbackRecoveries)
	}
}

func TestQueryFallback_FallbackAlsoFails(t *testing.T) {
	// Start a mock DNS server that always returns SERVFAIL.
	fallbackMock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build(),
				QDCount: 1,
			},
			Questions: q.Questions,
		}
	})
	defer fallbackMock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		UpstreamPort:      fallbackMock.port,
		FallbackResolvers: []string{fallbackMock.ip},
	}, m, logger)

	result := r.queryFallback("example.com", dns.TypeA, dns.ClassIN)
	if result != nil {
		t.Error("expected nil when fallback also returns SERVFAIL")
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 1 {
		t.Errorf("expected 1 fallback query, got %d", snap.FallbackQueries)
	}
	if snap.FallbackRecoveries != 0 {
		t.Errorf("expected 0 fallback recoveries, got %d", snap.FallbackRecoveries)
	}
}

func TestQueryFallback_NXDOMAIN_IsRecovery(t *testing.T) {
	// NXDOMAIN from fallback is a valid answer (domain doesn't exist),
	// so it should count as a recovery from the primary's SERVFAIL.
	fallbackMock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
				QDCount: 1,
			},
			Questions: q.Questions,
		}
	})
	defer fallbackMock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		UpstreamPort:      fallbackMock.port,
		FallbackResolvers: []string{fallbackMock.ip},
	}, m, logger)

	result := r.queryFallback("nonexistent.example.com", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected non-nil result for NXDOMAIN from fallback")
	}
	if result.RCODE != dns.RCodeNXDomain {
		t.Errorf("expected NXDOMAIN, got %d", result.RCODE)
	}

	snap := m.Snapshot()
	if snap.FallbackRecoveries != 1 {
		t.Errorf("expected 1 recovery (NXDOMAIN is still a valid response), got %d", snap.FallbackRecoveries)
	}
}

func TestResolve_FallbackOnServFail(t *testing.T) {
	// Single mock: iterative queries (RD=0) return SERVFAIL,
	// recursive/fallback queries (RD=1) return a valid A record.
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		if q.Header.RD() {
			// Fallback query (recursive, RD=1) → success
			return &dns.Message{
				Header: dns.Header{
					Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(),
					QDCount: 1,
					ANCount: 1,
				},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
				}},
			}
		}
		// Primary iterative query (RD=0) → SERVFAIL
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build(),
				QDCount: 1,
			},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		MaxCNAMEDepth:     10,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		QMinEnabled:       false,
		PreferIPv4:        true,
		UpstreamPort:      mock.port,
		FallbackResolvers: []string{mock.ip},
	}, m, logger)

	r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}
	r.ready = true

	result, err := r.Resolve("example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR from fallback, got %d", result.RCODE)
	}
	if len(result.Answers) != 1 {
		t.Errorf("expected 1 answer from fallback, got %d", len(result.Answers))
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 1 {
		t.Errorf("expected 1 fallback query, got %d", snap.FallbackQueries)
	}
	if snap.FallbackRecoveries != 1 {
		t.Errorf("expected 1 fallback recovery, got %d", snap.FallbackRecoveries)
	}
}

func TestResolve_NoFallbackOnSuccess(t *testing.T) {
	// Primary returns success — fallback should not be triggered.
	primaryMock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
				QDCount: 1,
				ANCount: 1,
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	})
	defer primaryMock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		MaxCNAMEDepth:     10,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		QMinEnabled:       false,
		PreferIPv4:        true,
		UpstreamPort:      primaryMock.port,
		FallbackResolvers: []string{"8.8.8.8"}, // configured but should not be used
	}, m, logger)

	r.rootServers = []NameServer{{Name: "mock.root", IPv4: primaryMock.ip}}
	r.ready = true

	result, err := r.Resolve("example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 0 {
		t.Errorf("expected 0 fallback queries, got %d", snap.FallbackQueries)
	}
}

func TestResolve_NoFallbackOnNXDOMAIN(t *testing.T) {
	// Primary returns NXDOMAIN — should NOT trigger fallback.
	primaryMock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
				QDCount: 1,
			},
			Questions: q.Questions,
		}
	})
	defer primaryMock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		MaxCNAMEDepth:     10,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		QMinEnabled:       false,
		PreferIPv4:        true,
		UpstreamPort:      primaryMock.port,
		FallbackResolvers: []string{"8.8.8.8"},
	}, m, logger)

	r.rootServers = []NameServer{{Name: "mock.root", IPv4: primaryMock.ip}}
	r.ready = true

	result, err := r.Resolve("nonexistent.test", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RCODE != dns.RCodeNXDomain {
		t.Errorf("expected NXDOMAIN, got %d", result.RCODE)
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 0 {
		t.Errorf("expected 0 fallback queries for NXDOMAIN, got %d", snap.FallbackQueries)
	}
}

func TestResolve_ForwardZone_FallbackOnServFail(t *testing.T) {
	// Forward zone upstream returns SERVFAIL, fallback should recover.
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		if !q.Header.RD() {
			// Non-recursive (iterative) — not expected here but handle
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build(), QDCount: 1},
				Questions: q.Questions,
			}
		}
		name := q.Questions[0].Name
		// Forward zone upstream: return SERVFAIL for forward zone queries
		if name == "fwd.example.com" || name == "fwd.example.com." {
			// Check if this is a "second chance" (fallback) by looking at
			// whether we've been called before. Use a simple heuristic:
			// the forward zone tries all addrs first, then fallback picks one.
			// Both use RD=1, so we distinguish by... we can't easily.
			// Instead: first 2 calls (forward retries) = SERVFAIL, then success.
		}
		// Just always return SERVFAIL — both forward and fallback go to same mock.
		// But we need the fallback to succeed. Use the same RD trick won't work
		// since both are RD=1. Let's use a counter approach.
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build(), QDCount: 1},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	// This test verifies the code PATH (forward zone → SERVFAIL → shouldFallback → queryFallback).
	// Even though fallback also returns SERVFAIL (same mock), the important thing
	// is that the fallback code path is exercised.
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		MaxCNAMEDepth:     10,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		QMinEnabled:       false,
		PreferIPv4:        true,
		UpstreamPort:      mock.port,
		FallbackResolvers: []string{mock.ip},
	}, m, logger)

	r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}
	r.ready = true
	r.SetForwardTable(NewForwardTable([]ForwardZone{
		{Name: "example.com", Addrs: []string{mock.ip}, IsStub: false},
	}))

	result, err := r.Resolve("fwd.example.com", dns.TypeA, dns.ClassIN)
	// Forward fails, fallback also fails (same mock returns SERVFAIL for all)
	// => final result is SERVFAIL
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL, got %d", result.RCODE)
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 1 {
		t.Errorf("expected 1 fallback query (forward zone path), got %d", snap.FallbackQueries)
	}
}

func TestResolve_ForwardZone_FallbackRecovers(t *testing.T) {
	// Two mock servers on different behaviors via a shared counter.
	var callCount int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		// Forward zone retry sends ~2 queries (UpstreamRetries=1 means 1 attempt).
		// Then fallback sends 1 query. The forward upstream returns SERVFAIL,
		// the fallback (which also goes to same mock) needs to return success.
		// We count calls: first call = forward zone (SERVFAIL), second = fallback (success).
		count := atomic.AddInt32(&callCount, 1)
		if count <= 1 {
			// Forward zone upstream → SERVFAIL
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build(), QDCount: 1},
				Questions: q.Questions,
			}
		}
		// Fallback → success
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(),
				QDCount: 1,
				ANCount: 1,
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{5, 6, 7, 8},
			}},
		}
	})
	defer mock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		MaxCNAMEDepth:     10,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		QMinEnabled:       false,
		PreferIPv4:        true,
		UpstreamPort:      mock.port,
		FallbackResolvers: []string{mock.ip},
	}, m, logger)

	r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}
	r.ready = true
	r.SetForwardTable(NewForwardTable([]ForwardZone{
		{Name: "example.com", Addrs: []string{mock.ip}, IsStub: false},
	}))

	result, err := r.Resolve("fwd.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR from fallback recovery, got %d", result.RCODE)
	}
	if len(result.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(result.Answers))
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 1 {
		t.Errorf("expected 1 fallback query, got %d", snap.FallbackQueries)
	}
	if snap.FallbackRecoveries != 1 {
		t.Errorf("expected 1 fallback recovery, got %d", snap.FallbackRecoveries)
	}
}

func TestResolve_StubZone_FallbackOnServFail(t *testing.T) {
	// Stub zone: iterative queries (RD=0) return SERVFAIL.
	// Fallback (RD=1) returns success.
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		if q.Header.RD() {
			// Fallback query (RD=1) → success
			return &dns.Message{
				Header: dns.Header{
					Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(),
					QDCount: 1,
					ANCount: 1,
				},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
				}},
			}
		}
		// Stub iterative query (RD=0) → SERVFAIL
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build(), QDCount: 1},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		MaxCNAMEDepth:     10,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		QMinEnabled:       false,
		PreferIPv4:        true,
		UpstreamPort:      mock.port,
		FallbackResolvers: []string{mock.ip},
	}, m, logger)

	r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}
	r.ready = true
	r.SetForwardTable(NewForwardTable([]ForwardZone{
		{Name: "internal.corp", Addrs: []string{mock.ip}, IsStub: true},
	}))

	result, err := r.Resolve("host.internal.corp", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR from fallback, got %d", result.RCODE)
	}
	if len(result.Answers) != 1 {
		t.Errorf("expected 1 answer from fallback, got %d", len(result.Answers))
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 1 {
		t.Errorf("expected 1 fallback query (stub zone path), got %d", snap.FallbackQueries)
	}
	if snap.FallbackRecoveries != 1 {
		t.Errorf("expected 1 fallback recovery, got %d", snap.FallbackRecoveries)
	}
}

func TestQueryFallback_NetworkError(t *testing.T) {
	// Fallback resolver is unreachable (no server listening).
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		UpstreamTimeout:   500 * time.Millisecond,
		UpstreamRetries:   1,
		FallbackResolvers: []string{"192.0.2.1"}, // RFC 5737 TEST-NET, unreachable
	}, m, logger)

	result := r.queryFallback("example.com", dns.TypeA, dns.ClassIN)
	if result != nil {
		t.Error("expected nil when fallback resolver is unreachable")
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 1 {
		t.Errorf("expected 1 fallback query, got %d", snap.FallbackQueries)
	}
	if snap.FallbackRecoveries != 0 {
		t.Errorf("expected 0 recoveries, got %d", snap.FallbackRecoveries)
	}
}

func TestQueryFallback_MultipleResolvers_PicksOne(t *testing.T) {
	// Verify that with multiple fallback resolvers, exactly one query is made.
	fallbackMock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(),
				QDCount: 1,
				ANCount: 1,
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 1, 1, 1},
			}},
		}
	})
	defer fallbackMock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// All three entries point to the same mock, but the resolver picks one randomly.
	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		UpstreamPort:      fallbackMock.port,
		FallbackResolvers: []string{fallbackMock.ip, fallbackMock.ip, fallbackMock.ip},
	}, m, logger)

	result := r.queryFallback("example.com", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	snap := m.Snapshot()
	if snap.FallbackQueries != 1 {
		t.Errorf("expected exactly 1 fallback query (not 3), got %d", snap.FallbackQueries)
	}
}
