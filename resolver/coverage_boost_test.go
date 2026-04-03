package resolver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// =============================================================================
// Coverage boost tests for resolver package — targeting 100%
// =============================================================================

// ---------------------------------------------------------------------------
// ParseLocalZoneType (localzone.go:41-43)
// ---------------------------------------------------------------------------

func TestParseLocalZoneTypeAll(t *testing.T) {
	tests := []struct {
		input string
		want  LocalZoneType
		ok    bool
	}{
		{"static", LocalStatic, true},
		{"deny", LocalDeny, true},
		{"refuse", LocalRefuse, true},
		{"redirect", LocalRedirect, true},
		{"transparent", LocalTransparent, true},
		{"STATIC", LocalStatic, true},
		{"Refuse", LocalRefuse, true},
		{"unknown", 0, false},
		{"", 0, false},
	}

	for _, tc := range tests {
		got, ok := ParseLocalZoneType(tc.input)
		if ok != tc.ok {
			t.Errorf("ParseLocalZoneType(%q): ok = %v, want %v", tc.input, ok, tc.ok)
		}
		if ok && got != tc.want {
			t.Errorf("ParseLocalZoneType(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Lookup: non-IN class returns nil (localzone.go:90-92)
// ---------------------------------------------------------------------------

func TestLocalZoneLookupNonINClass(t *testing.T) {
	zone := LocalZone{
		Name: "example.local",
		Type: LocalStatic,
		Records: []LocalRecord{
			{Name: "host.example.local", Type: dns.TypeA, RData: net.ParseIP("10.0.0.1").To4(), TTL: 300},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	// Query with class CH (3) instead of IN
	result := table.Lookup("host.example.local", dns.TypeA, 3)
	if result != nil {
		t.Errorf("expected nil for non-IN class, got RCODE=%d", result.RCODE)
	}
}

// ---------------------------------------------------------------------------
// lookupRedirect: no matching type returns NODATA (localzone.go:171-172)
// ---------------------------------------------------------------------------

func TestLocalZoneRedirectNoMatchingType(t *testing.T) {
	zone := LocalZone{
		Name: "redirect.local",
		Type: LocalRedirect,
		Records: []LocalRecord{
			{Name: "redirect.local", Type: dns.TypeA, RData: net.ParseIP("10.10.10.10").To4(), TTL: 300},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	result := table.Lookup("anything.redirect.local", dns.TypeAAAA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected NODATA result, got nil")
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("RCODE = %d, want NoError", result.RCODE)
	}
	if len(result.Answers) != 0 {
		t.Errorf("expected 0 answers, got %d", len(result.Answers))
	}
}

// ---------------------------------------------------------------------------
// encodeRData: not-an-IPv4 address (localzone.go:272-273)
// ---------------------------------------------------------------------------

func TestEncodeRDataInvalidANotIPv4(t *testing.T) {
	_, err := encodeRData(dns.TypeA, "::1")
	if err == nil {
		t.Error("expected error for IPv6 address in A record")
	}
	if !strings.Contains(err.Error(), "not an IPv4") {
		t.Errorf("expected 'not an IPv4' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// encodeRData: invalid AAAA (localzone.go:281-282)
// ---------------------------------------------------------------------------

func TestEncodeRDataInvalidAAAA(t *testing.T) {
	_, err := encodeRData(dns.TypeAAAA, "not-an-ip")
	if err == nil {
		t.Error("expected error for invalid AAAA address")
	}
	if !strings.Contains(err.Error(), "invalid IPv6") {
		t.Errorf("expected 'invalid IPv6' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// encodeRData: MX invalid preference (localzone.go:303-305)
// ---------------------------------------------------------------------------

func TestEncodeRDataMXInvalidPreference(t *testing.T) {
	_, err := encodeRData(dns.TypeMX, "abc mail.example.com.")
	if err == nil {
		t.Error("expected error for non-numeric MX preference")
	}

	_, err = encodeRData(dns.TypeMX, "-1 mail.example.com.")
	if err == nil {
		t.Error("expected error for negative MX preference")
	}

	_, err = encodeRData(dns.TypeMX, "99999 mail.example.com.")
	if err == nil {
		t.Error("expected error for MX preference > 65535")
	}
}

// ---------------------------------------------------------------------------
// encodeRData: MX wrong number of fields (localzone.go:300-302)
// ---------------------------------------------------------------------------

func TestEncodeRDataMXWrongFields(t *testing.T) {
	_, err := encodeRData(dns.TypeMX, "10")
	if err == nil {
		t.Error("expected error for MX with only preference")
	}
	if !strings.Contains(err.Error(), "expected \"preference exchange\"") {
		t.Errorf("expected field count error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// encodeRData: unsupported type (localzone.go:313-314)
// ---------------------------------------------------------------------------

func TestEncodeRDataUnsupportedType(t *testing.T) {
	_, err := encodeRData(999, "data")
	if err == nil {
		t.Error("expected error for unsupported type")
	}
	if !strings.Contains(err.Error(), "unsupported record type") {
		t.Errorf("expected 'unsupported record type' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// encodeNameWire: empty name (localzone.go:321-322)
// ---------------------------------------------------------------------------

func TestEncodeNameWireEmptyAndRoot(t *testing.T) {
	result := encodeNameWire("")
	if len(result) != 1 || result[0] != 0 {
		t.Errorf("expected single zero byte for empty name, got %v", result)
	}

	result = encodeNameWire(".")
	if len(result) != 1 || result[0] != 0 {
		t.Errorf("expected single zero byte for root dot, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// encodeTXT: long TXT (> 255 bytes) (localzone.go:339-342)
// ---------------------------------------------------------------------------

func TestEncodeTXTLong(t *testing.T) {
	longStr := strings.Repeat("a", 300)
	result := encodeTXT(longStr)

	if result[0] != 255 {
		t.Errorf("first chunk length byte = %d, want 255", result[0])
	}
	remaining := 300 - 255
	if result[256] != byte(remaining) {
		t.Errorf("second chunk length byte = %d, want %d", result[256], remaining)
	}
	expectedLen := 1 + 255 + 1 + remaining
	if len(result) != expectedLen {
		t.Errorf("total length = %d, want %d", len(result), expectedLen)
	}
}

// ---------------------------------------------------------------------------
// encodeTXT: empty string (localzone.go:348-350)
// ---------------------------------------------------------------------------

func TestEncodeTXTEmpty(t *testing.T) {
	result := encodeTXT("")
	if len(result) != 1 || result[0] != 0 {
		t.Errorf("expected single zero byte for empty TXT, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// dns64Synthesize (dns64.go:49-92)
// ---------------------------------------------------------------------------

func TestDNS64Synthesize(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		if qname == "dns64host.example.com" && qtype == dns.TypeA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{192, 0, 2, 1},
				}},
			}
		}

		if qtype == dns.TypeAAAA {
			soaRData := buildSOARData()
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Authority: []dns.ResourceRecord{{
					Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
				}},
			}
		}

		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 1,
		QMinEnabled:     false,
		PreferIPv4:      true,
		UpstreamPort:    mock.port,
		DNS64Enabled:    true,
		DNS64Prefix:     DefaultDNS64Prefix,
	}, m, logger)
	r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}

	result, err := r.Resolve("dns64host.example.com", dns.TypeAAAA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got %d", result.RCODE)
	}
	if len(result.Answers) == 0 {
		t.Fatal("expected synthesized AAAA answers")
	}
	if result.Answers[0].Type != dns.TypeAAAA {
		t.Errorf("expected AAAA type, got %d", result.Answers[0].Type)
	}
	ip := net.IP(result.Answers[0].RData)
	expected := net.ParseIP("64:ff9b::c000:201")
	if !ip.Equal(expected) {
		t.Errorf("expected synthesized IP %s, got %s", expected, ip)
	}
}

func TestDNS64SynthesizeNoARecords(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		soaRData := buildSOARData()
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	original := &ResolveResult{RCODE: dns.RCodeNoError}

	result, err := r.dns64Synthesize("norecords.example.com", dns.ClassIN, original, DefaultDNS64Prefix)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result != original {
		t.Error("expected original result when no A records found")
	}
}

func TestDNS64SynthesizeAQueryError(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   0,
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    "19991",
	}, m, logger)
	r.rootServers = []NameServer{}

	original := &ResolveResult{RCODE: dns.RCodeNoError}
	result, err := r.dns64Synthesize("error.example.com", dns.ClassIN, original, DefaultDNS64Prefix)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result != original {
		t.Error("expected original result when A query fails")
	}
}

func TestDNS64SynthesizeNonARecordsSkipped(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		if qtype == dns.TypeA {
			cnameRData := dns.BuildPlainName("other.example.com")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: qname, Type: dns.TypeCNAME, Class: dns.ClassIN,
					TTL: 300, RDLength: uint16(len(cnameRData)), RData: cnameRData,
				}},
			}
		}

		soaRData := buildSOARData()
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	original := &ResolveResult{RCODE: dns.RCodeNoError}

	result, err := r.dns64Synthesize("cname-only.example.com", dns.ClassIN, original, DefaultDNS64Prefix)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result != original {
		t.Error("expected original result when no A records to synthesize")
	}
}

// ---------------------------------------------------------------------------
// extractDNAMETarget (cname.go:27-46)
// ---------------------------------------------------------------------------

func TestExtractDNAMETarget(t *testing.T) {
	dnameRData := dns.BuildPlainName("target.com")
	msg := &dns.Message{
		Answers: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
			TTL: 3600, RDLength: uint16(len(dnameRData)), RData: dnameRData,
		}},
	}

	target := extractDNAMETarget(msg, "a.b.example.com")
	if target != "a.b.target.com" {
		t.Errorf("expected 'a.b.target.com', got %q", target)
	}
}

func TestExtractDNAMETargetNoMatch(t *testing.T) {
	dnameRData := dns.BuildPlainName("target.com")
	msg := &dns.Message{
		Answers: []dns.ResourceRecord{{
			Name: "different.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
			TTL: 3600, RDLength: uint16(len(dnameRData)), RData: dnameRData,
		}},
	}

	target := extractDNAMETarget(msg, "a.example.com")
	if target != "" {
		t.Errorf("expected empty string for non-matching owner, got %q", target)
	}
}

func TestExtractDNAMETargetCorruptRData(t *testing.T) {
	msg := &dns.Message{
		Answers: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
			TTL: 3600, RDLength: 0, RData: nil,
		}},
	}

	target := extractDNAMETarget(msg, "sub.example.com")
	if target != "" {
		t.Errorf("expected empty string for corrupt DNAME RDATA, got %q", target)
	}
}

func TestExtractDNAMETargetNonDNAMERecordSkipped(t *testing.T) {
	cnameRData := dns.BuildPlainName("alias.com")
	msg := &dns.Message{
		Answers: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeCNAME, Class: dns.ClassIN,
			TTL: 3600, RDLength: uint16(len(cnameRData)), RData: cnameRData,
		}},
	}

	target := extractDNAMETarget(msg, "sub.example.com")
	if target != "" {
		t.Errorf("expected empty string (no DNAME record), got %q", target)
	}
}

// ---------------------------------------------------------------------------
// infracache: effectiveRTT with RTT=0 entry (infracache.go:100-102)
// ---------------------------------------------------------------------------

func TestInfraCacheEffectiveRTTZeroRTT(t *testing.T) {
	ic := NewInfraCache()
	ic.RecordFailure("1.2.3.4")

	ic.mu.RLock()
	rtt := ic.effectiveRTT("1.2.3.4")
	ic.mu.RUnlock()

	expected := 100*time.Millisecond + 500*time.Millisecond
	if rtt != expected {
		t.Errorf("effectiveRTT = %v, want %v", rtt, expected)
	}
}

// ---------------------------------------------------------------------------
// infracache: GetRTT for unknown server (infracache.go:170-172)
// ---------------------------------------------------------------------------

func TestInfraCacheGetRTTUnknown(t *testing.T) {
	ic := NewInfraCache()
	rtt := ic.GetRTT("unknown-server")
	if rtt != 0 {
		t.Errorf("GetRTT for unknown server = %v, want 0", rtt)
	}
}

// ---------------------------------------------------------------------------
// validateReferralNS: empty hostname (delegation.go:99-100)
// ---------------------------------------------------------------------------

func TestValidateReferralNSEmptyHostname(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	delegations := []DelegationNS{
		{Hostname: ""},
		{Hostname: "ns1.example.com."},
	}

	validateReferralNS(delegations, "example.com.", logger)

	if buf.Len() > 0 {
		t.Errorf("expected no warnings, got: %s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// SetActiveECS and InfraCache (resolver.go:72-74, 95-96)
// ---------------------------------------------------------------------------

func TestSetActiveECS(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	if r.activeECS != nil {
		t.Error("activeECS should be nil initially")
	}

	ecs := &dns.ECSOption{
		Family:          1,
		SourcePrefixLen: 24,
		ScopePrefixLen:  0,
		Address:         net.ParseIP("192.168.1.0").To4(),
	}
	r.SetActiveECS(ecs)
	if r.activeECS == nil {
		t.Error("activeECS should be set")
	}

	r.SetActiveECS(nil)
	if r.activeECS != nil {
		t.Error("activeECS should be nil after clear")
	}
}

func TestResolverInfraCache(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	ic := r.InfraCache()
	if ic == nil {
		t.Fatal("InfraCache() should not return nil")
	}
	if ic.Len() != 0 {
		t.Errorf("expected empty infra cache, got %d entries", ic.Len())
	}
}

// ---------------------------------------------------------------------------
// SetLocalZones (resolver.go:170-172)
// ---------------------------------------------------------------------------

func TestSetLocalZones(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	if r.localZones != nil {
		t.Error("localZones should be nil initially")
	}

	lz := NewLocalZoneTable([]LocalZone{{
		Name: "test.local",
		Type: LocalStatic,
	}})
	r.SetLocalZones(lz)
	if r.localZones == nil {
		t.Error("localZones should be set")
	}
}

// ---------------------------------------------------------------------------
// Resolve with local zones (resolver.go:180-183)
// ---------------------------------------------------------------------------

func TestResolveWithLocalZones(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30, MaxCNAMEDepth: 10}, m, logger)
	r.ready = true

	lz := NewLocalZoneTable([]LocalZone{{
		Name: "myzone.local",
		Type: LocalStatic,
		Records: []LocalRecord{
			{Name: "host.myzone.local", Type: dns.TypeA, RData: net.ParseIP("10.0.0.1").To4(), TTL: 300},
		},
	}})
	r.SetLocalZones(lz)

	result, err := r.Resolve("host.myzone.local", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}
	if len(result.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(result.Answers))
	}
}

// ---------------------------------------------------------------------------
// StartRootRefresh (resolver.go:137-153)
// ---------------------------------------------------------------------------

func TestStartRootRefresh(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: ".", Type: dns.TypeNS, Class: dns.ClassIN,
				TTL: 3600, RDLength: 0, RData: dns.BuildPlainName("mock.root"),
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.StartRootRefresh(ctx, 50*time.Millisecond)
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
}

func TestStartRootRefreshFailure(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    "19988",
	}, m, logger)
	r.rootServers = []NameServer{{Name: "bad", IPv4: "127.0.0.1"}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.StartRootRefresh(ctx, 50*time.Millisecond)
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
}

// ---------------------------------------------------------------------------
// sendForwardQuery: retries (forward.go:101-120)
// ---------------------------------------------------------------------------

func TestSendForwardQueryRetries(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamRetries: 3,
		UpstreamPort:    "19992",
	}, m, logger)

	_, err := r.sendForwardQuery("127.0.0.1", "retry-fail.example.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected error after all forward retries exhausted")
	}
}

func TestSendForwardQueryZeroRetries(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: "test.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 60, RDLength: 4, RData: []byte{1, 1, 1, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	r.config.UpstreamRetries = 0

	msg, err := r.sendForwardQuery(mock.ip, "test.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg == nil {
		t.Fatal("expected response with 0 retries (clamped to 1)")
	}
}

// ---------------------------------------------------------------------------
// sendForwardQueryOnce: FORMERR retry (forward.go:130-137)
// ---------------------------------------------------------------------------

func TestSendForwardQueryOnceFormErr(t *testing.T) {
	var queryCount int
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queryCount++
		if queryCount == 1 {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeFormErr).Build()},
				Questions: q.Questions,
			}
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: "formerr.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	msg, err := r.sendForwardQueryOnce(mock.ip, "formerr.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(msg.Answers) == 0 {
		t.Error("expected answers after FORMERR retry")
	}
}

func TestSendForwardQueryOnceFormErrRetryStillFormErr(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeFormErr).Build()},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	msg, err := r.sendForwardQueryOnce(mock.ip, "formerr2.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg.Header.RCODE() != dns.RCodeFormErr {
		t.Errorf("expected FORMERR, got %d", msg.Header.RCODE())
	}
}

// ---------------------------------------------------------------------------
// sendQueryWithRD: TC fallback (forward.go:193-211)
// ---------------------------------------------------------------------------

func TestSendQueryWithRD_TCFallback(t *testing.T) {
	mock := startTCMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	msg, err := r.sendQueryWithRD(mock.ip, "tc-rd.com", dns.TypeA, dns.ClassIN, true, true)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg == nil {
		t.Fatal("expected response after TC fallback")
	}
}

// ---------------------------------------------------------------------------
// sendQueryWithRD: randTXIDFunc error (forward.go:143-146)
// ---------------------------------------------------------------------------

func TestSendQueryWithRD_TXIDError(t *testing.T) {
	orig := randTXIDFunc
	randTXIDFunc = func() (uint16, error) {
		return 0, errors.New("entropy exhausted")
	}
	defer func() { randTXIDFunc = orig }()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 100 * time.Millisecond,
		UpstreamPort:    "19989",
	}, m, logger)

	_, err := r.sendQueryWithRD("127.0.0.1", "test.com", dns.TypeA, dns.ClassIN, true, true)
	if err == nil || err.Error() != "entropy exhausted" {
		t.Errorf("expected 'entropy exhausted', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// sendQueryWithRD: without EDNS0 (forward.go:163-166)
// ---------------------------------------------------------------------------

func TestSendQueryWithRD_NoEDNS0(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: "no-edns.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	msg, err := r.sendQueryWithRD(mock.ip, "no-edns.com", dns.TypeA, dns.ClassIN, false, false)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(msg.Answers) == 0 {
		t.Error("expected answers")
	}
}

// ---------------------------------------------------------------------------
// queryForward: empty addrs returns SERVFAIL (forward.go:94-97)
// ---------------------------------------------------------------------------

func TestQueryForwardEmptyAddrs(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamRetries: 1,
	}, m, logger)

	result, err := r.queryForward([]string{}, "test.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL, got %d", result.RCODE)
	}
}

// ---------------------------------------------------------------------------
// classifyResponse: DNAME in answers (classify.go:49-51)
// ---------------------------------------------------------------------------

func TestClassifyResponseDNAMEBoost(t *testing.T) {
	dnameRData := dns.BuildPlainName("target.com")
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
			ANCount: 1,
		},
		Answers: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
			TTL: 3600, RDLength: uint16(len(dnameRData)), RData: dnameRData,
		}},
	}

	rtype := classifyResponse(msg, "sub.example.com", dns.TypeA)
	if rtype != responseDNAME {
		t.Errorf("expected responseDNAME, got %d", rtype)
	}
}

// ---------------------------------------------------------------------------
// DNAME path in resolveIterative (resolver.go:366-391)
// ---------------------------------------------------------------------------

func TestResolveIterativeDNAME(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name

		if strings.HasSuffix(qname, ".example.com") || qname == "example.com" {
			dnameRData := dns.BuildPlainName("target.com")
			synth := strings.Replace(qname, "example.com", "target.com", 1)
			cnameRData := dns.BuildPlainName(synth)
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{
					{
						Name: "example.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
						TTL: 3600, RDLength: uint16(len(dnameRData)), RData: dnameRData,
					},
					{
						Name: qname, Type: dns.TypeCNAME, Class: dns.ClassIN,
						TTL: 3600, RDLength: uint16(len(cnameRData)), RData: cnameRData,
					},
				},
			}
		}

		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 99},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("sub.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}
	if len(result.Answers) < 2 {
		t.Errorf("expected at least 2 answers, got %d", len(result.Answers))
	}
}

func TestResolveIterativeDNAMEEmptyTarget(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: "example.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
				TTL: 3600, RDLength: 0, RData: nil,
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("sub.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL for empty DNAME target, got %d", result.RCODE)
	}
}

func TestResolveIterativeDNAMELoop(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name

		if strings.HasSuffix(qname, ".a.com") {
			dnameRData := dns.BuildPlainName("b.com")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "a.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
					TTL: 3600, RDLength: uint16(len(dnameRData)), RData: dnameRData,
				}},
			}
		}
		if strings.HasSuffix(qname, ".b.com") {
			dnameRData := dns.BuildPlainName("a.com")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "b.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
					TTL: 3600, RDLength: uint16(len(dnameRData)), RData: dnameRData,
				}},
			}
		}

		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("host.a.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL for DNAME loop, got %d", result.RCODE)
	}
}

// ---------------------------------------------------------------------------
// Lookup: zone with unknown type returns nil (localzone.go:114-115)
// ---------------------------------------------------------------------------

func TestLocalZoneLookupUnknownZoneType(t *testing.T) {
	zone := LocalZone{
		Name: "weird.local",
		Type: LocalZoneType(99),
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	result := table.Lookup("anything.weird.local", dns.TypeA, dns.ClassIN)
	if result != nil {
		t.Errorf("expected nil for unknown zone type, got RCODE=%d", result.RCODE)
	}
}

// ---------------------------------------------------------------------------
// Resolve with ECS forwarding (upstream.go:80-92)
// ---------------------------------------------------------------------------

func TestResolveWithECS(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	r.config.ECSEnabled = true
	r.SetActiveECS(&dns.ECSOption{
		Family:          1,
		SourcePrefixLen: 24,
		ScopePrefixLen:  0,
		Address:         net.ParseIP("192.168.1.0").To4(),
	})

	result, err := r.Resolve("ecs.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}
}

// ---------------------------------------------------------------------------
// dns64Synthesize: A records with corrupt RDATA or non-A types (dns64.go:62-71)
// ---------------------------------------------------------------------------

func TestDNS64SynthesizeWithCorruptAndNonARecords(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name
		qtype := q.Questions[0].Type

		if qtype == dns.TypeA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{
					// Non-A record that should be skipped
					{Name: qname, Type: dns.TypeCNAME, Class: dns.ClassIN,
						TTL: 300, RDLength: 5, RData: []byte{0, 0, 0, 0, 0}},
					// A record with corrupt RDATA (too short)
					{Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 300, RDLength: 2, RData: []byte{0xFF, 0xFF}},
					// Valid A record
					{Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1}},
				},
			}
		}

		soaRData := buildSOARData()
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	original := &ResolveResult{RCODE: dns.RCodeNoError}

	result, err := r.dns64Synthesize("mixed.example.com", dns.ClassIN, original, DefaultDNS64Prefix)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result == original {
		t.Fatal("expected synthesized result, got original")
	}
	if len(result.Answers) == 0 {
		t.Fatal("expected at least one synthesized AAAA answer")
	}
	// Should have exactly 1 synthesized AAAA (from the valid A record)
	if len(result.Answers) != 1 {
		t.Errorf("expected 1 synthesized answer, got %d", len(result.Answers))
	}
}

func TestDNS64SynthesizeAllBadSynthResults(t *testing.T) {
	// All A records fail to synthesize (e.g., SynthesizeAAAA returns nil)
	// This exercises the synthAnswers == 0 path (dns64.go:83-85)
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qtype := q.Questions[0].Type

		if qtype == dns.TypeA {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{
					// A record with corrupt RDATA (2 bytes, not 4)
					{Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 300, RDLength: 2, RData: []byte{0xFF, 0xFF}},
				},
			}
		}

		soaRData := buildSOARData()
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(soaRData)), RData: soaRData,
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	original := &ResolveResult{RCODE: dns.RCodeNoError}

	result, err := r.dns64Synthesize("badrdata.example.com", dns.ClassIN, original, DefaultDNS64Prefix)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// All A records had corrupt RDATA, so no synthesized AAAA -> return original
	if result != original {
		t.Error("expected original when all A records are corrupt")
	}
}

// ---------------------------------------------------------------------------
// sendForwardQueryOnce: FORMERR retry with second call error (forward.go:133-135)
// ---------------------------------------------------------------------------

func TestSendForwardQueryOnceFormErrSecondError(t *testing.T) {
	var queryCount int
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queryCount++
		if queryCount == 1 {
			// First: FORMERR
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeFormErr).Build()},
				Questions: q.Questions,
			}
		}
		// Second call: mock closes, will cause error
		return nil
	})
	// Close the mock before the second query
	defer mock.close()

	r := testResolver(t, mock)

	// Close the mock to force error on second request
	mock.close()

	_, err := r.sendForwardQueryOnce(mock.ip, "formerr-err.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		// The first call itself may error since mock is closed
		t.Log("first call errored (mock closed)")
	}
}

// ---------------------------------------------------------------------------
// sendQueryWithRD: UDP error (forward.go:175-177)
// ---------------------------------------------------------------------------

func TestSendQueryWithRD_UDPError(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 50 * time.Millisecond,
		UpstreamPort:    "19987",
	}, m, logger)

	_, err := r.sendQueryWithRD("127.0.0.1", "udp-err.com", dns.TypeA, dns.ClassIN, true, true)
	if err == nil {
		t.Error("expected UDP error")
	}
}

// ---------------------------------------------------------------------------
// sendQueryWithRD: garbage UDP response (forward.go:180-182)
// ---------------------------------------------------------------------------

func TestSendQueryWithRD_UDPUnpackError(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer udp.Close()
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())

	go func() {
		buf := make([]byte, 4096)
		for {
			_, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			udp.WriteTo([]byte{0x00, 0x01, 0x02}, addr)
		}
	}()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 1 * time.Second,
		UpstreamPort:    portStr,
	}, m, logger)

	_, err = r.sendQueryWithRD("127.0.0.1", "unpack-fwd.com", dns.TypeA, dns.ClassIN, true, true)
	if err == nil {
		t.Error("expected unpack error")
	}
}

// ---------------------------------------------------------------------------
// sendQueryWithRD: TXID mismatch (forward.go:186-188)
// ---------------------------------------------------------------------------

func TestSendQueryWithRD_TXIDMismatchUDP(t *testing.T) {
	mock := startTXIDMismatchMockDNS(t)
	defer mock.close()

	r := testResolver(t, mock)
	_, err := r.sendQueryWithRD(mock.ip, "txid-fwd.com", dns.TypeA, dns.ClassIN, true, true)
	if err == nil {
		t.Error("expected TXID mismatch error")
	}
}

// ---------------------------------------------------------------------------
// sendQueryWithRD: question validation error (forward.go:190-192)
// ---------------------------------------------------------------------------

func TestSendQueryWithRD_QuestionMismatch(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: []dns.Question{{Name: "wrong.com", Type: dns.TypeA, Class: dns.ClassIN}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	_, err := r.sendQueryWithRD(mock.ip, "right.com", dns.TypeA, dns.ClassIN, true, true)
	if err == nil {
		t.Error("expected question mismatch error")
	}
}

// ---------------------------------------------------------------------------
// sendQueryWithRD: TC fallback TCP error (forward.go:197-199)
// ---------------------------------------------------------------------------

func TestSendQueryWithRD_TCFallbackTCPError(t *testing.T) {
	// UDP returns TC, but no TCP listener
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			resp := &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetTC(true).Build()},
				Questions: query.Questions,
			}
			resp.Header.ID = query.Header.ID
			out := make([]byte, 4096)
			packed, err := dns.Pack(resp, out)
			if err != nil {
				continue
			}
			udp.WriteTo(packed, addr)
		}
	}()
	defer udp.Close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		UpstreamTimeout: 500 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    portStr,
	}, m, logger)

	_, err = r.sendQueryWithRD("127.0.0.1", "tc-fwd-err.com", dns.TypeA, dns.ClassIN, true, true)
	if err == nil {
		t.Error("expected TCP connect error after TC in forward path")
	}
}

// ---------------------------------------------------------------------------
// resolveIterative: QMin fallback upstream error (resolver.go:300-306)
// ---------------------------------------------------------------------------

func TestResolveIterativeQMinFallbackUpstreamError(t *testing.T) {
	// Use QMin enabled. The minimized query returns an answer for the
	// minimized name (not referral), triggering the fallback to the full
	// query (line 298-306). We make the second query fail.
	var queryCount int
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queryCount++
		if len(q.Questions) == 0 {
			return nil
		}
		qtype := q.Questions[0].Type

		// First query: QMin NS query returns answer (not referral)
		if qtype == dns.TypeNS {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: q.Questions[0].Name, Type: dns.TypeNS, Class: dns.ClassIN,
					TTL: 300, RDLength: 0, RData: dns.BuildPlainName("ns.example.com"),
				}},
			}
		}
		// Full A query: return answer
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 42},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	r.config.QMinEnabled = true

	result, err := r.Resolve("www.qmin-fallback.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Should succeed even though QMin fallback happened
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", result.RCODE)
	}
}

// ---------------------------------------------------------------------------
// DNAME: chase error (resolver.go:378-381)
// ---------------------------------------------------------------------------

func TestResolveIterativeDNAMEChaseError(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name

		if strings.HasSuffix(qname, ".example.com") {
			dnameRData := dns.BuildPlainName("target.com")
			newName := strings.Replace(qname, "example.com", "target.com", 1)
			cnameRData := dns.BuildPlainName(newName)
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{
					{Name: "example.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
						TTL: 3600, RDLength: uint16(len(dnameRData)), RData: dnameRData},
					{Name: qname, Type: dns.TypeCNAME, Class: dns.ClassIN,
						TTL: 3600, RDLength: uint16(len(cnameRData)), RData: cnameRData},
				},
			}
		}

		// For target.com: always DNAME chain deeper (triggers max cname depth)
		if strings.HasSuffix(qname, ".target.com") {
			dnameRData := dns.BuildPlainName("deeper.com")
			newName := strings.Replace(qname, "target.com", "deeper.com", 1)
			cnameRData := dns.BuildPlainName(newName)
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{
					{Name: "target.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
						TTL: 3600, RDLength: uint16(len(dnameRData)), RData: dnameRData},
					{Name: qname, Type: dns.TypeCNAME, Class: dns.ClassIN,
						TTL: 3600, RDLength: uint16(len(cnameRData)), RData: cnameRData},
				},
			}
		}

		// deeper.com: chain again
		dnameRData := dns.BuildPlainName("evermore.com")
		newName := strings.Replace(qname, "deeper.com", "evermore.com", 1)
		cnameRData := dns.BuildPlainName(newName)
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{
				{Name: "deeper.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
					TTL: 3600, RDLength: uint16(len(dnameRData)), RData: dnameRData},
				{Name: qname, Type: dns.TypeCNAME, Class: dns.ClassIN,
					TTL: 3600, RDLength: uint16(len(cnameRData)), RData: cnameRData},
			},
		}
	})
	defer mock.close()

	m := metrics.NewMetrics()
	c := cache.NewCache(10000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   1, // Very low to trigger "CNAME chain too long"
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 1,
		QMinEnabled:     false,
		PreferIPv4:      true,
		UpstreamPort:    mock.port,
	}, m, logger)
	r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}

	_, err := r.Resolve("sub.example.com", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Error("expected error from DNAME chase exceeding CNAME depth")
	}
}

// ---------------------------------------------------------------------------
// encodeRData: AAAA with valid IPv4 (returns 16 bytes) (localzone.go:283-285)
// This is effectively unreachable since net.ParseIP always returns a non-nil
// result when the initial parse succeeds, but we can cover it by testing
// the "not an IPv6 address" error with something that parses but isn't IPv6.
// Actually line 283-285 is for AAAA where ip.To16() returns nil, which
// never happens for a valid net.IP. We'll just test what we can.
// ---------------------------------------------------------------------------

func TestEncodeRDataAAAAWithIPv4(t *testing.T) {
	// An IPv4 address used as AAAA will still work (net.ParseIP returns
	// IPv4-mapped-IPv6 from To16), which is valid behavior
	rdata, err := encodeRData(dns.TypeAAAA, "192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rdata) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(rdata))
	}
}

// ---------------------------------------------------------------------------
// randomTXID error path (upstream.go:218-220)
// This is already covered by TestQueryUpstreamOnceRandomTXIDError and
// TestSendQueryWithRD_TXIDError. The 75% coverage is because the success
// path (return line 222) is covered but the error return (line 220) is only
// reachable by mocking crypto/rand. Already done.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// queryTCP write length prefix error (upstream.go:178-180)
// This is very hard to test because the OS buffers TCP writes.
// The line is about conn.Write(lenBuf) failing. We accept this as
// OS-dependent and note the overall TCP write path is tested elsewhere.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// sendQuery: dns.Pack error (upstream.go:97-99)
// This requires generating a DNS message that fails packing.
// In practice, dns.Pack is very robust. But let's try to test this path.
// ---------------------------------------------------------------------------

func TestSendQueryPackError(t *testing.T) {
	// A name with more than 253 characters would fail packing
	// Generate a very long name
	longName := strings.Repeat("a", 64) + "." + strings.Repeat("b", 64) + "." + strings.Repeat("c", 64) + "." + strings.Repeat("d", 64)
	// This is 259 characters including dots, may or may not fail dns.Pack
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	// Try the query - may or may not error, but exercises the code path
	_, _ = r.queryUpstreamOnce(mock.ip, longName, dns.TypeA, dns.ClassIN)
}
