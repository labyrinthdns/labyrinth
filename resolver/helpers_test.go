package resolver

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/labyrinth-dns/labyrinth/cache"
	"github.com/labyrinth-dns/labyrinth/dns"
	"github.com/labyrinth-dns/labyrinth/metrics"
)

func TestParseIPv4Bytes(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"1.2.3.4", []byte{1, 2, 3, 4}},
		{"192.168.1.1", []byte{192, 168, 1, 1}},
		{"0.0.0.0", []byte{0, 0, 0, 0}},
		{"255.255.255.255", []byte{255, 255, 255, 255}},
	}
	for _, tt := range tests {
		result := parseIPv4Bytes(tt.input)
		if len(result) != 4 {
			t.Errorf("parseIPv4Bytes(%q): expected 4 bytes, got %d", tt.input, len(result))
			continue
		}
		for i, b := range result {
			if b != tt.expected[i] {
				t.Errorf("parseIPv4Bytes(%q)[%d]: expected %d, got %d", tt.input, i, tt.expected[i], b)
			}
		}
	}
}

func TestParseIPv4BytesInvalid(t *testing.T) {
	invalids := []string{"", "1.2.3", "1.2.3.4.5", "256.0.0.1", "abc"}
	for _, s := range invalids {
		result := parseIPv4Bytes(s)
		if result != nil {
			t.Errorf("parseIPv4Bytes(%q) should return nil, got %v", s, result)
		}
	}
}

func TestNewResolver(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	r := NewResolver(c, ResolverConfig{
		MaxDepth: 30, MaxCNAMEDepth: 10,
		UpstreamTimeout: 2 * time.Second, UpstreamRetries: 3,
		QMinEnabled: true, PreferIPv4: true,
	}, m, logger)

	if r == nil {
		t.Fatal("NewResolver returned nil")
	}
	if r.IsReady() {
		t.Error("should not be ready before priming")
	}
	if r.inflight == nil {
		t.Error("inflight should be initialized")
	}
}

func TestCacheDelegation(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	nsRData := buildPlainNameRData("ns1.example.com")
	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN,
				TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData},
		},
	}

	r.cacheDelegation(msg, "example.com")

	entry, ok := c.Get("example.com", dns.TypeNS, dns.ClassIN)
	if !ok {
		t.Fatal("NS delegation should be cached")
	}
	if len(entry.Records) != 1 {
		t.Errorf("expected 1 NS record, got %d", len(entry.Records))
	}
}

func TestCacheDelegationEmpty(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 3600},
		},
	}

	r.cacheDelegation(msg, "example.com")

	_, ok := c.Get("example.com", dns.TypeNS, dns.ClassIN)
	if ok {
		t.Error("should not cache when no NS records")
	}
}

func TestExtractCNAMERecords(t *testing.T) {
	cnameRData := buildPlainNameRData("cdn.example.com")
	msg := &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "www.example.com", Type: dns.TypeCNAME, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(cnameRData)), RData: cnameRData},
			{Name: "cdn.example.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4}},
		},
	}

	records := extractCNAMERecords(msg, "www.example.com")
	if len(records) != 1 {
		t.Errorf("expected 1 CNAME record, got %d", len(records))
	}
}

func TestExtractCNAMERecordsNone(t *testing.T) {
	msg := &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "test.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4}},
		},
	}

	records := extractCNAMERecords(msg, "test.com")
	if len(records) != 0 {
		t.Errorf("expected 0 CNAME records, got %d", len(records))
	}
}

func TestResolveCNAMEDepthExceeded(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{
		MaxDepth: 5, MaxCNAMEDepth: 0, // force CNAME chain too long
		UpstreamTimeout: 100 * time.Millisecond, UpstreamRetries: 1,
	}, m, logger)

	// resolveIterative with cnameDepth > MaxCNAMEDepth should error
	_, err := r.resolveIterative("test.com", dns.TypeA, dns.ClassIN, 1, newVisitedSet())
	if err == nil {
		t.Error("expected error for CNAME chain too long")
	}
}

func TestRemoveNSByIPNoneMatch(t *testing.T) {
	entries := []nsEntry{
		{hostname: "ns1.test.com", ipv4: "1.1.1.1"},
		{hostname: "ns2.test.com", ipv4: "2.2.2.2"},
	}
	result := removeNSByIP(entries, "9.9.9.9")
	if len(result) != 2 {
		t.Errorf("expected 2 (no match), got %d", len(result))
	}
}

func TestRemoveNSByIPv6(t *testing.T) {
	entries := []nsEntry{
		{hostname: "ns1.test.com", ipv6: "::1"},
		{hostname: "ns2.test.com", ipv6: "::2"},
	}
	result := removeNSByIP(entries, "::1")
	if len(result) != 1 {
		t.Errorf("expected 1, got %d", len(result))
	}
}
