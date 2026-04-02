package dnssec

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// mockQuerier implements the Querier interface for testing.
type mockQuerier struct {
	responses map[string]*dns.Message
}

func (m *mockQuerier) QueryDNSSEC(name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	key := fmt.Sprintf("%s|%d", name, qtype)
	if resp, ok := m.responses[key]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("no mock response for %s type %d", name, qtype)
}

func TestValidationResultString(t *testing.T) {
	tests := []struct {
		result   ValidationResult
		expected string
	}{
		{Secure, "Secure"},
		{Insecure, "Insecure"},
		{Bogus, "Bogus"},
		{Indeterminate, "Indeterminate"},
		{ValidationResult(99), "ValidationResult(99)"},
		{ValidationResult(-1), "ValidationResult(-1)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.result.String()
			if got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestValidateResponse_NilResponse(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	result := v.ValidateResponse(nil, "example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("nil response: got %v, want Insecure", result)
	}
}

func TestValidateResponse_EmptyAnswers(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	resp := &dns.Message{
		Answers: []dns.ResourceRecord{},
	}

	result := v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("empty answers: got %v, want Insecure", result)
	}
}

func TestValidateResponse_NoRRSIG(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	resp := &dns.Message{
		Answers: []dns.ResourceRecord{
			{
				Name:  "example.com.",
				Type:  dns.TypeA,
				Class: dns.ClassIN,
				TTL:   300,
				RData: []byte{93, 184, 216, 34},
			},
		},
	}

	result := v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("no RRSIG: got %v, want Insecure", result)
	}
}

func TestNewValidator(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}

	// With nil logger.
	v := NewValidator(mq, nil)
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if v.querier != mq {
		t.Error("querier not set correctly")
	}
	if v.keyCache == nil {
		t.Error("keyCache not initialized")
	}
	if len(v.trustAnchors) == 0 {
		t.Error("trustAnchors should be initialized with RootDSRecords")
	}
	if v.logger == nil {
		t.Error("logger should be set to default when nil is passed")
	}

	// With explicit logger.
	logger := slog.Default()
	v2 := NewValidator(mq, logger)
	if v2.logger != logger {
		t.Error("explicit logger not set correctly")
	}
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "."},
		{".", "."},
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
		{"com", "com."},
		{"com.", "com."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeName(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestBuildZoneChain(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		expected []string
	}{
		{
			name:     "root",
			zone:     ".",
			expected: []string{"."},
		},
		{
			name:     "TLD",
			zone:     "com.",
			expected: []string{".", "com."},
		},
		{
			name:     "second level domain",
			zone:     "example.com.",
			expected: []string{".", "com.", "example.com."},
		},
		{
			name:     "third level domain",
			zone:     "www.example.com.",
			expected: []string{".", "com.", "example.com.", "www.example.com."},
		},
		{
			name:     "without trailing dot",
			zone:     "example.com",
			expected: []string{".", "com.", "example.com."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildZoneChain(tt.zone)
			if len(got) != len(tt.expected) {
				t.Fatalf("buildZoneChain(%q) returned %d zones, want %d: got %v",
					tt.zone, len(got), len(tt.expected), got)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("buildZoneChain(%q)[%d] = %q, want %q",
						tt.zone, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestFilterRRSet(t *testing.T) {
	rrs := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, RData: []byte{1, 2, 3, 4}},
		{Name: "example.com.", Type: dns.TypeAAAA, RData: make([]byte, 16)},
		{Name: "example.com.", Type: dns.TypeA, RData: []byte{5, 6, 7, 8}},
		{Name: "example.com.", Type: dns.TypeMX, RData: []byte{0, 10}},
	}

	aRecords := filterRRSet(rrs, dns.TypeA)
	if len(aRecords) != 2 {
		t.Errorf("expected 2 A records, got %d", len(aRecords))
	}

	aaaaRecords := filterRRSet(rrs, dns.TypeAAAA)
	if len(aaaaRecords) != 1 {
		t.Errorf("expected 1 AAAA record, got %d", len(aaaaRecords))
	}

	txtRecords := filterRRSet(rrs, dns.TypeTXT)
	if len(txtRecords) != 0 {
		t.Errorf("expected 0 TXT records, got %d", len(txtRecords))
	}

	emptyInput := filterRRSet(nil, dns.TypeA)
	if len(emptyInput) != 0 {
		t.Errorf("expected 0 records for nil input, got %d", len(emptyInput))
	}
}

func TestValidateResponse_WithMalformedRRSIG(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	// Create a response with a malformed RRSIG (RDATA too short to parse).
	resp := &dns.Message{
		Answers: []dns.ResourceRecord{
			{
				Name:  "example.com.",
				Type:  dns.TypeA,
				Class: dns.ClassIN,
				TTL:   300,
				RData: []byte{93, 184, 216, 34},
			},
			{
				Name:  "example.com.",
				Type:  dns.TypeRRSIG,
				Class: dns.ClassIN,
				TTL:   300,
				RData: []byte{0, 1, 2}, // too short to be a valid RRSIG
			},
		},
	}

	// Malformed RRSIG is skipped, so no valid RRSIGs found -> Insecure.
	result := v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("malformed RRSIG: got %v, want Insecure", result)
	}
}

func TestFetchDNSKEYs_CacheMiss(t *testing.T) {
	dnskeyRData := make([]byte, 4+32)
	binary.BigEndian.PutUint16(dnskeyRData[0:2], 256) // flags
	dnskeyRData[2] = 3                                 // protocol
	dnskeyRData[3] = dns.AlgED25519                    // algorithm
	// 32 bytes of fake public key follow (already zeroed).

	mq := &mockQuerier{
		responses: map[string]*dns.Message{
			"example.com.|48": { // TypeDNSKEY = 48
				Answers: []dns.ResourceRecord{
					{
						Name:  "example.com.",
						Type:  dns.TypeDNSKEY,
						Class: dns.ClassIN,
						TTL:   3600,
						RData: dnskeyRData,
					},
				},
			},
		},
	}

	v := NewValidator(mq, nil)

	keys, err := v.fetchDNSKEYs("example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYs failed: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 DNSKEY, got %d", len(keys))
	}

	// Fetch again: should come from cache.
	keys2, err := v.fetchDNSKEYs("example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYs (cached) failed: %v", err)
	}
	if len(keys2) != 1 {
		t.Errorf("expected 1 DNSKEY from cache, got %d", len(keys2))
	}
}

func TestFetchDNSKEYs_QueryError(t *testing.T) {
	// Empty mock: no responses configured, so query will fail.
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	_, err := v.fetchDNSKEYs("example.com.")
	if err == nil {
		t.Error("expected error when querier has no response")
	}
}

