package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestRootDSRecordsExist(t *testing.T) {
	if len(RootDSRecords) == 0 {
		t.Fatal("RootDSRecords should not be empty")
	}
}

func TestRootKSK20326(t *testing.T) {
	// The well-known root KSK (2017) should be present with key tag 20326
	// and algorithm RSA/SHA-256 (algorithm 8).
	var found bool
	for _, ds := range RootDSRecords {
		if ds.KeyTag == 20326 {
			found = true

			if ds.Algorithm != dns.AlgRSASHA256 {
				t.Errorf("root KSK 20326 algorithm: got %d, want %d (RSASHA256)",
					ds.Algorithm, dns.AlgRSASHA256)
			}

			if ds.DigestType != dns.DigestSHA256 {
				t.Errorf("root KSK 20326 digest type: got %d, want %d (SHA-256)",
					ds.DigestType, dns.DigestSHA256)
			}

			if len(ds.Digest) == 0 {
				t.Error("root KSK 20326 digest should not be empty")
			}

			// SHA-256 digest is 32 bytes.
			if len(ds.Digest) != 32 {
				t.Errorf("root KSK 20326 digest length: got %d, want 32", len(ds.Digest))
			}

			break
		}
	}

	if !found {
		t.Error("root KSK with key tag 20326 not found in RootDSRecords")
	}
}

func TestHexDecode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "simple hex",
			input:    "AABB",
			expected: []byte{0xAA, 0xBB},
		},
		{
			name:     "hex with spaces",
			input:    "AA BB CC",
			expected: []byte{0xAA, 0xBB, 0xCC},
		},
		{
			name:     "lowercase hex",
			input:    "aabbcc",
			expected: []byte{0xAA, 0xBB, 0xCC},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hexDecode(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("length mismatch: got %d, want %d", len(result), len(tt.expected))
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestHexDecode_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid hex input")
		}
	}()
	hexDecode("ZZZZ") // invalid hex should panic
}
