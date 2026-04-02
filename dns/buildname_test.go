package dns

import "testing"

func TestBuildPlainName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"example.com", "example.com"},
		{"www.google.com", "www.google.com"},
		{"a.b.c", "a.b.c"},
		{"single", "single"},
		{".", ""},
		{"", ""},
	}

	for _, tt := range tests {
		b := BuildPlainName(tt.name)
		if b == nil {
			t.Fatalf("BuildPlainName(%q) returned nil", tt.name)
		}

		decoded, _, err := DecodeName(b, 0)
		if err != nil {
			t.Fatalf("BuildPlainName(%q) → decode error: %v", tt.name, err)
		}
		if decoded != tt.expected {
			t.Errorf("BuildPlainName(%q) → decoded %q, want %q", tt.name, decoded, tt.expected)
		}
	}
}

func TestBuildPlainNameRoundTrip(t *testing.T) {
	names := []string{"ns1.google.com", "mail.example.org", "a.b.c.d.e.f.com"}
	for _, name := range names {
		b := BuildPlainName(name)
		decoded, _, err := DecodeName(b, 0)
		if err != nil {
			t.Fatalf("round-trip %q error: %v", name, err)
		}
		if decoded != name {
			t.Errorf("round-trip %q got %q", name, decoded)
		}
	}
}
