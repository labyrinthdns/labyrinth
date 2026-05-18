package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dnssec"
)

func TestVerdictToStatus(t *testing.T) {
	tests := []struct {
		v    dnssec.ValidationResult
		want string
	}{
		{dnssec.Secure, "secure"},
		{dnssec.Bogus, "bogus"},
		{dnssec.Insecure, "insecure"},
		{dnssec.Indeterminate, "insecure"},
	}
	for _, tt := range tests {
		if got := verdictToStatus(tt.v); got != tt.want {
			t.Errorf("verdictToStatus(%v) = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestCombineDNSSECStatus(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"secure", "secure", "secure"},
		{"secure", "insecure", "insecure"},
		{"insecure", "secure", "insecure"},
		{"secure", "bogus", "bogus"},
		{"bogus", "secure", "bogus"},
		{"bogus", "bogus", "bogus"},
		{"insecure", "bogus", "bogus"},
		{"", "secure", "secure"},
		{"secure", "", "secure"},
		{"", "", ""},
		{"", "insecure", "insecure"},
		{"insecure", "insecure", "insecure"},
	}
	for _, tt := range tests {
		if got := combineDNSSECStatus(tt.a, tt.b); got != tt.want {
			t.Errorf("combineDNSSECStatus(%q,%q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}
