package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestDNSKEY_IsRevoked verifies the flag-bit decoding for the RFC 5011 §3
// REVOKE bit (bit 8, mask 0x0080).
func TestDNSKEY_IsRevoked(t *testing.T) {
	cases := []struct {
		name  string
		flags uint16
		want  bool
	}{
		{"plain ZSK", 0x0100, false},
		{"plain KSK (SEP set)", 0x0101, false},
		{"KSK + REVOKE", 0x0181, true},
		{"ZSK + REVOKE (rare but valid)", 0x0180, true},
		{"REVOKE bit alone", 0x0080, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := &dns.DNSKEYRecord{Flags: c.flags}
			if got := k.IsRevoked(); got != c.want {
				t.Errorf("IsRevoked(flags=%#04x) = %v, want %v", c.flags, got, c.want)
			}
		})
	}
}

// TestFindMatchingDNSKEY_SkipsRevoked pins the RFC 5011 §3 enforcement at
// the signature-verification site: a revoked DNSKEY MUST NOT be returned
// from findMatchingDNSKEY, regardless of how well its key tag / algorithm
// match the RRSIG. The chain must rebuild from unrevoked siblings.
func TestFindMatchingDNSKEY_SkipsRevoked(t *testing.T) {
	// Build an RData blob for a "revoked" KSK and a regular KSK with the
	// same key tag would be ideal, but key tag depends on RDATA bytes
	// which depend on flags — so they'll have different tags. We test
	// that the revoked one is NOT returned even when it's the only key
	// in the list.
	revoked := &dns.DNSKEYRecord{
		Flags:     0x0181, // KSK + REVOKE
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("revoked-key-bytes"),
	}
	good := &dns.DNSKEYRecord{
		Flags:     0x0101, // KSK
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("good-key-bytes-different"),
	}
	revokedRR := dns.ResourceRecord{
		Name:  "example.",
		Type:  dns.TypeDNSKEY,
		Class: dns.ClassIN,
		TTL:   3600,
		RData: encodeDNSKEYRData(revoked.Flags, revoked.Protocol, revoked.Algorithm, revoked.PublicKey),
	}
	goodRR := dns.ResourceRecord{
		Name:  "example.",
		Type:  dns.TypeDNSKEY,
		Class: dns.ClassIN,
		TTL:   3600,
		RData: encodeDNSKEYRData(good.Flags, good.Protocol, good.Algorithm, good.PublicKey),
	}

	// Reparse to recompute the key tags reliably.
	revokedParsed, _ := dns.ParseDNSKEY(revokedRR.RData)
	goodParsed, _ := dns.ParseDNSKEY(goodRR.RData)

	// Asking for the revoked key's tag → must NOT find it.
	keys := []dns.ResourceRecord{revokedRR, goodRR}
	if _, err := findMatchingDNSKEY(keys, revokedParsed.KeyTag(), dns.AlgRSASHA256); err == nil {
		t.Error("findMatchingDNSKEY returned a revoked DNSKEY (RFC 5011 §3 violation)")
	}
	// Asking for the good key's tag → must find it.
	if _, err := findMatchingDNSKEY(keys, goodParsed.KeyTag(), dns.AlgRSASHA256); err != nil {
		t.Errorf("findMatchingDNSKEY rejected a non-revoked key: %v", err)
	}
}
