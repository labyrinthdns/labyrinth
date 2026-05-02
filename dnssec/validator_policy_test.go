package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// Algorithm-policy unit tests for the weak-primitive rejection added in the
// dnssec hardening pass. By default the validator refuses RSASHA1 RRSIGs and
// SHA1 DS digests; AllowSHA1(true) restores legacy behavior for operators
// running against zones that have not migrated.

func TestValidator_DefaultsRejectSHA1(t *testing.T) {
	v := NewValidator(&mockQuerier{}, nil)

	if !v.isWeakRRSIGAlg(dns.AlgRSASHA1) {
		t.Error("RSASHA1 RRSIG should be rejected by default")
	}
	if !v.isWeakDSDigest(dns.DigestSHA1) {
		t.Error("SHA1 DS digest should be rejected by default")
	}

	// Strong primitives are never weak.
	if v.isWeakRRSIGAlg(dns.AlgRSASHA256) {
		t.Error("RSASHA256 must not be flagged as weak")
	}
	if v.isWeakRRSIGAlg(dns.AlgECDSAP256) {
		t.Error("ECDSAP256 must not be flagged as weak")
	}
	if v.isWeakRRSIGAlg(dns.AlgED25519) {
		t.Error("ED25519 must not be flagged as weak")
	}
	if v.isWeakDSDigest(dns.DigestSHA256) {
		t.Error("DigestSHA256 must not be flagged as weak")
	}
	if v.isWeakDSDigest(dns.DigestSHA384) {
		t.Error("DigestSHA384 must not be flagged as weak")
	}
}

func TestValidator_AllowSHA1Override(t *testing.T) {
	v := NewValidator(&mockQuerier{}, nil)
	v.AllowSHA1(true)

	if v.isWeakRRSIGAlg(dns.AlgRSASHA1) {
		t.Error("AllowSHA1(true) should permit RSASHA1")
	}
	if v.isWeakDSDigest(dns.DigestSHA1) {
		t.Error("AllowSHA1(true) should permit SHA1 DS digest")
	}
}

func TestValidateResponse_AllRRSIGsWeakReturnsInsecure(t *testing.T) {
	// Build a response whose only RRSIG uses RSASHA1. With the default policy
	// the validator should treat the response as Insecure (zone effectively
	// unsigned for us), not Bogus or Indeterminate.
	rrsigRData := buildRRSIGRData(&dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgRSASHA1,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFE,
		Inception:   0,
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   []byte{0xAB, 0xCD},
	})

	resp := &dns.Message{
		Header: dns.Header{Flags: 0x8000, ANCount: 2},
		Questions: []dns.Question{
			{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN},
		},
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300,
				RDLength: 4, RData: []byte{93, 184, 216, 34}},
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
				RDLength: uint16(len(rrsigRData)), RData: rrsigRData},
		},
	}

	v := NewValidator(&mockQuerier{}, nil)
	got := v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if got != Insecure {
		t.Errorf("expected Insecure for RSASHA1-only response, got %s", got)
	}

	// With AllowSHA1(true), the validator proceeds to fetch DNSKEYs (which
	// the empty mockQuerier cannot satisfy), so the result becomes
	// Indeterminate rather than Insecure. Either way it must not be Secure.
	v.AllowSHA1(true)
	got = v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if got == Secure {
		t.Errorf("AllowSHA1 path must not declare Secure without DNSKEY, got %s", got)
	}
}
