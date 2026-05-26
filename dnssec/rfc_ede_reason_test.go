package dnssec

import (
	"testing"

	"crypto/ed25519"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateResponseWithReason_SignatureExpired pins the Y9 fix: when
// validation fails because every RRSIG's Expiration is in the past, the
// validator must surface ReasonSignatureExpired so the server can emit
// EDE info code 7 (RFC 8914 §4.7) instead of the generic EDE 6. Operators
// distinguishing "the auth's signing key drifted" from "a forgery on the
// wire" depend on this granularity.
func TestValidateResponseWithReason_SignatureExpired(t *testing.T) {
	s := newFullTestSetup(t)

	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  1, // already expired
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}
	signedData := buildSignedData(rrset, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	verdict, reason := s.v.ValidateResponseWithReason(resp, "example.com.", dns.TypeA)
	if verdict != Bogus {
		t.Fatalf("verdict: got %v, want Bogus", verdict)
	}
	if reason != ReasonSignatureExpired {
		t.Errorf("reason: got %v, want ReasonSignatureExpired (so server emits EDE 7 per RFC 8914 §4.7)", reason)
	}
}

// TestValidateResponseWithReason_SignatureNotYetValid is the inception-in-
// the-future counterpart — must surface ReasonSignatureNotYetValid → EDE 8.
func TestValidateResponseWithReason_SignatureNotYetValid(t *testing.T) {
	s := newFullTestSetup(t)

	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0xFFFFFFFE, // far future
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}
	signedData := buildSignedData(rrset, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	verdict, reason := s.v.ValidateResponseWithReason(resp, "example.com.", dns.TypeA)
	if verdict != Bogus {
		t.Fatalf("verdict: got %v, want Bogus", verdict)
	}
	if reason != ReasonSignatureNotYetValid {
		t.Errorf("reason: got %v, want ReasonSignatureNotYetValid (EDE 8)", reason)
	}
}

// TestFailureReason_StringRoundTrip pins the string token surface used at
// the resolver/server boundary (ResolveResult.DNSSECReason is a string so
// resolver doesn't import dnssec just for the type). A drift in either
// direction silently downgrades every granular EDE to the generic code.
func TestFailureReason_StringRoundTrip(t *testing.T) {
	cases := []FailureReason{
		ReasonNone,
		ReasonSignatureExpired,
		ReasonSignatureNotYetValid,
		ReasonDNSKEYMissing,
		ReasonNoMatchingDNSKEY,
		ReasonRRSIGsMissing,
		ReasonUnsupportedDNSKEYAlgo,
		ReasonUnsupportedDSDigest,
		ReasonOther,
	}
	for _, r := range cases {
		round := FailureReasonFromString(r.String())
		if round != r {
			t.Errorf("round-trip of %v via %q produced %v", r, r.String(), round)
		}
	}
}
