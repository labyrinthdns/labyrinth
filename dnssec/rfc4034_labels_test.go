package dnssec

import (
	"errors"
	"testing"

	"crypto/ed25519"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestVerifyRRSIG_RejectsMalformedLabels pins the Y11 fix to RFC 4034
// §3.1.3: "The value of the Labels field MUST be less than or equal to
// the number of labels in the RRSIG owner name." A larger Labels value is
// structurally malformed — no legitimate signer could have produced it,
// since Labels is supposed to record how many labels the signed owner
// actually contained (root and wildcard label excluded). Accepting it
// also widens the surface for fuzzing the wildcard-reconstruction path.
//
// Construction: a real signature over rrset, then we artificially bump
// rrsig.Labels to a value larger than the owner-name label count. The
// verifier must refuse before reaching the cryptographic check.
func TestVerifyRRSIG_RejectsMalformedLabels(t *testing.T) {
	s := newFullTestSetup(t)

	rrset := []dns.ResourceRecord{
		// owner = "example.com" → 2 labels (excluding root).
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}
	signedData := buildSignedData(rrset, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	// Now bump Labels to 5 — strictly greater than the owner's two-label
	// count. RFC 4034 §3.1.3 says this RRSIG is malformed; the verifier
	// must reject without even trying to validate cryptographically.
	rrsig.Labels = 5

	err := VerifyRRSIG(rrset, rrsig, s.dnskey)
	if err == nil {
		t.Fatal("VerifyRRSIG accepted RRSIG.Labels (5) > owner-label-count (2); " +
			"RFC 4034 §3.1.3 requires rejection")
	}
	if !errors.Is(err, errMalformedLabels) {
		t.Errorf("expected errMalformedLabels, got %v", err)
	}
}

// TestVerifyRRSIG_AcceptsLabelsEqualToOwner is the positive counterpart:
// the most common signing case — Labels == owner-label-count — must still
// validate cleanly. Catches an off-by-one in the new bound check.
func TestVerifyRRSIG_AcceptsLabelsEqualToOwner(t *testing.T) {
	s := newFullTestSetup(t)

	rrset := []dns.ResourceRecord{
		{Name: "foo.example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      3, // owner has 3 labels (excluding root)
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}
	signedData := buildSignedData(rrset, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	if err := VerifyRRSIG(rrset, rrsig, s.dnskey); err != nil {
		t.Errorf("Labels == owner-label-count must validate; got %v", err)
	}
}

// TestVerifyRRSIG_AcceptsWildcardLabelsLessThanOwner: wildcard expansion
// is the case where Labels < owner-label-count (RFC 4035 §5.3.2). Must
// remain accepted — this is the whole point of the existing wildcard-
// reconstruction logic in canonicalWildcardOwner.
func TestVerifyRRSIG_AcceptsWildcardLabelsLessThanOwner(t *testing.T) {
	s := newFullTestSetup(t)

	// Original signed owner was "*.example.com" (Labels=2 excludes the
	// wildcard label). The expanded response shows owner "foo.example.com"
	// (3 labels). RFC 4035 §5.3.2 says rebuild canonical owner as
	// "*." + last Labels labels, i.e. "*.example.com" — which is what was
	// actually signed.
	signedOwner := "*.example.com."
	signedSet := []dns.ResourceRecord{
		{Name: signedOwner, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2, // excludes wildcard label
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}
	signedData := buildSignedData(signedSet, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	// Verifier receives the expanded RR — owner has 3 labels, Labels=2.
	expanded := []dns.ResourceRecord{
		{Name: "foo.example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	if err := VerifyRRSIG(expanded, rrsig, s.dnskey); err != nil {
		t.Errorf("wildcard expansion (Labels<owner) must validate; got %v", err)
	}
}

// TestLabelCountExcludingRoot pins the helper's exact semantics — these
// match RFC 4034 §3.1.3 ("not counting the null label"). A drift here
// silently flips the Y11 bound check.
func TestLabelCountExcludingRoot(t *testing.T) {
	cases := []struct {
		name string
		want int
	}{
		{".", 0},
		{"", 0},
		{"com", 1},
		{"com.", 1},
		{"example.com", 2},
		{"example.com.", 2},
		{"a.b.c.example.com.", 5},
	}
	for _, c := range cases {
		if got := labelCountExcludingRoot(c.name); got != c.want {
			t.Errorf("labelCountExcludingRoot(%q) = %d, want %d", c.name, got, c.want)
		}
	}
}
