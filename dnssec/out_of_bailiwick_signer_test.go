package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// newSignedParentInsecureChild sets up "parent." securely delegated from the
// root and "child.parent." as an authenticated insecure delegation (NSEC: NS,
// no DS).
func newSignedParentInsecureChild(t *testing.T) *testInfra {
	t.Helper()
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kskR := encodeDNSKEYRData(257, 3, dns.AlgED25519, pub)
	ksk, _ := dns.ParseDNSKEY(kskR)
	ti.mq.responses["parent.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "parent.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: kskR},
		},
	}
	digest := sha256.Sum256(buildDSDigestInput("parent.", ksk))
	dsRR := dns.ResourceRecord{
		Name: "parent.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600,
		RData: encodeDSRData(ksk.KeyTag(), dns.AlgED25519, dns.DigestSHA256, digest[:]),
	}
	dsSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeDS, Algorithm: dns.AlgED25519, Labels: 1,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: ti.rootKSK.KeyTag(), SignerName: ".",
	}
	dsSig.Signature = ed25519.Sign(ti.rootPrivKey, buildSignedData([]dns.ResourceRecord{dsRR}, dsSig))
	ti.mq.responses["parent.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			dsRR,
			{Name: "parent.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(dsSig)},
		},
	}

	delNSEC := dns.ResourceRecord{
		Name: "child.parent.", Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 300,
		RData: buildNSECRData("next.parent.", []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}),
	}
	delSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC, Algorithm: dns.AlgED25519, Labels: 2,
		OrigTTL: 300, Expiration: 0xFFFFFFFF, KeyTag: ksk.KeyTag(), SignerName: "parent.",
	}
	delSig.Signature = ed25519.Sign(priv, buildSignedData([]dns.ResourceRecord{delNSEC}, delSig))
	ti.mq.responses["child.parent.|43"] = &dns.Message{
		Authority: []dns.ResourceRecord{
			delNSEC,
			{Name: "child.parent.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(delSig)},
		},
	}
	return ti
}

// answerSignedByUnrelatedZone returns an A answer for owner carrying an
// RRSIG whose signer ("cdn.other.") is not an ancestor of owner.
func answerSignedByUnrelatedZone(t *testing.T, owner string) *dns.Message {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rrset := []dns.ResourceRecord{
		{Name: owner, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{192, 0, 2, 96}},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA, Algorithm: dns.AlgED25519, Labels: uint8(countLabels(owner)),
		OrigTTL: 300, Expiration: 0xFFFFFFFF, KeyTag: 34505, SignerName: "cdn.other.",
	}
	rrsig.Signature = ed25519.Sign(priv, buildSignedData(rrset, rrsig))
	return &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: owner, Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig),
		}),
	}
}

func countLabels(name string) int {
	n := 0
	for _, c := range normalizeName(name) {
		if c == '.' {
			n++
		}
	}
	return n
}

// TestValidateResponse_UnrelatedSignerUnderInsecureDelegation_IsInsecure
// pins the telefonica.com shape: no DS in com, and the auth answers A with an
// RRSIG whose signer is cloudflare.net. That signer cannot have signed the
// name, so Unbound omits it, treats the answer as unsigned and finds the
// insecure delegation; Google and Cloudflare return the answer without AD.
// Labyrinth called it Bogus and sent every query to the public fallback.
func TestValidateResponse_UnrelatedSignerUnderInsecureDelegation_IsInsecure(t *testing.T) {
	ti := newSignedParentInsecureChild(t)
	resp := answerSignedByUnrelatedZone(t, "child.parent.")

	verdict, reason := ti.v.ValidateResponseWithReason(resp, "child.parent.", dns.TypeA)
	if verdict != Insecure {
		t.Fatalf("verdict=%v reason=%v, want Insecure (unrelated signer, no DS)", verdict, reason)
	}

	resp = answerSignedByUnrelatedZone(t, "www.child.parent.")
	verdict, reason = ti.v.ValidateResponseWithReason(resp, "www.child.parent.", dns.TypeA)
	if verdict != Insecure {
		t.Fatalf("below the cut: verdict=%v reason=%v, want Insecure", verdict, reason)
	}
}

// TestValidateResponse_UnrelatedSignerInSignedZone_StaysBogus: in a zone with
// a DS the same answer is an unsigned answer where signatures are required,
// so it must stay Bogus (fail closed), as in Unbound.
func TestValidateResponse_UnrelatedSignerInSignedZone_StaysBogus(t *testing.T) {
	ti := newSignedParentInsecureChild(t)
	resp := answerSignedByUnrelatedZone(t, "parent.")

	verdict, _ := ti.v.ValidateResponseWithReason(resp, "parent.", dns.TypeA)
	if verdict != Bogus {
		t.Fatalf("verdict=%v, want Bogus (unrelated signer inside a signed zone)", verdict)
	}
}
