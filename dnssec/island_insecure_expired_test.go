package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateResponse_ExpiredRRSIG_InsecureDelegation_IsInsecure pins the
// leitecastro/inara.pk failure mode: a zone publishes local RRSIGs (island of
// security) whose Expiration is in the past, but the parent authenticates
// no-DS. Pre-fix Labyrinth returned Bogus→SERVFAIL→fallback; public
// resolvers correctly answer as Insecure (no AD). Post-fix the validator
// must return Insecure so primary resolution succeeds without fallback.
func TestValidateResponse_ExpiredRRSIG_InsecureDelegation_IsInsecure(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	// Parent "parent." is securely delegated from root.
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

	// child.parent. — authenticated insecure delegation (NSEC: NS, no DS).
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

	// Island DNSKEY + expired RRSIG over A at www.child.parent.
	childPub, childPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	childKeyR := encodeDNSKEYRData(257, 3, dns.AlgED25519, childPub)
	childKey, _ := dns.ParseDNSKEY(childKeyR)
	ti.mq.responses["child.parent.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "child.parent.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: childKeyR},
		},
	}

	rrset := []dns.ResourceRecord{
		{Name: "www.child.parent.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      3,
		OrigTTL:     60,
		Expiration:  1, // expired
		Inception:   0,
		KeyTag:      childKey.KeyTag(),
		SignerName:  "child.parent.",
	}
	rrsig.Signature = ed25519.Sign(childPriv, buildSignedData(rrset, rrsig))

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "www.child.parent.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 60,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	verdict, reason := ti.v.ValidateResponseWithReason(resp, "www.child.parent.", dns.TypeA)
	if verdict != Insecure {
		t.Fatalf("verdict=%v reason=%v, want Insecure (island expired RRSIG under no-DS)", verdict, reason)
	}
	if reason != ReasonNone {
		t.Errorf("reason=%v, want ReasonNone for insecure delegation", reason)
	}
}

// TestValidateResponse_ExpiredRRSIG_RootSigner_StillBogus ensures the
// insecure-delegation downgrade does not apply to the root (always chained).
func TestValidateResponse_ExpiredRRSIG_RootSigner_StillBogus(t *testing.T) {
	s := newFullTestSetup(t)

	rrset := []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA, Algorithm: dns.AlgED25519, Labels: 0,
		OrigTTL: 300, Expiration: 1, Inception: 0,
		KeyTag: s.dnskey.KeyTag(), SignerName: ".",
	}
	rrsig.Signature = ed25519.Sign(s.privKey, buildSignedData(rrset, rrsig))
	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	verdict, reason := s.v.ValidateResponseWithReason(resp, ".", dns.TypeA)
	if verdict != Bogus {
		t.Fatalf("root expired RRSIG: verdict=%v, want Bogus", verdict)
	}
	if reason != ReasonSignatureExpired {
		t.Errorf("reason=%v, want ReasonSignatureExpired", reason)
	}
}
