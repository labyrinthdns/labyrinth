package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateTrustChain_UnsupportedAlgDNSKEYSig_IsInsecure pins the
// norwoodlight reverse zone shape: parent DS matches an alg-7 KSK, and the
// DNSKEY RRset is signed only with that unsupported algorithm. Pre-fix
// Labyrinth returned Bogus (DNSKEY RRSIG did not validate) → SERVFAIL →
// fallback. RFC 6840 §5.2 requires Insecure when the validator cannot
// recognize the signing algorithm.
func TestValidateTrustChain_UnsupportedAlgDNSKEYSig_IsInsecure(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	// Secure parent "arpa." with Ed25519 (supported).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kskR := encodeDNSKEYRData(257, 3, dns.AlgED25519, pub)
	ksk, _ := dns.ParseDNSKEY(kskR)
	dnskeySig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeDNSKEY, Algorithm: dns.AlgED25519, Labels: 1,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: ksk.KeyTag(), SignerName: "arpa.",
	}
	dnskeyRR := dns.ResourceRecord{Name: "arpa.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: kskR}
	dnskeySig.Signature = ed25519.Sign(priv, buildSignedData([]dns.ResourceRecord{dnskeyRR}, dnskeySig))
	ti.mq.responses["arpa.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			dnskeyRR,
			{Name: "arpa.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(dnskeySig)},
		},
	}
	digest := sha256.Sum256(buildDSDigestInput("arpa.", ksk))
	dsRR := dns.ResourceRecord{
		Name: "arpa.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600,
		RData: encodeDSRData(ksk.KeyTag(), dns.AlgED25519, dns.DigestSHA256, digest[:]),
	}
	dsSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeDS, Algorithm: dns.AlgED25519, Labels: 1,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: ti.rootKSK.KeyTag(), SignerName: ".",
	}
	dsSig.Signature = ed25519.Sign(ti.rootPrivKey, buildSignedData([]dns.ResourceRecord{dsRR}, dsSig))
	ti.mq.responses["arpa.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			dsRR,
			{Name: "arpa.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(dsSig)},
		},
	}

	// Child "rev.arpa." — DS matches an alg-7 (unsupported) KSK. DNSKEY RRset
	// carries only an alg-7 RRSIG (unusable by this validator).
	childPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Encode as alg-7 DNSKEY: reuse Ed25519 key bytes but label algorithm 7 so
	// DS matching / keytag work; VerifyRRSIG will never be asked (unsupported).
	childKSKR := encodeDNSKEYRData(257, 3, dns.AlgRSASHA1NSEC3, childPub)
	childKSK, _ := dns.ParseDNSKEY(childKSKR)
	childDigest := sha256.Sum256(buildDSDigestInput("rev.arpa.", childKSK))
	childDS := dns.ResourceRecord{
		Name: "rev.arpa.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600,
		RData: encodeDSRData(childKSK.KeyTag(), dns.AlgRSASHA1NSEC3, dns.DigestSHA256, childDigest[:]),
	}
	childDSSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeDS, Algorithm: dns.AlgED25519, Labels: 2,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: ksk.KeyTag(), SignerName: "arpa.",
	}
	childDSSig.Signature = ed25519.Sign(priv, buildSignedData([]dns.ResourceRecord{childDS}, childDSSig))
	ti.mq.responses["rev.arpa.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			childDS,
			{Name: "rev.arpa.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(childDSSig)},
		},
	}

	childDNSKEY := dns.ResourceRecord{Name: "rev.arpa.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: childKSKR}
	// Alg-7 RRSIG over DNSKEY by the DS-matched key — skipped as unsupported.
	childDNSKEYSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeDNSKEY, Algorithm: dns.AlgRSASHA1NSEC3, Labels: 2,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: childKSK.KeyTag(), SignerName: "rev.arpa.",
		Signature: make([]byte, 64), // never verified
	}
	ti.mq.responses["rev.arpa.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			childDNSKEY,
			{Name: "rev.arpa.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(childDNSKEYSig)},
		},
	}

	got := ti.v.validateTrustChain("rev.arpa.", nil)
	if got != Insecure {
		t.Fatalf("trust chain=%v, want Insecure (unsupported alg-7 DNSKEY sig under matching DS)", got)
	}
}

func TestTrustedKeySignaturesUnusable(t *testing.T) {
	v := NewValidator(nil, nil)
	trusted := []dns.ResourceRecord{{
		Name: "z.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600,
		RData: encodeDNSKEYRData(257, 3, dns.AlgRSASHA1NSEC3, make([]byte, 32)),
	}}
	key, _ := dns.ParseDNSKEY(trusted[0].RData)
	sig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeDNSKEY, Algorithm: dns.AlgRSASHA1NSEC3, Labels: 1,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: key.KeyTag(), SignerName: "z.",
		Signature: []byte{1},
	}
	sigs := []dns.ResourceRecord{{
		Name: "z.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(sig),
	}}
	if !v.trustedKeySignaturesUnusable(sigs, trusted, "z.", dns.TypeDNSKEY) {
		t.Fatal("alg-7-only trusted signatures must be unusable")
	}
}
