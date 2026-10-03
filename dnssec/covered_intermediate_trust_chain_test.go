package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateTrustChain_SkipsCoveredIntermediate pins the Afrinic→Larus
// reverse-DNS shape that forced PTR NXDOMAIN through Bogus→fallback:
//
//	154.in-addr.arpa publishes NS for 8.222.154.in-addr.arpa (no DS),
//	while DS queries for the intermediate 222.154.in-addr.arpa are
//	answered with a covering NSEC gap (name proven nonexistent).
//
// Pre-fix the walker returned Bogus at the intermediate; post-fix it
// skips the covered label and authenticates the insecure delegation at
// the real cut.
func TestValidateTrustChain_SkipsCoveredIntermediate(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	// Parent zone parent. — Ed25519 KSK/ZSK.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kskR := encodeDNSKEYRData(257, 3, dns.AlgED25519, pub)
	ksk, _ := dns.ParseDNSKEY(kskR)
	dnskeyRR := dns.ResourceRecord{Name: "parent.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: kskR}
	ti.mq.responses["parent.|48"] = &dns.Message{Answers: []dns.ResourceRecord{dnskeyRR}}

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

	// DS for mid.parent. — covering NSEC (alpha.parent. → cut.mid.parent.)
	// proving mid.parent. does not exist as an owner.
	coverNSEC := dns.ResourceRecord{
		Name: "alpha.parent.", Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 300,
		RData: buildNSECRData("cut.mid.parent.", []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}),
	}
	coverSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC, Algorithm: dns.AlgED25519, Labels: 2,
		OrigTTL: 300, Expiration: 0xFFFFFFFF, KeyTag: ksk.KeyTag(), SignerName: "parent.",
	}
	coverSig.Signature = ed25519.Sign(priv, buildSignedData([]dns.ResourceRecord{coverNSEC}, coverSig))
	ti.mq.responses["mid.parent.|43"] = &dns.Message{
		Authority: []dns.ResourceRecord{
			coverNSEC,
			{Name: "alpha.parent.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(coverSig)},
		},
	}

	// DS for cut.mid.parent. — insecure delegation (NSEC at name, NS, no DS).
	delNSEC := dns.ResourceRecord{
		Name: "cut.mid.parent.", Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 300,
		RData: buildNSECRData("next.mid.parent.", []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}),
	}
	delSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC, Algorithm: dns.AlgED25519, Labels: 3,
		OrigTTL: 300, Expiration: 0xFFFFFFFF, KeyTag: ksk.KeyTag(), SignerName: "parent.",
	}
	delSig.Signature = ed25519.Sign(priv, buildSignedData([]dns.ResourceRecord{delNSEC}, delSig))
	ti.mq.responses["cut.mid.parent.|43"] = &dns.Message{
		Authority: []dns.ResourceRecord{
			delNSEC,
			{Name: "cut.mid.parent.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(delSig)},
		},
	}

	// Island-of-security DNSKEY at the cut (unused for Secure, but fetched).
	childPub, _, _ := ed25519.GenerateKey(rand.Reader)
	childKeyR := encodeDNSKEYRData(257, 3, dns.AlgED25519, childPub)
	ti.mq.responses["cut.mid.parent.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "cut.mid.parent.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: childKeyR},
		},
	}

	childKey, _ := dns.ParseDNSKEY(childKeyR)
	got := ti.v.validateTrustChainForKey("cut.mid.parent.",
		[]dns.ResourceRecord{{Name: "cut.mid.parent.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: childKeyR}},
		nil, childKey)
	if got != Insecure {
		t.Fatalf("validateTrustChainForKey(covered intermediate) = %v, want Insecure", got)
	}
}
