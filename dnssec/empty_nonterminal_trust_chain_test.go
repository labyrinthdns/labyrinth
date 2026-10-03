package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// buildNSECTypeBitmap encodes a window-0 NSEC type bitmap for the given types.
func buildNSECTypeBitmap(types []uint16) []byte {
	var max uint16
	for _, t := range types {
		if t > max {
			max = t
		}
	}
	nbytes := int(max)/8 + 1
	bm := make([]byte, nbytes)
	for _, t := range types {
		bm[int(t)/8] |= 0x80 >> (t % 8)
	}
	out := []byte{0x00, byte(len(bm))}
	return append(out, bm...)
}

func encodeDNSNameUncompressed(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out
}

func buildNSECRData(next string, types []uint16) []byte {
	var rdata []byte
	rdata = append(rdata, encodeDNSNameUncompressed(next)...)
	rdata = append(rdata, buildNSECTypeBitmap(types)...)
	return rdata
}

// TestValidateTrustChain_SkipsEmptyNonTerminal pins the New Relic / nr-data.net
// shape: buildZoneChain emits every label, but eu.nr-data.net (here:
// ent.example.) is only an empty non-terminal inside example. while
// cell.ent.example. holds the real signed DS. Pre-fix the ENT's NS-less
// NSEC failed verifyDSDenial → Bogus for the whole child zone. Post-fix
// the walker skips the ENT and validates the deeper DS against the parent.
func TestValidateTrustChain_SkipsEmptyNonTerminal(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	// Parent zone example. — real Ed25519 KSK so we can sign the ENT NSEC.
	exPub, exPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exKSKR := encodeDNSKEYRData(257, 3, dns.AlgED25519, exPub)
	exKSK, _ := dns.ParseDNSKEY(exKSKR)
	exDNSKEYRR := dns.ResourceRecord{Name: "example.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: exKSKR}
	ti.mq.responses["example.|48"] = &dns.Message{Answers: []dns.ResourceRecord{exDNSKEYRR}}

	digestEx := sha256.Sum256(buildDSDigestInput("example.", exKSK))
	exDSRR := dns.ResourceRecord{
		Name: "example.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600,
		RData: encodeDSRData(exKSK.KeyTag(), dns.AlgED25519, dns.DigestSHA256, digestEx[:]),
	}
	exDSSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeDS, Algorithm: dns.AlgED25519, Labels: 1,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: ti.rootKSK.KeyTag(), SignerName: ".",
	}
	exDSSig.Signature = ed25519.Sign(ti.rootPrivKey, buildSignedData([]dns.ResourceRecord{exDSRR}, exDSSig))
	ti.mq.responses["example.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			exDSRR,
			{Name: "example.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(exDSSig)},
		},
	}

	// ENT ent.example. — empty DS + parent-signed NSEC (bitmap: NSEC+RRSIG only).
	nsecRR := dns.ResourceRecord{
		Name: "ent.example.", Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 3600,
		RData: buildNSECRData("\\000.ent.example.", []uint16{dns.TypeNSEC, dns.TypeRRSIG}),
	}
	nsecSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC, Algorithm: dns.AlgED25519, Labels: 2,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: exKSK.KeyTag(), SignerName: "example.",
	}
	nsecSig.Signature = ed25519.Sign(exPriv, buildSignedData([]dns.ResourceRecord{nsecRR}, nsecSig))
	ti.mq.responses["ent.example.|43"] = &dns.Message{
		Answers: nil,
		Authority: []dns.ResourceRecord{
			nsecRR,
			{Name: "ent.example.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(nsecSig)},
		},
	}
	// No DNSKEY at the ENT (NODATA) — walker must not require one.
	ti.mq.responses["ent.example.|48"] = &dns.Message{Answers: nil, Authority: []dns.ResourceRecord{nsecRR}}

	// Child zone cell.ent.example. — DS published by example. (grandparent of ENT).
	childPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	childKSKR := encodeDNSKEYRData(257, 3, dns.AlgED25519, childPub)
	childKSK, _ := dns.ParseDNSKEY(childKSKR)
	ti.mq.responses["cell.ent.example.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "cell.ent.example.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: childKSKR},
		},
	}
	digestChild := sha256.Sum256(buildDSDigestInput("cell.ent.example.", childKSK))
	childDSRR := dns.ResourceRecord{
		Name: "cell.ent.example.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600,
		RData: encodeDSRData(childKSK.KeyTag(), dns.AlgED25519, dns.DigestSHA256, digestChild[:]),
	}
	childDSSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeDS, Algorithm: dns.AlgED25519, Labels: 3,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: exKSK.KeyTag(), SignerName: "example.",
	}
	childDSSig.Signature = ed25519.Sign(exPriv, buildSignedData([]dns.ResourceRecord{childDSRR}, childDSSig))
	ti.mq.responses["cell.ent.example.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			childDSRR,
			{Name: "cell.ent.example.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(childDSSig)},
		},
	}

	result := ti.v.validateTrustChain("cell.ent.example.", nil)
	if result != Secure {
		t.Fatalf("validateTrustChain through empty non-terminal: got %v, want Secure", result)
	}
}

// TestIsAuthenticatedEmptyNonTerminal_RejectsDelegationNSEC ensures an
// NS-present DS-absent NSEC is NOT classified as ENT (that is insecure
// delegation territory for verifyDSDenial).
func TestIsAuthenticatedEmptyNonTerminal_RejectsDelegationNSEC(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	nsecRR := dns.ResourceRecord{
		Name: "child.", Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 3600,
		RData: buildNSECRData("next.", []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}),
	}
	nsecSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC, Algorithm: dns.AlgED25519, Labels: 1,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: ti.rootKSK.KeyTag(), SignerName: ".",
	}
	nsecSig.Signature = ed25519.Sign(ti.rootPrivKey, buildSignedData([]dns.ResourceRecord{nsecRR}, nsecSig))
	authority := []dns.ResourceRecord{
		nsecRR,
		{Name: "child.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(nsecSig)},
	}
	parentKeys := []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: ti.rootKSKR},
	}
	if ti.v.isAuthenticatedEmptyNonTerminal("child.", ".", parentKeys, authority) {
		t.Fatal("NS-present NSEC must not be classified as empty non-terminal")
	}
}
