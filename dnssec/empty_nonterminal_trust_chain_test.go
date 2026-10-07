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

// TestValidateTrustChain_SkipsNSEC3EmptyNonTerminal pins the as8758.net FTTH
// shape: buildZoneChain emits 83.ftth… and 150.83.ftth… as intermediate labels
// whose DS replies are matching NSEC3 with an empty type bitmap (ENT). Pre-fix
// isAuthenticatedEmptyNonTerminal only understood NSEC, so those intermediates
// fell through to Bogus and island children (43.43.150.83.ftth.as8758.net)
// engaged public-resolver fallback. Post-fix the walker skips NSEC3 ENTs and
// authenticates the insecure cut at the real zone.
func TestValidateTrustChain_SkipsNSEC3EmptyNonTerminal(t *testing.T) {
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

	salt := []byte{}
	entHash, err := ComputeNSEC3Hash("mid.parent.", 1, 0, salt)
	if err != nil {
		t.Fatal(err)
	}
	entNext := make([]byte, len(entHash))
	copy(entNext, entHash)
	entNext[len(entNext)-1]++ // next hash > owner
	entOwner := NSEC3HashToString(entHash) + ".parent."
	entNSEC3 := dns.ResourceRecord{
		Name: entOwner, Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 3600,
		RData: buildNSEC3RData(1, 0, 0, salt, entNext, nil), // empty bitmap = ENT
	}
	entSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC3, Algorithm: dns.AlgED25519, Labels: 2,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: ksk.KeyTag(), SignerName: "parent.",
	}
	entSig.Signature = ed25519.Sign(priv, buildSignedData([]dns.ResourceRecord{entNSEC3}, entSig))
	ti.mq.responses["mid.parent.|43"] = &dns.Message{
		Authority: []dns.ResourceRecord{
			entNSEC3,
			{Name: entOwner, Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(entSig)},
		},
	}

	cutHash, err := ComputeNSEC3Hash("cut.mid.parent.", 1, 0, salt)
	if err != nil {
		t.Fatal(err)
	}
	cutNext := make([]byte, len(cutHash))
	copy(cutNext, cutHash)
	cutNext[len(cutNext)-1]++
	cutOwner := NSEC3HashToString(cutHash) + ".parent."
	cutNSEC3 := dns.ResourceRecord{
		Name: cutOwner, Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 3600,
		RData: buildNSEC3RData(1, 0, 0, salt, cutNext, []uint16{dns.TypeNS}),
	}
	cutSig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC3, Algorithm: dns.AlgED25519, Labels: 2,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: ksk.KeyTag(), SignerName: "parent.",
	}
	cutSig.Signature = ed25519.Sign(priv, buildSignedData([]dns.ResourceRecord{cutNSEC3}, cutSig))
	ti.mq.responses["cut.mid.parent.|43"] = &dns.Message{
		Authority: []dns.ResourceRecord{
			cutNSEC3,
			{Name: cutOwner, Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(cutSig)},
		},
	}

	childPub, _, _ := ed25519.GenerateKey(rand.Reader)
	childKeyR := encodeDNSKEYRData(257, 3, dns.AlgED25519, childPub)
	ti.mq.responses["cut.mid.parent.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "cut.mid.parent.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: childKeyR},
		},
	}
	childKey, _ := dns.ParseDNSKEY(childKeyR)

	parentKeys := []dns.ResourceRecord{
		{Name: "parent.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: kskR},
	}
	if !ti.v.isAuthenticatedEmptyNonTerminal("mid.parent.", "parent.", parentKeys, ti.mq.responses["mid.parent.|43"].Authority) {
		t.Fatal("matching empty-bitmap NSEC3 must classify as empty non-terminal")
	}
	if ti.v.isAuthenticatedEmptyNonTerminal("cut.mid.parent.", "parent.", parentKeys, ti.mq.responses["cut.mid.parent.|43"].Authority) {
		t.Fatal("NS-present NSEC3 must not classify as empty non-terminal")
	}

	got := ti.v.validateTrustChainForKey("cut.mid.parent.",
		[]dns.ResourceRecord{{Name: "cut.mid.parent.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: childKeyR}},
		nil, childKey)
	if got != Insecure {
		t.Fatalf("validateTrustChainForKey(NSEC3 ENT intermediate) = %v, want Insecure", got)
	}
}
