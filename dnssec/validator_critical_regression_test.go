package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func signedTestRR(t *testing.T, rrset []dns.ResourceRecord, owner string, key *dns.DNSKEYRecord, priv ed25519.PrivateKey) dns.ResourceRecord {
	t.Helper()
	sig := &dns.RRSIGRecord{
		TypeCovered: rrset[0].Type,
		Algorithm:   key.Algorithm,
		Labels:      uint8(labelCountExcludingRoot(rrset[0].Name)),
		OrigTTL:     rrset[0].TTL,
		Expiration:  0xFFFFFFFF,
		KeyTag:      key.KeyTag(),
		SignerName:  owner,
	}
	sig.Signature = ed25519.Sign(priv, buildSignedData(rrset, sig))
	return dns.ResourceRecord{Name: rrset[0].Name, Type: dns.TypeRRSIG, Class: rrset[0].Class, TTL: rrset[0].TTL, RData: buildRRSIGRData(sig)}
}

func addRootSiblingWithDNSKEYSignature(t *testing.T, s *fullTestSetup, siblingRData []byte, signer *dns.DNSKEYRecord, priv ed25519.PrivateKey) {
	t.Helper()
	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	keys := []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
		{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: siblingRData},
	}
	s.mq.responses[".|48"] = &dns.Message{Answers: append(keys, signedTestRR(t, keys, ".", signer, priv))}
}

func TestValidateResponse_RejectsUnauthenticatedDNSKEYSibling(t *testing.T) {
	s := newFullTestSetup(t)
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerRData := encodeDNSKEYRData(256, 3, dns.AlgED25519, attackerPub)
	attackerKey, _ := dns.ParseDNSKEY(attackerRData)
	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{Answers: []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
		{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: attackerRData},
	}}

	rrset := []dns.ResourceRecord{{Name: ".", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{203, 0, 113, 9}}}
	resp := &dns.Message{Answers: append(rrset, signedTestRR(t, rrset, ".", attackerKey, attackerPriv))}
	if got := s.v.ValidateResponse(resp, ".", dns.TypeA); got == Secure {
		t.Fatalf("injected sibling DNSKEY authenticated forged answer: got %v", got)
	}
}

func TestValidateResponse_AcceptsSiblingAfterCompleteDNSKEYRRSetAuthentication(t *testing.T) {
	s := newFullTestSetup(t)
	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	rootKSK, _ := dns.ParseDNSKEY(rootKSKR)
	addRootSiblingWithDNSKEYSignature(t, s, s.zskRData, rootKSK, s.privKey)

	rrset := []dns.ResourceRecord{{Name: ".", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{192, 0, 2, 1}}}
	resp := &dns.Message{Answers: append(rrset, signedTestRR(t, rrset, ".", s.dnskey, s.privKey))}
	if got := s.v.ValidateResponse(resp, ".", dns.TypeA); got != Secure {
		t.Fatalf("authenticated DNSKEY sibling rejected: got %v, want Secure", got)
	}
}

func TestValidateDenialResponse_RequiresSecureTrustChain(t *testing.T) {
	s := newFullTestSetup(t)
	s.v.trustAnchors = nil
	nsec := dns.ResourceRecord{
		Name: ".", Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 300,
		RData: append(dns.BuildPlainName("."), 0, 1, 0x40), // bitmap contains only A
	}
	resp := &dns.Message{
		Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build()},
		Authority: []dns.ResourceRecord{nsec, signedTestRR(t, []dns.ResourceRecord{nsec}, ".", s.dnskey, s.privKey)},
	}
	if got := s.v.ValidateResponse(resp, "missing.", dns.TypeAAAA); got == Secure {
		t.Fatalf("denial proof signed by an unchained key returned Secure")
	}
}

func TestValidateResponse_RequiresEveryPositiveRRSet(t *testing.T) {
	s := newFullTestSetup(t)
	aRRset := []dns.ResourceRecord{{Name: ".", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{192, 0, 2, 10}}}
	txtRRset := []dns.ResourceRecord{{Name: ".", Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 300, RData: []byte{3, 'b', 'a', 'd'}}}
	resp := &dns.Message{Answers: append(append(aRRset, txtRRset...), signedTestRR(t, aRRset, ".", s.dnskey, s.privKey))}
	if got := s.v.ValidateResponse(resp, ".", dns.TypeA); got == Secure {
		t.Fatalf("response with unsigned positive TXT RRset returned Secure")
	}
}

func TestValidateTrustChain_RejectsUnsignedPositiveDSRRSet(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()
	childRData := encodeDNSKEYRData(257, 3, dns.AlgED25519, make([]byte, ed25519.PublicKeySize))
	childKey, _ := dns.ParseDNSKEY(childRData)
	ti.mq.responses["com.|48"] = &dns.Message{Answers: []dns.ResourceRecord{{Name: "com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: childRData}}}
	digest := sha256.Sum256(buildDSDigestInput("com.", childKey))
	ti.mq.responses["com.|43"] = &dns.Message{Answers: []dns.ResourceRecord{{Name: "com.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600, RData: encodeDSRData(childKey.KeyTag(), childKey.Algorithm, dns.DigestSHA256, digest[:])}}}
	if got := ti.v.validateTrustChain("com.", nil); got == Secure {
		t.Fatalf("unsigned positive DS RRset returned Secure")
	}
}
