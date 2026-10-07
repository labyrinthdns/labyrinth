package dnssec

import (
	"crypto/ed25519"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateDenialResponse_NXDOMAINOptOutIsInsecureNotBogus pins the
// .com/.net opt-out NXDOMAIN shape that previously forced every nonexistent
// name under those TLDs through SERVFAIL → public-resolver fallback:
//
//	closest-encloser match + next-closer COVER with opt-out flag +
//	(optional) wildcard cover.
//
// RFC 5155 §6 forbids AD=1 for that proof, but it is not a forgery —
// Unbound/BIND/1.1.1.1 return NXDOMAIN with AD=0 (Insecure). Pre-fix the
// validator fell through to Bogus.
func TestValidateDenialResponse_NXDOMAINOptOutIsInsecureNotBogus(t *testing.T) {
	s := newFullTestSetup(t)

	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	const qname = "missing.unsigned-child.test."
	salt := []byte{0xCD}
	const iter uint16 = 0

	// Closest encloser = "test." (parent of unsigned-child.test.).
	ceHash, err := ComputeNSEC3Hash("test.", 1, iter, salt)
	if err != nil {
		t.Fatal(err)
	}
	// Next closer = "unsigned-child.test." — covered by opt-out span.
	ncHash, err := ComputeNSEC3Hash("unsigned-child.test.", 1, iter, salt)
	if err != nil {
		t.Fatal(err)
	}
	wcHash, err := ComputeNSEC3Hash("*.test.", 1, iter, salt)
	if err != nil {
		t.Fatal(err)
	}

	ceNext := make([]byte, len(ceHash))
	for i := range ceNext {
		ceNext[i] = 0xFF
	}
	ncOwner := make([]byte, len(ncHash))
	ncNext := make([]byte, len(ncHash))
	copy(ncOwner, ncHash)
	copy(ncNext, ncHash)
	ncOwner[len(ncOwner)-1]--
	ncNext[len(ncNext)-1]++
	wcOwner := make([]byte, len(wcHash))
	wcNext := make([]byte, len(wcHash))
	copy(wcOwner, wcHash)
	copy(wcNext, wcHash)
	wcOwner[len(wcOwner)-1]--
	wcNext[len(wcNext)-1]++

	ceRR := dns.ResourceRecord{
		Name: NSEC3HashToString(ceHash) + ".", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300,
		RData: buildNSEC3RData(1, 0, iter, salt, ceNext, []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeDNSKEY, dns.TypeNSEC3PARAM, dns.TypeRRSIG}),
	}
	ncRR := dns.ResourceRecord{
		Name: NSEC3HashToString(ncOwner) + ".", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300,
		RData: buildNSEC3RData(1, 0x01 /* opt-out */, iter, salt, ncNext, []uint16{dns.TypeNS}),
	}
	wcRR := dns.ResourceRecord{
		Name: NSEC3HashToString(wcOwner) + ".", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300,
		RData: buildNSEC3RData(1, 0, iter, salt, wcNext, []uint16{dns.TypeA}),
	}

	signNSEC3 := func(rr dns.ResourceRecord) dns.ResourceRecord {
		rrsig := &dns.RRSIGRecord{
			TypeCovered: dns.TypeNSEC3, Algorithm: dns.AlgED25519, Labels: 0,
			OrigTTL: 300, Expiration: 0xFFFFFFFF, Inception: 0,
			KeyTag: s.dnskey.KeyTag(), SignerName: ".",
		}
		rrsig.Signature = ed25519.Sign(s.privKey, buildSignedData([]dns.ResourceRecord{rr}, rrsig))
		return dns.ResourceRecord{
			Name: rr.Name, Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}
	}

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			ceRR, signNSEC3(ceRR),
			ncRR, signNSEC3(ncRR),
			wcRR, signNSEC3(wcRR),
		},
	}

	got := s.v.ValidateResponse(resp, qname, dns.TypeA)
	if got != Insecure {
		t.Fatalf("ValidateResponse(NXDOMAIN opt-out) = %v, want Insecure (not Bogus/SERVFAIL)", got)
	}
}
