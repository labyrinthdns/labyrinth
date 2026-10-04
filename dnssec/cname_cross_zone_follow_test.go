package dnssec

import (
	"crypto/ed25519"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateResponse_SignedCNAME_UnsignedCrossZoneFollow_NotBogus pins the
// norwoodlight reverse-PTR shape: auth returns a Secure CNAME plus an
// unsigned out-of-zone PTR in the same ANSWER. Pre-fix the validator
// required every answer RRset to authenticate; failed sibling RRSIGs then
// fell through to Bogus → SERVFAIL → fallback. Public resolvers (and delv)
// accept the CNAME as Secure and treat the follow-on as a separate hop.
func TestValidateResponse_SignedCNAME_UnsignedCrossZoneFollow_NotBogus(t *testing.T) {
	s := newFullTestSetup(t)

	cname := dns.ResourceRecord{
		Name: "205.123.59.199.in-addr.arpa.", Type: dns.TypeCNAME, Class: dns.ClassIN, TTL: 3600,
		RData: dns.BuildPlainName("205.123.59.199.mta.example."),
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeCNAME, Algorithm: dns.AlgED25519, Labels: 6,
		OrigTTL: 3600, Expiration: 0xFFFFFFFF, Inception: 0,
		KeyTag: s.dnskey.KeyTag(), SignerName: ".",
	}
	rrsig.Signature = ed25519.Sign(s.privKey, buildSignedData([]dns.ResourceRecord{cname}, rrsig))

	// Unsigned out-of-zone follow-on (same shape as mta.norwoodlight.com PTR).
	follow := dns.ResourceRecord{
		Name: "205.123.59.199.mta.example.", Type: dns.TypePTR, Class: dns.ClassIN, TTL: 3600,
		RData: dns.BuildPlainName("host.example."),
	}

	resp := &dns.Message{
		Answers: []dns.ResourceRecord{
			cname,
			{Name: cname.Name, Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(rrsig)},
			follow,
		},
	}

	verdict, reason := s.v.ValidateResponseWithReason(resp, "205.123.59.199.in-addr.arpa.", dns.TypeCNAME)
	if verdict != Secure {
		t.Fatalf("CNAME+unsigned cross-zone follow: verdict=%v reason=%v, want Secure", verdict, reason)
	}

	// Resolver CNAME-chase path validates with TypeCNAME; PTR query path
	// that still sees the combined answer must also not Bogus the CNAME.
	verdict, reason = s.v.ValidateResponseWithReason(resp, "205.123.59.199.in-addr.arpa.", dns.TypePTR)
	if verdict != Secure {
		t.Fatalf("TypePTR on CNAME+follow answer: verdict=%v reason=%v, want Secure", verdict, reason)
	}
}

func TestAnswerRRsetRelevant(t *testing.T) {
	if !answerRRsetRelevant("alias.example.", dns.TypeCNAME, "alias.example.", dns.TypePTR) {
		t.Fatal("CNAME at qname must be relevant")
	}
	if !answerRRsetRelevant("alias.example.", dns.TypeTXT, "alias.example.", dns.TypeA) {
		t.Fatal("same-owner unsigned sibling must remain relevant")
	}
	if answerRRsetRelevant("other.example.", dns.TypePTR, "alias.example.", dns.TypePTR) {
		t.Fatal("out-of-qname PTR must not be required here")
	}
	if !answerRRsetRelevant("example.", dns.TypeDNAME, "www.example.", dns.TypeA) {
		t.Fatal("covering DNAME must be relevant")
	}
}
