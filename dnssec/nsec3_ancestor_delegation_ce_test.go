package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// RFC 6840 §4.1: a parent-side delegation NSEC3 (NS without SOA) or a DNAME
// owner cannot be the closest encloser of an NXDOMAIN proof; otherwise the
// parent's signed NSEC3 chain could forge Secure NXDOMAIN under any cut.
func TestValidateResponse_NSEC3AncestorDelegationCannotBeClosestEncloser(t *testing.T) {
	for _, tc := range []struct {
		title string
		types []uint16
		want  ValidationResult
	}{
		{"ordinary closest encloser", []uint16{dns.TypeTXT}, Secure},
		{"parent-side delegation", []uint16{dns.TypeNS}, Bogus},
		{"delegation with DS", []uint16{dns.TypeNS, dns.TypeDS}, Bogus},
		{"DNAME owner", []uint16{dns.TypeDNAME}, Bogus},
	} {
		t.Run(tc.title, func(t *testing.T) {
			s := newFullTestSetup(t)
			rootKey, _ := dns.ParseDNSKEY(s.mq.responses[".|48"].Answers[0].RData)
			addRootSiblingWithDNSKEYSignature(t, s, s.zskRData, rootKey, s.privKey)
			ceHash, err := ComputeNSEC3Hash("child.", 1, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			zero, ff := make([]byte, 20), make([]byte, 20)
			for i := range ff {
				ff[i] = 0xff
			}
			ce := dns.ResourceRecord{Name: NSEC3HashToString(ceHash) + ".", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: buildNSEC3RData(1, 0, 0, nil, ff, tc.types)}
			cover := dns.ResourceRecord{Name: NSEC3HashToString(zero) + ".", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: buildNSEC3RData(1, 0, 0, nil, ff, []uint16{dns.TypeA})}
			resp := &dns.Message{
				Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build()},
				Authority: []dns.ResourceRecord{
					ce, signedTestRR(t, []dns.ResourceRecord{ce}, ".", s.dnskey, s.privKey),
					cover, signedTestRR(t, []dns.ResourceRecord{cover}, ".", s.dnskey, s.privKey),
				},
			}
			if got := s.v.ValidateResponse(resp, "a.child.", dns.TypeA); got != tc.want {
				t.Fatalf("ValidateResponse(a.child. NXDOMAIN) = %v, want %v", got, tc.want)
			}
		})
	}
}
