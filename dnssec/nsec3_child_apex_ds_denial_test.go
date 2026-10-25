package dnssec

import (
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// A DS denial must come from the parent side of the zone cut. The child's own
// apex NSEC3 (NS+SOA, never DS) must not authenticate "no DS" for the child.
func TestValidateResponse_ChildApexNSEC3CannotDenyDS(t *testing.T) {
	apex := []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeDNSKEY, dns.TypeNSEC3PARAM}
	for _, tc := range []struct {
		title, signer, ownerSuffix string
		types                      []uint16
		want                       ValidationResult
	}{
		{"child apex signed by child", "child.", ".child.", apex, Bogus},
		{"parent-side insecure delegation", ".", ".", []uint16{dns.TypeNS}, Insecure},
	} {
		t.Run(tc.title, func(t *testing.T) {
			s := newFullTestSetup(t)
			rootKey, _ := dns.ParseDNSKEY(s.mq.responses[".|48"].Answers[0].RData)
			addRootSiblingWithDNSKEYSignature(t, s, s.zskRData, rootKey, s.privKey)
			digest := sha256.Sum256(buildDSDigestInput("child.", s.dnskey))
			ds := dns.ResourceRecord{Name: "child.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 300,
				RData: append([]byte{byte(s.dnskey.KeyTag() >> 8), byte(s.dnskey.KeyTag()), s.dnskey.Algorithm, dns.DigestSHA256}, digest[:]...)}
			s.mq.responses["child.|43"] = &dns.Message{Answers: []dns.ResourceRecord{ds, signedTestRR(t, []dns.ResourceRecord{ds}, ".", s.dnskey, s.privKey)}}
			key := dns.ResourceRecord{Name: "child.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 300, RData: s.zskRData}
			s.mq.responses["child.|48"] = &dns.Message{Answers: []dns.ResourceRecord{key, signedTestRR(t, []dns.ResourceRecord{key}, "child.", s.dnskey, s.privKey)}}

			h, err := ComputeNSEC3Hash("child.", 1, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			next := append([]byte(nil), h...)
			next[len(next)-1]++
			rr := dns.ResourceRecord{Name: NSEC3HashToString(h) + tc.ownerSuffix, Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: buildNSEC3RData(1, 0, 0, nil, next, tc.types)}
			resp := &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Authority: []dns.ResourceRecord{rr, signedTestRR(t, []dns.ResourceRecord{rr}, tc.signer, s.dnskey, s.privKey)},
			}
			if got := s.v.ValidateResponse(resp, "child.", dns.TypeDS); got != tc.want {
				t.Fatalf("ValidateResponse(child. DS NODATA) = %v, want %v", got, tc.want)
			}
		})
	}
}
