package dnssec

import (
	"github.com/labyrinthdns/labyrinth/dns"
	"testing"
)

func TestValidateDenialResponse_NSEC3DelegationCannotDenyChildData(t *testing.T) {
	failed := false
	for _, tc := range []struct {
		title string
		types []uint16
		want  ValidationResult
		qtype uint16
	}{
		{"ordinary owner control", []uint16{dns.TypeTXT}, Secure, dns.TypeA},
		{"parent delegation", []uint16{dns.TypeNS}, Bogus, dns.TypeA},
		{"zone apex", []uint16{dns.TypeNS, dns.TypeSOA}, Secure, dns.TypeA},
		{"DS delegation", []uint16{dns.TypeNS}, Insecure, dns.TypeDS},
		{"CNAME present", []uint16{dns.TypeCNAME}, Bogus, dns.TypeA},
	} {
		s := newFullTestSetup(t)
		rootKey, _ := dns.ParseDNSKEY(s.mq.responses[".|48"].Answers[0].RData)
		addRootSiblingWithDNSKEYSignature(t, s, s.zskRData, rootKey, s.privKey)
		name := "child."
		hash, err := ComputeNSEC3Hash(name, 1, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		next := make([]byte, 20)
		for i := range next {
			next[i] = 255
		}
		rr := dns.ResourceRecord{Name: NSEC3HashToString(hash) + ".", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: buildNSEC3RData(1, 0, 0, nil, next, tc.types)}
		resp := &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()}, Authority: []dns.ResourceRecord{rr, signedTestRR(t, []dns.ResourceRecord{rr}, ".", s.dnskey, s.privKey)}}
		got := s.v.ValidateResponse(resp, name, tc.qtype)
		t.Logf("%s EXPECTED: %v ACTUAL: %v", tc.title, tc.want, got)
		if got != tc.want {
			failed = true
		}
	}
	if failed {
		t.Fatal("PROBLEM CONFIRMED")
	}
	t.Log("FIX VERIFIED")
}
