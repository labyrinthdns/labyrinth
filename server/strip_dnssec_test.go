package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestIsDNSSECRRType(t *testing.T) {
	dnssecTypes := []uint16{
		dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeDS,
		dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM,
	}
	for _, tt := range dnssecTypes {
		if !isDNSSECRRType(tt) {
			t.Errorf("isDNSSECRRType(%d) = false, want true", tt)
		}
	}
	nonDNSSEC := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS, dns.TypeMX, dns.TypeTXT}
	for _, tt := range nonDNSSEC {
		if isDNSSECRRType(tt) {
			t.Errorf("isDNSSECRRType(%d) = true, want false", tt)
		}
	}
}

func TestStripDNSSECRRs_Empty(t *testing.T) {
	got := stripDNSSECRRs(nil, dns.TypeA)
	if got != nil {
		t.Errorf("expected nil for nil input, got %v", got)
	}
	got = stripDNSSECRRs([]dns.ResourceRecord{}, dns.TypeA)
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

func TestStripDNSSECRRs_RemovesDNSSECTypesForNonMatchingQType(t *testing.T) {
	rrs := []dns.ResourceRecord{
		{Name: "example.com", Type: dns.TypeA},
		{Name: "example.com", Type: dns.TypeRRSIG},
		{Name: "example.com", Type: dns.TypeDNSKEY},
		{Name: "example.com", Type: dns.TypeNSEC},
		{Name: "example.com", Type: dns.TypeAAAA},
	}
	got := stripDNSSECRRs(rrs, dns.TypeA)
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
	if got[0].Type != dns.TypeA || got[1].Type != dns.TypeAAAA {
		t.Errorf("unexpected types after strip: %d, %d", got[0].Type, got[1].Type)
	}
}

func TestStripDNSSECRRs_KeepsDirectQuery(t *testing.T) {
	rrs := []dns.ResourceRecord{
		{Name: "example.com", Type: dns.TypeDNSKEY},
		{Name: "example.com", Type: dns.TypeRRSIG},
	}
	// qtype == DNSKEY: keep DNSKEY records; drop RRSIG.
	got := stripDNSSECRRs(rrs, dns.TypeDNSKEY)
	if len(got) != 1 || got[0].Type != dns.TypeDNSKEY {
		t.Fatalf("expected DNSKEY kept, got %+v", got)
	}
	// qtype == RRSIG: keep RRSIGs.
	got = stripDNSSECRRs(rrs, dns.TypeRRSIG)
	if len(got) != 1 || got[0].Type != dns.TypeRRSIG {
		t.Fatalf("expected RRSIG kept, got %+v", got)
	}
}
