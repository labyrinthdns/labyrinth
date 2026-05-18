package resolver

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// buildRRSIGRData returns a minimal RRSIG RDATA payload with the given
// TypeCovered. SignerName is set to the wire-encoded root label so the
// fixture can be parsed by dns.ParseRRSIG.
func buildRRSIGRData(typeCovered uint16) []byte {
	rdata := make([]byte, 18)
	binary.BigEndian.PutUint16(rdata[0:], typeCovered)
	rdata[2] = 8 // Algorithm
	rdata[3] = 0 // Labels
	binary.BigEndian.PutUint32(rdata[4:], 300)
	binary.BigEndian.PutUint32(rdata[8:], 1700000000)
	binary.BigEndian.PutUint32(rdata[12:], 1699000000)
	binary.BigEndian.PutUint16(rdata[16:], 12345)
	rdata = append(rdata, 0x00)             // root signer name
	rdata = append(rdata, 0xDE, 0xAD, 0xBE) // signature
	return rdata
}

func TestExtractCNAMERecords_IncludesCoveringRRSIG(t *testing.T) {
	rrsigCNAME := dns.ResourceRecord{
		Name:  "www.example.com",
		Type:  dns.TypeRRSIG,
		Class: dns.ClassIN,
		TTL:   60,
		RData: buildRRSIGRData(dns.TypeCNAME),
	}
	rrsigA := dns.ResourceRecord{
		Name:  "www.example.com",
		Type:  dns.TypeRRSIG,
		Class: dns.ClassIN,
		TTL:   60,
		RData: buildRRSIGRData(dns.TypeA),
	}
	cname := dns.ResourceRecord{
		Name:  "www.example.com",
		Type:  dns.TypeCNAME,
		Class: dns.ClassIN,
		TTL:   60,
		RData: []byte{0x00},
	}
	other := dns.ResourceRecord{
		Name:  "other.example.com",
		Type:  dns.TypeCNAME,
		Class: dns.ClassIN,
	}
	msg := &dns.Message{Answers: []dns.ResourceRecord{cname, rrsigCNAME, rrsigA, other}}

	got := extractCNAMERecords(msg, "www.example.com")
	// Expect CNAME + RRSIG(CNAME); not the RRSIG(A) or the other-owner record.
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
	if got[0].Type != dns.TypeCNAME || got[1].Type != dns.TypeRRSIG {
		t.Fatalf("unexpected record types: %v, %v", got[0].Type, got[1].Type)
	}
}

func TestExtractCNAMERecords_BadRRSIGSkipped(t *testing.T) {
	bad := dns.ResourceRecord{
		Name:  "www.example.com",
		Type:  dns.TypeRRSIG,
		Class: dns.ClassIN,
		RData: []byte{0x01}, // too short
	}
	msg := &dns.Message{Answers: []dns.ResourceRecord{bad}}
	got := extractCNAMERecords(msg, "www.example.com")
	if len(got) != 0 {
		t.Fatalf("expected unparseable RRSIG to be skipped, got %d records", len(got))
	}
}

func TestExtractRRsForOwnerWithRRSIG(t *testing.T) {
	a := dns.ResourceRecord{Name: "host.example.com", Type: dns.TypeA, Class: dns.ClassIN}
	aaaa := dns.ResourceRecord{Name: "host.example.com", Type: dns.TypeAAAA, Class: dns.ClassIN}
	rrsigA := dns.ResourceRecord{
		Name:  "host.example.com",
		Type:  dns.TypeRRSIG,
		Class: dns.ClassIN,
		RData: buildRRSIGRData(dns.TypeA),
	}
	rrsigNS := dns.ResourceRecord{
		Name:  "host.example.com",
		Type:  dns.TypeRRSIG,
		Class: dns.ClassIN,
		RData: buildRRSIGRData(dns.TypeNS),
	}
	wrongOwner := dns.ResourceRecord{Name: "other.example.com", Type: dns.TypeA, Class: dns.ClassIN}
	badRRSIG := dns.ResourceRecord{
		Name:  "host.example.com",
		Type:  dns.TypeRRSIG,
		Class: dns.ClassIN,
		RData: []byte{0xff}, // unparseable
	}

	msg := &dns.Message{Answers: []dns.ResourceRecord{a, aaaa, rrsigA, rrsigNS, wrongOwner, badRRSIG}}
	keep := map[uint16]struct{}{dns.TypeA: {}}
	got := extractRRsForOwnerWithRRSIG(msg, "host.example.com", keep)

	// Expect: A (kept by type), RRSIG(A) (kept because TypeCovered ∈ keep).
	// Excluded: AAAA (type not in keep), RRSIG(NS) (covered type not in keep),
	// other owner, unparseable RRSIG.
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d: %+v", len(got), got)
	}
	if got[0].Type != dns.TypeA {
		t.Errorf("first record should be A, got %d", got[0].Type)
	}
	if got[1].Type != dns.TypeRRSIG {
		t.Errorf("second record should be RRSIG, got %d", got[1].Type)
	}
}
