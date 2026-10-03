package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// Real Afrinic/ARIN reverse shapes that previously forced TypeDS through
// Bogus → public-resolver fallback because VerifyNSECDenial rejects
// NS-without-SOA NODATA and covering proofs unless RCODE is NXDOMAIN.

func TestVerifyNSECDenialDSAbsent_InsecureDelegationCut(t *testing.T) {
	// 8.222.154.in-addr.arpa DS → NSEC at name: NS RRSIG NSEC (no DS).
	records := []NSECRecordWithOwner{{
		OwnerName: "8.222.154.in-addr.arpa.",
		NSECRecord: dns.NSECRecord{
			NextDomainName: "128.223.154.in-addr.arpa.",
			TypeBitMaps:    []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
		},
	}}
	ok, err := VerifyNSECDenialDSAbsent("8.222.154.in-addr.arpa.", records)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("insecure reverse cut DS NODATA must be accepted")
	}
	// Generic denial path must still reject this for non-DS (child data).
	denied, err := VerifyNSECDenial("8.222.154.in-addr.arpa.", dns.TypePTR, dns.RCodeNoError, records)
	if err != nil {
		t.Fatal(err)
	}
	if denied {
		t.Fatal("NS-without-SOA NSEC must not prove PTR NODATA")
	}
}

func TestVerifyNSECDenialDSAbsent_CoveredIntermediate_NOERROR(t *testing.T) {
	// 222.154.in-addr.arpa sits in the gap 33.221.154 → 8.222.154.
	records := []NSECRecordWithOwner{{
		OwnerName: "33.221.154.in-addr.arpa.",
		NSECRecord: dns.NSECRecord{
			NextDomainName: "8.222.154.in-addr.arpa.",
			TypeBitMaps:    []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
		},
	}}
	ok, err := VerifyNSECDenialDSAbsent("222.154.in-addr.arpa.", records)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("covering NSEC must prove DS absent for intermediate reverse label")
	}
	// Generic path requires NXDOMAIN for covering proofs.
	denied, err := VerifyNSECDenial("222.154.in-addr.arpa.", dns.TypeDS, dns.RCodeNoError, records)
	if err != nil {
		t.Fatal(err)
	}
	if denied {
		t.Fatal("VerifyNSECDenial must not accept covering proof under NOERROR")
	}
}

func TestVerifyNSECDenialDSAbsent_ARINCoveredIntermediate(t *testing.T) {
	// 94.167.in-addr.arpa covered by 93.167 → 0.94.167.
	records := []NSECRecordWithOwner{{
		OwnerName: "93.167.in-addr.arpa.",
		NSECRecord: dns.NSECRecord{
			NextDomainName: "0.94.167.in-addr.arpa.",
			TypeBitMaps:    []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
		},
	}}
	ok, err := VerifyNSECDenialDSAbsent("94.167.in-addr.arpa.", records)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("ARIN covering NSEC must prove DS absent at 94.167.in-addr.arpa")
	}
}

func TestVerifyNSECDenialDSAbsent_RejectsWhenDSBitSet(t *testing.T) {
	records := []NSECRecordWithOwner{{
		OwnerName: "child.example.",
		NSECRecord: dns.NSECRecord{
			NextDomainName: "next.example.",
			TypeBitMaps:    []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC},
		},
	}}
	ok, err := VerifyNSECDenialDSAbsent("child.example.", records)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("NSEC with DS bit set must not prove DS absence")
	}
}
