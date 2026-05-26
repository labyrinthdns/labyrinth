package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestVerifyNSECDenial_CompactDenial_RejectsBitmapWithQType pins the Y7
// fix to the "black lies" (compact denial of existence, Cloudflare-style)
// shape: a legitimate compact-denial NSEC at qname carries a bitmap with
// effectively no application types — typically only [NSEC, RRSIG] or a
// sentinel NXNAME. An attacker who replays a real signed NSEC for a
// name that DOES exist (bitmap actually lists A/AAAA/MX) can otherwise
// pair it with a forged NXDOMAIN RCODE: owner == qname, no CNAME/DNAME
// in the bitmap, no parent-side NS-without-SOA. The pre-fix code
// accepted that replay as proof of nonexistence. The fix requires the
// qtype to be ABSENT from the bitmap — if the bitmap says the type
// exists, the NXDOMAIN claim is structurally a lie.
func TestVerifyNSECDenial_CompactDenial_RejectsBitmapWithQType(t *testing.T) {
	// NSEC at qname asserting [A, AAAA, RRSIG, NSEC] — i.e. a real
	// existing name with addresses. Replaying this with RCODE=NXDOMAIN
	// must be rejected.
	records := []NSECRecordWithOwner{{
		NSECRecord: dns.NSECRecord{
			NextDomainName: "next.example.com",
			TypeBitMaps:    []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNSEC, dns.TypeRRSIG},
		},
		OwnerName: "foo.example.com",
	}}

	// Query was for A — the bitmap LISTS A, so this can't be NXDOMAIN.
	denied, err := VerifyNSECDenial("foo.example.com", dns.TypeA, dns.RCodeNXDomain, records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Error("compact denial NSEC whose bitmap LISTS the qtype must NOT prove NXDOMAIN " +
			"(RFC 6840 §4.1 / replay-NSEC-as-NXDOMAIN attack)")
	}
}

// TestVerifyNSECDenial_CompactDenial_AcceptsCleanBitmap is the positive
// counterpart: a real compact-denial NSEC (bitmap excludes the qtype
// and CNAME/DNAME) is still accepted as proof of NXDOMAIN.
func TestVerifyNSECDenial_CompactDenial_AcceptsCleanBitmap(t *testing.T) {
	records := []NSECRecordWithOwner{{
		NSECRecord: dns.NSECRecord{
			NextDomainName: "next.example.com",
			// "Black lies" shape: only NSEC + RRSIG.
			TypeBitMaps: []uint16{dns.TypeNSEC, dns.TypeRRSIG},
		},
		OwnerName: "foo.example.com",
	}}

	denied, err := VerifyNSECDenial("foo.example.com", dns.TypeA, dns.RCodeNXDomain, records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Error("legitimate compact-denial NSEC was rejected")
	}
}
