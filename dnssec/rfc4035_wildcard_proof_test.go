package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestVerifyNSECDenial_NXDOMAIN_RequiresWildcardCover pins RFC 4035
// §5.4 NXDOMAIN proof structure: a valid NXDOMAIN denial requires TWO
// NSEC records — one covering qname AND one covering (or matching) the
// wildcard `*.<closest_encloser>`. Without the wildcard cover, an
// attacker with a single legitimately-signed NSEC anywhere in the zone
// could replay it to "prove" NXDOMAIN for arbitrary unrelated names
// inside that zone — the wildcard could have a real RR that we'd be
// hiding (the "naked NSEC" forgery).
//
// We pin two cases:
//
//   1. Full proof: qname-cover + wildcard-cover NSEC pair → accepted.
//   2. Naked NSEC: only the qname-cover NSEC, no wildcard proof → MUST
//      be rejected (the validator returns false; the response decays
//      to Bogus upstream).
//
// The qname is chosen so its closest encloser is the zone apex; the
// wildcard the proof must cover is `*.example.com`.
func TestVerifyNSECDenial_NXDOMAIN_RequiresWildcardCover(t *testing.T) {
	// NSEC at "alpha.example.com" covering (alpha, gamma) — proves
	// "beta.example.com" doesn't exist in the (alpha, gamma) gap.
	qnameCover := NSECRecordWithOwner{
		OwnerName: "alpha.example.com",
		NSECRecord: dns.NSECRecord{
			NextDomainName: "gamma.example.com",
			TypeBitMaps:    []uint16{dns.TypeA},
		},
	}

	// NSEC at "example.com" covering (example.com, alpha.example.com) —
	// the gap between zone apex and "alpha". Because "*.example.com"
	// sorts canonically BEFORE alpha.example.com (the '*' byte 0x2A
	// is below 'a' byte 0x61), the wildcard interval needs an NSEC
	// at the apex itself covering that range.
	wildcardCover := NSECRecordWithOwner{
		OwnerName: "example.com",
		NSECRecord: dns.NSECRecord{
			NextDomainName: "alpha.example.com",
			TypeBitMaps:    []uint16{dns.TypeNS, dns.TypeSOA},
		},
	}

	t.Run("full NSEC proof (qname-cover + wildcard-cover) → accepted", func(t *testing.T) {
		records := []NSECRecordWithOwner{qnameCover, wildcardCover}
		ok, err := VerifyNSECDenial("beta.example.com", dns.TypeA, dns.RCodeNXDomain, records)
		if err != nil {
			t.Fatalf("VerifyNSECDenial: %v", err)
		}
		if !ok {
			t.Errorf("legitimate two-NSEC NXDOMAIN proof rejected — denial structure broken; would Bogus every real signed NXDOMAIN response")
		}
	})

	t.Run("naked NSEC (qname-cover only, no wildcard-cover) → rejected", func(t *testing.T) {
		records := []NSECRecordWithOwner{qnameCover}
		ok, err := VerifyNSECDenial("beta.example.com", dns.TypeA, dns.RCodeNXDomain, records)
		if err != nil {
			t.Fatalf("VerifyNSECDenial: %v", err)
		}
		if ok {
			t.Errorf("naked-NSEC NXDOMAIN accepted — RFC 4035 §5.4 violation; attacker could replay a single zone NSEC to forge NXDOMAIN for any name in the gap and hide real wildcard-matched records")
		}
	})
}

// TestVerifyNSECDenial_NODATA_DelegationNSECRejected pins RFC 4035
// §5.4: a NODATA proof requires an NSEC at the qname itself whose
// type bitmap excludes the queried type. BUT — and this is the
// security-critical wrinkle — a "delegation point NSEC" (NS bit
// set, SOA bit clear) lives on the PARENT side of a zone cut and
// proves NOTHING about the child zone's data. Accepting it as a
// NODATA proof would let a parent-zone NSEC silently deny existence
// of records actually served by the child.
//
// The classic exploit: attacker mints a fake "NODATA" for
// `mail.victim.com TYPE=MX` using the parent zone's delegation
// NSEC at `victim.com` which has NS but not MX in its bitmap.
// The validator must reject this — the NSEC needs SOA in the
// bitmap to prove it's the child-side authority's NSEC.
func TestVerifyNSECDenial_NODATA_DelegationNSECRejected(t *testing.T) {
	// Delegation-point NSEC (parent-side): NS but not SOA → cannot
	// authenticate child-zone NODATA.
	delegationNSEC := NSECRecordWithOwner{
		OwnerName: "child.example.com",
		NSECRecord: dns.NSECRecord{
			NextDomainName: "next.example.com",
			TypeBitMaps:    []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
		},
	}

	// Authoritative NSEC (child-side apex): has SOA + NS → can
	// authenticate child-zone NODATA.
	authoritativeNSEC := NSECRecordWithOwner{
		OwnerName: "child.example.com",
		NSECRecord: dns.NSECRecord{
			NextDomainName: "next.child.example.com",
			TypeBitMaps:    []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC},
		},
	}

	t.Run("delegation NSEC (NS, no SOA) rejected as NODATA proof", func(t *testing.T) {
		ok, err := VerifyNSECDenial("child.example.com", dns.TypeMX,
			dns.RCodeNoError, []NSECRecordWithOwner{delegationNSEC})
		if err != nil {
			t.Fatalf("VerifyNSECDenial: %v", err)
		}
		if ok {
			t.Errorf("parent-side delegation NSEC accepted as NODATA proof — attacker could use parent's NSEC to forge NODATA for child-zone records (RFC 4035 §5.4)")
		}
	})

	t.Run("authoritative NSEC (NS + SOA) accepted as NODATA proof", func(t *testing.T) {
		ok, err := VerifyNSECDenial("child.example.com", dns.TypeMX,
			dns.RCodeNoError, []NSECRecordWithOwner{authoritativeNSEC})
		if err != nil {
			t.Fatalf("VerifyNSECDenial: %v", err)
		}
		if !ok {
			t.Errorf("authoritative-side NSEC rejected — child-zone apex NSECs must be accepted as NODATA proof")
		}
	})
}
