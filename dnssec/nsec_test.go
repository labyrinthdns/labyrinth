package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func nsecRec(owner, next string, types ...uint16) NSECRecordWithOwner {
	return NSECRecordWithOwner{
		NSECRecord: dns.NSECRecord{
			NextDomainName: next,
			TypeBitMaps:    append([]uint16{}, types...),
		},
		OwnerName: owner,
	}
}

func TestVerifyNSECDenial_NoRecords(t *testing.T) {
	_, err := VerifyNSECDenial("example.com", dns.TypeA, dns.RCodeNoError, nil)
	if err == nil {
		t.Fatal("expected error for empty record set")
	}
}

func TestVerifyNSECDenial_NODATAByOwnerMatch(t *testing.T) {
	// host.example.com has AAAA + RRSIG + NSEC but no A.
	records := []NSECRecordWithOwner{
		nsecRec("host.example.com.", "z.example.com.",
			dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, err := VerifyNSECDenial("host.example.com", dns.TypeA, dns.RCodeNoError, records)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ok {
		t.Fatal("expected NODATA proof to validate")
	}
}

func TestVerifyNSECDenial_NODATARejectedWhenTypePresent(t *testing.T) {
	// Bitmap contains A — cannot be a NODATA proof for A.
	records := []NSECRecordWithOwner{
		nsecRec("host.example.com.", "z.example.com.", dns.TypeA, dns.TypeNSEC),
	}
	ok, _ := VerifyNSECDenial("host.example.com", dns.TypeA, dns.RCodeNoError, records)
	if ok {
		t.Fatal("expected NODATA proof to fail when qtype is in bitmap")
	}
}

func TestVerifyNSECDenial_NODATARejectedWhenCNAMEPresent(t *testing.T) {
	// CNAME in bitmap means the name has a CNAME — auth should have followed
	// it. NODATA is bogus.
	records := []NSECRecordWithOwner{
		nsecRec("host.example.com.", "z.example.com.", dns.TypeCNAME, dns.TypeNSEC),
	}
	ok, _ := VerifyNSECDenial("host.example.com", dns.TypeA, dns.RCodeNoError, records)
	if ok {
		t.Fatal("expected NODATA proof to fail when CNAME is in bitmap")
	}
}

func TestVerifyNSECDenial_NODATARejectedAtParentDelegation(t *testing.T) {
	// Parent-side NSEC at a delegation point: NS set, SOA clear. Proves
	// nothing about the child's NODATA.
	records := []NSECRecordWithOwner{
		nsecRec("child.example.com.", "z.example.com.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, _ := VerifyNSECDenial("child.example.com", dns.TypeA, dns.RCodeNoError, records)
	if ok {
		t.Fatal("delegation NSEC must not authenticate NODATA at the child")
	}
}

func TestVerifyNSECDenial_NODATAAcceptedAtZoneApex(t *testing.T) {
	// Apex NSEC: both NS and SOA present — this is the zone's own NSEC and
	// can authenticate NODATA at the apex.
	records := []NSECRecordWithOwner{
		nsecRec("example.com.", "a.example.com.",
			dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, err := VerifyNSECDenial("example.com", dns.TypeA, dns.RCodeNoError, records)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ok {
		t.Fatal("apex NSEC (NS+SOA, no A) must authenticate NODATA for A")
	}
}

func TestVerifyNSECDenial_CompactDenialNXDOMAIN(t *testing.T) {
	// Cloudflare black-lies pattern: NXDOMAIN with NSEC at qname whose
	// bitmap excludes CNAME/DNAME.
	records := []NSECRecordWithOwner{
		nsecRec("missing.example.com.", "\\000.missing.example.com.",
			dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, err := VerifyNSECDenial("missing.example.com", dns.TypeA, dns.RCodeNXDomain, records)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ok {
		t.Fatal("compact denial (NXDOMAIN with NSEC at qname) must validate")
	}
}

func TestVerifyNSECDenial_CompactDenialRejectedOnCNAME(t *testing.T) {
	// If the NSEC at qname has CNAME in bitmap, the name does exist and the
	// auth should have chased the CNAME — NXDOMAIN is bogus.
	records := []NSECRecordWithOwner{
		nsecRec("missing.example.com.", "\\000.missing.example.com.",
			dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, _ := VerifyNSECDenial("missing.example.com", dns.TypeA, dns.RCodeNXDomain, records)
	if ok {
		t.Fatal("compact denial must fail when bitmap has CNAME")
	}
}

func TestVerifyNSECDenial_StandardNXDOMAIN(t *testing.T) {
	// Classic two-NSEC proof:
	//   a.example.com NSEC c.example.com (covers b.example.com)
	//   example.com NSEC a.example.com (covers *.example.com — the wildcard
	//                                   sorts before the first label "a")
	records := []NSECRecordWithOwner{
		nsecRec("a.example.com.", "c.example.com.",
			dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
		nsecRec("example.com.", "a.example.com.",
			dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, err := VerifyNSECDenial("b.example.com", dns.TypeA, dns.RCodeNXDomain, records)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ok {
		t.Fatal("standard NXDOMAIN proof must validate")
	}
}

func TestVerifyNSECDenial_NXDOMAINMissingCoveringNSEC(t *testing.T) {
	// Only the wildcard-covering NSEC is present; the qname-covering NSEC
	// is missing. Standard proof must fail (no compact-denial fallback
	// either, since no NSEC owner == qname).
	records := []NSECRecordWithOwner{
		nsecRec("example.com.", "a.example.com.",
			dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, _ := VerifyNSECDenial("b.example.com", dns.TypeA, dns.RCodeNXDomain, records)
	if ok {
		t.Fatal("must not validate NXDOMAIN without a qname-covering NSEC")
	}
}

func TestVerifyNSECDenial_NODATAReturnsFalseForNonExistentName(t *testing.T) {
	// NOERROR (NODATA) but no NSEC at qname — the response is bogus, not
	// authenticated. We must NOT fall through into the NXDOMAIN paths.
	records := []NSECRecordWithOwner{
		nsecRec("a.example.com.", "c.example.com.",
			dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, _ := VerifyNSECDenial("b.example.com", dns.TypeA, dns.RCodeNoError, records)
	if ok {
		t.Fatal("NOERROR/NODATA with no NSEC at qname must not validate")
	}
}

func TestCanonicalCompareName(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"a.example.com", "b.example.com", -1},
		{"b.example.com", "a.example.com", 1},
		{"example.com", "example.com", 0},
		{"example.com.", "example.com", 0}, // root dot normalized
		{"EXAMPLE.com", "example.com", 0},  // case normalized
		// Shorter sorts before longer when prefix shared.
		{"example.com", "a.example.com", -1},
		{"a.example.com", "example.com", 1},
		// Different TLDs sort by rightmost label.
		{"a.example.com", "a.example.org", -1},
	}
	for _, tc := range cases {
		if got := canonicalCompareName(tc.a, tc.b); got != tc.want {
			t.Errorf("canonicalCompareName(%q, %q) = %d, want %d",
				tc.a, tc.b, got, tc.want)
		}
	}
}

func TestNSECCoversName(t *testing.T) {
	// Normal range
	if !nsecCoversName("a.example.com", "c.example.com", "b.example.com") {
		t.Error("b must be covered by (a, c)")
	}
	if nsecCoversName("a.example.com", "c.example.com", "a.example.com") {
		t.Error("owner itself must not be in open range")
	}
	if nsecCoversName("a.example.com", "c.example.com", "c.example.com") {
		t.Error("next itself must not be in open range")
	}
	// Wrap-around (last NSEC in zone): owner > next, range wraps.
	if !nsecCoversName("z.example.com", "a.example.com", "zz.example.com") {
		t.Error("wrap range must cover names greater than owner")
	}
	if !nsecCoversName("z.example.com", "a.example.com", "0.example.com") {
		t.Error("wrap range must cover names less than next")
	}
	if nsecCoversName("z.example.com", "a.example.com", "m.example.com") {
		t.Error("wrap range must not cover middle names")
	}
}

func TestClosestEncloser(t *testing.T) {
	ce := closestEncloser("b.sub.example.com", "a.sub.example.com", "c.sub.example.com")
	if ce != "sub.example.com" {
		t.Errorf("expected closest encloser 'sub.example.com', got %q", ce)
	}
}
