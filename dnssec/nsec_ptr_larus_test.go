package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// Real-world NXDOMAIN from ns1.larus.net for 141.8.222.154.in-addr.arpa —
// two-NSEC proof that previously fell through to Bogus and triggered fallback.
func TestVerifyNSECDenial_LarusPTR_NXDOMAIN(t *testing.T) {
	records := []NSECRecordWithOwner{
		{
			OwnerName: "108.8.222.154.in-addr.arpa.",
			NSECRecord: dns.NSECRecord{
				NextDomainName: "49.8.222.154.in-addr.arpa.",
				TypeBitMaps:    []uint16{dns.TypePTR, dns.TypeRRSIG, dns.TypeNSEC},
			},
		},
		{
			OwnerName: "8.222.154.in-addr.arpa.",
			NSECRecord: dns.NSECRecord{
				NextDomainName: "106.8.222.154.in-addr.arpa.",
				TypeBitMaps:    []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
			},
		},
	}
	ok, err := VerifyNSECDenial("141.8.222.154.in-addr.arpa.", dns.TypePTR, dns.RCodeNXDomain, records)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		// debug helpers
		q := canonicalName("141.8.222.154.in-addr.arpa.")
		o := canonicalName("108.8.222.154.in-addr.arpa.")
		n := canonicalName("49.8.222.154.in-addr.arpa.")
		t.Logf("covers qname? %v", nsecCoversName(o, n, q))
		ce := closestEncloser(q, o, n)
		t.Logf("ce=%q wc=%q", ce, "*."+ce)
		ao := canonicalName("8.222.154.in-addr.arpa.")
		an := canonicalName("106.8.222.154.in-addr.arpa.")
		wc := "*." + ce
		t.Logf("apex covers wc? %v (cmp wc/owner=%d wc/next=%d owner/next=%d)",
			nsecCoversName(ao, an, wc),
			canonicalCompareName(wc, ao),
			canonicalCompareName(wc, an),
			canonicalCompareName(ao, an),
		)
		t.Fatal("legitimate larus.net PTR NXDOMAIN NSEC proof rejected")
	}
}
