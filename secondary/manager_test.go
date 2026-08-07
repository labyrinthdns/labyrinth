package secondary

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/xfr"
)

// The secondary-zone manager is what makes the xfr package reachable. Before
// it existed, Labyrinth carried a correct AXFR-over-TLS client that nothing
// called — the compliance matrix claimed RFC 9103 on the strength of a file
// existing, and no configuration could cause a single byte to be transferred.
//
// These tests cover the parts of the manager where a mistake corrupts the
// served zone rather than failing loudly: applying an incremental delta, and
// the RRset-precision of deletions.

func rr(name string, rtype uint16, rdata ...byte) dns.ResourceRecord {
	return dns.ResourceRecord{
		Name: name, Type: rtype, Class: dns.ClassIN, TTL: 300,
		RData: rdata, RDLength: uint16(len(rdata)),
	}
}

// TestApplyDelta_DeletionsBeforeAdditions pins the ordering of RFC 1995 §2.
// A version step that changes a record's value arrives as a delete of the old
// RDATA followed by an add of the new one. Applying additions first would add
// the new record and then have the deletion pass fail to find the old one —
// or worse, match and remove what was just added.
func TestApplyDelta_DeletionsBeforeAdditions(t *testing.T) {
	zone := []dns.ResourceRecord{
		rr("www.example.com", dns.TypeA, 192, 0, 2, 1),
	}
	delta := xfr.Delta{
		FromSerial: 1, ToSerial: 2,
		Deleted: []dns.ResourceRecord{rr("www.example.com", dns.TypeA, 192, 0, 2, 1)},
		Added:   []dns.ResourceRecord{rr("www.example.com", dns.TypeA, 192, 0, 2, 99)},
	}

	got := applyDelta(zone, delta)
	if len(got) != 1 {
		t.Fatalf("zone holds %d records after a replace, want 1: %+v", len(got), got)
	}
	if got[0].RData[3] != 99 {
		t.Errorf("record RDATA = %v, want the replacement value .99", got[0].RData)
	}
}

// TestRemoveRecord_RDataPrecision pins that deletion matches on RDATA, not
// just name and type. A zone commonly holds several A records under one name;
// a delta retiring one of them must not take the whole RRset with it.
func TestRemoveRecord_RDataPrecision(t *testing.T) {
	zone := []dns.ResourceRecord{
		rr("www.example.com", dns.TypeA, 192, 0, 2, 1),
		rr("www.example.com", dns.TypeA, 192, 0, 2, 2),
		rr("www.example.com", dns.TypeA, 192, 0, 2, 3),
	}

	got := removeRecord(zone, rr("www.example.com", dns.TypeA, 192, 0, 2, 2))
	if len(got) != 2 {
		t.Fatalf("removed %d records, want 1 — deletion must be RDATA-precise, "+
			"or one retired address takes out the whole RRset", 3-len(got))
	}
	for _, r := range got {
		if r.RData[3] == 2 {
			t.Error("the targeted record survived")
		}
	}
}

// TestRemoveRecord_NameCaseInsensitive pins RFC 4343. A primary that emits
// the owner name with different capitalisation than the copy holds must still
// have its deletions applied, or the zone accumulates records that were meant
// to be removed.
func TestRemoveRecord_NameCaseInsensitive(t *testing.T) {
	zone := []dns.ResourceRecord{rr("WWW.Example.COM", dns.TypeA, 192, 0, 2, 1)}
	got := removeRecord(zone, rr("www.example.com", dns.TypeA, 192, 0, 2, 1))
	if len(got) != 0 {
		t.Error("case-differing owner name prevented the deletion")
	}
}

// TestRemoveRecord_NoMatchIsNoOp pins that a deletion naming something absent
// leaves the zone alone rather than removing an arbitrary near-match.
func TestRemoveRecord_NoMatchIsNoOp(t *testing.T) {
	zone := []dns.ResourceRecord{rr("www.example.com", dns.TypeA, 192, 0, 2, 1)}
	got := removeRecord(zone, rr("other.example.com", dns.TypeA, 192, 0, 2, 1))
	if len(got) != 1 {
		t.Errorf("zone holds %d records, want 1 — an unmatched deletion must be a no-op", len(got))
	}
}

// TestRefreshClamping pins the bounds applied to SOA timers. Those values come
// from the primary and are not fully trusted: a zone whose SOA names a
// one-second REFRESH would otherwise turn this resolver into a transfer flood
// against its own primary.
func TestRefreshClamping(t *testing.T) {
	if got := clampRefresh(0); got != minRefresh {
		t.Errorf("clampRefresh(0) = %v, want the %v floor", got, minRefresh)
	}
	if got := clampRefresh(maxRefresh * 10); got != maxRefresh {
		t.Errorf("clampRefresh(huge) = %v, want the %v ceiling", got, maxRefresh)
	}
	if got := clampRefresh(minRetry); got != minRetry {
		t.Errorf("clampRefresh(%v) = %v, want it unchanged", minRetry, got)
	}
	if got := clampRetry(0); got != minRetry {
		t.Errorf("clampRetry(0) = %v, want the %v floor", got, minRetry)
	}
}

// TestToLocalRecords_RDataPassthrough pins that transferred RDATA reaches the
// local zone table byte-for-byte. Re-encoding would only create chances to
// corrupt record types neither layer parses — exactly what RFC 3597 §3 warns
// against.
func TestToLocalRecords_RDataPassthrough(t *testing.T) {
	// A TLSA record: a type the local-zone encoder cannot construct from
	// presentation format, which is precisely why passthrough matters.
	tlsa := rr("_443._tcp.example.com", dns.TypeTLSA, 3, 1, 1, 0xDE, 0xAD, 0xBE, 0xEF)
	got := toLocalRecords([]dns.ResourceRecord{tlsa})

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].Type != dns.TypeTLSA {
		t.Errorf("type = %d, want TLSA", got[0].Type)
	}
	if len(got[0].RData) != len(tlsa.RData) {
		t.Fatalf("RDATA length changed: %d -> %d", len(tlsa.RData), len(got[0].RData))
	}
	for i := range tlsa.RData {
		if got[0].RData[i] != tlsa.RData[i] {
			t.Fatalf("RDATA octet %d changed: %#x -> %#x", i, tlsa.RData[i], got[0].RData[i])
		}
	}
	if got[0].TTL != tlsa.TTL {
		t.Errorf("TTL = %d, want %d", got[0].TTL, tlsa.TTL)
	}
}
