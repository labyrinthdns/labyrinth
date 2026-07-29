package server

import (
	"testing"
)

// TestQueryHasEDNS_DetectsEDNSByARCount pins the helper that gates
// EDE emission on the refuse-path. The byte-level check (header
// ARCount != 0) is enough because the refuse paths only fire BEFORE
// we have a parsed query, and a non-EDNS client has ARCount=0 by
// definition. A FORMERR client with garbage in additional is fine to
// flag — its REFUSED carrying an EDE 18 helps it debug.
func TestQueryHasEDNS_DetectsEDNSByARCount(t *testing.T) {
	// Header: id=0x1234, flags=0x0100 (RD), qd=1, an=0, ns=0, ar=1
	withEDNS := []byte{
		0x12, 0x34, // id
		0x01, 0x00, // flags
		0x00, 0x01, // qdcount
		0x00, 0x00, // ancount
		0x00, 0x00, // nscount
		0x00, 0x01, // arcount = 1 → EDNS likely
	}
	if !queryHasEDNS(withEDNS) {
		t.Error("ARCount=1 must report EDNS present")
	}

	withoutEDNS := []byte{
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, // arcount = 0
	}
	if queryHasEDNS(withoutEDNS) {
		t.Error("ARCount=0 must report no EDNS")
	}
}

// TestQueryHasEDNS_RejectsTooShort pins the defensive guard: a
// truncated query (less than the 12-byte DNS header) MUST report no
// EDNS rather than panic on out-of-bounds indexing.
func TestQueryHasEDNS_RejectsTooShort(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("short query must not panic: %v", r)
		}
	}()
	if queryHasEDNS([]byte{0x00}) {
		t.Error("11-byte query must not be considered EDNS-bearing")
	}
	if queryHasEDNS(nil) {
		t.Error("nil query must not be considered EDNS-bearing")
	}
}
