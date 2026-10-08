package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestBuildError_DoesNotEchoAD pins RFC 6840 §5.8: AD in a query only asks
// for the AD bit in the response, and an error response carries no
// authenticated data. buildError copied the query flags, so a client
// sending AD (dig's default) got SERVFAIL with AD=1 for a Bogus name
// (sigfail.verteiltesysteme.net). Opcode, RD and CD must still be echoed.
func TestBuildError_DoesNotEchoAD(t *testing.T) {
	h := testHandler()
	query := buildTestQuery("sigfail.example", dns.TypeA)
	qflags := binary.BigEndian.Uint16(query[2:4])
	qflags |= 1<<10 | 1<<9 | 1<<8 | 1<<6 | 1<<5 | 1<<4 // AA, TC, RD, Z, AD, CD
	binary.BigEndian.PutUint16(query[2:4], qflags)

	for _, rcode := range []uint8{dns.RCodeServFail, dns.RCodeRefused, dns.RCodeFormErr} {
		resp, err := h.buildError(query, rcode)
		if err != nil {
			t.Fatalf("buildError: %v", err)
		}
		hdr := dns.Header{Flags: binary.BigEndian.Uint16(resp[2:4])}
		if hdr.AD() {
			t.Errorf("rcode %d: AD echoed from query", rcode)
		}
		if hdr.AA() || hdr.TC() || hdr.Flags&(1<<6) != 0 {
			t.Errorf("rcode %d: AA/TC/Z echoed from query (flags=%#04x)", rcode, hdr.Flags)
		}
		if !hdr.RD() || !hdr.CD() {
			t.Errorf("rcode %d: RD/CD must be echoed (flags=%#04x)", rcode, hdr.Flags)
		}
		if !hdr.QR() || !hdr.RA() || hdr.RCODE() != rcode {
			t.Errorf("rcode %d: bad QR/RA/RCODE (flags=%#04x)", rcode, hdr.Flags)
		}
	}
}
