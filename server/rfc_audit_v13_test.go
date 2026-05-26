package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestEDECode_StaleNXDOMAINIsCode19 pins the Y2 wire constant: RFC 8914
// §4.4 assigns info code 19 to "Stale NXDOMAIN Answer", distinct from
// info code 3 ("Stale Answer") used for positive serves. The handler's
// serve-stale path selects the code based on entry.RCODE; if this
// constant ever drifts, the wire compatibility silently breaks.
func TestEDECode_StaleNXDOMAINIsCode19(t *testing.T) {
	if dns.EDECodeStaleNXDOMAINAnswer != 19 {
		t.Errorf("EDECodeStaleNXDOMAINAnswer must be 19 per RFC 8914 §4.4, got %d",
			dns.EDECodeStaleNXDOMAINAnswer)
	}
	if dns.EDECodeStaleAnswer != 3 {
		t.Errorf("EDECodeStaleAnswer must be 3 per RFC 8914 §4.4, got %d",
			dns.EDECodeStaleAnswer)
	}
	if dns.EDECodeStaleNXDOMAINAnswer == dns.EDECodeStaleAnswer {
		t.Error("stale-NXDOMAIN and stale-answer EDE codes must be distinct")
	}
}

// TestEDECode_ForgedAnswerIsCode4 pins the Y4 wire constant: RFC 8914
// §4.6 assigns info code 4 to "Forged Answer", the standardised signal
// for resolver-side answer mutation (rebind protection, blocklisting).
func TestEDECode_ForgedAnswerIsCode4(t *testing.T) {
	if dns.EDECodeForgedAnswer != 4 {
		t.Errorf("EDECodeForgedAnswer must be 4 per RFC 8914 §4.6, got %d",
			dns.EDECodeForgedAnswer)
	}
}
