package dns

import "testing"

// TestTypeRegistry_SVCB_HTTPS_CAA pins the Y19 fix: modern record types
// must show up by name in logs and the queries UI instead of as
// "TYPE64"/"TYPE65"/"TYPE257". Operators chasing real-world HTTP/3, ECH,
// or cert-issuance traffic depend on this — a UI that says "HTTPS"
// instead of "TYPE65" is the difference between debugging in seconds
// vs. minutes for issues that are routine on modern networks.
func TestTypeRegistry_SVCB_HTTPS_CAA(t *testing.T) {
	cases := []struct {
		code uint16
		name string
		rfc  string
	}{
		{TypeSVCB, "SVCB", "RFC 9460 §2.1"},
		{TypeHTTPS, "HTTPS", "RFC 9460 §9"},
		{TypeCAA, "CAA", "RFC 8659"},
	}
	for _, c := range cases {
		got, ok := TypeToString[c.code]
		if !ok {
			t.Errorf("type %d (%s, %s) missing from TypeToString registry", c.code, c.name, c.rfc)
			continue
		}
		if got != c.name {
			t.Errorf("type %d: want name %q (%s), got %q", c.code, c.name, c.rfc, got)
		}
	}
}

// TestTypeRegistry_AssignedNumbersAreCorrect pins the IANA-assigned numeric
// values so a rename or accidental renumber breaks a test rather than
// silently misclassifying live traffic.
func TestTypeRegistry_AssignedNumbersAreCorrect(t *testing.T) {
	if TypeSVCB != 64 {
		t.Errorf("SVCB type code must be 64 per IANA / RFC 9460, got %d", TypeSVCB)
	}
	if TypeHTTPS != 65 {
		t.Errorf("HTTPS type code must be 65 per IANA / RFC 9460, got %d", TypeHTTPS)
	}
	if TypeCAA != 257 {
		t.Errorf("CAA type code must be 257 per IANA / RFC 8659, got %d", TypeCAA)
	}
}
