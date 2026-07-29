package dns

import "testing"

// TestRFC6975_OptionCodes pins the RFC 6975 option-code constants. A
// regression that drifts these silently breaks the auth-server hint we
// give about which signatures the resolver can actually validate.
func TestRFC6975_OptionCodes(t *testing.T) {
	if EDNSOptionCodeDAU != 5 {
		t.Errorf("EDNSOptionCodeDAU must be 5 per RFC 6975 §3, got %d", EDNSOptionCodeDAU)
	}
	if EDNSOptionCodeDHU != 6 {
		t.Errorf("EDNSOptionCodeDHU must be 6 per RFC 6975 §3, got %d", EDNSOptionCodeDHU)
	}
	if EDNSOptionCodeN3U != 7 {
		t.Errorf("EDNSOptionCodeN3U must be 7 per RFC 6975 §3, got %d", EDNSOptionCodeN3U)
	}
}

// TestBuildDAUOption_PayloadIsAlgorithmList verifies that BuildDAUOption
// serialises its algorithm list verbatim (RFC 6975 §3: "The DAU option
// data is a list of algorithm numbers").
func TestBuildDAUOption_PayloadIsAlgorithmList(t *testing.T) {
	algs := []uint8{AlgRSASHA256, AlgECDSAP256, AlgED25519}
	opt := BuildDAUOption(algs)
	if opt.Code != EDNSOptionCodeDAU {
		t.Errorf("option code: want %d, got %d", EDNSOptionCodeDAU, opt.Code)
	}
	if len(opt.Data) != len(algs) {
		t.Fatalf("data length: want %d, got %d", len(algs), len(opt.Data))
	}
	for i, a := range algs {
		if opt.Data[i] != a {
			t.Errorf("data[%d]: want %d, got %d", i, a, opt.Data[i])
		}
	}
}
