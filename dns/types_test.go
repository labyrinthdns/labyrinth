package dns

import "testing"

func TestTypeConstants(t *testing.T) {
	// Verify all type constants have correct values per RFC 1035
	types := map[uint16]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
		15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT",
	}
	for val, name := range types {
		if got, ok := TypeToString[val]; !ok {
			t.Errorf("TypeToString missing value %d (%s)", val, name)
		} else if got != name {
			t.Errorf("TypeToString[%d]: expected %q, got %q", val, name, got)
		}
	}
}

func TestRCodeConstants(t *testing.T) {
	rcodes := map[uint8]string{
		0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
		3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
	}
	for val, name := range rcodes {
		if got, ok := RCodeToString[val]; !ok {
			t.Errorf("RCodeToString missing value %d (%s)", val, name)
		} else if got != name {
			t.Errorf("RCodeToString[%d]: expected %q, got %q", val, name, got)
		}
	}
}

func TestOpcodeConstants(t *testing.T) {
	if OpcodeQuery != 0 {
		t.Errorf("OpcodeQuery: expected 0, got %d", OpcodeQuery)
	}
	if OpcodeIQuery != 1 {
		t.Errorf("OpcodeIQuery: expected 1, got %d", OpcodeIQuery)
	}
	if OpcodeStatus != 2 {
		t.Errorf("OpcodeStatus: expected 2, got %d", OpcodeStatus)
	}
}

func TestClassINConstant(t *testing.T) {
	if ClassIN != 1 {
		t.Errorf("ClassIN: expected 1, got %d", ClassIN)
	}
}

func TestErrorSentinels(t *testing.T) {
	errs := []error{errTruncated, errBufferFull, errNameTooLong, errLabelTooLong, errPointerLoop, errPointerForward, errInvalidMessage}
	for _, e := range errs {
		if e == nil {
			t.Error("error sentinel should not be nil")
		}
		if e.Error() == "" {
			t.Error("error sentinel should have non-empty message")
		}
	}
}

func TestMessageStructLayout(t *testing.T) {
	// Verify struct fields exist and are usable
	msg := Message{
		Header: Header{ID: 1, Flags: 2, QDCount: 3, ANCount: 4, NSCount: 5, ARCount: 6},
		Questions: []Question{{Name: "test", Type: TypeA, Class: ClassIN}},
		Answers:   []ResourceRecord{{Name: "test", Type: TypeA, TTL: 300}},
	}
	if msg.Header.ID != 1 {
		t.Error("struct layout broken")
	}
	if len(msg.Questions) != 1 {
		t.Error("questions slice broken")
	}
}
