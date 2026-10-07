package resolver

import (
	"fmt"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestExtractTraceEDE_SupportedNames(t *testing.T) {
	cases := []struct {
		code uint16
		name string
		text string
	}{
		{dns.EDECodeInvalidData, "Invalid Data", "existing code"},
		{dns.EDECodeSignatureExpiredBeforeValid, "Signature Expired Before Valid", "expiration before inception"},
		{dns.EDECodeTooEarly, "Too Early", ""},
		{dns.EDECodeUnsupportedNSEC3IterationsValue, "Unsupported NSEC3 Iterations", "iteration count"},
		{dns.EDECodeUnableToConformToPolicy, "Unable to Conform to Policy", "policy detail"},
		{dns.EDECodeSynthesized, "Synthesized", "synthesized answer"},
		{65535, "EDE65535", "private detail"},
	}
	options := make([]dns.EDNSOption, len(cases))
	for i, tc := range cases {
		options[i] = dns.BuildEDEOption(tc.code, tc.text)
	}
	for _, cd := range []bool{false, true} {
		t.Run(fmt.Sprintf("CD=%v", cd), func(t *testing.T) {
			msg := &dns.Message{
				Header:     dns.Header{Flags: dns.NewFlagBuilder().SetCD(cd).Build()},
				Additional: []dns.ResourceRecord{dns.BuildOPTWithOptions(1232, false, options)},
			}
			got, gotCD := extractTraceEDE(msg)
			if gotCD != cd || len(got) != len(cases) {
				t.Fatalf("CD=%v descriptors=%d, want CD=%v descriptors=%d", gotCD, len(got), cd, len(cases))
			}
			for i, tc := range cases {
				if got[i]["code"] != tc.code || got[i]["name"] != tc.name || got[i]["text"] != tc.text {
					t.Errorf("descriptor %d = %v, want code=%d name=%q text=%q", i, got[i], tc.code, tc.name, tc.text)
				}
			}
		})
	}
}
