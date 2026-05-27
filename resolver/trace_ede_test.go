package resolver

import (
	"strings"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestExtractTraceEDE_ParsesCDAndEDE pins Y41: when a response carries the
// CD bit and one or more Extended DNS Errors (RFC 8914 §3), the trace
// helper surfaces both so the upstream-stage event details can render
// "CD=1" and per-code badges in the diagnostics UI.
//
// We construct a minimal Message with an OPT pseudo-record whose RData
// carries two EDE options (Blocked + Filtered), then assert:
//  1. CD bit is reported as true
//  2. extractTraceEDE returns exactly the two descriptors with the right
//     numeric codes, RFC-named labels, and the extra-text passthrough.
func TestExtractTraceEDE_ParsesCDAndEDE(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetCD(true).Build(),
			ARCount: 1,
		},
	}

	opt := dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{
		dns.BuildEDEOption(dns.EDECodeBlocked, "ACL denied"),
		dns.BuildEDEOption(dns.EDECodeFiltered, "RPZ hit"),
	})
	msg.Additional = []dns.ResourceRecord{opt}

	got, cd := extractTraceEDE(msg)

	if !cd {
		t.Errorf("CD bit not surfaced — diagnostics UI cannot render CD=1 badge")
	}
	if len(got) != 2 {
		t.Fatalf("got %d EDE descriptors, want 2", len(got))
	}

	first := got[0]
	if first["code"].(uint16) != dns.EDECodeBlocked {
		t.Errorf("first EDE code = %v, want %d (Blocked)", first["code"], dns.EDECodeBlocked)
	}
	if !strings.Contains(first["name"].(string), "Blocked") {
		t.Errorf("first EDE name = %q, want to contain \"Blocked\"", first["name"])
	}
	if first["text"].(string) != "ACL denied" {
		t.Errorf("first EDE text = %q, want \"ACL denied\"", first["text"])
	}

	second := got[1]
	if second["code"].(uint16) != dns.EDECodeFiltered {
		t.Errorf("second EDE code = %v, want %d (Filtered)", second["code"], dns.EDECodeFiltered)
	}
	if !strings.Contains(second["name"].(string), "Filtered") {
		t.Errorf("second EDE name = %q, want to contain \"Filtered\"", second["name"])
	}
}

// TestExtractTraceEDE_NoOPT: a response without an OPT pseudo-record (the
// common case for legacy upstreams) MUST return nil EDE and propagate the
// CD bit honestly from the header.
func TestExtractTraceEDE_NoOPT(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().Build(), // CD=0
		},
	}
	got, cd := extractTraceEDE(msg)
	if cd {
		t.Errorf("CD reported as true on a CD=0 header")
	}
	if got != nil {
		t.Errorf("got %v EDE descriptors, want nil for OPT-less response", got)
	}
}

// TestExtractTraceEDE_NilMessage: nil input is a real possibility during
// trace shutdown — must not panic, must return the zero value.
func TestExtractTraceEDE_NilMessage(t *testing.T) {
	got, cd := extractTraceEDE(nil)
	if got != nil || cd {
		t.Errorf("nil message: got (%v, %v), want (nil, false)", got, cd)
	}
}

// TestEDECodeName_KnownCodes pins the RFC 8914 §4 code → name mapping so a
// renumber or typo surfaces here instead of as a garbled badge in the UI.
func TestEDECodeName_KnownCodes(t *testing.T) {
	for _, c := range []struct {
		code uint16
		want string
	}{
		{dns.EDECodeStaleAnswer, "Stale Answer"},
		{dns.EDECodeDNSSECBogus, "DNSSEC Bogus"},
		{dns.EDECodeFiltered, "Filtered"},
		{dns.EDECodeProhibited, "Prohibited"},
		{dns.EDECodeNoReachableAuthority, "No Reachable Authority"},
	} {
		if got := edeCodeName(c.code); got != c.want {
			t.Errorf("edeCodeName(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

// TestEDECodeName_UnknownCodeFallsThrough: a code we don't have a label for
// (e.g. a future IANA assignment) renders as "EDE<n>" so the UI shows the
// number, not blank. Pin the fallback so a future refactor doesn't silently
// swallow unknown codes.
func TestEDECodeName_UnknownCodeFallsThrough(t *testing.T) {
	if got := edeCodeName(9999); got != "EDE9999" {
		t.Errorf("edeCodeName(9999) = %q, want \"EDE9999\"", got)
	}
}
