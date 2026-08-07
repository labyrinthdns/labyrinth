package dns

import (
	"strings"
	"testing"
)

// RFC 9567 turns a resolver's private verdict ("this zone is broken") into a
// signal the zone's operator can act on. The whole mechanism rides on one
// specially-shaped query name, so the name construction in §6.2 and the
// loop guard in §6.3 are where the correctness lives. These tests pin both.

// TestRFC9567_ReportQNameShape pins the §6.2 layout:
//
//	_er.<qtype>.<qname>.<extended-error>._er.<agent-domain>
//
// The worked example is the one from the RFC: a DNSSEC-bogus (EDE 6) failure
// on an A (qtype 1) query for broken.test., reported to agent domain
// a.example.
func TestRFC9567_ReportQNameShape(t *testing.T) {
	got, ok := BuildReportQName("a.example", "broken.test", TypeA, EDECodeDNSSECBogus)
	if !ok {
		t.Fatal("BuildReportQName refused a well-formed report")
	}
	const want = "_er.1.broken.test.6._er.a.example"
	if got != want {
		t.Fatalf("report QNAME = %q, want %q", got, want)
	}
}

// TestRFC9567_NumericLabels pins that the QTYPE and EDE code are emitted as
// decimal numbers rather than mnemonics. An agent-domain log pipeline splits
// labels and parses integers; "AAAA" or "DNSSEC Bogus" in those positions
// would be unparseable, and worse, "DNSSEC Bogus" is not even a legal label.
func TestRFC9567_NumericLabels(t *testing.T) {
	got, ok := BuildReportQName("agent.example", "www.zone.test", TypeAAAA, EDECodeSignatureExpired)
	if !ok {
		t.Fatal("BuildReportQName refused a well-formed report")
	}
	// AAAA = 28, EDECodeSignatureExpired = 7.
	const want = "_er.28.www.zone.test.7._er.agent.example"
	if got != want {
		t.Fatalf("report QNAME = %q, want %q", got, want)
	}
}

// TestRFC9567_LoopGuard pins §6.3. A report query can itself fail — the agent
// domain may be unreachable, or delegated into the very zone that is broken.
// If a failure on a report produced another report, a single broken agent
// domain would make the resolver amplify its own error into an unbounded
// loop aimed at a server that is already in trouble.
func TestRFC9567_LoopGuard(t *testing.T) {
	t.Run("report qname is not re-reported", func(t *testing.T) {
		reportName := "_er.1.broken.test.6._er.a.example"
		if _, ok := BuildReportQName("b.example", reportName, TypeTXT, EDECodeDNSSECBogus); ok {
			t.Error("built a report about a report — RFC 9567 §6.3 forbids this, " +
				"and without the guard one broken agent domain loops forever")
		}
	})

	t.Run("agent domain containing _er is refused", func(t *testing.T) {
		if _, ok := BuildReportQName("_er.a.example", "broken.test", TypeA, EDECodeDNSSECBogus); ok {
			t.Error("accepted an agent domain that is itself inside the report namespace")
		}
	})

	t.Run("IsReportQName matches only whole labels", func(t *testing.T) {
		// A name that merely *contains* the substring must not be treated
		// as a report — "_error.example" is an ordinary name and reports
		// about it are legitimate.
		if IsReportQName("_error.example") {
			t.Error("IsReportQName matched a substring rather than a whole label")
		}
		if !IsReportQName("x._er.example") {
			t.Error("IsReportQName missed a real _er label")
		}
	})
}

// TestRFC9567_OversizedNameRefused pins that a report which cannot be encoded
// is dropped, not truncated. Reporting adds four labels plus the whole agent
// domain on top of the original qname, so deep names overflow the 255-octet
// limit routinely. A truncated report would name a different zone than the
// one that broke — worse than no report at all.
func TestRFC9567_OversizedNameRefused(t *testing.T) {
	// 200 octets of qname + a long agent domain overflows once the report
	// wrapper is added.
	deep := strings.TrimSuffix(strings.Repeat("label123456789012345678901234567890123456789.", 5), ".")
	agent := strings.TrimSuffix(strings.Repeat("agentlabel1234567890123456789012345678901234.", 4), ".")

	name, ok := BuildReportQName(agent, deep, TypeA, EDECodeDNSSECBogus)
	if ok {
		t.Fatalf("built an over-long report QNAME (%d chars): %q", len(name), name)
	}
}

// TestRFC9567_ReportChannelParsing pins the §6.1 option payload: an agent
// domain in uncompressed DNS wire format.
func TestRFC9567_ReportChannelParsing(t *testing.T) {
	t.Run("well-formed", func(t *testing.T) {
		data := BuildPlainName("a.example")
		if got := ParseReportChannelOption(data); got != "a.example" {
			t.Fatalf("agent domain = %q, want %q", got, "a.example")
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		if got := ParseReportChannelOption(nil); got != "" {
			t.Fatalf("agent domain = %q, want empty for an empty payload", got)
		}
	})

	t.Run("root name is not a usable agent domain", func(t *testing.T) {
		if got := ParseReportChannelOption([]byte{0x00}); got != "" {
			t.Fatalf("agent domain = %q, want empty for the root name", got)
		}
	})

	t.Run("compression pointer rejected", func(t *testing.T) {
		// The option arrives from an authoritative server we have just
		// decided not to trust. A compression pointer in a standalone
		// RDATA buffer has nothing legitimate to point at, and honouring
		// one would be an out-of-bounds read primitive. The wire decoder
		// rejects it because a pointer must target an offset strictly
		// earlier than its own, and nothing precedes offset 0.
		if got := ParseReportChannelOption([]byte{0xC0, 0x00}); got != "" {
			t.Fatalf("agent domain = %q, want empty for a compression pointer", got)
		}
	})

	t.Run("truncated name", func(t *testing.T) {
		// Length byte claims 9 octets, buffer holds 3.
		if got := ParseReportChannelOption([]byte{0x09, 'a', 'b'}); got != "" {
			t.Fatalf("agent domain = %q, want empty for a truncated name", got)
		}
	})
}

// TestRFC9567_ExtractReportChannel pins the option lookup against a parsed
// OPT record, including the common case: the zone did not opt in and there is
// no option at all.
func TestRFC9567_ExtractReportChannel(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		e := &EDNS0{Options: []EDNSOption{
			{Code: EDNSOptionCodeCookie, Data: make([]byte, 8)},
			{Code: EDNSOptionCodeReportChannel, Data: BuildPlainName("agent.example")},
		}}
		if got := ExtractReportChannel(e); got != "agent.example" {
			t.Fatalf("agent domain = %q, want %q", got, "agent.example")
		}
	})

	t.Run("absent", func(t *testing.T) {
		e := &EDNS0{Options: []EDNSOption{{Code: EDNSOptionCodeCookie, Data: make([]byte, 8)}}}
		if got := ExtractReportChannel(e); got != "" {
			t.Fatalf("agent domain = %q, want empty when the zone did not opt in", got)
		}
	})

	t.Run("nil EDNS0", func(t *testing.T) {
		if got := ExtractReportChannel(nil); got != "" {
			t.Fatalf("agent domain = %q, want empty for a non-EDNS response", got)
		}
	})
}

// TestRFC9567_OptionCodeIsIANAAssigned pins the wire value. Getting this
// wrong would make Labyrinth read some other option's bytes as a domain
// name — the option code is the only thing distinguishing them on the wire.
func TestRFC9567_OptionCodeIsIANAAssigned(t *testing.T) {
	if EDNSOptionCodeReportChannel != 18 {
		t.Fatalf("Report-Channel option code = %d, want 18 (IANA, RFC 9567 §6.1)",
			EDNSOptionCodeReportChannel)
	}
}
