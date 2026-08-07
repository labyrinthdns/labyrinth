package dns

import (
	"strconv"
	"strings"
)

// RFC 9567 (DNS Error Reporting) closes a long-standing operational gap:
// when a resolver rejects a zone — a bad signature, a missing DNSKEY, an
// unreachable delegation — the zone's operator is the last to find out. The
// resolver knows exactly what broke and says so in an RFC 8914 Extended DNS
// Error, but that EDE travels *downstream* to the client, never back to the
// authority that could fix it. Operators have historically learned about
// DNSSEC breakage from user complaints hours later.
//
// The mechanism is deliberately small. An authoritative server attaches a
// Report-Channel option (EDNS code 18) naming an "agent domain" it monitors.
// A resolver that hits an error on that zone sends one throwaway TXT query
// to a specially-constructed name under the agent domain. The query itself
// is the report — its QNAME encodes what failed, for what name, with which
// EDE code. Nothing is expected in reply, and the resolver ignores whatever
// comes back.
//
// That design is why the reporting side is cheap to implement correctly:
// there is no new protocol, no new record type, and no response handling.
// The two things that need care are the name construction (§6.2) and not
// reporting on reports (§6.3), both handled here.

// ReportQueryLabel is the "_er" label that brackets a report QNAME on both
// sides (RFC 9567 §6.2). It appears twice: once leading the encoded query
// details, once immediately before the agent domain. Recognising it is also
// how a resolver avoids reporting on its own reports.
const ReportQueryLabel = "_er"

// ParseReportChannelOption decodes the agent domain from a Report-Channel
// option's data (RFC 9567 §6.1). The payload is a domain name in
// uncompressed DNS wire format.
//
// The name is decoded with the ordinary wire decoder, which rejects
// compression pointers here for free: a pointer must target an offset
// strictly earlier than its own, and inside a standalone RDATA buffer the
// earliest possible offset is 0, so no pointer can ever be valid. That
// matters because the option arrives from an authoritative server we do not
// trust — a pointer that escaped into the surrounding message buffer would
// be an out-of-bounds read primitive.
//
// Returns "" for a malformed or empty payload, and for the root name, which
// cannot be a usable agent domain.
func ParseReportChannelOption(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	name, _, err := DecodeName(data, 0)
	if err != nil {
		return ""
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return ""
	}
	return name
}

// ExtractReportChannel returns the agent domain advertised in a response's
// Report-Channel option, or "" when the responder did not advertise one
// (which is the common case — the option is opt-in per zone).
func ExtractReportChannel(e *EDNS0) string {
	if e == nil {
		return ""
	}
	for _, opt := range e.Options {
		if opt.Code == EDNSOptionCodeReportChannel {
			return ParseReportChannelOption(opt.Data)
		}
	}
	return ""
}

// IsReportQName reports whether a name is itself an error report, i.e. it
// contains the "_er" bracket label. RFC 9567 §6.3 requires a resolver not to
// send reports about failures encountered while resolving a report — without
// that check a broken agent domain would trigger a report about the report,
// which fails, which triggers another, and the resolver amplifies its own
// error into a loop against the very server that is already struggling.
func IsReportQName(name string) bool {
	for _, label := range strings.Split(strings.ToLower(name), ".") {
		if label == ReportQueryLabel {
			return true
		}
	}
	return false
}

// BuildReportQName constructs the report query name for a failure, per
// RFC 9567 §6.2:
//
//	_er.<qtype>.<qname>.<extended-error>._er.<agent-domain>
//
// So a DNSSEC-bogus (EDE 6) failure on an A query for broken.test., reported
// to agent domain a.example., becomes:
//
//	_er.1.broken.test.6._er.a.example.
//
// The QTYPE and EDE code are decimal, not the mnemonic — the agent's log
// pipeline parses labels, not names.
//
// Returns ok=false when the report should not be sent:
//
//   - the agent domain or qname is empty;
//   - the qname is itself a report (§6.3 loop guard — see IsReportQName);
//   - the assembled name would exceed the 255-octet DNS limit, which happens
//     for legitimately deep qnames since reporting adds the agent domain plus
//     four labels of overhead. A name that cannot be encoded must be dropped
//     rather than truncated: a truncated report names the *wrong* zone.
func BuildReportQName(agentDomain, qname string, qtype uint16, edeCode uint16) (string, bool) {
	agentDomain = strings.TrimSuffix(agentDomain, ".")
	qname = strings.TrimSuffix(qname, ".")
	if agentDomain == "" || qname == "" {
		return "", false
	}
	if IsReportQName(qname) || IsReportQName(agentDomain) {
		return "", false
	}

	var b strings.Builder
	b.WriteString(ReportQueryLabel)
	b.WriteByte('.')
	b.WriteString(strconv.FormatUint(uint64(qtype), 10))
	b.WriteByte('.')
	b.WriteString(qname)
	b.WriteByte('.')
	b.WriteString(strconv.FormatUint(uint64(edeCode), 10))
	b.WriteByte('.')
	b.WriteString(ReportQueryLabel)
	b.WriteByte('.')
	b.WriteString(agentDomain)

	name := b.String()
	if !reportNameFitsOnWire(name) {
		return "", false
	}
	return name, true
}

// reportNameFitsOnWire checks the assembled report name against the 255-octet
// wire limit of RFC 1035 §2.3.4. The check is done on the encoded length —
// one length byte per label plus the label bytes, plus the root terminator —
// rather than on len(name), because the dotted presentation form is one byte
// shorter than the wire form and a name sitting exactly on the boundary would
// otherwise be built and then rejected by the packer.
func reportNameFitsOnWire(name string) bool {
	total := 1 // root terminator
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > maxLabelLength {
			return false
		}
		total += 1 + len(label)
	}
	return total <= maxNameLength
}
