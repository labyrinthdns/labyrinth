package resolver

import (
	"fmt"

	"github.com/labyrinthdns/labyrinth/dns"
)

// extractTraceEDE walks msg.Additional, finds the OPT pseudo-record (if any),
// and returns a slice of trace-friendly EDE descriptors plus the CD bit from
// the response header. Each EDE descriptor is a map[string]any with the keys
// the diagnostics UI expects to render a badge: "code" (numeric), "name"
// (human-readable per RFC 8914 §4), and "text" (the operator-supplied extra
// text, may be empty). Returns (nil, cd) if the message has no OPT or no EDE
// options.
//
// The function is intentionally tolerant — a corrupt OPT or a malformed EDE
// option is silently skipped rather than rejected, because a trace event is a
// diagnostic, not a validator. The point is to surface what the upstream sent;
// rejecting the trace on a malformed option would hide the very signal the
// operator is looking for ("why is this upstream sending garbage?").
func extractTraceEDE(msg *dns.Message) ([]map[string]any, bool) {
	if msg == nil {
		return nil, false
	}
	cd := msg.Header.CD()
	var out []map[string]any
	for i := range msg.Additional {
		rr := &msg.Additional[i]
		if rr.Type != dns.TypeOPT {
			continue
		}
		opt, err := dns.ParseOPT(rr)
		if err != nil {
			continue
		}
		for _, o := range opt.Options {
			if o.Code != dns.EDNSOptionCodeEDE {
				continue
			}
			code, text, err := dns.ParseEDEOption(o.Data)
			if err != nil {
				continue
			}
			out = append(out, map[string]any{
				"code": code,
				"name": edeCodeName(code),
				"text": text,
			})
		}
	}
	return out, cd
}

// edeCodeName maps an EDE info code (RFC 8914 §4) to the operator-facing
// string the dashboard renders inside the badge. Unknown codes fall through to
// the raw number — this is forward-compatible with future IANA assignments
// without forcing a code update.
func edeCodeName(code uint16) string {
	switch code {
	case dns.EDECodeOtherError:
		return "Other"
	case dns.EDECodeUnsupportedDNSKEYAlgo:
		return "Unsupported DNSKEY Algorithm"
	case dns.EDECodeUnsupportedDSDigestType:
		return "Unsupported DS Digest Type"
	case dns.EDECodeStaleAnswer:
		return "Stale Answer"
	case dns.EDECodeForgedAnswer:
		return "Forged Answer"
	case dns.EDECodeDNSSECIndeterminate:
		return "DNSSEC Indeterminate"
	case dns.EDECodeDNSSECBogus:
		return "DNSSEC Bogus"
	case dns.EDECodeSignatureExpired:
		return "Signature Expired"
	case dns.EDECodeSignatureNotYetValid:
		return "Signature Not Yet Valid"
	case dns.EDECodeDNSKEYMissing:
		return "DNSKEY Missing"
	case dns.EDECodeRRSIGsMissing:
		return "RRSIGs Missing"
	case dns.EDECodeNoZoneKeyBitSet:
		return "No Zone Key Bit Set"
	case dns.EDECodeNSECMissing:
		return "NSEC Missing"
	case dns.EDECodeCachedError:
		return "Cached Error"
	case dns.EDECodeNotReady:
		return "Not Ready"
	case dns.EDECodeBlocked:
		return "Blocked"
	case dns.EDECodeCensored:
		return "Censored"
	case dns.EDECodeFiltered:
		return "Filtered"
	case dns.EDECodeProhibited:
		return "Prohibited"
	case dns.EDECodeStaleNXDOMAINAnswer:
		return "Stale NXDOMAIN Answer"
	case dns.EDECodeNotAuthoritative:
		return "Not Authoritative"
	case dns.EDECodeNotSupported:
		return "Not Supported"
	case dns.EDECodeNoReachableAuthority:
		return "No Reachable Authority"
	case dns.EDECodeNetworkError:
		return "Network Error"
	case dns.EDECodeInvalidData:
		return "Invalid Data"
	}
	return fmt.Sprintf("EDE%d", code)
}
