package dns

import (
	"strings"

	"golang.org/x/net/idna"
)

// Internationalised domain names (IDNA2008 — RFC 5890 through RFC 5894).
//
// The DNS protocol itself has no notion of Unicode: a query for "münchen.de"
// travels the wire as "xn--mnchen-3ya.de", and the conversion is the
// *application's* job (RFC 5891 §4). Labyrinth's resolver is therefore
// already correct — it never sees a Unicode name, because a conforming stub
// resolver converted it before sending.
//
// The gap this closes is at the human-facing boundary. An operator pasting
// "müller.example" into the dashboard's cache-lookup or diagnostics box was
// getting a query for the literal UTF-8 octets, which is not a name that
// exists anywhere: the lookup failed and the reason was invisible, because
// the string looked exactly like what they meant. Doing the conversion here
// makes the dashboard behave like every other DNS client.
//
// # Why the non-transitional profile
//
// IDNA2008 has two dispositions for four characters — ß, ς, and the two
// zero-width joiners — inherited from the IDNA2003 transition. Transitional
// processing maps ß to "ss", so "faß.example" and "fass.example" become the
// same name. Non-transitional keeps them distinct, which is what IDNA2008
// specifies and what browsers have used since around 2016. Using the
// transitional profile here would mean the dashboard silently looked up a
// different domain than the one typed.

// idnaProfile is the conversion profile used for all presentation-to-wire
// name handling.
//
// VerifyDNSLength is deliberately off. It rejects names over 253 octets and
// empty labels, which is correct for *registering* a name but wrong for
// looking one up: the resolver has its own length handling, and a diagnostic
// tool should be able to send a deliberately malformed name to see what comes
// back. Callers that need the check do it themselves.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
)

// ToASCII converts a domain name to its A-label (Punycode) form.
//
// Names that are already pure ASCII pass through with only case folding, so
// this is safe to call unconditionally on any name arriving from a human.
// Conversion failures return the input unchanged rather than an error: the
// caller is about to look the name up, and a name that cannot be converted is
// better sent as typed — the resolver will reject it and say why — than
// replaced by an error message that hides what the operator actually asked
// for.
func ToASCII(name string) string {
	if name == "" {
		return name
	}
	// Fast path: pure ASCII needs no conversion, and this is the
	// overwhelming majority of names.
	if isASCII(name) {
		return name
	}
	// Preserve a trailing dot across the conversion; idna treats it as an
	// empty final label and drops it.
	trailingDot := strings.HasSuffix(name, ".")
	converted, err := idnaProfile.ToASCII(strings.TrimSuffix(name, "."))
	if err != nil {
		return name
	}
	if trailingDot {
		return converted + "."
	}
	return converted
}

// ToUnicode converts an A-label name back to its Unicode presentation form,
// for display. Failures return the input unchanged — showing the Punycode is
// worse than showing Unicode, but far better than showing nothing.
func ToUnicode(name string) string {
	if name == "" || !strings.Contains(strings.ToLower(name), "xn--") {
		return name
	}
	trailingDot := strings.HasSuffix(name, ".")
	converted, err := idnaProfile.ToUnicode(strings.TrimSuffix(name, "."))
	if err != nil {
		return name
	}
	if trailingDot {
		return converted + "."
	}
	return converted
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
