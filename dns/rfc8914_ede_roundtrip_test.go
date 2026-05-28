package dns

import (
	"testing"
)

// TestEDE_RoundTripsAllInfoCodes pins the wire-format contract for every
// EDE info code Labyrinth currently emits: Build → Parse → equality.
// RFC 8914 §2 fixes the option encoding (16-bit info code, then UTF-8
// extra text); a regression in either Build or Parse would surface as
// either a wrong code or extra-text mangling.
//
// The pin enumerates the full RFC 8914 §4 set (0-24) plus the post-8914
// codes the resolver actually emits (25 RFC 9606, 26 RFC 9539, 27 RFC
// 9276 §3.2, 28 RFC 8914 §4.28, 29 RFC 8914 §4.29). New codes added in
// future releases should extend this slice and the SecurityPage's EDE
// label table together so the operator's UI never shows "Unknown" for
// a code the resolver itself can emit.
func TestEDE_RoundTripsAllInfoCodes(t *testing.T) {
	codes := []struct {
		code uint16
		name string
	}{
		{EDECodeOtherError, "Other"},
		{EDECodeUnsupportedDNSKEYAlgo, "Unsupported DNSKEY Algorithm"},
		{EDECodeUnsupportedDSDigestType, "Unsupported DS Digest Type"},
		{EDECodeStaleAnswer, "Stale Answer"},
		{EDECodeForgedAnswer, "Forged Answer"},
		{EDECodeDNSSECIndeterminate, "DNSSEC Indeterminate"},
		{EDECodeDNSSECBogus, "DNSSEC Bogus"},
		{EDECodeSignatureExpired, "Signature Expired"},
		{EDECodeSignatureNotYetValid, "Signature Not Yet Valid"},
		{EDECodeDNSKEYMissing, "DNSKEY Missing"},
		{EDECodeRRSIGsMissing, "RRSIGs Missing"},
		{EDECodeNoZoneKeyBitSet, "No Zone Key Bit Set"},
		{EDECodeNSECMissing, "NSEC Missing"},
		{EDECodeCachedError, "Cached Error"},
		{EDECodeNotReady, "Not Ready"},
		{EDECodeBlocked, "Blocked"},
		{EDECodeCensored, "Censored"},
		{EDECodeFiltered, "Filtered"},
		{EDECodeProhibited, "Prohibited"},
		{EDECodeStaleNXDOMAINAnswer, "Stale NXDOMAIN Answer"},
		{EDECodeNotAuthoritative, "Not Authoritative"},
		{EDECodeNotSupported, "Not Supported"},
		{EDECodeNoReachableAuthority, "No Reachable Authority"},
		{EDECodeNetworkError, "Network Error"},
		{EDECodeInvalidData, "Invalid Data"},
		{EDECodeSignatureExpiredBeforeValid, "Signature Expired Before Valid (RFC 9606)"},
		{EDECodeTooEarly, "Too Early (RFC 9539)"},
		{EDECodeUnsupportedNSEC3IterationsValue, "Unsupported NSEC3 Iterations Value (RFC 9276)"},
		{EDECodeUnableToConformToPolicy, "Unable to Conform to Policy"},
		{EDECodeSynthesized, "Synthesized"},
	}

	// Sanity: contiguous 0..29 — a code accidentally renumbered (e.g.
	// duplicate const, mis-typed constant) would fail this gate.
	for i, c := range codes {
		if c.code != uint16(i) {
			t.Errorf("codes[%d] = %d, want %d (constants must match IANA registry numbering)", i, c.code, i)
		}
	}

	for _, c := range codes {
		opt := BuildEDEOption(c.code, c.name)
		if opt.Code != EDNSOptionCodeEDE {
			t.Errorf("BuildEDEOption returned option code %d, want EDE (%d)", opt.Code, EDNSOptionCodeEDE)
		}
		gotCode, gotText, err := ParseEDEOption(opt.Data)
		if err != nil {
			t.Errorf("ParseEDEOption(%d): %v", c.code, err)
			continue
		}
		if gotCode != c.code {
			t.Errorf("code roundtrip: got %d, want %d", gotCode, c.code)
		}
		if gotText != c.name {
			t.Errorf("extra-text roundtrip for code %d: got %q, want %q", c.code, gotText, c.name)
		}
	}
}

// TestEDE_ParseRejectsTooShort pins the §2 minimum wire length (2-byte
// info code). A parser that accepted 0- or 1-byte option data would
// produce a zero info code for malformed input, masking a structural
// bug as "Other Error".
func TestEDE_ParseRejectsTooShort(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {0x00}} {
		_, _, err := ParseEDEOption(data)
		if err == nil {
			t.Errorf("ParseEDEOption(%v) returned no error; want too-short rejection", data)
		}
	}
}
