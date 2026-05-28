package dns

import "testing"

// TestEDECodes_IANA0Through27 pins the complete EDE info code table
// against the IANA registry as of January 2026 (RFC 8914 base, RFC
// 9606 +25, RFC 9539 +26, RFC 9276 +27). Without this pin, a typo
// while adding code 28+ in the future could silently shift one of the
// existing values, and every dashboard / log / EDE consumer that
// relies on the numeric code would mis-classify the cause.
//
// The numeric values are wire-format and CANNOT be renumbered. They
// are pinned individually so a misaligned single line is caught at
// build time rather than as a runtime mystery.
func TestEDECodes_IANA0Through27(t *testing.T) {
	cases := []struct {
		got  uint16
		want uint16
		name string
	}{
		{EDECodeOtherError, 0, "OtherError"},
		{EDECodeUnsupportedDNSKEYAlgo, 1, "UnsupportedDNSKEYAlgo"},
		{EDECodeUnsupportedDSDigestType, 2, "UnsupportedDSDigestType"},
		{EDECodeStaleAnswer, 3, "StaleAnswer"},
		{EDECodeForgedAnswer, 4, "ForgedAnswer"},
		{EDECodeDNSSECIndeterminate, 5, "DNSSECIndeterminate"},
		{EDECodeDNSSECBogus, 6, "DNSSECBogus"},
		{EDECodeSignatureExpired, 7, "SignatureExpired"},
		{EDECodeSignatureNotYetValid, 8, "SignatureNotYetValid"},
		{EDECodeDNSKEYMissing, 9, "DNSKEYMissing"},
		{EDECodeRRSIGsMissing, 10, "RRSIGsMissing"},
		{EDECodeNoZoneKeyBitSet, 11, "NoZoneKeyBitSet"},
		{EDECodeNSECMissing, 12, "NSECMissing"},
		{EDECodeCachedError, 13, "CachedError"},
		{EDECodeNotReady, 14, "NotReady"},
		{EDECodeBlocked, 15, "Blocked"},
		{EDECodeCensored, 16, "Censored"},
		{EDECodeFiltered, 17, "Filtered"},
		{EDECodeProhibited, 18, "Prohibited"},
		{EDECodeStaleNXDOMAINAnswer, 19, "StaleNXDOMAINAnswer"},
		{EDECodeNotAuthoritative, 20, "NotAuthoritative"},
		{EDECodeNotSupported, 21, "NotSupported"},
		{EDECodeNoReachableAuthority, 22, "NoReachableAuthority"},
		{EDECodeNetworkError, 23, "NetworkError"},
		{EDECodeInvalidData, 24, "InvalidData"},
		{EDECodeSignatureExpiredBeforeValid, 25, "SignatureExpiredBeforeValid (RFC 9606)"},
		{EDECodeTooEarly, 26, "TooEarly (RFC 9539)"},
		{EDECodeUnsupportedNSEC3IterationsValue, 27, "UnsupportedNSEC3IterationsValue (RFC 9276)"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("EDE code drift: got %d, want %d (IANA wire value MUST NOT change)", c.got, c.want)
			}
		})
	}
}

// TestEDECodes_Late_AreDistinct catches a different class of bug —
// accidentally giving two constants the same numeric value. The
// pinned table above asserts each value individually, but if two
// names map to the same number both rows pass while the table is
// silently corrupt. This guard walks the late additions (which were
// added in a single commit and are the most likely place for a
// copy-paste duplicate) and verifies the set is unique.
func TestEDECodes_Late_AreDistinct(t *testing.T) {
	codes := []uint16{
		EDECodeSignatureExpiredBeforeValid,
		EDECodeTooEarly,
		EDECodeUnsupportedNSEC3IterationsValue,
	}
	seen := make(map[uint16]int)
	for _, c := range codes {
		seen[c]++
	}
	for code, count := range seen {
		if count > 1 {
			t.Errorf("duplicate EDE code %d (appears %d times) — copy-paste regression on the RFC 9276/9539/9606 backfill", code, count)
		}
	}
}
