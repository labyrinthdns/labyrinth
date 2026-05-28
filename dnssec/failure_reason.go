package dnssec

// FailureReason classifies why DNSSEC validation produced a non-Secure
// verdict. Designed to be mapped by callers to RFC 8914 Extended DNS Error
// (EDE) info codes so that clients and operators can distinguish, for
// example, "the auth's signature expired" (operational issue on the auth
// side) from "we saw a cryptographically forged signature" (security
// event). Without this distinction every Bogus collapses into the generic
// EDE 6 and the cause is lost.
//
// Suggested EDE mapping (RFC 8914 §4):
//
//	ReasonSignatureExpired      → EDE  7 (Signature Expired)
//	ReasonSignatureNotYetValid  → EDE  8 (Signature Not Yet Valid)
//	ReasonDNSKEYMissing         → EDE  9 (DNSKEY Missing)
//	ReasonNoMatchingDNSKEY      → EDE  9 (DNSKEY Missing — no key by tag/alg)
//	ReasonRRSIGsMissing         → EDE 10 (RRSIGs Missing)
//	ReasonUnsupportedDNSKEYAlgo → EDE  1 (Unsupported DNSKEY Algorithm)
//	ReasonUnsupportedDSDigest   → EDE  2 (Unsupported DS Digest Type)
//	ReasonOther                 → EDE  6 (DNSSEC Bogus, generic)
type FailureReason int

const (
	// ReasonNone means no specific failure reason was recorded (verdict
	// is Secure, or the validator didn't tag a specific cause).
	ReasonNone FailureReason = iota
	// ReasonSignatureExpired — an RRSIG's expiration is in the past.
	ReasonSignatureExpired
	// ReasonSignatureNotYetValid — an RRSIG's inception is in the future.
	ReasonSignatureNotYetValid
	// ReasonDNSKEYMissing — no DNSKEY rrset could be fetched for the signer.
	ReasonDNSKEYMissing
	// ReasonNoMatchingDNSKEY — DNSKEYs were fetched but none matched the
	// RRSIG's key-tag/algorithm.
	ReasonNoMatchingDNSKEY
	// ReasonRRSIGsMissing — the response is in a signed zone but lacks RRSIG.
	ReasonRRSIGsMissing
	// ReasonUnsupportedDNSKEYAlgo — every RRSIG used an algorithm this
	// resolver cannot verify.
	ReasonUnsupportedDNSKEYAlgo
	// ReasonUnsupportedDSDigest — every DS digest type was unsupported.
	ReasonUnsupportedDSDigest
	// ReasonOther — cryptographic verify failed, bailiwick failed, or some
	// other Bogus cause the validator has not classified further.
	ReasonOther
	// ReasonNTAOverride — a Negative Trust Anchor (RFC 7646) is active for
	// the queried zone subtree, suppressing the validation verdict to
	// Insecure regardless of what the chain would have produced. The
	// operator installed the NTA explicitly; this is the audit trail.
	ReasonNTAOverride
)

// String returns a stable token for the reason — used in logs, metrics,
// and ResolveResult.DNSSECReason so the value crosses package boundaries
// without leaking the int representation.
func (r FailureReason) String() string {
	switch r {
	case ReasonSignatureExpired:
		return "signature-expired"
	case ReasonSignatureNotYetValid:
		return "signature-not-yet-valid"
	case ReasonDNSKEYMissing:
		return "dnskey-missing"
	case ReasonNoMatchingDNSKEY:
		return "no-matching-dnskey"
	case ReasonRRSIGsMissing:
		return "rrsigs-missing"
	case ReasonUnsupportedDNSKEYAlgo:
		return "unsupported-dnskey-algo"
	case ReasonUnsupportedDSDigest:
		return "unsupported-ds-digest"
	case ReasonOther:
		return "other"
	case ReasonNTAOverride:
		return "nta-override"
	}
	return ""
}

// FailureReasonFromString is the inverse of FailureReason.String. Returns
// ReasonNone for the empty string and ReasonOther for unrecognised tokens
// (we'd rather fall through to the generic EDE 6 than drop the signal).
func FailureReasonFromString(s string) FailureReason {
	switch s {
	case "":
		return ReasonNone
	case "signature-expired":
		return ReasonSignatureExpired
	case "signature-not-yet-valid":
		return ReasonSignatureNotYetValid
	case "dnskey-missing":
		return ReasonDNSKEYMissing
	case "no-matching-dnskey":
		return ReasonNoMatchingDNSKEY
	case "rrsigs-missing":
		return ReasonRRSIGsMissing
	case "unsupported-dnskey-algo":
		return ReasonUnsupportedDNSKEYAlgo
	case "unsupported-ds-digest":
		return ReasonUnsupportedDSDigest
	case "nta-override":
		return ReasonNTAOverride
	}
	return ReasonOther
}
