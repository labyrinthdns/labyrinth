package server

import "github.com/labyrinthdns/labyrinth/dns"

// bogusReasonToEDE maps a dnssec.FailureReason token (carried through
// resolver.ResolveResult.DNSSECReason as a stable string) to the most
// informative RFC 8914 §4 Extended DNS Error info code we can emit. The
// generic EDE 6 (DNSSEC Bogus) is the fallback when the validator did not
// classify the cause more specifically. Granular codes help operators and
// clients distinguish "the auth's signature expired" (an operational
// failure at the auth side, retry later) from "we saw a cryptographic
// forgery" (a security event worth investigating).
//
// The token-string indirection — instead of typed enum across packages —
// lets resolver.ResolveResult avoid importing dnssec just for the type.
func bogusReasonToEDE(reason string) (uint16, string) {
	switch reason {
	case "signature-expired":
		return dns.EDECodeSignatureExpired, "RRSIG expiration in the past"
	case "signature-not-yet-valid":
		return dns.EDECodeSignatureNotYetValid, "RRSIG inception in the future"
	case "dnskey-missing", "no-matching-dnskey":
		return dns.EDECodeDNSKEYMissing, "no DNSKEY available for signer"
	case "rrsigs-missing":
		return dns.EDECodeRRSIGsMissing, "answer in signed zone has no RRSIG"
	case "unsupported-dnskey-algo":
		return dns.EDECodeUnsupportedDNSKEYAlgo, "no supported DNSKEY algorithm"
	case "unsupported-ds-digest":
		return dns.EDECodeUnsupportedDSDigestType, "no supported DS digest type"
	}
	return dns.EDECodeDNSSECBogus, "DNSSEC validation failure"
}
