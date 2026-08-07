package dns

// BogusReasonToEDE maps a dnssec.FailureReason token (carried through
// resolver.ResolveResult.DNSSECReason as a stable string) to the most
// informative RFC 8914 §4 Extended DNS Error info code we can emit. The
// generic EDE 6 (DNSSEC Bogus) is the fallback when the validator did not
// classify the cause more specifically. Granular codes help operators and
// clients distinguish "the auth's signature expired" (an operational
// failure at the auth side, retry later) from "we saw a cryptographic
// forgery" (a security event worth investigating).
//
// The token-string indirection — instead of a typed enum across packages —
// lets resolver.ResolveResult avoid importing dnssec just for the type.
//
// This lives in the dns package rather than next to its original caller in
// server/ because there are now two consumers with no import path between
// them: the server picks the EDE it sends *downstream* to the client, and
// the resolver picks the EDE it puts in an RFC 9567 report sent *upstream*
// to the zone's agent domain. Both must name the same failure the same way,
// or an operator correlating their agent-domain logs against a client's
// error would see two different codes for one event.
func BogusReasonToEDE(reason string) (uint16, string) {
	switch reason {
	case "signature-expired":
		return EDECodeSignatureExpired, "RRSIG expiration in the past"
	case "signature-not-yet-valid":
		return EDECodeSignatureNotYetValid, "RRSIG inception in the future"
	case "dnskey-missing", "no-matching-dnskey":
		return EDECodeDNSKEYMissing, "no DNSKEY available for signer"
	case "rrsigs-missing":
		return EDECodeRRSIGsMissing, "answer in signed zone has no RRSIG"
	case "unsupported-dnskey-algo":
		return EDECodeUnsupportedDNSKEYAlgo, "no supported DNSKEY algorithm"
	case "unsupported-ds-digest":
		return EDECodeUnsupportedDSDigestType, "no supported DS digest type"
	}
	return EDECodeDNSSECBogus, "DNSSEC validation failure"
}
