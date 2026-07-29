package dns

// DNSSEC algorithm numbers (RFC 8624).
const (
	AlgRSASHA1   uint8 = 5
	AlgRSASHA256 uint8 = 8
	AlgRSASHA512 uint8 = 10
	AlgECDSAP256 uint8 = 13
	AlgECDSAP384 uint8 = 14
	AlgED25519   uint8 = 15
	AlgED448     uint8 = 16
)

// DNSSEC digest types (RFC 8624).
const (
	// DigestReserved (0) is the IANA-reserved DS digest type. RFC 4509
	// §2.4 / RFC 8624 §3.3 say a DS RR carrying digest type 0 MUST NOT
	// be used to authenticate the corresponding DNSKEY. If the parent
	// publishes ONLY digest-type-0 DS records for a delegation, the
	// delegation has no usable DS — RFC 4035 §5.2 treats that the same
	// as no DS at all and the validator falls through to Insecure.
	DigestReserved uint8 = 0
	DigestSHA1     uint8 = 1
	DigestSHA256   uint8 = 2
	DigestSHA384   uint8 = 4
)

// DNSSEC algorithm numbers that this resolver explicitly does NOT
// validate. The verify-switch in dnssec/verify.go falls through to
// "unsupported" for any algorithm not enumerated above, so listing
// these as named constants is for spec-completeness and pin-test
// readability — never for acceptance.
//
//   - RSAMD5 (1):       MD5 is cryptographically broken (RFC 6151) and
//                       MUST NOT be used for new signatures (RFC 6944).
//   - DSA (3):          DSA-SHA1 is deprecated and dropped from the
//                       Internet root signing key rollover (RFC 8624 §3.1).
//   - DSA-NSEC3 (6):    Same DSA constraints, NSEC3 variant.
//   - RSASHA1-NSEC3 (7):RSA/SHA-1 in any form is deprecated; we honour
//                       the validator's allowSHA1 gate via algorithm 5
//                       only when explicitly opted in. Algorithm 7 is
//                       legacy and we leave it strictly off.
const (
	AlgRSAMD5         uint8 = 1
	AlgDSA            uint8 = 3
	AlgDSANSEC3SHA1   uint8 = 6
	AlgRSASHA1NSEC3   uint8 = 7
)
