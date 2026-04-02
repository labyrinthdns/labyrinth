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
	DigestSHA1   uint8 = 1
	DigestSHA256 uint8 = 2
	DigestSHA384 uint8 = 4
)
