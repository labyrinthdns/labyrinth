package dns

// Record types
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeHINFO uint16 = 13
	TypeDNAME uint16 = 39
	TypeOPT   uint16 = 41
	TypeANY   uint16 = 255

	// DNSSEC types
	TypeDS         uint16 = 43
	TypeRRSIG      uint16 = 46
	TypeNSEC       uint16 = 47
	TypeDNSKEY     uint16 = 48
	TypeNSEC3      uint16 = 50
	TypeNSEC3PARAM uint16 = 51
	// RFC 7344 — child-published DS/DNSKEY records the parent zone uses
	// to update the child's delegation. CDS RDATA is byte-identical to
	// DS; CDNSKEY RDATA is byte-identical to DNSKEY. Distinct types
	// only at the owner-side semantics: present at the apex of the
	// CHILD zone, signed by the child's keys, instructing the parent.
	TypeCDS     uint16 = 59
	TypeCDNSKEY uint16 = 60

	// Zone transfer types (RFC 5936 AXFR, RFC 1995 IXFR)
	TypeAXFR uint16 = 252
	TypeIXFR uint16 = 251

	// Modern service-discovery types. We do not parse their RDATA into
	// rich Go structs (the wire layer treats them as opaque, which is
	// the right behaviour for a forwarding recursive resolver per RFC
	// 3597 — pass unknown RDATA through verbatim so signatures remain
	// verifiable downstream). But registering them in TypeToString so
	// logs, the queries UI, and DNSSEC trace events show "HTTPS" and
	// "SVCB" instead of "TYPE65"/"TYPE64" is important for operators
	// chasing real-world traffic on networks where these dominate
	// (Apple devices, HTTP/3 / QUIC clients, ECH-enabled browsers).
	TypeSVCB  uint16 = 64 // RFC 9460 §2.1 — service binding
	TypeHTTPS uint16 = 65 // RFC 9460 §9   — HTTPS specialisation of SVCB
	// RFC 8659 (obsoletes 6844). DNS-based authorization for X.509
	// issuance — every CA on the public PKI MUST honour CAA, so
	// resolvers that mangle this RDATA can silently break cert renewal.
	TypeCAA uint16 = 257
)

// Classes
const (
	ClassIN uint16 = 1
)

// Response codes
const (
	RCodeNoError  uint8 = 0
	RCodeFormErr  uint8 = 1
	RCodeServFail uint8 = 2
	RCodeNXDomain uint8 = 3
	RCodeNotImp   uint8 = 4
	RCodeRefused  uint8 = 5
	// RCodeBadCookie is the extended RCODE 23 (RFC 7873 §5.2). It must be
	// transmitted using the EDNS0 ExtRCODE split: the low 4 bits (0x07) go
	// into the DNS header RCODE field, the high 8 bits (0x01) go into the
	// OPT pseudo-RR TTL byte 0. See buildBadCookieResponse.
	RCodeBadCookie uint8 = 23
)

// Opcodes
const (
	OpcodeQuery  uint8 = 0
	OpcodeIQuery uint8 = 1
	OpcodeStatus uint8 = 2
)

// TypeToString maps type values to human-readable names.
var TypeToString = map[uint16]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA",
	TypeHINFO: "HINFO", TypePTR: "PTR", TypeMX: "MX", TypeTXT: "TXT",
	TypeAAAA: "AAAA", TypeSRV: "SRV", TypeDNAME: "DNAME", TypeOPT: "OPT",
	TypeDS: "DS", TypeRRSIG: "RRSIG", TypeNSEC: "NSEC",
	TypeDNSKEY: "DNSKEY", TypeNSEC3: "NSEC3", TypeNSEC3PARAM: "NSEC3PARAM",
	TypeCDS: "CDS", TypeCDNSKEY: "CDNSKEY",
	TypeANY: "ANY",
	TypeSVCB: "SVCB", TypeHTTPS: "HTTPS", TypeCAA: "CAA",
}

// RCodeToString maps response codes to human-readable names.
var RCodeToString = map[uint8]string{
	RCodeNoError:   "NOERROR",
	RCodeFormErr:   "FORMERR",
	RCodeServFail:  "SERVFAIL",
	RCodeNXDomain:  "NXDOMAIN",
	RCodeNotImp:    "NOTIMP",
	RCodeRefused:   "REFUSED",
	RCodeBadCookie: "BADCOOKIE",
}
