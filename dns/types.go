package dns

import (
	"strconv"
	"strings"
)

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

	// Meta types used by transaction security. TSIG travels as the last
	// record of a message and is stripped before the message is otherwise
	// interpreted; TKEY negotiates the shared secret TSIG uses.
	TypeTKEY uint16 = 249 // RFC 2930
	TypeTSIG uint16 = 250 // RFC 8945

	// Types below are recognised but not parsed into Go structs. RFC 3597
	// §3 is explicit that the correct handling for an RR type an
	// implementation does not implement is to treat the RDATA as an opaque
	// block, and for a recursive resolver that is not a limitation — it is
	// the whole point. Rewriting RDATA we do not understand would break the
	// signatures over it.
	//
	// What registering them buys is naming. Before this, a TLSA record in
	// the cache viewer showed as blank and a `dig`-style query for it from
	// the dashboard was rejected outright as an "unsupported query type",
	// even though the resolver had been resolving them correctly all
	// along. An operator could not inspect what the resolver already held.
	TypeLOC        uint16 = 29  // RFC 1876 — geographic location
	TypeNAPTR      uint16 = 35  // RFC 3403 — naming authority pointer (ENUM, SIP)
	TypeCERT       uint16 = 37  // RFC 4398 — certificates
	TypeSSHFP      uint16 = 44  // RFC 4255 — SSH host key fingerprints
	TypeIPSECKEY   uint16 = 45  // RFC 4025 — IPsec keying material
	TypeDHCID      uint16 = 49  // RFC 4701 — DHCP identifier
	TypeTLSA       uint16 = 52  // RFC 6698 — DANE TLS anchors
	TypeSMIMEA     uint16 = 53  // RFC 8162 — S/MIME cert association
	TypeHIP        uint16 = 55  // RFC 8005 — host identity protocol
	TypeOPENPGPKEY uint16 = 61  // RFC 7929 — OpenPGP public keys
	TypeCSYNC      uint16 = 62  // RFC 7477 — child-to-parent synchronization
	TypeZONEMD     uint16 = 63  // RFC 8976 — message digest for zone files
	TypeSPF        uint16 = 99  // RFC 7208 — deprecated in favour of TXT
	TypeNID        uint16 = 104 // RFC 6742 — ILNP node identifier
	TypeL32        uint16 = 105 // RFC 6742
	TypeL64        uint16 = 106 // RFC 6742
	TypeLP         uint16 = 107 // RFC 6742
	TypeEUI48      uint16 = 108 // RFC 7043
	TypeEUI64      uint16 = 109 // RFC 7043
	TypeURI        uint16 = 256 // RFC 7553 — URI mapping
	TypeRESINFO    uint16 = 261 // RFC 9606 — resolver information
	TypeTA         uint16 = 32768
	TypeDLV        uint16 = 32769 // RFC 4431; the protocol is deprecated by RFC 8749

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
	// OpcodeNotify (RFC 1996) and OpcodeUpdate (RFC 2136) are recognised
	// so the handler can name what it is refusing. Labyrinth answers both
	// with NOTIMP — it is a recursive resolver with no zone to be notified
	// about or updated — but "NOTIMP for OPCODE 5" in a log is a far
	// better lead for an operator who misconfigured a primary than a bare
	// counter increment.
	OpcodeNotify uint8 = 4
	OpcodeUpdate uint8 = 5
	OpcodeDSO    uint8 = 6 // RFC 8490 — DNS Stateful Operations
)

// TypeToString maps type values to human-readable names. Use TypeName for
// lookups that must always yield a string — it falls back to the RFC 3597 §5
// generic "TYPE<n>" form for anything not listed here.
var TypeToString = map[uint16]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA",
	TypeHINFO: "HINFO", TypePTR: "PTR", TypeMX: "MX", TypeTXT: "TXT",
	TypeAAAA: "AAAA", TypeSRV: "SRV", TypeDNAME: "DNAME", TypeOPT: "OPT",
	TypeDS: "DS", TypeRRSIG: "RRSIG", TypeNSEC: "NSEC",
	TypeDNSKEY: "DNSKEY", TypeNSEC3: "NSEC3", TypeNSEC3PARAM: "NSEC3PARAM",
	TypeCDS: "CDS", TypeCDNSKEY: "CDNSKEY",
	TypeANY:  "ANY",
	TypeSVCB: "SVCB", TypeHTTPS: "HTTPS", TypeCAA: "CAA",
	TypeAXFR: "AXFR", TypeIXFR: "IXFR",
	TypeTKEY: "TKEY", TypeTSIG: "TSIG",
	TypeLOC: "LOC", TypeNAPTR: "NAPTR", TypeCERT: "CERT",
	TypeSSHFP: "SSHFP", TypeIPSECKEY: "IPSECKEY", TypeDHCID: "DHCID",
	TypeTLSA: "TLSA", TypeSMIMEA: "SMIMEA", TypeHIP: "HIP",
	TypeOPENPGPKEY: "OPENPGPKEY", TypeCSYNC: "CSYNC", TypeZONEMD: "ZONEMD",
	TypeSPF: "SPF",
	TypeNID: "NID", TypeL32: "L32", TypeL64: "L64", TypeLP: "LP",
	TypeEUI48: "EUI48", TypeEUI64: "EUI64",
	TypeURI: "URI", TypeRESINFO: "RESINFO",
	TypeTA: "TA", TypeDLV: "DLV",
}

// StringToType is the inverse of TypeToString, built once at init so the two
// can never disagree. Adding a type to TypeToString automatically makes it
// queryable from the dashboard and the diagnostics endpoint.
//
// It previously did not exist, and three hand-maintained partial copies stood
// in for it — one in the cache API, one in the trace API, one implied by the
// UI. They had drifted to different subsets, so which record types you could
// inspect depended on which page you were looking at.
var StringToType = func() map[string]uint16 {
	m := make(map[string]uint16, len(TypeToString))
	for t, s := range TypeToString {
		m[s] = t
	}
	return m
}()

// TypeName returns the presentation name for an RR type, falling back to the
// RFC 3597 §5 generic form "TYPE<n>" for types with no mnemonic. Every
// display path should use this rather than indexing TypeToString directly,
// which yields "" for unknown types and renders as a blank column.
func TypeName(t uint16) string {
	if s, ok := TypeToString[t]; ok {
		return s
	}
	return "TYPE" + strconv.FormatUint(uint64(t), 10)
}

// ParseType resolves a presentation type name to its numeric value. It
// accepts both mnemonics ("TLSA") and the RFC 3597 §5 generic form
// ("TYPE52"), case-insensitively and ignoring surrounding whitespace.
//
// Accepting the generic form matters: it means an operator can inspect a
// record type this build has never heard of, which is exactly the situation
// RFC 3597 exists to handle. The resolver already caches such records
// correctly; without this it just could not show them.
func ParseType(s string) (uint16, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, false
	}
	if t, ok := StringToType[s]; ok {
		return t, true
	}
	if rest, found := strings.CutPrefix(s, "TYPE"); found {
		n, err := strconv.ParseUint(rest, 10, 16)
		if err != nil {
			return 0, false
		}
		return uint16(n), true
	}
	return 0, false
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
