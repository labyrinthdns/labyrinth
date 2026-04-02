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
	TypeOPT   uint16 = 41
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
	TypePTR: "PTR", TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA",
	TypeSRV: "SRV", TypeOPT: "OPT",
}

// RCodeToString maps response codes to human-readable names.
var RCodeToString = map[uint8]string{
	RCodeNoError:  "NOERROR",
	RCodeFormErr:  "FORMERR",
	RCodeServFail: "SERVFAIL",
	RCodeNXDomain: "NXDOMAIN",
	RCodeNotImp:   "NOTIMP",
	RCodeRefused:  "REFUSED",
}
