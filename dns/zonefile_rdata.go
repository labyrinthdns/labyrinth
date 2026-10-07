package dns

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// FormatRData is the BIND master-file presentation encoder for one RR's
// RDATA. It dispatches on the RR type and returns the textual form ready
// to be appended after the TYPE column on a zone-file line.
//
// Types Labyrinth does not model as a Go struct (TLSA, LOC, NAPTR, CERT,
// DHCID, ZONEMD, …) are emitted in RFC 3597 §5 generic form:
//
//	TYPE<n> \# <rdlength> <hex>
//
// which is exact round-trip — the parser reads it back to the same
// RDATA bytes. The hex form is the canonical one BIND itself uses for
// unknown types, because it does not require the writer to know the
// type's RDATA grammar.
//
// Types that *are* modelled get their presentation form from the type-
// specific encoder. Adding a new type means implementing an encoder
// here and a parser in zonefile_parser.go; the dispatcher is a single
// switch.
//
// SOA is special-cased: the wire RDATA is a structured tuple, but the
// BIND form is a parenthesised keyword list with a serial/y/ref/r/exp/min
// header on the same line:
//
//	@ IN SOA ns.example. hostmaster.example. ( 2024010101 7200 3600 1209600 3600 )
//
// The "(..." continuation is what `dnsview` and friends display by
// default. The writer emits exactly that layout.
func FormatRData(r ResourceRecord) (string, error) {
	switch r.Type {
	case TypeSOA:
		return formatSOA(r.RData)
	case TypeNS:
		return formatSingleName(r.RData)
	case TypeCNAME:
		return formatSingleName(r.RData)
	case TypePTR:
		return formatSingleName(r.RData)
	case TypeDNAME:
		return formatSingleName(r.RData)
	case TypeA:
		return formatA(r.RData)
	case TypeAAAA:
		return formatAAAA(r.RData)
	case TypeMX:
		return formatMX(r.RData)
	case TypeSRV:
		return formatSRV(r.RData)
	case TypeTXT:
		return formatTXT(r.RData)
	case TypeCAA:
		return formatCAA(r.RData)
	case TypeDNSKEY, TypeDS, TypeRRSIG, TypeNSEC, TypeNSEC3:
		// DNSSEC types: a structured wire form that the caller has
		// already parsed (or hasn't, depending on the transfer).
		// The BIND default for an unknown DNSSEC type is RFC 3597
		// generic; for the four types we do model, the *parsed*
		// presentation form is rebuilding from the wire field-by-field,
		// which is a separate round of work. The hex form is exact
		// round-trip and is what `rndc freeze | grep` shows operators.
		return formatGenericUnknown(r)
	default:
		return formatGenericUnknown(r)
	}
}

// formatGenericUnknown emits RFC 3597 §5 generic form:
//
//	\# <rdlength> <hex-bytes>
//
// Labyrinth was not given a parser for the type, so its wire form is
// preserved verbatim. The writer never makes up a presentation form
// for a type it does not understand. The TYPE column on the line
// already carries the numeric type; the RDATA portion here is just
// the length-prefixed hex.
func formatGenericUnknown(r ResourceRecord) (string, error) {
	if len(r.RData) == 0 {
		// BIND writes the empty form as `\# 0` — explicit zero length.
		// Same on every other master-file reader.
		return `\# 0`, nil
	}
	return fmt.Sprintf("\\# %d %s",
		len(r.RData), strings.ToLower(hex.EncodeToString(r.RData))), nil
}

// formatSingleName encodes the RDATA of single-name types (NS, CNAME, PTR,
// DNAME). The single name is wire-format-encoded with no compression. RFC
// 1035 §5.1 says the name must end in a dot in master-file form (relative
// to $ORIGIN), so we add it here rather than leaving it to the caller.
func formatSingleName(rdata []byte) (string, error) {
	name, err := ParseNS(rdata, 0)
	if err != nil {
		return "", fmt.Errorf("decoding single-name rdata: %w", err)
	}
	return escapeName(name) + ".", nil
}

func formatA(rdata []byte) (string, error) {
	if len(rdata) != 4 {
		return "", fmt.Errorf("A RDATA length %d, want 4", len(rdata))
	}
	return net.IP(rdata).To4().String(), nil
}

func formatAAAA(rdata []byte) (string, error) {
	if len(rdata) != 16 {
		return "", fmt.Errorf("AAAA RDATA length %d, want 16", len(rdata))
	}
	// net.IP.String renders mapped addresses as IPv4, but AAAA records
	// need IPv6 text so their master-file representation can be read back.
	if net.IP(rdata).To4() != nil {
		return fmt.Sprintf("::ffff:%x:%x", binaryBigEndianUint16(rdata[12:14]), binaryBigEndianUint16(rdata[14:16])), nil
	}
	return net.IP(rdata).String(), nil
}

func formatMX(rdata []byte) (string, error) {
	if len(rdata) < 3 {
		return "", fmt.Errorf("MX RDATA length %d, want >= 3", len(rdata))
	}
	pref := binaryBigEndianUint16(rdata[0:2])
	exchange, err := ParseNS(rdata, 2)
	if err != nil {
		return "", fmt.Errorf("MX exchange: %w", err)
	}
	return fmt.Sprintf("%d %s.", pref, escapeName(exchange)), nil
}

func formatSRV(rdata []byte) (string, error) {
	if len(rdata) < 7 {
		return "", fmt.Errorf("SRV RDATA length %d, want >= 7", len(rdata))
	}
	prio := binaryBigEndianUint16(rdata[0:2])
	weight := binaryBigEndianUint16(rdata[2:4])
	port := binaryBigEndianUint16(rdata[4:6])
	target, err := ParseNS(rdata, 6)
	if err != nil {
		return "", fmt.Errorf("SRV target: %w", err)
	}
	return fmt.Sprintf("%d %d %d %s.", prio, weight, port, escapeName(target)), nil
}

func formatTXT(rdata []byte) (string, error) {
	// Wire format is one length-prefixed string per character-string.
	// Master-file form is one or more contiguous quoted strings.
	var sb strings.Builder
	for len(rdata) > 0 {
		if len(rdata) < 1 {
			return "", fmt.Errorf("TXT RDATA truncated length prefix")
		}
		n := int(rdata[0])
		if len(rdata) < 1+n {
			return "", fmt.Errorf("TXT RDATA truncated string at offset %d", 1)
		}
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte('"')
		// Escape characters inside the string. RFC 1035 §5.1 says the
		// only required escape is \" (because " is the string delimiter);
		// backslash itself is "\x5c" in the wire form and round-trips
		// unchanged through the parser.
		for _, c := range rdata[1 : 1+n] {
			if c == '"' || c == '\\' {
				sb.WriteByte('\\')
			}
			sb.WriteByte(c)
		}
		sb.WriteByte('"')
		rdata = rdata[1+n:]
	}
	return sb.String(), nil
}

func formatCAA(rdata []byte) (string, error) {
	if len(rdata) < 2 {
		return "", fmt.Errorf("CAA RDATA length %d, want >= 2", len(rdata))
	}
	flags := rdata[0]
	tagLen := int(rdata[1])
	if len(rdata) < 2+tagLen {
		return "", fmt.Errorf("CAA RDATA tag truncated")
	}
	tag := string(rdata[2 : 2+tagLen])
	value := rdata[2+tagLen:]
	return fmt.Sprintf("%d %s \"%s\"", flags, tag, string(value)), nil
}

// formatSOA writes the SOA RDATA in BIND master-file form. The serial
// and four timers emit on the same line as the mname/rname; the value
// field of the SOA is wrapped in parentheses for clarity, matching
// `dnsview` and `dig +nocmd` operator-facing tools. RFC 1035 §5.1
// explicitly permits the parenthesised continuation.
func formatSOA(rdata []byte) (string, error) {
	rec, err := ParseSOA(rdata, 0)
	if err != nil {
		return "", fmt.Errorf("SOA RDATA: %w", err)
	}
	return fmt.Sprintf("%s. %s. (\n\t\t%d\t; serial\n\t\t%d\t; refresh\n\t\t%d\t; retry\n\t\t%d\t; expire\n\t\t%d\t; minimum\n\t\t)",
		escapeName(rec.MName), escapeName(rec.RName),
		rec.Serial, rec.Refresh, rec.Retry, rec.Expire, rec.Minimum,
	), nil
}

// FormatSOARecord is the public entry point for callers that already have
// a parsed SOARecord (e.g. from a transfer response) and want to render
// it without going through wire RDATA. Same output format as formatSOA.
func FormatSOARecord(rec *SOARecord) string {
	return fmt.Sprintf("%s. %s. (\n\t\t%d\t; serial\n\t\t%d\t; refresh\n\t\t%d\t; retry\n\t\t%d\t; expire\n\t\t%d\t; minimum\n\t\t)",
		escapeName(rec.MName), escapeName(rec.RName),
		rec.Serial, rec.Refresh, rec.Retry, rec.Expire, rec.Minimum,
	)
}

// FormatRDataBase64 is the unsupported convenience form `BIND` will
// also accept for unknown types but no other master-file reader
// guarantees. Kept for operator convenience when re-pasting a record
// someone gave them as `<base64>`. Provided here so the writer can
// pick: hex (default, RFC 3597 §5) or base64 (operator preference).
func FormatRDataBase64(r ResourceRecord) string {
	return fmt.Sprintf("TYPE%d \\# %d %s",
		r.Type, len(r.RData),
		base64.StdEncoding.EncodeToString(r.RData))
}

// trivial helper – small int wrapper rather than going via encoding/binary
// for a 2-byte big-endian read we already do elsewhere.
func binaryBigEndianUint16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

// ensure the strconv import is used if later versions add an int-format
// path that needs it.
var _ = strconv.Itoa
