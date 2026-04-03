package dns

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ParseA extracts an IPv4 address from A record RDATA.
func ParseA(rdata []byte) (net.IP, error) {
	if len(rdata) != 4 {
		return nil, fmt.Errorf("dns: A record RDATA length %d, want 4", len(rdata))
	}
	ip := make(net.IP, 4)
	copy(ip, rdata)
	return ip.To4(), nil
}

// ParseAAAA extracts an IPv6 address from AAAA record RDATA.
func ParseAAAA(rdata []byte) (net.IP, error) {
	if len(rdata) != 16 {
		return nil, fmt.Errorf("dns: AAAA record RDATA length %d, want 16", len(rdata))
	}
	ip := make(net.IP, 16)
	copy(ip, rdata)
	return ip.To16(), nil
}

// ParseNS extracts the nameserver hostname from NS record RDATA.
func ParseNS(msg []byte, rdataOffset int) (string, error) {
	name, _, err := DecodeName(msg, rdataOffset)
	return name, err
}

// ParseCNAME extracts the canonical name from CNAME record RDATA.
func ParseCNAME(msg []byte, rdataOffset int) (string, error) {
	name, _, err := DecodeName(msg, rdataOffset)
	return name, err
}

// ParsePTR extracts the pointer domain name from PTR record RDATA.
func ParsePTR(msg []byte, rdataOffset int) (string, error) {
	name, _, err := DecodeName(msg, rdataOffset)
	return name, err
}

// ParseDNAME extracts the delegation name from DNAME record RDATA (RFC 6672).
func ParseDNAME(msg []byte, rdataOffset int) (string, error) {
	name, _, err := DecodeName(msg, rdataOffset)
	return name, err
}

// SOARecord holds parsed SOA RDATA fields.
type SOARecord struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

// ParseSOA extracts all SOA fields from SOA record RDATA.
func ParseSOA(msg []byte, rdataOffset int) (*SOARecord, error) {
	var soa SOARecord
	var err error
	var offset int

	soa.MName, offset, err = DecodeName(msg, rdataOffset)
	if err != nil {
		return nil, err
	}

	soa.RName, offset, err = DecodeName(msg, offset)
	if err != nil {
		return nil, err
	}

	r := &wireReader{buf: msg, offset: offset}

	if soa.Serial, err = r.readUint32(); err != nil {
		return nil, err
	}
	if soa.Refresh, err = r.readUint32(); err != nil {
		return nil, err
	}
	if soa.Retry, err = r.readUint32(); err != nil {
		return nil, err
	}
	if soa.Expire, err = r.readUint32(); err != nil {
		return nil, err
	}
	if soa.Minimum, err = r.readUint32(); err != nil {
		return nil, err
	}

	return &soa, nil
}

// MXRecord holds parsed MX RDATA fields.
type MXRecord struct {
	Preference uint16
	Exchange   string
}

// ParseMX extracts preference and exchange from MX record RDATA.
func ParseMX(msg []byte, rdataOffset int) (*MXRecord, error) {
	r := &wireReader{buf: msg, offset: rdataOffset}
	pref, err := r.readUint16()
	if err != nil {
		return nil, err
	}

	exchange, _, err := DecodeName(msg, r.offset)
	if err != nil {
		return nil, err
	}

	return &MXRecord{Preference: pref, Exchange: exchange}, nil
}

// SRVRecord holds parsed SRV RDATA fields.
type SRVRecord struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// ParseSRV extracts all SRV fields from SRV record RDATA.
func ParseSRV(msg []byte, rdataOffset int) (*SRVRecord, error) {
	r := &wireReader{buf: msg, offset: rdataOffset}

	var srv SRVRecord
	var err error

	if srv.Priority, err = r.readUint16(); err != nil {
		return nil, err
	}
	if srv.Weight, err = r.readUint16(); err != nil {
		return nil, err
	}
	if srv.Port, err = r.readUint16(); err != nil {
		return nil, err
	}

	srv.Target, _, err = DecodeName(msg, r.offset)
	if err != nil {
		return nil, err
	}

	return &srv, nil
}

// ParseTXT extracts character strings from TXT record RDATA.
func ParseTXT(rdata []byte) ([]string, error) {
	var result []string
	offset := 0

	for offset < len(rdata) {
		length := int(rdata[offset])
		offset++

		if offset+length > len(rdata) {
			return nil, errTruncated
		}

		result = append(result, string(rdata[offset:offset+length]))
		offset += length
	}

	return result, nil
}

// --- DNSSEC record types ---

// DNSKEYRecord holds parsed DNSKEY RDATA fields (RFC 4034 Section 2).
type DNSKEYRecord struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

// ParseDNSKEY extracts DNSKEY fields from RDATA.
func ParseDNSKEY(rdata []byte) (*DNSKEYRecord, error) {
	if len(rdata) < 4 {
		return nil, fmt.Errorf("dns: DNSKEY RDATA too short: %d bytes", len(rdata))
	}
	rec := &DNSKEYRecord{
		Flags:     binary.BigEndian.Uint16(rdata[0:2]),
		Protocol:  rdata[2],
		Algorithm: rdata[3],
	}
	if len(rdata) > 4 {
		rec.PublicKey = make([]byte, len(rdata)-4)
		copy(rec.PublicKey, rdata[4:])
	}
	return rec, nil
}

// KeyTag computes the key tag per RFC 4034 Appendix B.
func (k *DNSKEYRecord) KeyTag() uint16 {
	var ac uint32
	wire := make([]byte, 4+len(k.PublicKey))
	binary.BigEndian.PutUint16(wire[0:2], k.Flags)
	wire[2] = k.Protocol
	wire[3] = k.Algorithm
	copy(wire[4:], k.PublicKey)
	for i, b := range wire {
		if i&1 == 1 {
			ac += uint32(b)
		} else {
			ac += uint32(b) << 8
		}
	}
	ac += ac >> 16 & 0xFFFF
	return uint16(ac & 0xFFFF)
}

// IsKSK reports whether the key-signing-key flag (SEP bit) is set.
func (k *DNSKEYRecord) IsKSK() bool {
	return k.Flags&0x0001 != 0
}

// DSRecord holds parsed DS RDATA fields (RFC 4034 Section 5).
type DSRecord struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// ParseDS extracts DS fields from RDATA.
func ParseDS(rdata []byte) (*DSRecord, error) {
	if len(rdata) < 4 {
		return nil, fmt.Errorf("dns: DS RDATA too short: %d bytes", len(rdata))
	}
	rec := &DSRecord{
		KeyTag:     binary.BigEndian.Uint16(rdata[0:2]),
		Algorithm:  rdata[2],
		DigestType: rdata[3],
	}
	if len(rdata) > 4 {
		rec.Digest = make([]byte, len(rdata)-4)
		copy(rec.Digest, rdata[4:])
	}
	return rec, nil
}

// RRSIGRecord holds parsed RRSIG RDATA fields (RFC 4034 Section 3).
type RRSIGRecord struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   []byte
}

// ParseRRSIG extracts RRSIG fields from RDATA.
// The rdata slice must be self-contained (signer name not compressed).
// The offset parameter is unused but kept for API consistency with other
// name-bearing parsers; pass 0.
func ParseRRSIG(rdata []byte, offset int) (*RRSIGRecord, error) {
	if len(rdata) < 18 {
		return nil, fmt.Errorf("dns: RRSIG RDATA too short: %d bytes", len(rdata))
	}
	rec := &RRSIGRecord{
		TypeCovered: binary.BigEndian.Uint16(rdata[0:2]),
		Algorithm:   rdata[2],
		Labels:      rdata[3],
		OrigTTL:     binary.BigEndian.Uint32(rdata[4:8]),
		Expiration:  binary.BigEndian.Uint32(rdata[8:12]),
		Inception:   binary.BigEndian.Uint32(rdata[12:16]),
		KeyTag:      binary.BigEndian.Uint16(rdata[16:18]),
	}
	name, nameEnd, err := DecodeName(rdata, 18)
	if err != nil {
		return nil, fmt.Errorf("dns: RRSIG signer name: %w", err)
	}
	rec.SignerName = name
	if nameEnd < len(rdata) {
		rec.Signature = make([]byte, len(rdata)-nameEnd)
		copy(rec.Signature, rdata[nameEnd:])
	}
	return rec, nil
}

// NSECRecord holds parsed NSEC RDATA fields (RFC 4034 Section 4).
type NSECRecord struct {
	NextDomainName string
	TypeBitMaps    []uint16
}

// ParseNSEC extracts NSEC fields from RDATA.
// The rdata slice must be self-contained (next domain name not compressed).
// The offset parameter is unused but kept for API consistency; pass 0.
func ParseNSEC(rdata []byte, offset int) (*NSECRecord, error) {
	if len(rdata) == 0 {
		return nil, fmt.Errorf("dns: NSEC RDATA empty")
	}
	name, nameEnd, err := DecodeName(rdata, 0)
	if err != nil {
		return nil, fmt.Errorf("dns: NSEC next domain name: %w", err)
	}
	rec := &NSECRecord{
		NextDomainName: name,
		TypeBitMaps:    parseTypeBitMaps(rdata[nameEnd:]),
	}
	return rec, nil
}

// NSEC3Record holds parsed NSEC3 RDATA fields (RFC 5155).
type NSEC3Record struct {
	HashAlgorithm uint8
	Flags         uint8
	Iterations    uint16
	Salt          []byte
	NextHash      []byte
	TypeBitMaps   []uint16
}

// ParseNSEC3 extracts NSEC3 fields from RDATA.
func ParseNSEC3(rdata []byte) (*NSEC3Record, error) {
	if len(rdata) < 5 {
		return nil, fmt.Errorf("dns: NSEC3 RDATA too short: %d bytes", len(rdata))
	}
	rec := &NSEC3Record{
		HashAlgorithm: rdata[0],
		Flags:         rdata[1],
		Iterations:    binary.BigEndian.Uint16(rdata[2:4]),
	}
	saltLen := int(rdata[4])
	off := 5
	if off+saltLen > len(rdata) {
		return nil, fmt.Errorf("dns: NSEC3 salt overflows RDATA")
	}
	if saltLen > 0 {
		rec.Salt = make([]byte, saltLen)
		copy(rec.Salt, rdata[off:off+saltLen])
	}
	off += saltLen

	if off >= len(rdata) {
		return nil, fmt.Errorf("dns: NSEC3 RDATA truncated at hash length")
	}
	hashLen := int(rdata[off])
	off++
	if off+hashLen > len(rdata) {
		return nil, fmt.Errorf("dns: NSEC3 next hash overflows RDATA")
	}
	if hashLen > 0 {
		rec.NextHash = make([]byte, hashLen)
		copy(rec.NextHash, rdata[off:off+hashLen])
	}
	off += hashLen

	rec.TypeBitMaps = parseTypeBitMaps(rdata[off:])
	return rec, nil
}

// parseTypeBitMaps decodes NSEC/NSEC3 type bitmap windows (RFC 4034 Section 4.1.2).
func parseTypeBitMaps(data []byte) []uint16 {
	var types []uint16
	off := 0
	for off+2 <= len(data) {
		window := int(data[off])
		bitmapLen := int(data[off+1])
		off += 2
		if off+bitmapLen > len(data) {
			break
		}
		for i := 0; i < bitmapLen; i++ {
			b := data[off+i]
			for bit := 0; bit < 8; bit++ {
				if b&(0x80>>uint(bit)) != 0 {
					types = append(types, uint16(window*256+i*8+bit))
				}
			}
		}
		off += bitmapLen
	}
	return types
}
