package dns

import (
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
