package dns

import (
	"encoding/binary"
	"fmt"
)

// EDNS0 represents parsed EDNS0 extension data.
type EDNS0 struct {
	UDPSize  uint16
	ExtRCODE uint8
	Version  uint8
	DOFlag   bool
	Options  []EDNSOption
}

// EDNSOption represents a single EDNS0 option.
type EDNSOption struct {
	Code uint16
	Data []byte
}

// ParseOPT extracts EDNS0 information from an OPT pseudo-record.
func ParseOPT(rr *ResourceRecord) (*EDNS0, error) {
	if rr.Type != TypeOPT {
		return nil, fmt.Errorf("dns: not an OPT record (type %d)", rr.Type)
	}

	edns := &EDNS0{
		UDPSize:  rr.Class,
		ExtRCODE: uint8(rr.TTL >> 24),
		Version:  uint8(rr.TTL >> 16 & 0xFF),
		DOFlag:   rr.TTL>>15&1 == 1,
	}

	// Parse RDATA options
	offset := 0
	for offset+4 <= int(rr.RDLength) {
		code := binary.BigEndian.Uint16(rr.RData[offset:])
		optLen := binary.BigEndian.Uint16(rr.RData[offset+2:])
		offset += 4

		if offset+int(optLen) > int(rr.RDLength) {
			break
		}

		data := make([]byte, optLen)
		copy(data, rr.RData[offset:offset+int(optLen)])
		edns.Options = append(edns.Options, EDNSOption{Code: code, Data: data})
		offset += int(optLen)
	}

	return edns, nil
}

// BuildOPT creates an OPT pseudo-record for outgoing queries.
func BuildOPT(udpSize uint16, doFlag bool) ResourceRecord {
	var ttl uint32
	if doFlag {
		ttl |= 1 << 15
	}

	return ResourceRecord{
		Name:     "",
		Type:     TypeOPT,
		Class:    udpSize,
		TTL:      ttl,
		RDLength: 0,
		RData:    nil,
	}
}
