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

// BuildOPTWithOptions creates an OPT pseudo-record with EDNS0 options.
func BuildOPTWithOptions(udpSize uint16, doFlag bool, options []EDNSOption) ResourceRecord {
	rr := BuildOPT(udpSize, doFlag)
	if len(options) == 0 {
		return rr
	}

	var rdata []byte
	for _, opt := range options {
		buf := make([]byte, 4+len(opt.Data))
		binary.BigEndian.PutUint16(buf[0:2], opt.Code)
		binary.BigEndian.PutUint16(buf[2:4], uint16(len(opt.Data)))
		copy(buf[4:], opt.Data)
		rdata = append(rdata, buf...)
	}
	rr.RData = rdata
	rr.RDLength = uint16(len(rdata))
	return rr
}

// EDE info codes (RFC 8914).
const (
	EDECodeOtherError              uint16 = 0
	EDECodeUnsupportedDNSKEYAlgo   uint16 = 1
	EDECodeUnsupportedDSDigestType uint16 = 2
	EDECodeStaleAnswer             uint16 = 3
	EDECodeForgedAnswer            uint16 = 4
	EDECodeDNSSECIndeterminate     uint16 = 5
	EDECodeDNSSECBogus             uint16 = 6
	EDECodeSignatureExpired        uint16 = 7
	EDECodeSignatureNotYetValid    uint16 = 8
	EDECodeDNSKEYMissing           uint16 = 9
	EDECodeRRSIGsMissing           uint16 = 10
	EDECodeNoZoneKeyBitSet         uint16 = 11
	EDECodeNSECMissing             uint16 = 12
	EDECodeCachedError             uint16 = 13
	EDECodeNotReady                uint16 = 14
	EDECodeBlocked                 uint16 = 15
	EDECodeCensored                uint16 = 16
	EDECodeFiltered                uint16 = 17
	EDECodeProhibited              uint16 = 18
	EDECodeStaleNXDOMAINAnswer     uint16 = 19
	EDECodeNotAuthoritative        uint16 = 20
	EDECodeNotSupported            uint16 = 21
	EDECodeNoReachableAuthority    uint16 = 22
	EDECodeNetworkError            uint16 = 23
	EDECodeInvalidData             uint16 = 24
)

// EDNS option codes.
const (
	EDNSOptionCodeECS    uint16 = 8
	EDNSOptionCodeCookie uint16 = 10
	EDNSOptionCodeEDE    uint16 = 15
)

// BuildEDEOption constructs an Extended DNS Error option (RFC 8914, option code 15).
// infoCode is the EDE info code, extraText is an optional UTF-8 string.
func BuildEDEOption(infoCode uint16, extraText string) EDNSOption {
	data := make([]byte, 2+len(extraText))
	binary.BigEndian.PutUint16(data[0:2], infoCode)
	if len(extraText) > 0 {
		copy(data[2:], extraText)
	}
	return EDNSOption{
		Code: EDNSOptionCodeEDE,
		Data: data,
	}
}

// ParseEDEOption parses an Extended DNS Error option from EDNS0 option data.
// Returns the info code and extra text.
func ParseEDEOption(data []byte) (infoCode uint16, extraText string, err error) {
	if len(data) < 2 {
		return 0, "", fmt.Errorf("dns: EDE option data too short: %d bytes", len(data))
	}
	infoCode = binary.BigEndian.Uint16(data[0:2])
	if len(data) > 2 {
		extraText = string(data[2:])
	}
	return infoCode, extraText, nil
}

// ParseCookieOption parses a DNS Cookie option (RFC 7873, option code 10).
// Returns the client cookie (8 bytes) and optional server cookie (8-32 bytes).
func ParseCookieOption(data []byte) (clientCookie []byte, serverCookie []byte) {
	if len(data) < 8 {
		return nil, nil
	}
	clientCookie = make([]byte, 8)
	copy(clientCookie, data[:8])
	if len(data) > 8 {
		serverCookie = make([]byte, len(data)-8)
		copy(serverCookie, data[8:])
	}
	return clientCookie, serverCookie
}
