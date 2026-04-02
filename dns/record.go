package dns

import "encoding/binary"

// UnpackRR decodes a resource record from the wire format.
// For types with compressed domain names in RDATA (NS, CNAME, PTR, MX, SOA, SRV),
// the names are decompressed during unpack so stored RDATA is self-contained.
func UnpackRR(msg []byte, offset int) (ResourceRecord, int, error) {
	var rr ResourceRecord
	var err error

	rr.Name, offset, err = DecodeName(msg, offset)
	if err != nil {
		return rr, 0, err
	}

	r := &wireReader{buf: msg, offset: offset}

	if rr.Type, err = r.readUint16(); err != nil {
		return rr, 0, err
	}
	if rr.Class, err = r.readUint16(); err != nil {
		return rr, 0, err
	}
	if rr.TTL, err = r.readUint32(); err != nil {
		return rr, 0, err
	}

	var wireRDLength uint16
	if wireRDLength, err = r.readUint16(); err != nil {
		return rr, 0, err
	}

	if r.remaining() < int(wireRDLength) {
		return rr, 0, errTruncated
	}

	rdataStart := r.offset
	rr.RDataOffset = rdataStart
	newOffset := rdataStart + int(wireRDLength)

	// Decompress name-bearing RDATA types so stored RData is self-contained
	switch rr.Type {
	case TypeNS, TypeCNAME, TypePTR:
		name, _, nameErr := DecodeName(msg, rdataStart)
		if nameErr == nil {
			rr.RData = encodePlainName(name)
		} else {
			rr.RData = copyRData(msg, rdataStart, int(wireRDLength))
		}

	case TypeMX:
		if wireRDLength >= 2 {
			pref := binary.BigEndian.Uint16(msg[rdataStart:])
			name, _, nameErr := DecodeName(msg, rdataStart+2)
			if nameErr == nil {
				nameBytes := encodePlainName(name)
				rr.RData = make([]byte, 2+len(nameBytes))
				binary.BigEndian.PutUint16(rr.RData, pref)
				copy(rr.RData[2:], nameBytes)
			} else {
				rr.RData = copyRData(msg, rdataStart, int(wireRDLength))
			}
		} else {
			rr.RData = copyRData(msg, rdataStart, int(wireRDLength))
		}

	case TypeSOA:
		mname, off1, err1 := DecodeName(msg, rdataStart)
		if err1 != nil {
			rr.RData = copyRData(msg, rdataStart, int(wireRDLength))
			break
		}
		rname, off2, err2 := DecodeName(msg, off1)
		if err2 != nil {
			rr.RData = copyRData(msg, rdataStart, int(wireRDLength))
			break
		}
		serialsEnd := off2 + 20
		if serialsEnd > newOffset {
			rr.RData = copyRData(msg, rdataStart, int(wireRDLength))
			break
		}
		mnameBytes := encodePlainName(mname)
		rnameBytes := encodePlainName(rname)
		rr.RData = make([]byte, len(mnameBytes)+len(rnameBytes)+20)
		copy(rr.RData, mnameBytes)
		copy(rr.RData[len(mnameBytes):], rnameBytes)
		copy(rr.RData[len(mnameBytes)+len(rnameBytes):], msg[off2:off2+20])

	case TypeSRV:
		if wireRDLength >= 6 {
			header := make([]byte, 6)
			copy(header, msg[rdataStart:rdataStart+6])
			name, _, nameErr := DecodeName(msg, rdataStart+6)
			if nameErr == nil {
				nameBytes := encodePlainName(name)
				rr.RData = make([]byte, 6+len(nameBytes))
				copy(rr.RData, header)
				copy(rr.RData[6:], nameBytes)
			} else {
				rr.RData = copyRData(msg, rdataStart, int(wireRDLength))
			}
		} else {
			rr.RData = copyRData(msg, rdataStart, int(wireRDLength))
		}

	default:
		rr.RData = copyRData(msg, rdataStart, int(wireRDLength))
	}

	rr.RDLength = uint16(len(rr.RData))
	return rr, newOffset, nil
}

func copyRData(msg []byte, offset, n int) []byte {
	b := make([]byte, n)
	copy(b, msg[offset:offset+n])
	return b
}

// BuildPlainName encodes a domain name as uncompressed wire-format label sequence.
// Exported for use in tests and delegation handling.
func BuildPlainName(name string) []byte {
	return encodePlainName(name)
}

// encodePlainName encodes a domain name as uncompressed wire-format label sequence.
func encodePlainName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0x00}
	}
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	var buf []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
			start = i + 1
		}
	}
	buf = append(buf, 0x00)
	return buf
}
