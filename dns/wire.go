package dns

import "encoding/binary"

// wireReader is a zero-allocation cursor reader over a byte slice.
type wireReader struct {
	buf    []byte
	offset int
}

func newWireReader(buf []byte) *wireReader {
	return &wireReader{buf: buf, offset: 0}
}

func (r *wireReader) remaining() int {
	return len(r.buf) - r.offset
}

func (r *wireReader) readUint16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, errTruncated
	}
	v := binary.BigEndian.Uint16(r.buf[r.offset:])
	r.offset += 2
	return v, nil
}

func (r *wireReader) readUint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, errTruncated
	}
	v := binary.BigEndian.Uint32(r.buf[r.offset:])
	r.offset += 4
	return v, nil
}

func (r *wireReader) readBytes(n int) ([]byte, error) {
	if r.remaining() < n {
		return nil, errTruncated
	}
	b := r.buf[r.offset : r.offset+n]
	r.offset += n
	return b, nil
}

func (r *wireReader) peek() (byte, error) {
	if r.remaining() < 1 {
		return 0, errTruncated
	}
	return r.buf[r.offset], nil
}

// wireWriter is a cursor writer that builds DNS messages into a pre-allocated buffer.
type wireWriter struct {
	buf        []byte
	offset     int
	compressed map[string]int
}

func newWireWriter(buf []byte) *wireWriter {
	return &wireWriter{
		buf:        buf,
		offset:     0,
		compressed: make(map[string]int, 16),
	}
}

func (w *wireWriter) writeUint16(v uint16) error {
	if len(w.buf)-w.offset < 2 {
		return errBufferFull
	}
	binary.BigEndian.PutUint16(w.buf[w.offset:], v)
	w.offset += 2
	return nil
}

func (w *wireWriter) writeUint32(v uint32) error {
	if len(w.buf)-w.offset < 4 {
		return errBufferFull
	}
	binary.BigEndian.PutUint32(w.buf[w.offset:], v)
	w.offset += 4
	return nil
}

func (w *wireWriter) writeBytes(b []byte) error {
	if len(w.buf)-w.offset < len(b) {
		return errBufferFull
	}
	copy(w.buf[w.offset:], b)
	w.offset += len(b)
	return nil
}

func (w *wireWriter) bytes() []byte {
	return w.buf[:w.offset]
}

// Unpack parses a DNS message from wire format.
func Unpack(buf []byte) (*Message, error) {
	if len(buf) < 12 {
		return nil, errTruncated
	}

	msg := &Message{}
	msg.Raw = make([]byte, len(buf))
	copy(msg.Raw, buf)

	r := newWireReader(buf)

	if err := msg.Header.Unpack(r); err != nil {
		return nil, err
	}

	// Questions
	offset := r.offset
	for i := 0; i < int(msg.Header.QDCount); i++ {
		q, newOffset, err := UnpackQuestion(buf, offset)
		if err != nil {
			return nil, err
		}
		offset = newOffset
		msg.Questions = append(msg.Questions, q)
	}

	// Helper: unpack N resource records
	unpackRRs := func(count uint16) ([]ResourceRecord, error) {
		var rrs []ResourceRecord
		for i := 0; i < int(count); i++ {
			rr, newOffset, err := UnpackRR(buf, offset)
			if err != nil {
				return nil, err
			}
			rrs = append(rrs, rr)
			offset = newOffset
		}
		return rrs, nil
	}

	var err error

	if msg.Answers, err = unpackRRs(msg.Header.ANCount); err != nil {
		return nil, err
	}
	if msg.Authority, err = unpackRRs(msg.Header.NSCount); err != nil {
		return nil, err
	}
	if msg.Additional, err = unpackRRs(msg.Header.ARCount); err != nil {
		return nil, err
	}

	// Extract EDNS0 from Additional
	for i, rr := range msg.Additional {
		if rr.Type == TypeOPT {
			msg.EDNS0, _ = ParseOPT(&msg.Additional[i])
			break
		}
	}

	return msg, nil
}

// Pack serializes a DNS message to wire format.
func Pack(msg *Message, buf []byte) ([]byte, error) {
	w := newWireWriter(buf)

	// Update counts
	msg.Header.QDCount = uint16(len(msg.Questions))
	msg.Header.ANCount = uint16(len(msg.Answers))
	msg.Header.NSCount = uint16(len(msg.Authority))
	msg.Header.ARCount = uint16(len(msg.Additional))

	if err := msg.Header.Pack(w); err != nil {
		return nil, err
	}

	// Questions
	for _, q := range msg.Questions {
		if err := EncodeName(w, q.Name); err != nil {
			return nil, err
		}
		if err := w.writeUint16(q.Type); err != nil {
			return nil, err
		}
		if err := w.writeUint16(q.Class); err != nil {
			return nil, err
		}
	}

	// Pack resource records with RDATA name compression for applicable types
	packRRs := func(rrs []ResourceRecord) error {
		for _, rr := range rrs {
			if err := EncodeName(w, rr.Name); err != nil {
				return err
			}
			if err := w.writeUint16(rr.Type); err != nil {
				return err
			}
			if err := w.writeUint16(rr.Class); err != nil {
				return err
			}
			if err := w.writeUint32(rr.TTL); err != nil {
				return err
			}

			if err := packRData(w, rr); err != nil {
				return err
			}
		}
		return nil
	}

	if err := packRRs(msg.Answers); err != nil {
		return nil, err
	}
	if err := packRRs(msg.Authority); err != nil {
		return nil, err
	}
	if err := packRRs(msg.Additional); err != nil {
		return nil, err
	}

	return w.bytes(), nil
}

// packRData writes a resource record's RDATA to the wire writer.
// For types containing domain names (NS, CNAME, PTR, MX, SOA, SRV),
// names are re-encoded with compression. Other types are written as raw bytes.
func packRData(w *wireWriter, rr ResourceRecord) error {
	// Reserve 2 bytes for RDLENGTH, fill in after writing RDATA
	rdLenOffset := w.offset
	if err := w.writeUint16(0); err != nil { // placeholder
		return err
	}
	rdStart := w.offset

	var err error
	if len(rr.RData) == 0 {
		// Nothing to write — RDLENGTH stays 0
		binary.BigEndian.PutUint16(w.buf[rdLenOffset:], 0)
		return nil
	}

	switch rr.Type {
	case TypeNS, TypeCNAME, TypePTR:
		// Single domain name — decompress from RData, re-encode with compression
		name, _, nameErr := DecodeName(rr.RData, 0)
		if nameErr != nil {
			err = w.writeBytes(rr.RData)
		} else {
			err = EncodeName(w, name)
		}

	case TypeMX:
		if len(rr.RData) >= 2 {
			// uint16 preference + domain name
			if err = w.writeBytes(rr.RData[:2]); err != nil {
				return err
			}
			name, _, nameErr := DecodeName(rr.RData, 2)
			if nameErr != nil {
				err = w.writeBytes(rr.RData[2:])
			} else {
				err = EncodeName(w, name)
			}
		} else {
			err = w.writeBytes(rr.RData)
		}

	case TypeSOA:
		mname, off1, err1 := DecodeName(rr.RData, 0)
		if err1 != nil {
			err = w.writeBytes(rr.RData)
			break
		}
		rname, off2, err2 := DecodeName(rr.RData, off1)
		if err2 != nil {
			err = w.writeBytes(rr.RData)
			break
		}
		if err = EncodeName(w, mname); err != nil {
			return err
		}
		if err = EncodeName(w, rname); err != nil {
			return err
		}
		// 5 × uint32 serials
		remaining := rr.RData[off2:]
		err = w.writeBytes(remaining)

	case TypeSRV:
		if len(rr.RData) >= 6 {
			// uint16 priority + uint16 weight + uint16 port + domain name
			if err = w.writeBytes(rr.RData[:6]); err != nil {
				return err
			}
			name, _, nameErr := DecodeName(rr.RData, 6)
			if nameErr != nil {
				err = w.writeBytes(rr.RData[6:])
			} else {
				err = EncodeName(w, name)
			}
		} else {
			err = w.writeBytes(rr.RData)
		}

	case TypeRRSIG:
		// 18 bytes fixed fields + signer name (plain) + signature
		if len(rr.RData) >= 18 {
			if err = w.writeBytes(rr.RData[:18]); err != nil {
				return err
			}
			signerName, nameEnd, nameErr := DecodeName(rr.RData, 18)
			if nameErr != nil {
				err = w.writeBytes(rr.RData[18:])
			} else {
				if err = EncodeName(w, signerName); err != nil {
					return err
				}
				// Write signature bytes after the signer name
				if nameEnd < len(rr.RData) {
					err = w.writeBytes(rr.RData[nameEnd:])
				}
			}
		} else {
			err = w.writeBytes(rr.RData)
		}

	case TypeNSEC:
		// Next domain name (plain) + type bitmaps
		name, nameEnd, nameErr := DecodeName(rr.RData, 0)
		if nameErr != nil {
			err = w.writeBytes(rr.RData)
		} else {
			if err = EncodeName(w, name); err != nil {
				return err
			}
			if nameEnd < len(rr.RData) {
				err = w.writeBytes(rr.RData[nameEnd:])
			}
		}

	default:
		// A, AAAA, TXT, OPT, unknown: write raw
		err = w.writeBytes(rr.RData)
	}

	if err != nil {
		return err
	}

	// Patch RDLENGTH with actual bytes written
	rdLen := w.offset - rdStart
	binary.BigEndian.PutUint16(w.buf[rdLenOffset:], uint16(rdLen))
	return nil
}
