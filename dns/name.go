package dns

import "strings"

const (
	maxNameLength   = 255
	maxLabelLength  = 63
	maxPointerDepth = 128
	compressionMask = 0xC0
	pointerMask     = 0x3FFF
)

// DecodeName reads a domain name from the wire format.
// It returns the decoded name and the number of bytes consumed
// from the ORIGINAL position (before any pointer jumps).
func DecodeName(msg []byte, offset int) (string, int, error) {
	var (
		name         []byte
		jumped       bool
		consumedEnd  int
		pointerDepth int
	)

	for {
		if offset >= len(msg) {
			return "", 0, errTruncated
		}

		length := int(msg[offset])

		// Terminator: zero-length label
		if length == 0 {
			if !jumped {
				consumedEnd = offset + 1
			}
			break
		}

		// Pointer: top 2 bits = 11
		if length&compressionMask == compressionMask {
			if offset+1 >= len(msg) {
				return "", 0, errTruncated
			}

			if !jumped {
				consumedEnd = offset + 2
			}

			pointerTarget := (int(msg[offset])<<8 | int(msg[offset+1])) & pointerMask

			// Security: pointer must reference EARLIER in the message
			if pointerTarget >= offset {
				return "", 0, errPointerForward
			}

			pointerDepth++
			if pointerDepth > maxPointerDepth {
				return "", 0, errPointerLoop
			}

			offset = pointerTarget
			jumped = true
			continue
		}

		// Regular label
		if length > maxLabelLength {
			return "", 0, errLabelTooLong
		}

		offset++ // skip length byte

		if offset+length > len(msg) {
			return "", 0, errTruncated
		}

		// Append dot separator (except for first label)
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, msg[offset:offset+length]...)
		offset += length

		if len(name) > maxNameLength {
			return "", 0, errNameTooLong
		}
	}

	if !jumped {
		consumedEnd = offset + 1
	}

	return string(name), consumedEnd, nil
}

// EncodeName writes a domain name in wire format with optional compression.
func EncodeName(w *wireWriter, name string) error {
	if name == "" || name == "." {
		return w.writeBytes([]byte{0x00})
	}

	// Check if full name was previously written
	if offset, ok := w.compressed[name]; ok && offset < 0x3FFF {
		pointer := uint16(0xC000) | uint16(offset)
		return w.writeUint16(pointer)
	}

	labels := splitLabels(name)

	for i := 0; i < len(labels); i++ {
		// Check if remaining suffix was previously written
		suffix := joinLabels(labels[i:])
		if offset, ok := w.compressed[suffix]; ok && offset < 0x3FFF {
			pointer := uint16(0xC000) | uint16(offset)
			return w.writeUint16(pointer)
		}

		// Record this suffix's offset for future compression
		w.compressed[suffix] = w.offset

		label := labels[i]
		if len(label) > maxLabelLength {
			return errLabelTooLong
		}

		// Write length + label
		if err := w.writeBytes([]byte{byte(len(label))}); err != nil {
			return err
		}
		if err := w.writeBytes([]byte(label)); err != nil {
			return err
		}
	}

	// Terminating zero
	return w.writeBytes([]byte{0x00})
}

func splitLabels(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

func joinLabels(labels []string) string {
	return strings.Join(labels, ".")
}
