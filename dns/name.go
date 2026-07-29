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

	// DNS names are case-insensitive (RFC 1035 §2.3.3, §3.1) and a compression
	// pointer may target an earlier occurrence of a name regardless of its
	// case. Key the compression dictionary on the lowercased name so that
	// 0x20-randomized variants (RFC 5452 §9.2) of the same name still compress
	// against each other. This matters for multi-hop CNAME chains: each hop is
	// resolved with independent 0x20 randomization, so the same domain comes
	// back from upstream with different casing at each owner/target. Keyed by
	// exact case, those variants never match and the whole chain is written out
	// in full — inflating the response past the 512-byte UDP limit and forcing
	// needless truncation + TCP retry (and an empty answer on transports where
	// the TC dance is mishandled). The bytes written stay in their original
	// case; only the dictionary lookup is case-folded.
	if offset, ok := w.compressed[strings.ToLower(name)]; ok && offset < 0x3FFF {
		pointer := uint16(0xC000) | uint16(offset)
		return w.writeUint16(pointer)
	}

	labels := splitLabels(name)

	for i := 0; i < len(labels); i++ {
		// Check if remaining suffix was previously written (case-insensitively).
		suffix := joinLabels(labels[i:])
		key := strings.ToLower(suffix)
		if offset, ok := w.compressed[key]; ok && offset < 0x3FFF {
			pointer := uint16(0xC000) | uint16(offset)
			return w.writeUint16(pointer)
		}

		// Record this suffix's offset for future compression
		w.compressed[key] = w.offset

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

// EncodeNameToBytes returns the uncompressed wire-format encoding of a
// domain name: a sequence of length-prefixed labels terminated by a zero
// byte (e.g. "foo.example.com" → 3 'f' 'o' 'o' 7 'e'...'m' 0). Used for
// callers that need to produce stand-alone RData bytes — DNAME→CNAME
// synthesis, hand-built test fixtures — without the message-level
// compression dictionary that EncodeName depends on. Returns an error on
// labels longer than 63 octets (RFC 1035 §2.3.4) or full names longer
// than 255 octets including the root terminator.
func EncodeNameToBytes(name string) ([]byte, error) {
	if name == "" || name == "." {
		return []byte{0x00}, nil
	}
	labels := splitLabels(name)
	out := make([]byte, 0, len(name)+2)
	total := 1 // root terminator
	for _, label := range labels {
		if len(label) > maxLabelLength {
			return nil, errLabelTooLong
		}
		total += 1 + len(label)
		if total > 255 {
			return nil, errNameTooLong
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0x00)
	return out, nil
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
