package dns

import "testing"

func TestDecodeNameSimple(t *testing.T) {
	// "www.google.com" → \x03www\x06google\x03com\x00
	buf := []byte{
		0x03, 'w', 'w', 'w',
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}

	name, consumed, err := DecodeName(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "www.google.com" {
		t.Errorf("expected 'www.google.com', got '%s'", name)
	}
	if consumed != len(buf) {
		t.Errorf("expected consumed=%d, got %d", len(buf), consumed)
	}
}

func TestDecodeNameRoot(t *testing.T) {
	buf := []byte{0x00}
	name, consumed, err := DecodeName(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "" {
		t.Errorf("expected empty string for root, got '%s'", name)
	}
	if consumed != 1 {
		t.Errorf("expected consumed=1, got %d", consumed)
	}
}

func TestDecodeNameLabelTooLong(t *testing.T) {
	buf := make([]byte, 66)
	buf[0] = 64 // label length > 63
	_, _, err := DecodeName(buf, 0)
	if err != errLabelTooLong {
		t.Fatalf("expected errLabelTooLong, got %v", err)
	}
}

func TestDecodeNameCompression(t *testing.T) {
	// Build a message with "google.com" at offset 0, then a pointer
	buf := []byte{
		// "google.com" at offset 0
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		// "www" + pointer to offset 0 ("google.com")
		0x03, 'w', 'w', 'w',
		0xC0, 0x00, // pointer to offset 0
	}

	name, consumed, err := DecodeName(buf, 12)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "www.google.com" {
		t.Errorf("expected 'www.google.com', got '%s'", name)
	}
	if consumed != 18 {
		t.Errorf("expected consumed=18, got %d", consumed)
	}
}

func TestDecodeNamePointerForward(t *testing.T) {
	// Forward pointer: offset 0 points to offset 2
	buf := []byte{
		0xC0, 0x02, // pointer to offset 2 (forward reference)
		0x03, 'c', 'o', 'm', 0x00,
	}

	_, _, err := DecodeName(buf, 0)
	if err != errPointerForward {
		t.Fatalf("expected errPointerForward, got %v", err)
	}
}

func TestDecodeNameSelfReference(t *testing.T) {
	// Self-referencing pointer at offset 0
	buf := []byte{0xC0, 0x00}

	_, _, err := DecodeName(buf, 0)
	if err != errPointerForward {
		t.Fatalf("expected errPointerForward, got %v", err)
	}
}

func TestDecodeNameTruncated(t *testing.T) {
	buf := []byte{0x03, 'w', 'w'} // label says 3 bytes but only 2 available
	_, _, err := DecodeName(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestEncodeNameSimple(t *testing.T) {
	buf := make([]byte, 256)
	w := newWireWriter(buf)

	if err := EncodeName(w, "www.google.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []byte{
		0x03, 'w', 'w', 'w',
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}

	result := w.bytes()
	if len(result) != len(expected) {
		t.Fatalf("expected %d bytes, got %d", len(expected), len(result))
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], result[i])
		}
	}
}

func TestEncodeNameRoot(t *testing.T) {
	buf := make([]byte, 10)
	w := newWireWriter(buf)

	if err := EncodeName(w, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := w.bytes()
	if len(result) != 1 || result[0] != 0x00 {
		t.Errorf("expected single zero byte for root, got %v", result)
	}
}

func TestEncodeNameCompression(t *testing.T) {
	buf := make([]byte, 256)
	w := newWireWriter(buf)

	// Write first name
	if err := EncodeName(w, "google.com"); err != nil {
		t.Fatalf("first encode error: %v", err)
	}
	firstLen := w.offset

	// Write same name again — should use pointer
	if err := EncodeName(w, "google.com"); err != nil {
		t.Fatalf("second encode error: %v", err)
	}
	secondLen := w.offset - firstLen

	// Pointer is 2 bytes
	if secondLen != 2 {
		t.Errorf("expected compressed name to be 2 bytes, got %d", secondLen)
	}

	// Write "mail.google.com" — should compress "google.com" suffix
	before := w.offset
	if err := EncodeName(w, "mail.google.com"); err != nil {
		t.Fatalf("third encode error: %v", err)
	}
	thirdLen := w.offset - before

	// "mail" label (1+4=5 bytes) + pointer (2 bytes) = 7 bytes
	if thirdLen != 7 {
		t.Errorf("expected 'mail.google.com' with compression to be 7 bytes, got %d", thirdLen)
	}
}

func TestDecodeNameTooLong(t *testing.T) {
	// Build a wire-format name with total length > 255 bytes.
	// We use many labels of length 10, separated by dots.
	// Each label = 1 (length) + 10 (data) = 11 bytes on wire.
	// 24 labels = 24*10 + 23 dots = 263 chars in the decoded name, exceeding 255.
	var buf []byte
	for i := 0; i < 24; i++ {
		buf = append(buf, 10) // label length
		for j := 0; j < 10; j++ {
			buf = append(buf, byte('a'+i%26))
		}
	}
	buf = append(buf, 0x00) // terminator

	_, _, err := DecodeName(buf, 0)
	if err != errNameTooLong {
		t.Fatalf("expected errNameTooLong, got %v", err)
	}
}

func TestEncodeNameLabelTooLong(t *testing.T) {
	// Build a domain name with a label > 63 characters
	longLabel := ""
	for i := 0; i < 64; i++ {
		longLabel += "a"
	}
	name := longLabel + ".example.com"

	buf := make([]byte, 512)
	w := newWireWriter(buf)
	err := EncodeName(w, name)
	if err != errLabelTooLong {
		t.Fatalf("expected errLabelTooLong, got %v", err)
	}
}

func TestDecodeNamePointerTruncated(t *testing.T) {
	// Pointer marker (0xC0) at end of buffer with no second byte
	buf := []byte{0x03, 'c', 'o', 'm', 0x00, 0xC0}
	_, _, err := DecodeName(buf, 5)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestDecodeNameEmptyAtOffset(t *testing.T) {
	// Offset beyond buffer
	buf := []byte{0x00}
	_, _, err := DecodeName(buf, 5)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestEncodeNameDotSuffix(t *testing.T) {
	// Name with trailing dot should be treated same as without
	buf1 := make([]byte, 256)
	w1 := newWireWriter(buf1)
	if err := EncodeName(w1, "example.com."); err != nil {
		t.Fatalf("encode error: %v", err)
	}

	buf2 := make([]byte, 256)
	w2 := newWireWriter(buf2)
	if err := EncodeName(w2, "example.com"); err != nil {
		t.Fatalf("encode error: %v", err)
	}

	r1 := w1.bytes()
	r2 := w2.bytes()
	if len(r1) != len(r2) {
		t.Errorf("trailing dot should produce same output: %d vs %d bytes", len(r1), len(r2))
	}
}

func TestSplitLabelsDot(t *testing.T) {
	// splitLabels(".") should return nil because TrimSuffix(., .) = "" and split of "" is nil
	result := splitLabels(".")
	if result != nil {
		t.Errorf("splitLabels(\".\") should return nil, got %v", result)
	}
}

func TestEncodeNameBufferFullMidName(t *testing.T) {
	// Buffer too small to encode a name: writeBytes fails mid-label
	buf := make([]byte, 3) // only 3 bytes — enough for length byte + 2 chars, not full label
	w := newWireWriter(buf)

	err := EncodeName(w, "example.com")
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull when buffer is too small mid-name, got %v", err)
	}
}

func TestEncodeNameBufferFullAtLengthByte(t *testing.T) {
	// Buffer just enough for first label but fails at the length byte of the second label
	// "a.b" → \x01 a \x01 b \x00 = 5 bytes
	// With 3 bytes, we can write \x01 a but fail at writing the length byte \x01 for "b"
	buf := make([]byte, 2) // only room for length byte + 'a', not the next length byte
	w := newWireWriter(buf)

	err := EncodeName(w, "a.b")
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull at length byte, got %v", err)
	}
}

func TestDecodeNamePointerLoop(t *testing.T) {
	// Create a chain of backward pointers that exceeds maxPointerDepth (128)
	// We'll lay out pointers from high to low, each pointing to the previous one,
	// creating a chain > 128 pointers deep.
	// Each pointer is 2 bytes: 0xC0 | (offset>>8), offset&0xFF
	// We need 130 pointers. Place them at offsets 0, 2, 4, ..., 258
	// Each pointer at offset N points to offset N-2 (backward).
	// The first pointer at offset 0 points to itself... no, that's a forward check.
	// Actually: pointer at offset N (for N >= 2) points to offset N-2.
	// pointer at offset 0 is the start — make it a regular label that loops.
	// Better approach: offset 0 has a real label, then pointer at offset 2 -> 0,
	// pointer at offset 4 -> 2, etc. But DecodeName would just decode the label at 0
	// and the pointer at 2 goes back to 0 (which is earlier, passes the forward check).
	// Actually all pointers need to eventually keep jumping. Let me think...
	//
	// Simplest approach: make many short pointer chains that all point backward.
	// Offset 0: pointer to 0? No — that fails the "pointer >= offset" check.
	// Use a circular chain:
	// Offset 0: \xC0\x02 (points to offset 2)  — but offset 2 >= 0, forward! fails.
	//
	// Need something more subtle. Two pointers at offsets 4 and 2:
	// Offset 2: \xC0\x00 (points to 0, which is < 2, OK)
	// Offset 0: \xC0\x02 (points to 2, which is >= 0, FORWARD — blocked!)
	//
	// The forward check prevents cycles. But maxPointerDepth handles a long linear chain:
	// offset 256: ptr to 254, offset 254: ptr to 252, ..., offset 2: ptr to 0, offset 0: label + ptr to ?
	// If offset 0 is a real label followed by \x00, the chain resolves. To get >128, we need the
	// chain to NOT resolve, but the forward check blocks true loops.
	//
	// Actually, the pointer loop detection is for chains that are very long but legal.
	// E.g.: offset 256 -> 254 -> 252 -> ... -> 0. That's 128 jumps. We need > 128.
	// Each pointer is 2 bytes, so for 130 jumps we need 260 bytes.
	// At offset 0 we place a zero-length label (\x00) so decoding terminates.
	// We start decoding from offset 260 which points to 258, then 256, ..., 0.
	// That's 130 jumps which exceeds maxPointerDepth (128).

	size := 2 * 131 // 262 bytes. 131 pointers + the entry point
	buf := make([]byte, size+2)

	// Offset 0: terminator (zero-length label)
	buf[0] = 0x00

	// Offsets 2, 4, ..., 260: each is a pointer to offset-2
	for i := 1; i <= 130; i++ {
		off := i * 2
		target := off - 2
		buf[off] = 0xC0 | byte(target>>8)
		buf[off+1] = byte(target & 0xFF)
	}

	// Start decoding from offset 260 (the 130th pointer)
	_, _, err := DecodeName(buf, 260)
	if err != errPointerLoop {
		t.Fatalf("expected errPointerLoop, got %v", err)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	names := []string{
		"example.com",
		"www.example.com",
		"a.b.c.d.example.com",
		"com",
	}

	for _, name := range names {
		buf := make([]byte, 256)
		w := newWireWriter(buf)

		if err := EncodeName(w, name); err != nil {
			t.Fatalf("encode '%s' error: %v", name, err)
		}

		decoded, _, err := DecodeName(w.bytes(), 0)
		if err != nil {
			t.Fatalf("decode '%s' error: %v", name, err)
		}
		if decoded != name {
			t.Errorf("round-trip '%s': got '%s'", name, decoded)
		}
	}
}
