package security

import (
	"encoding/binary"
	"testing"
)

// TestSipHash24_RFC_Vector tests against the SipHash-2-4 reference test vector
// from the original paper (key = 00..0f, msg = 00..0e, expected = a129ca6149be45e5).
func TestSipHash24_RFC_Vector(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	msg := make([]byte, 15)
	for i := range msg {
		msg[i] = byte(i)
	}

	got := SipHash24(key, msg)
	want := uint64(0xa129ca6149be45e5)
	if got != want {
		t.Errorf("SipHash24 = 0x%016x, want 0x%016x", got, want)
	}
}

// TestSipHash24_EmptyMessage tests with an empty message.
func TestSipHash24_EmptyMessage(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}

	got := SipHash24(key, nil)
	want := uint64(0x726fdb47dd0e0e31)
	if got != want {
		t.Errorf("SipHash24(empty) = 0x%016x, want 0x%016x", got, want)
	}
}

// TestSipHash24_SingleByte tests with a one-byte message.
func TestSipHash24_SingleByte(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}

	got := SipHash24(key, []byte{0x00})
	want := uint64(0x74f839c593dc67fd)
	if got != want {
		t.Errorf("SipHash24(0x00) = 0x%016x, want 0x%016x", got, want)
	}
}

// TestSipHash24_DifferentKeys ensures different keys produce different hashes.
func TestSipHash24_DifferentKeys(t *testing.T) {
	msg := []byte("dns-cookie-test")

	var key1, key2 [16]byte
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 0x80)
	}

	h1 := SipHash24(key1, msg)
	h2 := SipHash24(key2, msg)
	if h1 == h2 {
		t.Error("different keys should produce different hashes")
	}
}

// TestSipHash24_Deterministic ensures same inputs yield same output.
func TestSipHash24_Deterministic(t *testing.T) {
	var key [16]byte
	binary.LittleEndian.PutUint64(key[0:8], 0xdeadbeefcafebabe)
	binary.LittleEndian.PutUint64(key[8:16], 0x0123456789abcdef)
	msg := []byte("example.com")

	h1 := SipHash24(key, msg)
	h2 := SipHash24(key, msg)
	if h1 != h2 {
		t.Error("same inputs should produce same hash")
	}
}

// TestSipHash24_AllLengths tests messages of length 0..63 to exercise all
// code paths (full blocks + variable-length remainders).
func TestSipHash24_AllLengths(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}

	prev := uint64(0)
	for length := 0; length <= 63; length++ {
		msg := make([]byte, length)
		for i := range msg {
			msg[i] = byte(i)
		}
		h := SipHash24(key, msg)
		if length > 0 && h == prev {
			t.Errorf("length %d produced same hash as length %d", length, length-1)
		}
		prev = h
	}
}
