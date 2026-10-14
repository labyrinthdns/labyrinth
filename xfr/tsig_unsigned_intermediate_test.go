package xfr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// tsigStreamWires renders the messages of an AXFR of example.com one by one,
// signing those marked in signed per RFC 8945 §5.3.1.
func tsigStreamWires(t *testing.T, key dns.TSIGKey, requestMAC []byte, parts [][]dns.ResourceRecord, signed []bool) [][]byte {
	t.Helper()
	stream := signedAXFRStream(t, key, requestMAC, parts, signed)
	var wires [][]byte
	for len(stream) > 0 {
		n := int(binary.BigEndian.Uint16(stream))
		wires = append(wires, stream[2:2+n])
		stream = stream[2+n:]
	}
	return wires
}

func readWires(wires [][]byte, key dns.TSIGKey, requestMAC []byte) (*Result, error) {
	var stream bytes.Buffer
	for _, w := range wires {
		_ = binary.Write(&stream, binary.BigEndian, uint16(len(w)))
		stream.Write(w)
	}
	return readStream(&ixfrMemoryConn{bytes.NewReader(stream.Bytes())}, ClientConfig{Zone: "example.com", TSIGKey: key}, 77, dns.TypeAXFR, 0, requestMAC)
}

// TestRFC8945_UnsignedIntermediatesAuthenticated pins that an unsigned
// intermediate message is covered by the next signed one (RFC 8945 §5.3.1).
// The client used to carry the prior MAC across it without digesting it, so
// an on-path attacker could rewrite, drop or reorder unsigned messages, and a
// primary that signs every Nth message per the RFC failed verification.
func TestRFC8945_UnsignedIntermediatesAuthenticated(t *testing.T) {
	key := xfrTestKey()
	query, err := buildQuery(77, "example.com", dns.TypeAXFR, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, requestMAC, err := dns.TSIGSign(query, key, time.Now(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	soa := testSOA(t, "example.com", 7)
	parts := [][]dns.ResourceRecord{{soa, testA("example.com", 1)}, {testA("example.com", 2)}, {testA("example.com", 3)}, {testA("example.com", 4), soa}}
	wires := tsigStreamWires(t, key, requestMAC, parts, []bool{true, false, false, true})

	if _, err := readWires(wires, key, requestMAC); err != nil {
		t.Fatalf("unsigned intermediates covered by the next signature must be accepted: %v", err)
	}

	forged := (&dns.Message{
		Header:  dns.Header{ID: 77, Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()},
		Answers: []dns.ResourceRecord{testA("example.com", 66)},
	})
	packed, err := dns.Pack(forged, make([]byte, 512))
	if err != nil {
		t.Fatal(err)
	}
	for name, stream := range map[string][][]byte{
		"rewritten": {wires[0], wires[1], append([]byte(nil), packed...), wires[3]},
		"dropped":   {wires[0], wires[1], wires[3]},
		"reordered": {wires[0], wires[2], wires[1], wires[3]},
	} {
		if _, err := readWires(stream, key, requestMAC); !errors.Is(err, dns.ErrTSIGBadSig) {
			t.Fatalf("%s unsigned message: err=%v, want %v", name, err, dns.ErrTSIGBadSig)
		}
	}
}

// TestRFC8945_UnsignedRunLimit pins the §5.3.1 requirement of a TSIG on at
// least every 100th message, which also bounds how many unsigned messages
// the client holds for the next digest.
func TestRFC8945_UnsignedRunLimit(t *testing.T) {
	key := xfrTestKey()
	query, err := buildQuery(77, "example.com", dns.TypeAXFR, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, requestMAC, err := dns.TSIGSign(query, key, time.Now(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	soa := testSOA(t, "example.com", 7)
	run := func(unsigned int) error {
		parts := [][]dns.ResourceRecord{{soa}}
		signed := []bool{true}
		for i := 0; i < unsigned; i++ {
			parts = append(parts, []dns.ResourceRecord{testA("example.com", byte(i))})
			signed = append(signed, false)
		}
		parts = append(parts, []dns.ResourceRecord{soa})
		signed = append(signed, true)
		_, err := readWires(tsigStreamWires(t, key, requestMAC, parts, signed), key, requestMAC)
		return err
	}
	if err := run(maxUnsignedXFRMessages); err != nil {
		t.Fatalf("%d unsigned messages: %v", maxUnsignedXFRMessages, err)
	}
	if err := run(maxUnsignedXFRMessages + 1); !errors.Is(err, dns.ErrTSIGNotSigned) {
		t.Fatalf("%d unsigned messages: err=%v, want %v", maxUnsignedXFRMessages+1, err, dns.ErrTSIGNotSigned)
	}
}
