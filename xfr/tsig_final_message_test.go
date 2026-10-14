package xfr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// signedAXFRStream renders a response stream for an AXFR of example.com,
// TSIG-signing the messages marked in signed and chaining their MACs. Each
// signature covers the unsigned messages before it (RFC 8945 §5.3.1).
func signedAXFRStream(t *testing.T, key dns.TSIGKey, requestMAC []byte, parts [][]dns.ResourceRecord, signed []bool) []byte {
	t.Helper()
	var stream bytes.Buffer
	prior := requestMAC
	var unsigned [][]byte
	for i, part := range parts {
		msg := &dns.Message{Header: dns.Header{ID: 77, Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()}, Answers: part}
		if i == 0 {
			msg.Questions = []dns.Question{{Name: "example.com", Type: dns.TypeAXFR, Class: dns.ClassIN}}
		}
		packed, err := dns.Pack(msg, make([]byte, 8192))
		if err != nil {
			t.Fatal(err)
		}
		wire := append([]byte(nil), packed...)
		if signed[i] {
			var mac []byte
			if i == 0 {
				wire, mac, err = dns.TSIGSign(wire, key, time.Now(), 0, prior)
			} else {
				wire, mac, err = dns.TSIGSignStream(wire, key, time.Now(), 0, prior, unsigned...)
			}
			if err != nil {
				t.Fatal(err)
			}
			prior = mac
			unsigned = nil
		} else {
			unsigned = append(unsigned, wire)
		}
		if err := binary.Write(&stream, binary.BigEndian, uint16(len(wire))); err != nil {
			t.Fatal(err)
		}
		stream.Write(wire)
	}
	return stream.Bytes()
}

// TestRFC8945_UnsignedFinalMessageRejected pins RFC 8945 §5.3.1: a primary
// may leave intermediate messages of a transfer unsigned, but the final one
// must be signed, or nothing after the last signed message is authenticated.
// The client used to accept an unsigned tail, so an on-path attacker could
// strip the TSIG from the rest of the stream and rewrite the zone.
func TestRFC8945_UnsignedFinalMessageRejected(t *testing.T) {
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
	parts := [][]dns.ResourceRecord{{soa, testA("example.com", 1)}, {testA("example.com", 2)}, {testA("example.com", 66), soa}}
	run := func(signed []bool) error {
		wire := signedAXFRStream(t, key, requestMAC, parts, signed)
		_, err := readStream(&ixfrMemoryConn{bytes.NewReader(wire)}, ClientConfig{Zone: "example.com", TSIGKey: key}, 77, dns.TypeAXFR, 0, requestMAC)
		return err
	}

	if err := run([]bool{true, false, true}); err != nil {
		t.Fatalf("unsigned intermediate with a signed final message must be accepted: %v", err)
	}
	if err := run([]bool{true, true, false}); !errors.Is(err, dns.ErrTSIGNotSigned) {
		t.Fatalf("unsigned final message: err=%v, want %v", err, dns.ErrTSIGNotSigned)
	}
}
