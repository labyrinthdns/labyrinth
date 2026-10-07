package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestPackRDataLengthLimits(t *testing.T) {
	for _, size := range []int{0, 1, 65534, 65535, 65536} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{0xA5}, size)
			w := newWireWriter(make([]byte, 2+size))
			err := packRData(w, ResourceRecord{Type: 65280, RData: data})
			if size > 65535 {
				if err != errInvalidMessage {
					t.Fatalf("oversize RDATA error=%v, want invalid message", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := int(binary.BigEndian.Uint16(w.bytes()[:2])); got != size || !bytes.Equal(w.bytes()[2:], data) {
				t.Fatalf("RDLENGTH=%d, want %d and intact data", got, size)
			}
		})
	}
	// Keep this whole message within 65535 bytes, including its 23-byte framing.
	for _, size := range []int{0, 1, 65512, 65536} {
		t.Run(fmt.Sprintf("message/%d", size), func(t *testing.T) {
			data := bytes.Repeat([]byte{0xA5}, size)
			msg := &Message{Answers: []ResourceRecord{{Type: 65280, Class: ClassIN, RData: data}}}
			packed, err := Pack(msg, make([]byte, 23+size))
			if size > 65535 {
				if err != errInvalidMessage || packed != nil {
					t.Fatalf("oversize message error=%v bytes=%d", err, len(packed))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Unpack(packed)
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded.Answers) != 1 || !bytes.Equal(decoded.Answers[0].RData, data) {
				t.Fatal("RDATA lost during message roundtrip")
			}
		})
	}
}
