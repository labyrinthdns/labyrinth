package dns

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPackSectionCountLimits(t *testing.T) {
	for _, section := range []string{"questions", "answers", "authority", "additional"} {
		for _, count := range []int{0, 1, 65535, 65536} {
			t.Run(fmt.Sprintf("%s/%d", section, count), func(t *testing.T) {
				msg := &Message{Header: Header{ID: 123}}
				switch section {
				case "questions":
					msg.Questions = make([]Question, count)
				case "answers":
					msg.Answers = make([]ResourceRecord, count)
				case "authority":
					msg.Authority = make([]ResourceRecord, count)
				case "additional":
					msg.Additional = make([]ResourceRecord, count)
				}
				header := msg.Header
				buf := bytes.Repeat([]byte{0xA5}, 256)
				if count == 65535 {
					// The count fits; a short buffer should fail for capacity instead.
					buf = buf[:12]
				}
				packed, err := Pack(msg, buf)
				switch count {
				case 65536:
					if err != errInvalidMessage || packed != nil {
						t.Fatalf("Pack error=%v bytes=%d, want invalid message and nil bytes", err, len(packed))
					}
					if msg.Header != header || !bytes.Equal(buf, bytes.Repeat([]byte{0xA5}, len(buf))) {
						t.Fatal("count rejection changed the header or output buffer")
					}
				case 65535:
					if err != errBufferFull {
						t.Fatalf("representable count: error=%v, want buffer full", err)
					}
				default:
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := Unpack(packed)
					if err != nil {
						t.Fatal(err)
					}
					got := map[string]int{"questions": len(decoded.Questions), "answers": len(decoded.Answers), "authority": len(decoded.Authority), "additional": len(decoded.Additional)}[section]
					if got != count {
						t.Fatalf("roundtrip count=%d, want %d", got, count)
					}
				}
			})
		}
	}
}
