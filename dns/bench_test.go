package dns

import "testing"

// benchResponse is a realistic DNS response: google.com A with 1 answer.
// Built once and reused across benchmarks.
var benchResponse []byte

// benchMessage is the pre-parsed Message struct for Pack benchmarks.
var benchMessage *Message

func init() {
	msg := &Message{
		Header: Header{
			ID:    0x1234,
			Flags: NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(),
		},
		Questions: []Question{{
			Name:  "google.com",
			Type:  TypeA,
			Class: ClassIN,
		}},
		Answers: []ResourceRecord{{
			Name:     "google.com",
			Type:     TypeA,
			Class:    ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{142, 250, 80, 46},
		}},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		panic("init: failed to pack bench response: " + err.Error())
	}
	benchResponse = make([]byte, len(packed))
	copy(benchResponse, packed)

	// Re-unpack so benchMessage has realistic field values
	benchMessage, err = Unpack(benchResponse)
	if err != nil {
		panic("init: failed to unpack bench response: " + err.Error())
	}
}

func BenchmarkUnpack(b *testing.B) {
	data := make([]byte, len(benchResponse))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		copy(data, benchResponse)
		_, _ = Unpack(data)
	}
}

func BenchmarkPack(b *testing.B) {
	buf := make([]byte, 4096)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Pack(benchMessage, buf)
	}
}

// benchNameWire is "google.com" with a compression pointer, embedded in a
// minimal message so the pointer is valid.
var benchNameWire = func() []byte {
	// Build a buffer that has google.com at offset 0, then a pointer at offset 12.
	buf := []byte{
		0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0xC0, 0x00, // pointer to offset 0
	}
	return buf
}()

func BenchmarkDecodeName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = DecodeName(benchNameWire, 12)
	}
}

func BenchmarkEncodeName(b *testing.B) {
	buf := make([]byte, 256)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := newWireWriter(buf)
		_ = EncodeName(w, "google.com")
	}
}
