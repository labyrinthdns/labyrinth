package dns

import "testing"

// seedGoogleComQuery is a valid DNS query for google.com A (ID=0xAAAA, RD=1, QDCOUNT=1).
var seedGoogleComQuery = []byte{
	// Header: ID=0xAAAA, Flags=0x0100 (RD=1), QD=1, AN=0, NS=0, AR=0
	0xAA, 0xAA, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Question: google.com A IN
	0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
	0x00, 0x01, // Type A
	0x00, 0x01, // Class IN
}

// seedGoogleComResponse is a valid DNS response for google.com A with one answer.
var seedGoogleComResponse = []byte{
	// Header: ID=0xAAAA, Flags=0x8180 (QR=1, RD=1, RA=1), QD=1, AN=1, NS=0, AR=0
	0xAA, 0xAA, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	// Question: google.com A IN
	0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
	0x00, 0x01, // Type A
	0x00, 0x01, // Class IN
	// Answer: google.com A IN TTL=300 RDATA=142.250.80.46
	0xC0, 0x0C, // name pointer to offset 12
	0x00, 0x01, // Type A
	0x00, 0x01, // Class IN
	0x00, 0x00, 0x01, 0x2C, // TTL 300
	0x00, 0x04, // RDLength 4
	0x8E, 0xFA, 0x50, 0x2E, // 142.250.80.46
}

func FuzzUnpack(f *testing.F) {
	// Seed with valid messages
	f.Add(seedGoogleComQuery)
	f.Add(seedGoogleComResponse)
	// Seed with minimal valid header (no questions/answers)
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// Seed with truncated data
	f.Add([]byte{0x00, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic regardless of input; errors are fine.
		Unpack(data)
	})
}

func FuzzDecodeName(f *testing.F) {
	// Seed: "google.com" in wire format
	f.Add([]byte{0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}, 0)
	// Seed: root name
	f.Add([]byte{0x00}, 0)
	// Seed: compressed pointer (requires a prior name in the buffer)
	f.Add(seedGoogleComResponse, 28) // answer name at offset 28 is a pointer to offset 12
	// Seed: empty input
	f.Add([]byte{}, 0)

	f.Fuzz(func(t *testing.T, data []byte, offset int) {
		if offset < 0 {
			return
		}
		// Must not panic regardless of input; errors are fine.
		DecodeName(data, offset)
	})
}

func FuzzRoundTrip(f *testing.F) {
	f.Add(seedGoogleComQuery)
	f.Add(seedGoogleComResponse)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to unpack arbitrary bytes as a DNS message.
		msg, err := Unpack(data)
		if err != nil {
			return
		}

		// Pack the successfully unpacked message back to wire format.
		buf := make([]byte, 4096)
		packed, err := Pack(msg, buf)
		if err != nil {
			return
		}

		// Unpack again; must not panic.
		Unpack(packed)
	})
}
