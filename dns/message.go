package dns

// Header represents the fixed 12-byte DNS message header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question represents a DNS question entry.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ResourceRecord represents a DNS resource record.
type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte

	// RDataOffset is the offset of this RR's RDATA in the original wire message.
	// Used by type-specific parsers that need the full message for name decompression.
	RDataOffset int
}

// Message represents a complete DNS message.
type Message struct {
	Header     Header
	Questions  []Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
	EDNS0      *EDNS0
	// Raw holds the original wire-format bytes (needed for RDATA decompression)
	Raw []byte
}
