package security

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestFilterPrivateAddresses_AAAABadRData covers the branch in
// isPrivateAddressRecord where an AAAA record has wrong-length RDATA
// (not 16 bytes). It should pass through the filter (not be treated
// as private).
func TestFilterPrivateAddresses_AAAABadRData(t *testing.T) {
	answers := []dns.ResourceRecord{
		{
			Name: "test.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{0x20, 0x01, 0x0d, 0xb8},
		},
	}
	filtered := FilterPrivateAddresses(answers)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 record (bad AAAA RDATA should pass through), got %d", len(filtered))
	}
}
