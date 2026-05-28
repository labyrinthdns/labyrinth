package dnssec

import (
	"bytes"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestCanonicalRData_LowercasesEmbeddedNames pins RFC 4034 §6.2 item
// 3: for RR types whose RDATA contains embedded domain names, the
// names MUST be lowercased before forming the canonical RRset wire
// for RRSIG verification. The list (RFC 4034 §6.2 + RFC 6840 §5.1
// trimming to the modern set):
//
//   - CNAME, NS, PTR, DNAME — single embedded name
//   - MX — preference (2B) then name
//   - SRV — priority/weight/port (6B) then target
//   - SOA — MNAME then RNAME then 20 bytes of timers
//   - RRSIG — fixed 18B header + signer name + signature
//
// Without this normalisation, auth servers that emit uppercase in
// wire responses (or upstreams that don't normalize at the on-wire
// stage) would turn every CNAME hop into a false Bogus — the signer
// signed the lowercase form, but the verifier sees mixed case and
// computes a different signed-data hash.
//
// We pin two invariants for each type:
//   1. The embedded name is byte-identical-after-tolower in the
//      canonical output.
//   2. The total RDATA length is unchanged (lowercasing preserves
//      length because ASCII A-Z and a-z occupy the same byte count).
//
// We also pin a negative: a type NOT on the list (e.g. TypeA) gets
// its RDATA returned unchanged.
func TestCanonicalRData_LowercasesEmbeddedNames(t *testing.T) {
	// Encode "Example.COM" → [7] "Example" [3] "COM" [0] = 13 bytes.
	uppercaseName := []byte{
		7, 'E', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'C', 'O', 'M',
		0,
	}
	expectedLower := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}

	t.Run("CNAME — name lowercased", func(t *testing.T) {
		got := canonicalRData(uppercaseName, dns.TypeCNAME)
		if !bytes.Equal(got, expectedLower) {
			t.Errorf("CNAME canonical RDATA = %x, want %x — RFC 4034 §6.2 item 3 violation: uppercase RDATA leaks into signed-data input, every cached uppercase CNAME would Bogus", got, expectedLower)
		}
	})

	t.Run("NS — name lowercased", func(t *testing.T) {
		got := canonicalRData(uppercaseName, dns.TypeNS)
		if !bytes.Equal(got, expectedLower) {
			t.Errorf("NS canonical RDATA mismatch")
		}
	})

	t.Run("MX — preference preserved, name lowercased", func(t *testing.T) {
		mxRData := append([]byte{0x00, 0x0A}, uppercaseName...) // pref=10
		expected := append([]byte{0x00, 0x0A}, expectedLower...)
		got := canonicalRData(mxRData, dns.TypeMX)
		if !bytes.Equal(got, expected) {
			t.Errorf("MX canonical RDATA = %x, want %x — preference bytes must be preserved, embedded name must be lowercased", got, expected)
		}
	})

	t.Run("RRSIG — 18-byte fixed header preserved, signer lowercased", func(t *testing.T) {
		fixedHeader := make([]byte, 18)
		// Put non-zero bytes in the header to verify they're untouched
		// (a regression that lowercased the whole RDATA would corrupt
		// the signed binary fields).
		for i := range fixedHeader {
			fixedHeader[i] = 0x55
		}
		signature := []byte{0xAA, 0xBB, 0xCC, 0xDD}
		rrsigRData := append([]byte{}, fixedHeader...)
		rrsigRData = append(rrsigRData, uppercaseName...)
		rrsigRData = append(rrsigRData, signature...)

		got := canonicalRData(rrsigRData, dns.TypeRRSIG)

		// First 18 bytes must be untouched.
		if !bytes.Equal(got[:18], fixedHeader) {
			t.Errorf("RRSIG header corrupted by canonicalRData — must only touch the signer name field starting at offset 18")
		}
		// Signer must be lowercased.
		if !bytes.Equal(got[18:18+len(uppercaseName)], expectedLower) {
			t.Errorf("RRSIG signer name not lowercased")
		}
		// Signature must be preserved.
		if !bytes.Equal(got[18+len(uppercaseName):], signature) {
			t.Errorf("RRSIG signature bytes after signer name corrupted")
		}
		// Total length must be preserved.
		if len(got) != len(rrsigRData) {
			t.Errorf("length changed: got %d, want %d", len(got), len(rrsigRData))
		}
	})

	t.Run("type-A — RDATA passed through unchanged", func(t *testing.T) {
		// TypeA RDATA is 4 raw IPv4 bytes; the bytes 'A', 'B', 'C', 'D'
		// (which happen to be uppercase ASCII letters) MUST NOT be
		// lowercased — the bytes are NOT name labels, they're an IP.
		aRData := []byte{'A', 'B', 'C', 'D'} // = 65.66.67.68 if interpreted as IP
		got := canonicalRData(aRData, dns.TypeA)
		if !bytes.Equal(got, aRData) {
			t.Errorf("TypeA RDATA was modified — RFC 4034 §6.2 item 3 only applies to a specific list of name-bearing types; A is NOT one of them; lowercasing here would mangle real IP byte values")
		}
	})
}
