package dns

import "testing"

// Fuzz harness — RFC 8914 / RFC 7873 / RFC 4034 / RFC 5155 parsers
// all live downstream of unauthenticated client/upstream wire bytes
// and are a natural target for malformed-input attacks. This file
// hosts the `go test -fuzz=...` entry points so coverage can be
// extended automatically by CI or by an operator running the corpus
// against newly-discovered crashers.
//
// Invariants every parser MUST hold under any input (well-formed or
// adversarial):
//
//   1. No panic — wire-format parsers MUST translate every malformed
//      input into a typed error or nil-return, never into a Go panic.
//      A panic in the parser becomes a SERVFAIL pipeline crash at
//      best and a goroutine-leaking process restart at worst.
//   2. No infinite loops — bounded by the input length. Pathological
//      inputs (compression pointer cycles, oversized lengths) must
//      either error or short-circuit, not spin.
//   3. No out-of-bounds reads — every length field must be validated
//      against the slice length before indexing.
//
// Each fuzz target seeds a few well-known wire layouts to give the
// fuzzer a starting point. The bound on go-fuzz's mutation walks
// from those seeds outward by random byte flips, insertions, and
// removals; the property under test is the "no panic" invariant
// captured by the test's lack of recover.

// FuzzParseCookieOption pins the RFC 7873 §5.2 cookie option parser.
// The parser sits between the wire and every downstream cookie
// consumer (handler validation, resolver upstream cache) and MUST
// gracefully reject any byte sequence — empty, truncated, oversized,
// or containing a server cookie larger than the 32-byte RFC 9018 cap.
func FuzzParseCookieOption(f *testing.F) {
	// Seed corpus: the canonical well-formed layouts the parser
	// tries hardest to recognise.
	f.Add([]byte{})                                                     // empty
	f.Add([]byte{0x01, 0x02})                                           // way too short
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})                               // 8-byte client only (bootstrap)
	f.Add(append([]byte{1, 2, 3, 4, 5, 6, 7, 8}, make([]byte, 8)...))   // 8+8 RFC 7873 legacy
	f.Add(append([]byte{1, 2, 3, 4, 5, 6, 7, 8}, make([]byte, 16)...))  // 8+16 RFC 9018 current
	f.Add(append([]byte{1, 2, 3, 4, 5, 6, 7, 8}, make([]byte, 32)...))  // 8+32 RFC 9018 max server
	f.Add(append([]byte{1, 2, 3, 4, 5, 6, 7, 8}, make([]byte, 200)...)) // pathological: oversized server

	f.Fuzz(func(t *testing.T, data []byte) {
		client, server := ParseCookieOption(data)
		// Invariant 1: under-8 input ALWAYS returns (nil, nil) (per
		// the RFC 7873 §5.2.1 wire spec — the 8-byte client cookie
		// is mandatory).
		if len(data) < 8 {
			if client != nil || server != nil {
				t.Errorf("under-8 input %d bytes returned non-nil: client=%v server=%v — under-length client cookie must be reported as missing", len(data), client, server)
			}
			return
		}
		// Invariant 2: when client is returned, it MUST be exactly
		// 8 bytes. A regression that returned a partial client
		// cookie would silently slip past every downstream
		// `len(clientCookie) == 8` gate with misaligned hash inputs.
		if client != nil && len(client) != 8 {
			t.Errorf("client cookie length = %d, must be exactly 8 (RFC 7873 §5.2.1)", len(client))
		}
		// Invariant 3: the parser's documented contract is "return
		// the wire bytes verbatim; length policy is the caller's".
		// RFC 9018 §4 enforcement happens downstream (server.go
		// handler.go validates len == 16 before trusting). Pin
		// only the structural property: when server is non-nil it
		// equals data[8:] in length.
		if server != nil && len(server) != len(data)-8 {
			t.Errorf("server cookie length = %d, want len(data)-8 = %d (parser must return remainder verbatim, callers apply RFC 9018 §4 policy)", len(server), len(data)-8)
		}
	})
}

// FuzzUnpackMessage pins the top-level DNS wire-format parser against
// every shape of corrupted byte input. A panic here at runtime would
// translate into a SERVFAIL pipeline crash on a single malformed
// upstream response; a goroutine-leaking variant could exhaust file
// descriptors. The fuzz target asserts only "no panic" — semantic
// correctness is covered by the dedicated parser tests.
func FuzzUnpackMessage(f *testing.F) {
	// Seed with a few canonical well-formed messages and a couple
	// of intentionally-malformed shapes so the fuzzer has both
	// "near-valid" and "garbage" starting points.
	f.Add([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01}) // www.example.com A IN
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // minimal empty
	f.Add(make([]byte, 12))                                                                // header-only zeros
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})  // all-ones header

	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariant: no panic regardless of input.
		_, _ = Unpack(data)
	})
}

// FuzzParseDNSKEY pins the DNSKEY RDATA parser. A panic on a
// malformed DNSKEY would crash the validator path on a poisoned
// upstream response; this fuzzer drives the parser past every
// length-field boundary.
func FuzzParseDNSKEY(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})           // minimum: 4-byte fixed header, no key bytes
	f.Add([]byte{0x01, 0x00, 3, 8})     // flags=256, proto=3, alg=8, no key bytes
	f.Add(append([]byte{0x01, 0x00, 3, 8}, make([]byte, 64)...))  // with key bytes
	f.Add(append([]byte{0x01, 0x00, 3, 8}, make([]byte, 4096)...)) // pathological huge key

	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := ParseDNSKEY(data)
		if err != nil {
			return // expected for short / malformed input
		}
		// Sanity invariants on the returned struct.
		if k == nil {
			t.Errorf("ParseDNSKEY returned nil record without error")
			return
		}
		// PublicKey length MUST equal RDATA length minus the 4-byte
		// fixed header. A regression that mis-sliced would either
		// shorten the key (validation later fails inscrutably) or
		// run past the end (panic on a real crypto verify call).
		expected := len(data) - 4
		if expected < 0 {
			expected = 0
		}
		if len(k.PublicKey) != expected {
			t.Errorf("PublicKey length = %d, want %d (input len %d - 4 fixed header)", len(k.PublicKey), expected, len(data))
		}
	})
}

// FuzzParseDS mirrors FuzzParseDNSKEY for DS RDATA. Same panic-
// safety invariant; same length-field arithmetic gate.
func FuzzParseDS(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})             // minimum
	f.Add([]byte{0x12, 0x34, 8, 2})       // key tag=0x1234, alg=8, digest type=SHA256, no digest
	f.Add(append([]byte{0x12, 0x34, 8, 2}, make([]byte, 32)...)) // with SHA-256 digest

	f.Fuzz(func(t *testing.T, data []byte) {
		ds, err := ParseDS(data)
		if err != nil {
			return
		}
		if ds == nil {
			t.Errorf("ParseDS returned nil record without error")
			return
		}
		expected := len(data) - 4
		if expected < 0 {
			expected = 0
		}
		if len(ds.Digest) != expected {
			t.Errorf("Digest length = %d, want %d", len(ds.Digest), expected)
		}
	})
}
