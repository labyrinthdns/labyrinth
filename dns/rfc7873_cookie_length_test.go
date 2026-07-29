package dns

import (
	"bytes"
	"testing"
)

// TestParseCookieOption_LengthSemantics pins RFC 7873 §5.2.1 + RFC
// 9018 §4: the DNS Cookie option's wire layout is
//
//   client_cookie (8 bytes, mandatory)  ||  server_cookie (8..32 bytes, optional)
//
// The 8-byte client cookie is REQUIRED by §5.2.1 — anything shorter
// is malformed. The server cookie is 0 bytes (client-only / bootstrap
// query) or 8..32 bytes (RFC 9018 §4).
//
// `ParseCookieOption` is the parser sitting between the wire and
// every downstream consumer (handler cookie validation, resolver
// upstream-cookie cache). Its return contract:
//
//   - `len(data) < 8`   → (nil, nil) — the option is malformed
//   - `len(data) == 8`  → (8-byte client, nil) — client-only
//   - `len(data) > 8`   → (8-byte client, remainder) — full pair
//
// Why this matters: every cookie-validating call site
// (handler.go:649) gates on `len(clientCookie) == 8`. If the parser
// returned a partial client cookie (e.g. 7 bytes) instead of nil
// for under-length inputs, the gate condition would pass with a
// short cookie and downstream hash inputs would be misaligned —
// silently failing validation in a way that looks like the
// expected security guard. The pin keeps the parser's empty-on-error
// behaviour explicit.
func TestParseCookieOption_LengthSemantics(t *testing.T) {
	cases := []struct {
		name       string
		data       []byte
		wantClient []byte
		wantServer []byte
	}{
		{
			name:       "empty option — both nil",
			data:       nil,
			wantClient: nil, wantServer: nil,
		},
		{
			name:       "1 byte — too short, both nil",
			data:       []byte{0x01},
			wantClient: nil, wantServer: nil,
		},
		{
			name:       "7 bytes (one short of 8) — both nil",
			data:       []byte{1, 2, 3, 4, 5, 6, 7},
			wantClient: nil, wantServer: nil,
		},
		{
			name:       "exactly 8 bytes — client-only bootstrap",
			data:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
			wantClient: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			wantServer: nil,
		},
		{
			name: "16 bytes (8 client + 8 server, RFC 7873 legacy)",
			data: []byte{
				0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
				0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			},
			wantClient: []byte{0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7},
			wantServer: []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7},
		},
		{
			name: "24 bytes (8 client + 16 server, RFC 9018 current)",
			data: []byte{
				0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			},
			wantClient: []byte{0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7},
			wantServer: []byte{
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotClient, gotServer := ParseCookieOption(c.data)
			if !bytes.Equal(gotClient, c.wantClient) {
				t.Errorf("clientCookie = %v, want %v", gotClient, c.wantClient)
			}
			if !bytes.Equal(gotServer, c.wantServer) {
				t.Errorf("serverCookie = %v, want %v", gotServer, c.wantServer)
			}
		})
	}
}
