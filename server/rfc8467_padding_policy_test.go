package server

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// buildQueryWithPadding constructs a wire-format query that carries an
// EDNS PADDING option. The data is zero-length per RFC 8467 §4.3 —
// that's the canonical client-side "please pad my responses" signal.
func buildQueryWithPadding(t *testing.T) []byte {
	t.Helper()
	q := &dns.Message{
		Header:    dns.Header{ID: 0x1234, Flags: 0x0100, QDCount: 1, ARCount: 1},
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{
				{Code: dns.EDNSOptionCodePadding, Data: nil},
			}),
		},
	}
	raw, err := dns.Pack(q, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return raw
}

// buildResponseUnpadded constructs a small wire-format response that
// is NOT a multiple of PaddingBlockSize, so we can tell whether the
// padding policy actually ran.
func buildResponseUnpadded(t *testing.T) []byte {
	t.Helper()
	r := &dns.Message{
		Header: dns.Header{ID: 0x1234, Flags: 0x8180, QDCount: 1, ANCount: 1, ARCount: 1},
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Answers: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300,
			RData: []byte{93, 184, 216, 34}, RDLength: 4,
		}},
		Additional: []dns.ResourceRecord{dns.BuildOPT(1232, false)},
	}
	raw, err := dns.Pack(r, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	return raw
}

// TestApplyTCPTransportPolicies_PaddingGate pins RFC 8467 §6:
//
//   "The PADDING option MUST NOT be used on a transport where the
//    response can already be observed in cleartext."
//
// Concretely: a client that sends a PADDING option over plaintext TCP
// (port 53/tcp) MUST NOT receive a padded response. Pad-on-plaintext
// is pure overhead — a passive observer already sees the bytes — and
// signalling that we honour padding on an unencrypted channel teaches
// downstream operator tooling to misclassify the channel privacy.
//
// Truth table:
//
//   encrypted = true,  padding signalled  → pad (DoT / DoH path)
//   encrypted = true,  no padding option  → no pad (client opt-in)
//   encrypted = false, padding signalled  → no pad (RFC 8467 §6 hard rule)
//   encrypted = false, no padding option  → no pad
func TestApplyTCPTransportPolicies_PaddingGate(t *testing.T) {
	queryPadded := buildQueryWithPadding(t)
	queryNoPad := func() []byte {
		t.Helper()
		q := &dns.Message{
			Header:    dns.Header{ID: 0x5678, Flags: 0x0100, QDCount: 1, ARCount: 1},
			Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
			Additional: []dns.ResourceRecord{dns.BuildOPT(1232, false)},
		}
		raw, err := dns.Pack(q, make([]byte, 512))
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		return raw
	}()

	resp := buildResponseUnpadded(t)
	origLen := len(resp)

	cases := []struct {
		name      string
		query     []byte
		encrypted bool
		wantPad   bool
		why       string
	}{
		{
			name:      "DoT/DoH + padding opt → pad",
			query:     queryPadded,
			encrypted: true,
			wantPad:   true,
			why:       "encrypted transport + client opted in; this is the canonical RFC 8467 §4 path",
		},
		{
			name:      "DoT/DoH, no padding opt → no pad",
			query:     queryNoPad,
			encrypted: true,
			wantPad:   false,
			why:       "padding is client-opt-in; an unrequested pad would inflate response size for no benefit",
		},
		{
			name:      "plaintext TCP + padding opt → no pad (RFC 8467 §6)",
			query:     queryPadded,
			encrypted: false,
			wantPad:   false,
			why:       "RFC 8467 §6 hard rule: padding MUST NOT be sent on plaintext transports",
		},
		{
			name:      "plaintext TCP, no padding opt → no pad",
			query:     queryNoPad,
			encrypted: false,
			wantPad:   false,
			why:       "neither encrypted nor opted-in; trivial pass-through",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := applyTCPTransportPolicies(c.query, append([]byte(nil), resp...), 30*time.Second, c.encrypted)
			grew := len(out) > origLen
			if c.wantPad && !grew {
				t.Errorf("expected response to be padded but length unchanged (%d) — gate denied padding when it should have applied: %s", len(out), c.why)
			}
			if !c.wantPad && grew {
				t.Errorf("expected NO padding but length grew %d→%d — gate let padding leak through: %s", origLen, len(out), c.why)
			}
		})
	}
}
