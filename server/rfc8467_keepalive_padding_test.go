package server

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestApplyTCPTransportPoliciesKeepalivePadding(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		pad, keepalive, encrypted bool
	}{
		{"both_encrypted", true, true, true},
		{"padding_only", true, false, true},
		{"keepalive_only", false, true, true},
		{"both_plaintext", true, true, false},
		{"neither", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query, err := dns.Unpack(buildQueryWithPadding(t))
			if err != nil {
				t.Fatal(err)
			}
			var opts []dns.EDNSOption
			if tc.pad {
				opts = append(opts, dns.EDNSOption{Code: dns.EDNSOptionCodePadding})
			}
			if tc.keepalive {
				opts = append(opts, dns.EDNSOption{Code: dns.EDNSOptionCodeTCPKeepalive})
			}
			query.Additional = []dns.ResourceRecord{dns.BuildOPTWithOptions(1232, false, opts)}
			raw, err := dns.Pack(query, make([]byte, 512))
			if err != nil {
				t.Fatal(err)
			}
			got := applyTCPTransportPolicies(raw, buildResponseUnpadded(t), 5*time.Second, tc.encrypted)
			msg, err := dns.Unpack(got)
			if err != nil {
				t.Fatal(err)
			}
			wantPad := tc.pad && tc.encrypted
			if dns.HasPaddingOption(msg.EDNS0) != wantPad {
				t.Fatalf("padding option mismatch: want %v", wantPad)
			}
			if wantPad && len(got)%dns.PaddingBlockSize != 0 {
				t.Fatalf("length %d is not divisible by %d", len(got), dns.PaddingBlockSize)
			}
			if dns.HasTCPKeepaliveOption(msg.EDNS0) != tc.keepalive {
				t.Fatalf("keepalive option mismatch: want %v", tc.keepalive)
			}
			if tc.keepalive {
				for _, opt := range msg.EDNS0.Options {
					if opt.Code == dns.EDNSOptionCodeTCPKeepalive {
						if len(opt.Data) != 2 || binary.BigEndian.Uint16(opt.Data) != 50 {
							t.Fatalf("keepalive data=%v, want 50 units", opt.Data)
						}
					}
				}
			}
		})
	}
}
