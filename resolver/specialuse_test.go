package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestSpecialUseResponse(t *testing.T) {
	cases := []struct {
		name    string
		qname   string
		wantNX  bool
		wantNil bool
	}{
		// RFC 7686 — .onion is the high-stakes case (Tor de-anon)
		{"bare .onion", "facebookcorewwwi.onion", true, false},
		{"sub .onion", "www.facebookcorewwwi.onion", true, false},
		{"just onion label", "onion", true, false},

		// RFC 6761 §6.4 — .invalid
		{"bare invalid", "anything.invalid", true, false},
		{"deep invalid", "a.b.c.invalid", true, false},

		// RFC 6761 §6.2 — .test
		{"bare test", "foo.test", true, false},

		// RFC 6761 §6.5 — bare .example TLD: NX
		{"bare example TLD", "foo.example", true, false},

		// RFC 6761 §6.5 — example.{com,net,org}: real auth, fall through
		{"example.com", "example.com", false, true},
		{"www.example.com", "www.example.com", false, true},
		{"example.net", "example.net", false, true},
		{"sub.example.org", "sub.example.org", false, true},

		// RFC 6762 / 6761 §6.3 — .local mDNS
		{".local sub", "myprinter.local", true, false},

		// RFC 8375 — home.arpa
		{"home.arpa", "home.arpa", true, false},
		{"router.home.arpa", "router.home.arpa", true, false},

		// Negative cases — public DNS names must NOT match
		{"google.com", "google.com", false, true},
		{"in-addr.arpa real PTR", "1.1.1.1.in-addr.arpa", false, true},
		{"empty", "", false, true},
		{"localhost (handled elsewhere)", "localhost", false, true},

		// Edge: name containing "onion" but not as a label
		{"label-suffix not onion", "myonion.example.com", false, true},
		{"onion-prefix in label", "onion-shop.test", true, false}, // matches .test
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := specialUseResponse(c.qname, dns.TypeA, dns.ClassIN)
			if c.wantNil && r != nil {
				t.Errorf("%q: expected nil, got %+v", c.qname, r)
			}
			if c.wantNX && (r == nil || r.RCODE != dns.RCodeNXDomain) {
				t.Errorf("%q: expected NXDOMAIN, got %+v", c.qname, r)
			}
		})
	}
}

func TestNSHasCNAMERedirect(t *testing.T) {
	cases := []struct {
		name    string
		ns      string
		answers []dns.ResourceRecord
		want    bool
	}{
		{
			name: "clean A response",
			ns:   "ns1.example.com",
			answers: []dns.ResourceRecord{
				{Name: "ns1.example.com", Type: dns.TypeA, RData: []byte{1, 2, 3, 4}},
			},
			want: false,
		},
		{
			name: "CNAME redirect attack (RFC 2181 §10.3)",
			ns:   "ns1.example.com",
			answers: []dns.ResourceRecord{
				{Name: "ns1.example.com", Type: dns.TypeCNAME, RData: nil},
				{Name: "evil.attacker", Type: dns.TypeA, RData: []byte{6, 6, 6, 6}},
			},
			want: true,
		},
		{
			name: "CNAME for different owner — not the NS itself",
			ns:   "ns1.example.com",
			answers: []dns.ResourceRecord{
				{Name: "other.example.com", Type: dns.TypeCNAME, RData: nil},
				{Name: "ns1.example.com", Type: dns.TypeA, RData: []byte{1, 2, 3, 4}},
			},
			want: false,
		},
		{
			name:    "empty answers",
			ns:      "ns1.example.com",
			answers: nil,
			want:    false,
		},
		{
			name: "trailing dot tolerance",
			ns:   "ns1.example.com.",
			answers: []dns.ResourceRecord{
				{Name: "ns1.example.com.", Type: dns.TypeCNAME, RData: nil},
			},
			want: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nsHasCNAMERedirect(c.ns, c.answers)
			if got != c.want {
				t.Errorf("ns=%q want=%v got=%v", c.ns, c.want, got)
			}
		})
	}
}
