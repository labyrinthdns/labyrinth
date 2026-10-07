package security

import "testing"

// A source prefix length that no address can satisfy (ipv4_prefix: 33,
// ipv6_prefix: 200, or a negative length) makes net.CIDRMask return nil.
// ip.Mask(nil) returns nil and nil.String() is the literal "<nil>", so every
// source of that address family keys onto one shared budget and a single
// abusive client silently drops every other client's answers. The prefix must
// stay a real subnet for any length an operator can put in the config file.

func TestRRLSourcePrefixNeverCollapsesToNilKey(t *testing.T) {
	tests := []struct {
		name       string
		ipv4Prefix int
		ipv6Prefix int
		ip         string
		want       string
	}{
		// Past the family width: clamped to the narrowest real prefix,
		// so the key is the single address.
		{"ipv4 past width", 33, 56, "192.0.2.10", "192.0.2.10"},
		{"ipv4 far past width", 200, 56, "192.0.2.10", "192.0.2.10"},
		{"ipv6 past width", 24, 200, "2001:db8::1", "2001:db8::1"},
		// Below zero: clamped to the widest real prefix, the whole family.
		{"ipv4 negative", -1, 56, "192.0.2.10", "0.0.0.0"},
		{"ipv6 negative", 24, -1, "2001:db8::1", "::"},
		// In-range values are untouched.
		{"ipv4 in range", 24, 56, "192.0.2.10", "192.0.2.0"},
		{"ipv4 zero", 0, 56, "192.0.2.10", "0.0.0.0"},
		{"ipv6 in range", 24, 56, "2001:db8:abcd:12::1", "2001:db8:abcd::"},
		{"ipv6 zero", 24, 0, "2001:db8:abcd:12::1", "::"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rrl := NewRRL(5, 2, tc.ipv4Prefix, tc.ipv6Prefix)
			got := rrl.sourcePrefix(tc.ip)
			if got == "<nil>" || got == "" {
				t.Fatalf("sourcePrefix(%q) = %q; an unusable key collapses every %s client onto one budget",
					tc.ip, got, familyOf(tc.ip))
			}
			if got != tc.want {
				t.Errorf("sourcePrefix(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

func familyOf(ip string) string {
	if len(ip) > 0 && ip[len(ip)-1] == '1' && ip[0] == '2' {
		return "IPv6"
	}
	return "IPv4"
}

// slowTestRPS is small enough that a bucket needs hours of wall clock to regain
// one token, so exhaustion and isolation assertions do not depend on how fast
// the test machine is.
const slowTestRPS = 1e-4

func exhaustRRLBucket(t *testing.T, rrl *RRL, ip, qname string) {
	t.Helper()
	if action := rrl.AllowResponse(ip, qname, "NOERROR"); action != RRLAllow {
		t.Fatalf("setup: first response for %s was %v, want RRLAllow", ip, action)
	}
	if action := rrl.AllowResponse(ip, qname, "NOERROR"); action == RRLAllow {
		t.Fatalf("setup: second response for %s was allowed, budget not exhausted", ip)
	}
}

func TestRRLOutOfRangePrefixKeepsClientsIndependent(t *testing.T) {
	const q = "example.com."

	t.Run("ipv4 prefix past width", func(t *testing.T) {
		rrl := NewRRL(slowTestRPS, 0, 33, 56)
		exhaustRRLBucket(t, rrl, "192.0.2.10", q)
		if action := rrl.AllowResponse("198.51.100.77", q, "NOERROR"); action != RRLAllow {
			t.Errorf("client on an unrelated /24 got %v, want RRLAllow; an out-of-range prefix length collapsed every IPv4 client onto one budget", action)
		}
	})

	t.Run("ipv6 prefix past width", func(t *testing.T) {
		rrl := NewRRL(slowTestRPS, 0, 24, 200)
		exhaustRRLBucket(t, rrl, "2001:db8::1", q)
		if action := rrl.AllowResponse("2001:db8:abcd::1", q, "NOERROR"); action != RRLAllow {
			t.Errorf("client on an unrelated /56 got %v, want RRLAllow; an out-of-range prefix length collapsed every IPv6 client onto one budget", action)
		}
	})
}

func TestRRLInRangePrefixStillGroups(t *testing.T) {
	const q = "example.com."

	t.Run("ipv4 /24 groups neighbours", func(t *testing.T) {
		rrl := NewRRL(slowTestRPS, 0, 24, 56)
		exhaustRRLBucket(t, rrl, "192.0.2.10", q)
		if action := rrl.AllowResponse("192.0.2.11", q, "NOERROR"); action == RRLAllow {
			t.Error("neighbour inside the same /24 was allowed; prefix grouping regressed")
		}
	})

	t.Run("ipv4 /24 keeps other networks independent", func(t *testing.T) {
		rrl := NewRRL(slowTestRPS, 0, 24, 56)
		exhaustRRLBucket(t, rrl, "192.0.2.10", q)
		if action := rrl.AllowResponse("198.51.100.77", q, "NOERROR"); action != RRLAllow {
			t.Errorf("client on another /24 got %v, want RRLAllow", action)
		}
	})

	t.Run("ipv6 /56 groups neighbours", func(t *testing.T) {
		rrl := NewRRL(slowTestRPS, 0, 24, 56)
		exhaustRRLBucket(t, rrl, "2001:db8::1", q)
		if action := rrl.AllowResponse("2001:db8::2", q, "NOERROR"); action == RRLAllow {
			t.Error("neighbour inside the same /56 was allowed; prefix grouping regressed")
		}
	})

	t.Run("negative length groups the whole family like an explicit /0", func(t *testing.T) {
		rrl := NewRRL(slowTestRPS, 0, -1, -1)
		exhaustRRLBucket(t, rrl, "192.0.2.10", q)
		if action := rrl.AllowResponse("198.51.100.77", q, "NOERROR"); action == RRLAllow {
			t.Error("negative prefix length should behave like /0 and group every IPv4 client")
		}
		exhaustRRLBucket(t, rrl, "2001:db8::1", q)
		if action := rrl.AllowResponse("2001:db8:abcd::1", q, "NOERROR"); action == RRLAllow {
			t.Error("negative prefix length should behave like /0 and group every IPv6 client")
		}
	})
}
