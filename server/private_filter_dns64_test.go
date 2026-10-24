package server

import (
	"net"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// TestBuildResponse_PrivateFilterJudgesDNS64ByEmbeddedIPv4: with the private
// filter and DNS64 both enabled, a synthesised AAAA is judged by the IPv4 it
// embeds — a public IPv4 behind the reserved well-known prefix survives, and a
// private IPv4 behind a globally routable network-specific prefix is stripped.
func TestBuildResponse_PrivateFilterJudgesDNS64ByEmbeddedIPv4(t *testing.T) {
	for _, tc := range []struct {
		prefix, ipv4 string
		want         int
	}{
		{"64:ff9b::/96", "8.8.8.8", 1},
		{"64:ff9b::/96", "192.168.1.1", 0},
		{"2a00:1450:64::/96", "10.0.0.1", 0},
		{"2a00:1450:64::/96", "8.8.8.8", 1},
	} {
		m := metrics.NewMetrics()
		c := cache.NewCache(1000, 5, 86400, 3600, m)
		_, p, _ := net.ParseCIDR(tc.prefix)
		res := resolver.NewResolver(c, resolver.ResolverConfig{MaxDepth: 2, MaxCNAMEDepth: 2, DNS64Enabled: true, DNS64Prefix: *p}, m, discardLogger())
		h := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
		h.SetPrivateFilter(true)

		q := &dns.Message{Header: dns.Header{ID: 1, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
			Questions: []dns.Question{{Name: "v6only.example", Type: dns.TypeAAAA, Class: dns.ClassIN}}}
		result := &resolver.ResolveResult{RCODE: dns.RCodeNoError, Synthesized: true, Answers: []dns.ResourceRecord{{
			Name: "v6only.example", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 300, RDLength: 16,
			RData: resolver.SynthesizeAAAA(net.ParseIP(tc.ipv4), *p),
		}}}
		raw, err := h.buildResponse(q, result)
		if err != nil {
			t.Fatalf("buildResponse: %v", err)
		}
		msg, err := dns.Unpack(raw)
		if err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if len(msg.Answers) != tc.want {
			t.Errorf("prefix %s ipv4 %s: answers = %d, want %d", tc.prefix, tc.ipv4, len(msg.Answers), tc.want)
		}
	}
}
