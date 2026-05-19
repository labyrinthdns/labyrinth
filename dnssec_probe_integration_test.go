//go:build integration

package main

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// Run with:  go test -tags=integration -run TestDNSSECProbe -v -timeout 90s
//
// Requires outbound UDP/53 to the public Internet. Hits real Cloudflare
// nameservers to confirm the NSEC denial validator path actually rescues
// negative responses from Cloudflare-signed zones.

func newProbeResolver(t *testing.T) *resolver.Resolver {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	c := cache.NewCache(10000, 1, 86400, 600, metrics.NewMetrics())
	cfg := resolver.ResolverConfig{
		MaxDepth:              30,
		MaxCNAMEDepth:         10,
		UpstreamTimeout:       5 * time.Second,
		UpstreamRetries:       2,
		QMinEnabled:           true,
		DNSSECEnabled:         true,
		UpstreamUDPBufferSize: 1232,
	}
	r := resolver.NewResolver(c, cfg, metrics.NewMetrics(), logger)
	if err := r.PrimeRootHints(); err != nil {
		t.Fatalf("priming root hints: %v", err)
	}
	if !testing.Short() {
		r.EnableDNSSEC(logger)
	}

	// Start root refresh just to mirror real config; cancel right after.
	ctx, cancel := context.WithCancel(context.Background())
	go r.StartRootRefresh(ctx, time.Hour)
	t.Cleanup(cancel)

	return r
}

type probeCase struct {
	name       string
	qname      string
	qtype      uint16
	wantRcode  uint8
	wantSecure bool // expect DNSSECStatus == "secure"
}

func runProbe(t *testing.T, r *resolver.Resolver, tc probeCase) {
	t.Helper()
	result, err := r.Resolve(tc.qname, tc.qtype, dns.ClassIN)
	if err != nil {
		t.Fatalf("%s: Resolve error: %v", tc.name, err)
	}
	if result == nil {
		t.Fatalf("%s: nil result", tc.name)
	}
	types := map[uint16]int{}
	for _, rr := range result.Answers {
		types[rr.Type]++
	}
	authTypes := map[uint16]int{}
	for _, rr := range result.Authority {
		authTypes[rr.Type]++
	}
	t.Logf("%s: rcode=%d answers=%d dnssec=%q answer_types=%v auth_types=%v",
		tc.name, result.RCODE, len(result.Answers), result.DNSSECStatus, types, authTypes)
	if result.RCODE != tc.wantRcode {
		t.Errorf("%s: rcode=%d want=%d", tc.name, result.RCODE, tc.wantRcode)
	}
	if tc.wantSecure && result.DNSSECStatus != "secure" {
		t.Errorf("%s: DNSSECStatus=%q want=secure", tc.name, result.DNSSECStatus)
	}
}

// Probe the resolver's own ability to fetch the root DNSKEY RRset, which is
// the first thing the chain-of-trust walker needs.
func TestDNSSECProbeRootDNSKEY(t *testing.T) {
	r := newProbeResolver(t)
	for _, name := range []string{".", ""} {
		msg, err := r.QueryDNSSEC(name, dns.TypeDNSKEY, dns.ClassIN)
		if err != nil {
			t.Errorf("QueryDNSSEC(%q, DNSKEY): %v", name, err)
			continue
		}
		dnskeyCount := 0
		for _, rr := range msg.Answers {
			if rr.Type == dns.TypeDNSKEY {
				dnskeyCount++
			}
		}
		types := map[uint16]int{}
		for _, rr := range msg.Answers {
			types[rr.Type]++
		}
		t.Logf("name=%q rcode=%d answers=%d dnskeys=%d types=%v",
			name, msg.Header.RCODE(), len(msg.Answers), dnskeyCount, types)
		if len(msg.Answers) > 0 {
			t.Logf("  first answer: name=%q type=%d ttl=%d rdlen=%d",
				msg.Answers[0].Name, msg.Answers[0].Type, msg.Answers[0].TTL, len(msg.Answers[0].RData))
		}
	}
}

// Cloudflare-hosted DNSSEC-signed zones. Positive answers test that we
// didn't break anything; NODATA and NXDOMAIN test the NSEC validator.
func TestDNSSECProbeCloudflare(t *testing.T) {
	r := newProbeResolver(t)

	cases := []probeCase{
		// Baseline: non-Cloudflare DNSSEC zone (IANA). If THIS fails, the
		// validator is broken independently of Cloudflare.
		{
			name:       "baseline_A_iana.org",
			qname:      "iana.org",
			qtype:      dns.TypeA,
			wantRcode:  dns.RCodeNoError,
			wantSecure: true,
		},
		// 1. Positive A: cloudflare.com is signed and hosted on Cloudflare's
		//    own NS pool. If this fails the resolver is just broken.
		{
			name:       "positive_A_cloudflare.com",
			qname:      "cloudflare.com",
			qtype:      dns.TypeA,
			wantRcode:  dns.RCodeNoError,
			wantSecure: true,
		},
		// 2. Positive AAAA: same zone, IPv6.
		{
			name:       "positive_AAAA_cloudflare.com",
			qname:      "cloudflare.com",
			qtype:      dns.TypeAAAA,
			wantRcode:  dns.RCodeNoError,
			wantSecure: true,
		},
		// 3. NODATA via NSEC: TXT query against a name that exists but has no
		//    TXT — Cloudflare returns NODATA + NSEC. Previously: Bogus →
		//    SERVFAIL. After fix: Secure / NOERROR / no answers.
		{
			name:       "nodata_TXT_www.cloudflare.com",
			qname:      "www.cloudflare.com",
			qtype:      dns.TypeMX,
			wantRcode:  dns.RCodeNoError,
			wantSecure: true,
		},
		// 4. Non-existent name in a Cloudflare-signed zone. Cloudflare's
		//    online signer uses "compact denial of existence" and returns
		//    NOERROR + NSEC denying every type (rather than a real NXDOMAIN
		//    that would leak which names exist). Previously: Bogus →
		//    SERVFAIL. After fix: Secure / NOERROR / no answers.
		{
			name:       "compact_denial_cloudflare.com",
			qname:      "nonexistent-labyrinth-probe-zk7q9.cloudflare.com",
			qtype:      dns.TypeA,
			wantRcode:  dns.RCodeNoError,
			wantSecure: true,
		},
		// 5. Another Cloudflare-signed zone, same compact-denial pattern.
		{
			name:       "compact_denial_1.1.1.1",
			qname:      "definitely-not-a-real-name-x9q.one.one.one.one",
			qtype:      dns.TypeA,
			wantRcode:  dns.RCodeNoError,
			wantSecure: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runProbe(t, r, tc)
		})
	}
}
