package resolver

import (
	"log/slog"
	"os"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

func TestClosestCachedDelegation_UsesComNS(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	nsRData := buildPlainNameRData("a.gtld-servers.net")
	c.Store("com", dns.TypeNS, dns.ClassIN, []dns.ResourceRecord{{
		Name: "com", Type: dns.TypeNS, Class: dns.ClassIN,
		TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
	}}, nil)
	c.Store("a.gtld-servers.net", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "a.gtld-servers.net", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 3600, RDLength: 4, RData: []byte{192, 5, 6, 30},
	}}, nil)

	nss, zone := r.closestCachedDelegation("deneme.com")
	if zone != "com" {
		t.Fatalf("zone=%q, want com", zone)
	}
	if len(nss) != 1 || nss[0].hostname != "a.gtld-servers.net" {
		t.Fatalf("ns=%+v", nss)
	}
	if nss[0].ipv4 != "192.5.6.30" {
		t.Fatalf("glue ipv4=%q, want 192.5.6.30", nss[0].ipv4)
	}
}

func TestClosestCachedDelegation_PrefersLongerAncestor(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	comNS := buildPlainNameRData("a.gtld-servers.net")
	c.Store("com", dns.TypeNS, dns.ClassIN, []dns.ResourceRecord{{
		Name: "com", Type: dns.TypeNS, Class: dns.ClassIN,
		TTL: 3600, RDLength: uint16(len(comNS)), RData: comNS,
	}}, nil)
	exNS := buildPlainNameRData("ns1.example.com")
	c.Store("example.com", dns.TypeNS, dns.ClassIN, []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN,
		TTL: 3600, RDLength: uint16(len(exNS)), RData: exNS,
	}}, nil)
	c.Store("ns1.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "ns1.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 3600, RDLength: 4, RData: []byte{203, 0, 113, 1},
	}}, nil)

	_, zone := r.closestCachedDelegation("www.example.com")
	if zone != "example.com" {
		t.Fatalf("zone=%q, want example.com (longest ancestor)", zone)
	}
}

func TestClosestCachedDelegation_FallsBackToRoot(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	nss, zone := r.closestCachedDelegation("deneme.com")
	if zone != "" {
		t.Fatalf("zone=%q, want empty (roots)", zone)
	}
	if len(nss) == 0 {
		t.Fatal("expected root NS list")
	}
}

func TestSeedIterativeStart_TypeDSIgnoresChildCache(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	// Child NS + glue cached — A lookup would jump here, but DS must not.
	nsRData := buildPlainNameRData("cesar.ns.cloudflare.com")
	c.Store("turkmmo.com", dns.TypeNS, dns.ClassIN, []dns.ResourceRecord{{
		Name: "turkmmo.com", Type: dns.TypeNS, Class: dns.ClassIN,
		TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
	}}, nil)
	c.Store("cesar.ns.cloudflare.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "cesar.ns.cloudflare.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 3600, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}, nil)

	_, zoneA := r.seedIterativeStart("turkmmo.com", dns.TypeA)
	if zoneA != "turkmmo.com" {
		t.Fatalf("A seed zone=%q, want turkmmo.com", zoneA)
	}
	_, zoneDS := r.seedIterativeStart("turkmmo.com", dns.TypeDS)
	if zoneDS != "" {
		t.Fatalf("DS seed zone=%q, want roots (empty) to avoid child DS poison", zoneDS)
	}
}

func TestClosestCachedDelegation_SkipsNSWithoutGlue(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewResolver(c, ResolverConfig{MaxDepth: 30}, m, logger)

	nsRData := buildPlainNameRData("a.gtld-servers.net")
	c.Store("com", dns.TypeNS, dns.ClassIN, []dns.ResourceRecord{{
		Name: "com", Type: dns.TypeNS, Class: dns.ClassIN,
		TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData,
	}}, nil)
	// No A/AAAA for a.gtld-servers.net — must NOT jump to com.
	nss, zone := r.closestCachedDelegation("deneme.com")
	if zone != "" {
		t.Fatalf("zone=%q, want roots when cached NS lack glue", zone)
	}
	if len(nss) == 0 {
		t.Fatal("expected root NS list")
	}
}
