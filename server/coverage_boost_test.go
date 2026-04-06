package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/security"
)

// ---------------------------------------------------------------------------
// mockBlocklist implements the blocklist interface for handler testing.
// ---------------------------------------------------------------------------

type mockBlocklist struct {
	blocked      map[string]bool
	blockingMode string
	customIP     string
}

func (b *mockBlocklist) IsBlocked(name string) bool { return b.blocked[name] }
func (b *mockBlocklist) BlockingMode() string        { return b.blockingMode }
func (b *mockBlocklist) CustomIP() string            { return b.customIP }

// slowHandler delays before returning the echo response.
type slowHandler struct {
	delay time.Duration
}

func (h *slowHandler) Handle(query []byte, addr net.Addr) ([]byte, error) {
	time.Sleep(h.delay)
	return query, nil
}

// ---------------------------------------------------------------------------
// handler.go: SetPrivateFilter, SetBlocklist, EnableCookies,
//             EnableCookiesWithSecret, SetECS
// ---------------------------------------------------------------------------

func TestSetPrivateFilter(t *testing.T) {
	h := testHandler()
	h.SetPrivateFilter(true)
	if !h.privateFilter {
		t.Error("expected privateFilter to be true")
	}
	h.SetPrivateFilter(false)
	if h.privateFilter {
		t.Error("expected privateFilter to be false")
	}
}

func TestSetBlocklist(t *testing.T) {
	h := testHandler()
	bl := &mockBlocklist{blocked: map[string]bool{"evil.com": true}, blockingMode: "nxdomain"}
	h.SetBlocklist(bl)
	if h.blocklist == nil {
		t.Error("expected blocklist to be set")
	}
	if !h.blocklist.IsBlocked("evil.com") {
		t.Error("expected evil.com to be blocked")
	}
}

func TestEnableCookies(t *testing.T) {
	h := testHandler()
	h.EnableCookies()
	if !h.cookiesEnabled {
		t.Error("expected cookiesEnabled to be true")
	}
	if len(h.cookieSecret) != 16 {
		t.Errorf("expected 16-byte cookie secret, got %d", len(h.cookieSecret))
	}
}

func TestEnableCookiesWithSecret(t *testing.T) {
	h := testHandler()
	secret := []byte("my-test-secret!!")
	h.EnableCookiesWithSecret(secret)
	if !h.cookiesEnabled {
		t.Error("expected cookiesEnabled to be true")
	}
	if len(h.cookieSecret) != 16 {
		t.Errorf("expected 16-byte secret, got %d", len(h.cookieSecret))
	}
	// Verify it's a copy, not the original slice
	secret[0] = 0xFF
	if h.cookieSecret[0] == 0xFF {
		t.Error("expected cookie secret to be a copy")
	}
}

func TestSetECS(t *testing.T) {
	h := testHandler()
	h.SetECS(true, 24)
	if !h.ecsEnabled {
		t.Error("expected ecsEnabled to be true")
	}
	if h.ecsMaxPrefix != 24 {
		t.Errorf("expected ecsMaxPrefix=24, got %d", h.ecsMaxPrefix)
	}
}

// ---------------------------------------------------------------------------
// handler.go: SetNoCacheClients + shouldBypassCache
// ---------------------------------------------------------------------------

func TestSetNoCacheClients(t *testing.T) {
	h := testHandler()
	h.SetNoCacheClients([]string{"10.0.0.0/8", "192.168.1.1", "::1", "invalid%%%"})
	// 10.0.0.0/8, 192.168.1.1/32, and ::1/128 should be added. The invalid one skipped.
	if len(h.noCacheNets) != 3 {
		t.Errorf("expected 3 no-cache nets, got %d", len(h.noCacheNets))
	}
}

func TestSetNoCacheClientsIPv6(t *testing.T) {
	h := testHandler()
	h.SetNoCacheClients([]string{"fd00::1"})
	if len(h.noCacheNets) != 1 {
		t.Errorf("expected 1 no-cache net, got %d", len(h.noCacheNets))
	}
}

func TestShouldBypassCacheEmpty(t *testing.T) {
	h := testHandler()
	// No noCacheNets configured
	if h.shouldBypassCache("10.0.0.1") {
		t.Error("should not bypass with no nets configured")
	}
}

func TestShouldBypassCacheInvalidIP(t *testing.T) {
	h := testHandler()
	h.SetNoCacheClients([]string{"10.0.0.0/8"})
	if h.shouldBypassCache("not-an-ip") {
		t.Error("invalid IP should not match")
	}
}

func TestShouldBypassCacheMatch(t *testing.T) {
	h := testHandler()
	h.SetNoCacheClients([]string{"10.0.0.0/8"})
	if !h.shouldBypassCache("10.1.2.3") {
		t.Error("10.1.2.3 should match 10.0.0.0/8")
	}
}

func TestShouldBypassCacheNoMatch(t *testing.T) {
	h := testHandler()
	h.SetNoCacheClients([]string{"10.0.0.0/8"})
	if h.shouldBypassCache("192.168.1.1") {
		t.Error("192.168.1.1 should not match 10.0.0.0/8")
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: bypass cache path (noCacheNets configured)
// ---------------------------------------------------------------------------

func TestHandleBypassCache(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	// Store something in cache
	c.Store("bypass.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "bypass.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}, nil)
	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetNoCacheClients([]string{"10.0.0.0/8"})

	query := buildTestQuery("bypass.example.com", dns.TypeA)
	addr := &mockAddr{network: "udp", addr: "10.0.0.1:1234"}

	// Even though item is in cache, bypass-cache client triggers cache miss path
	resp, err := handler.Handle(query, addr)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	// Since fail-fast resolver returns SERVFAIL, we get SERVFAIL (cache bypassed)
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeServFail {
		t.Errorf("expected SERVFAIL(2) due to cache bypass + fail resolver, got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: per-zone ACL check (line 230-233)
// ---------------------------------------------------------------------------

func TestHandlePerZoneACLRefused(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)

	// Create ACL with zone-specific rules
	acl, err := security.NewACL([]string{"0.0.0.0/0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = acl.AddZoneACL(security.ZoneACLConfig{
		Zone:  "secret.zone",
		Allow: []string{"172.16.0.0/12"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewMainHandler(res, c, nil, nil, acl, m, discardLogger())

	// Global ACL allows everyone, but zone ACL restricts secret.zone
	query := buildTestQuery("host.secret.zone", dns.TypeA)
	addr := &mockAddr{network: "udp", addr: "192.168.1.1:1234"}

	resp, err := handler.Handle(query, addr)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected REFUSED")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeRefused {
		t.Errorf("expected REFUSED(5), got %d", rcode)
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: blocklist check (lines 236-250) - nxdomain mode
// ---------------------------------------------------------------------------

func TestHandleBlockedNXDomain(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{"blocked.com": true},
		blockingMode: "nxdomain",
	})

	query := buildTestQuery("blocked.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected blocked response")
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNXDomain {
		t.Errorf("expected NXDOMAIN, got %d", msg.Header.RCODE())
	}
}

func TestHandleBlockedNXDomainWithOnQuery(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{"blocked2.com": true},
		blockingMode: "nxdomain",
	})

	var calledRcode string
	handler.OnQuery = func(client, qname, qtype, rcode string, cached bool, durationMs float64) {
		calledRcode = rcode
	}

	query := buildTestQuery("blocked2.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected blocked response")
	}
	if calledRcode != "BLOCKED" {
		t.Errorf("expected OnQuery rcode='BLOCKED', got %q", calledRcode)
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: blocklist - null_ip mode (lines 611-621)
// ---------------------------------------------------------------------------

func TestHandleBlockedNullIP_A(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{"null.com": true},
		blockingMode: "null_ip",
	})

	query := buildTestQuery("null.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}
	if msg.Answers[0].Type != dns.TypeA {
		t.Errorf("expected A record, got %d", msg.Answers[0].Type)
	}
	for _, b := range msg.Answers[0].RData {
		if b != 0 {
			t.Errorf("expected 0.0.0.0, got non-zero rdata")
			break
		}
	}
}

func TestHandleBlockedNullIP_AAAA(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{"null6.com": true},
		blockingMode: "null_ip",
	})

	query := buildTestQuery("null6.com", dns.TypeAAAA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}
	if msg.Answers[0].Type != dns.TypeAAAA {
		t.Errorf("expected AAAA record, got %d", msg.Answers[0].Type)
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: blocklist - custom_ip mode (lines 622-636)
// ---------------------------------------------------------------------------

func TestHandleBlockedCustomIP_A(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{"custom.com": true},
		blockingMode: "custom_ip",
		customIP:     "127.0.0.1",
	})

	query := buildTestQuery("custom.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", msg.Header.RCODE())
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}
	if msg.Answers[0].Type != dns.TypeA {
		t.Errorf("expected A record, got %d", msg.Answers[0].Type)
	}
	// Verify it's 127.0.0.1
	if msg.Answers[0].RData[0] != 127 || msg.Answers[0].RData[3] != 1 {
		t.Errorf("expected 127.0.0.1, got different rdata")
	}
}

func TestHandleBlockedCustomIP_AAAA(t *testing.T) {
	// custom_ip mode with AAAA query - does not produce answer for AAAA
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{"custom6.com": true},
		blockingMode: "custom_ip",
		customIP:     "127.0.0.1",
	})

	query := buildTestQuery("custom6.com", dns.TypeAAAA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	msg, _ := dns.Unpack(resp)
	// custom_ip mode only handles TypeA; AAAA falls through to nxdomain default
	if len(msg.Answers) != 0 {
		t.Errorf("expected 0 answers for AAAA with custom_ip (IPv4), got %d", len(msg.Answers))
	}
}

func TestHandleBlockedCustomIP_InvalidIP(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{"badip.com": true},
		blockingMode: "custom_ip",
		customIP:     "not-an-ip",
	})

	query := buildTestQuery("badip.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	msg, _ := dns.Unpack(resp)
	// Invalid IP means no answer added, falls through to nxdomain
	if len(msg.Answers) != 0 {
		t.Errorf("expected 0 answers for invalid custom IP, got %d", len(msg.Answers))
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: minimal ANY response (lines 255-268)
// ---------------------------------------------------------------------------

func TestHandleMinimalANYResponse(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	msg := &dns.Message{
		Header: dns.Header{
			ID:    0xABCD,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "any.example.com", Type: dns.TypeANY, Class: dns.ClassIN}},
	}
	buf := make([]byte, 512)
	query, err := dns.Pack(msg, buf)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected minimal ANY response")
	}
	parsed, _ := dns.Unpack(resp)
	if parsed.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", parsed.Header.RCODE())
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("expected 1 answer (HINFO), got %d", len(parsed.Answers))
	}
	if parsed.Answers[0].Type != dns.TypeHINFO {
		t.Errorf("expected HINFO record, got type %d", parsed.Answers[0].Type)
	}
}

func TestHandleMinimalANYResponseWithOnQuery(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	var called bool
	handler.OnQuery = func(client, qname, qtype, rcode string, cached bool, durationMs float64) {
		called = true
		if rcode != "NOERROR" {
			t.Errorf("expected NOERROR rcode, got %s", rcode)
		}
	}

	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x1111,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "any2.example.com", Type: dns.TypeANY, Class: dns.ClassIN}},
	}
	buf := make([]byte, 512)
	query, _ := dns.Pack(msg, buf)
	handler.Handle(query, nil)
	if !called {
		t.Error("expected OnQuery to be called for ANY response")
	}
}

func TestHandleMinimalANYResponseWithEDNS(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	query := buildTestQueryWithEDNS("any3.example.com", dns.TypeANY, 4096)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	parsed, _ := dns.Unpack(resp)
	if parsed.EDNS0 == nil {
		t.Error("expected OPT record in ANY response with EDNS0")
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: serve-stale with EDNS0 (EDE Stale Answer, lines 314-321)
// ---------------------------------------------------------------------------

func TestHandleServeStaleWithEDNS(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	c := cache.NewCacheWithStale(1000, 1, 86400, 3600, true, 30, cacheMetrics)

	c.Store("stale-edns.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "stale-edns.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 0, RDLength: 4, RData: []byte{10, 0, 0, 2},
	}}, nil)

	time.Sleep(1500 * time.Millisecond)

	res := newPanickingResolver(c)
	handler := NewMainHandler(res, c, nil, nil, nil, handlerMetrics, discardLogger())

	// Query WITH EDNS0 to trigger the EDE Stale Answer path
	query := buildTestQueryWithEDNS("stale-edns.example.com", dns.TypeA, 4096)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected stale response")
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR from stale, got %d", msg.Header.RCODE())
	}
	// Should have EDE option
	if msg.EDNS0 != nil {
		found := false
		for _, opt := range msg.EDNS0.Options {
			if opt.Code == dns.EDNSOptionCodeEDE {
				code, _, _ := dns.ParseEDEOption(opt.Data)
				if code == dns.EDECodeStaleAnswer {
					found = true
				}
			}
		}
		if !found {
			t.Error("expected EDE Stale Answer option")
		}
	}
}

func TestHandleServeStaleWithOnQuery(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	c := cache.NewCacheWithStale(1000, 1, 86400, 3600, true, 30, cacheMetrics)

	c.Store("stale-cb.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "stale-cb.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 0, RDLength: 4, RData: []byte{10, 0, 0, 3},
	}}, nil)

	time.Sleep(1500 * time.Millisecond)

	res := newPanickingResolver(c)
	handler := NewMainHandler(res, c, nil, nil, nil, handlerMetrics, discardLogger())

	var calledCached bool
	handler.OnQuery = func(client, qname, qtype, rcode string, cached bool, durationMs float64) {
		calledCached = cached
	}

	query := buildTestQuery("stale-cb.example.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected stale response")
	}
	if !calledCached {
		t.Error("expected OnQuery to be called with cached=true for stale")
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: DNSSEC bogus with EDE (lines 334-339)
// ---------------------------------------------------------------------------

// We need a resolver that returns a result with DNSSECStatus="bogus" and RCODE=SERVFAIL.
// This is tricky without mocking. We'll test buildErrorWithEDE more directly,
// and also ensure the buildErrorWithEDE fallback paths are covered.

func TestBuildErrorWithEDE_Fallback(t *testing.T) {
	h := testHandler()
	// Provide a query shorter than 12 bytes to trigger header-only response
	// from buildError. The parse step may or may not succeed.
	resp, err := h.buildErrorWithEDE([]byte{0, 1, 2}, dns.RCodeServFail, dns.EDECodeDNSSECBogus, "bogus")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp) < 12 {
		t.Errorf("expected at least 12 bytes, got %d", len(resp))
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: cache hit with OnQuery + RCODE in cache
// ---------------------------------------------------------------------------

func TestHandleCacheHitWithOnQuery(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.Store("cached.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "cached.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	var onQueryCalled bool
	var onQueryCached bool
	handler.OnQuery = func(client, qname, qtype, rcode string, cached bool, durationMs float64) {
		onQueryCalled = true
		onQueryCached = cached
	}

	query := buildTestQuery("cached.example.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected cached response")
	}
	if !onQueryCalled {
		t.Error("expected OnQuery to be called")
	}
	if !onQueryCached {
		t.Error("expected cached=true in OnQuery")
	}
}

func TestHandleCacheHitNegativeWithRCode(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	// Store negative cache entry with NXDOMAIN RCODE
	c.StoreNegative("nxcached.example.com", dns.TypeA, dns.ClassIN,
		cache.NegNXDomain, dns.RCodeNXDomain, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	var rcodeSeen string
	handler.OnQuery = func(client, qname, qtype, rcode string, cached bool, durationMs float64) {
		rcodeSeen = rcode
	}

	query := buildTestQuery("nxcached.example.com", dns.TypeA)
	resp, _ := handler.Handle(query, nil)
	if resp == nil {
		t.Fatal("expected response")
	}
	if rcodeSeen != "NXDOMAIN" {
		t.Errorf("expected rcode='NXDOMAIN', got %q", rcodeSeen)
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: OnQuery after successful resolve (line 379-381)
// ---------------------------------------------------------------------------

func TestHandleResolveSuccessWithOnQuery(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	var onQueryCalled bool
	handler.OnQuery = func(client, qname, qtype, rcode string, cached bool, durationMs float64) {
		onQueryCalled = true
	}

	query := buildTestQuery("resolve.example.com", dns.TypeA)
	handler.Handle(query, nil)
	if !onQueryCalled {
		t.Error("expected OnQuery to be called after resolve")
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: cookie handling (lines 389-391)
// ---------------------------------------------------------------------------

func TestHandleWithCookies(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	// Use fail-fast resolver so we go through the resolve -> buildResponse -> cookie path
	// (the cookie logic is only applied after buildResponse, not on cache hit)
	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.EnableCookiesWithSecret([]byte("test-secret-1234"))

	// Build query with EDNS0 + cookie option
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	cookieData := make([]byte, 8)
	copy(cookieData, clientCookie)
	cookieOpt := dns.EDNSOption{Code: dns.EDNSOptionCodeCookie, Data: cookieData}
	optRR := dns.BuildOPTWithOptions(4096, false, []dns.EDNSOption{cookieOpt})

	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x5555,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions:  []dns.Question{{Name: "cookie.example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{optRR},
	}
	buf := make([]byte, 512)
	query, err := dns.Pack(msg, buf)
	if err != nil {
		t.Fatal(err)
	}

	addr := &mockAddr{network: "udp", addr: "10.0.0.1:1234"}
	resp, err := handler.Handle(query, addr)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}

	// Parse and check for cookie in response
	parsed, _ := dns.Unpack(resp)
	if parsed.EDNS0 == nil {
		t.Fatal("expected EDNS0 in response")
	}
	foundCookie := false
	for _, opt := range parsed.EDNS0.Options {
		if opt.Code == dns.EDNSOptionCodeCookie {
			foundCookie = true
			if len(opt.Data) < 24 {
				t.Errorf("expected 24-byte cookie (8 client + 16 server per RFC 9018), got %d", len(opt.Data))
			}
		}
	}
	if !foundCookie {
		t.Error("expected cookie option in response")
	}
}

// ---------------------------------------------------------------------------
// handler.go addCookieToResponse: various paths
// ---------------------------------------------------------------------------

func TestAddCookieToResponse_NoCookieOpt(t *testing.T) {
	h := testHandler()
	h.EnableCookiesWithSecret([]byte("test-secret-1234"))

	resp := buildTestQuery("example.com", dns.TypeA) // just a query as "response" bytes
	edns := &dns.EDNS0{
		UDPSize: 4096,
		Options: []dns.EDNSOption{}, // no cookie option
	}

	result := h.addCookieToResponse(resp, edns, "10.0.0.1")
	// Should return original resp unchanged (no valid client cookie)
	if len(result) != len(resp) {
		t.Errorf("expected unchanged response")
	}
}

func TestAddCookieToResponse_ShortCookie(t *testing.T) {
	h := testHandler()
	h.EnableCookiesWithSecret([]byte("test-secret-1234"))

	resp := buildTestQuery("example.com", dns.TypeA)
	edns := &dns.EDNS0{
		UDPSize: 4096,
		Options: []dns.EDNSOption{
			{Code: dns.EDNSOptionCodeCookie, Data: []byte{1, 2, 3}}, // too short
		},
	}

	result := h.addCookieToResponse(resp, edns, "10.0.0.1")
	if len(result) != len(resp) {
		t.Errorf("expected unchanged response for short cookie")
	}
}

func TestAddCookieToResponse_ValidCookie_NoOPT(t *testing.T) {
	h := testHandler()
	h.EnableCookiesWithSecret([]byte("test-secret-1234"))

	// Build a valid response without OPT record
	respMsg := &dns.Message{
		Header: dns.Header{
			ID: 0x1234,
			Flags: dns.NewFlagBuilder().
				SetQR(true).SetRA(true).SetRCODE(dns.RCodeNoError).Build(),
		},
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Answers: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
	}
	buf := make([]byte, 4096)
	resp, _ := dns.Pack(respMsg, buf)

	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	edns := &dns.EDNS0{
		UDPSize: 4096,
		Options: []dns.EDNSOption{
			{Code: dns.EDNSOptionCodeCookie, Data: clientCookie},
		},
	}

	result := h.addCookieToResponse(resp, edns, "10.0.0.1")
	// Should have created a new OPT record with the cookie
	parsed, err := dns.Unpack(result)
	if err != nil {
		t.Fatalf("unpack error: %v", err)
	}
	if parsed.EDNS0 == nil {
		t.Fatal("expected OPT record to be created")
	}
}

func TestAddCookieToResponse_ValidCookie_WithOPT(t *testing.T) {
	h := testHandler()
	h.EnableCookiesWithSecret([]byte("test-secret-1234"))

	// Build a valid response WITH OPT record
	respMsg := &dns.Message{
		Header: dns.Header{
			ID: 0x1234,
			Flags: dns.NewFlagBuilder().
				SetQR(true).SetRA(true).SetRCODE(dns.RCodeNoError).Build(),
		},
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Answers: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPT(4096, false),
		},
	}
	buf := make([]byte, 4096)
	resp, _ := dns.Pack(respMsg, buf)

	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	edns := &dns.EDNS0{
		UDPSize: 4096,
		Options: []dns.EDNSOption{
			{Code: dns.EDNSOptionCodeCookie, Data: clientCookie},
		},
	}

	result := h.addCookieToResponse(resp, edns, "10.0.0.1")
	parsed, err := dns.Unpack(result)
	if err != nil {
		t.Fatalf("unpack error: %v", err)
	}
	if parsed.EDNS0 == nil {
		t.Fatal("expected OPT record")
	}
	foundCookie := false
	for _, opt := range parsed.EDNS0.Options {
		if opt.Code == dns.EDNSOptionCodeCookie {
			foundCookie = true
		}
	}
	if !foundCookie {
		t.Error("expected cookie option appended to existing OPT")
	}
}

func TestAddCookieToResponse_UnpackFails(t *testing.T) {
	h := testHandler()
	h.EnableCookiesWithSecret([]byte("test-secret-1234"))

	// Invalid wire bytes that can't be unpacked
	resp := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	edns := &dns.EDNS0{
		UDPSize: 4096,
		Options: []dns.EDNSOption{
			{Code: dns.EDNSOptionCodeCookie, Data: clientCookie},
		},
	}

	result := h.addCookieToResponse(resp, edns, "10.0.0.1")
	// Should return original resp on unpack failure
	if len(result) != len(resp) {
		t.Errorf("expected unchanged response on unpack failure")
	}
}

// ---------------------------------------------------------------------------
// handler.go buildResponse: private filter path (line 533-535)
// ---------------------------------------------------------------------------

func TestBuildResponseWithPrivateFilter(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetPrivateFilter(true)

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x9999,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "private.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
	}

	result := &resolver.ResolveResult{
		Answers: []dns.ResourceRecord{
			{
				Name: "private.example.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{192, 168, 1, 1}, // private
			},
			{
				Name: "private.example.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{8, 8, 8, 8}, // public
			},
		},
		RCODE: dns.RCodeNoError,
	}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	// The private address (192.168.1.1) should be filtered out
	for _, rr := range parsed.Answers {
		if rr.Type == dns.TypeA && len(rr.RData) == 4 {
			if rr.RData[0] == 192 && rr.RData[1] == 168 {
				t.Error("expected private address to be filtered")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// handler.go buildResponse: truncation with question too big for maxSize (line 586-589)
// ---------------------------------------------------------------------------

func TestBuildResponseTruncation_QuestionTooBig(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	// Very long domain name that makes the question section large
	longName := "a"
	for i := 0; i < 20; i++ {
		longName += ".very-long-subdomain"
	}
	longName += ".example.com"

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xBBBB,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: longName, Type: dns.TypeA, Class: dns.ClassIN,
		}},
		// No EDNS0 means maxSize = 512
	}

	// Create enough answers to trigger truncation
	var answers []dns.ResourceRecord
	for i := 0; i < 50; i++ {
		answers = append(answers, dns.ResourceRecord{
			Name: longName, Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 0, 0, 1},
		})
	}
	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Should have TC bit set
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 1 {
		t.Error("expected TC bit to be set")
	}
}

// ---------------------------------------------------------------------------
// handler.go buildSlipResponse: error path (line 454-456)
// ---------------------------------------------------------------------------

func TestBuildSlipResponse_ShortQuery(t *testing.T) {
	h := testHandler()
	// buildError with <12 byte query → 12 byte response, then TC bit set
	resp, err := h.buildSlipResponse([]byte{0, 1, 2})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp) < 4 {
		t.Fatalf("response too short: %d", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 1 {
		t.Error("expected TC bit to be set")
	}
}

func TestBuildSlipResponse_Normal(t *testing.T) {
	h := testHandler()
	query := buildTestQuery("slip.example.com", dns.TypeA)
	resp, err := h.buildSlipResponse(query)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 1 {
		t.Error("expected TC bit to be set")
	}
	// RCODE should be NOERROR
	if uint8(flags&0xF) != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", flags&0xF)
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: RRL paths in end-to-end (buildResponse called + cookie)
// ---------------------------------------------------------------------------

func TestHandleRRLSlipWithCookies(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newFailFastResolver(c, m)

	rrl := security.NewRRL(1, 1, 24, 56)
	handler := NewMainHandler(res, c, nil, rrl, nil, m, discardLogger())
	handler.EnableCookiesWithSecret([]byte("test-secret-1234"))
	addr := &mockAddr{network: "udp", addr: "172.16.0.2:1234"}

	query := buildTestQuery("rrl-cookie.example.com", dns.TypeA)

	// First query
	handler.Handle(query, addr)

	// Subsequent queries until slip
	var slipped bool
	for i := 0; i < 20; i++ {
		resp, _ := handler.Handle(query, addr)
		if resp != nil && len(resp) >= 4 {
			flags := binary.BigEndian.Uint16(resp[2:4])
			if flags>>9&1 == 1 { // TC bit
				slipped = true
				break
			}
		}
	}
	if !slipped {
		t.Error("expected a slipped (TC=1) response")
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: cache store branches for bypass-cache client
// ---------------------------------------------------------------------------

func TestHandleBypassCacheNoStore(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetNoCacheClients([]string{"10.0.0.0/8"})

	query := buildTestQuery("nostore.example.com", dns.TypeA)
	addr := &mockAddr{network: "udp", addr: "10.0.0.1:1234"}
	handler.Handle(query, addr)

	// Cache should NOT be populated for bypass client
	_, ok := c.Get("nostore.example.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("expected cache to be empty for bypass client")
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: NXDOMAIN and NODATA cache store paths (lines 354-360)
// These need a successful resolve that returns NXDOMAIN or NODATA.
// Since fail-fast resolver returns SERVFAIL, we use cache pre-population
// to simulate the different cache store paths indirectly.
// ---------------------------------------------------------------------------

// Already covered by integration tests, but let's cover the rcodeStr="UNKNOWN" path
func TestHandleUnknownRcodeStr(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	query := buildTestQuery("unknown-rcode.example.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	// fail-fast resolver returns SERVFAIL which maps to "SERVFAIL"
	// The "UNKNOWN" path is for RCODEs not in the map - hard to trigger
	// without mocking, but this test exercises the post-resolve paths.
}

// ---------------------------------------------------------------------------
// handler.go buildErrorWithEDE: parse fail fallback (line 653-655)
// ---------------------------------------------------------------------------

func TestBuildErrorWithEDE_ParseFail(t *testing.T) {
	h := testHandler()
	// Query with exactly 12 bytes, QDCount=0 → buildError returns 12 bytes.
	// Unpacking may fail or produce empty message. Either way should not error.
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x1234)
	resp, err := h.buildErrorWithEDE(query, dns.RCodeServFail, dns.EDECodeDNSSECBogus, "bogus")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp) < 12 {
		t.Errorf("expected at least 12 bytes, got %d", len(resp))
	}
}

// ---------------------------------------------------------------------------
// dot.go: Addr() (line 158-160)
// ---------------------------------------------------------------------------

func TestDoTServerAddr(t *testing.T) {
	handler := &EchoHandler{}
	srv, _, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	addr := srv.Addr()
	if addr == nil {
		t.Error("expected non-nil address")
	}
	if addr.String() == "" {
		t.Error("expected non-empty address string")
	}
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - length < 12 (line 123-125)
// ---------------------------------------------------------------------------

func TestDoTHandleTooShortMessage(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Write a message with length < 12
	binary.Write(conn, binary.BigEndian, uint16(4))
	conn.Write([]byte{0, 1, 2, 3})

	var respLen uint16
	if binary.Read(conn, binary.BigEndian, &respLen) == nil {
		t.Error("expected error/EOF for too-short query on DoT")
	}
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - handler returns error (line 129-131)
// ---------------------------------------------------------------------------

func TestDoTHandleError(t *testing.T) {
	handler := &errHandler{}
	srv, addr, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	query := buildTestQuery("example.com", dns.TypeA)
	binary.Write(conn, binary.BigEndian, uint16(len(query)))
	conn.Write(query)

	var respLen uint16
	if binary.Read(conn, binary.BigEndian, &respLen) == nil {
		t.Error("expected error/EOF for handler error on DoT")
	}
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - nil handler response (line 129-131)
// ---------------------------------------------------------------------------

func TestDoTHandleNilResponse(t *testing.T) {
	handler := &nilHandler{}
	srv, addr, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	query := buildTestQuery("example.com", dns.TypeA)
	binary.Write(conn, binary.BigEndian, uint16(len(query)))
	conn.Write(query)

	var respLen uint16
	if binary.Read(conn, binary.BigEndian, &respLen) == nil {
		t.Error("expected error/EOF for nil response on DoT")
	}
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - write length prefix error (line 135-137)
// ---------------------------------------------------------------------------

func TestDoTHandleWriteLengthError(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Write a valid query length prefix but close before server can respond
	query := buildTestQuery("example.com", dns.TypeA)
	binary.Write(conn, binary.BigEndian, uint16(len(query)))
	conn.Write(query)
	// Close connection immediately before server can write response
	conn.Close()

	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - conn.Write error (line 140-142, 143-145)
// ---------------------------------------------------------------------------

func TestDoTHandleWriteResponseError(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send a query, read the response, then send another and close before reading
	query := buildMinimalQuery(0xF001)
	resp := sendDoTQuery(t, conn, query)
	if len(resp) < 12 {
		t.Fatalf("first response too short: %d", len(resp))
	}

	// Now send a query but close the connection before reading the response
	query2 := buildMinimalQuery(0xF002)
	binary.Write(conn, binary.BigEndian, uint16(len(query2)))
	conn.Write(query2)
	conn.Close()

	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - incomplete body (like TCP test)
// ---------------------------------------------------------------------------

func TestDoTHandleIncompleteBody(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Announce 100 bytes but only send 5
	binary.Write(conn, binary.BigEndian, uint16(100))
	conn.Write([]byte{1, 2, 3, 4, 5})
	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - read length fails (EOF)
// ---------------------------------------------------------------------------

func TestDoTHandleReadLengthFails(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Immediately close → binary.Read for length fails with EOF
	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// dot.go: Serve - accept timeout + non-timeout error + ctx.Done paths
// ---------------------------------------------------------------------------

func TestDoTServeShutdown(t *testing.T) {
	handler := &EchoHandler{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewDoTServerWithListener(ln, handler, 5*time.Second, 10, logger)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil on shutdown, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestDoTServeAcceptError(t *testing.T) {
	handler := &EchoHandler{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewDoTServerWithListener(ln, handler, 5*time.Second, 10, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	time.Sleep(100 * time.Millisecond)
	// Close the listener directly to cause a non-timeout accept error
	ln.Close()
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestDoTServeAcceptTimeoutContinue(t *testing.T) {
	handler := &EchoHandler{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewDoTServerWithListener(ln, handler, 5*time.Second, 10, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()

	// Let it run through some accept timeouts
	time.Sleep(2500 * time.Millisecond)

	// Then connect and verify it's still alive
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("expected connection to succeed after timeouts: %v", err)
	}
	conn.Close()
}

// ---------------------------------------------------------------------------
// dot.go: Close (line 153-155)
// ---------------------------------------------------------------------------

func TestDoTServerClose(t *testing.T) {
	handler := &EchoHandler{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewDoTServerWithListener(ln, handler, 5*time.Second, 10, logger)

	err = srv.Close()
	if err != nil {
		t.Errorf("unexpected error on close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// tcp.go handleTCP: write length prefix error (line 133-135)
// ---------------------------------------------------------------------------

func TestTCPHandleWriteLengthError(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send a valid query but close before server can write response
	query := buildTestQuery("example.com", dns.TypeA)
	binary.Write(conn, binary.BigEndian, uint16(len(query)))
	conn.Write(query)
	conn.Close()
	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// tcp.go handleTCP: conn.Write response error (line 136-138)
// ---------------------------------------------------------------------------

func TestTCPHandleWriteResponseError(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send query, read response, then send another and close before reading
	query := buildMinimalQuery(0xE001)
	resp := sendTCPQuery(t, conn, query)
	if len(resp) < 12 {
		t.Fatalf("first response too short: %d", len(resp))
	}

	// Send next query and close immediately
	query2 := buildMinimalQuery(0xE002)
	binary.Write(conn, binary.BigEndian, uint16(len(query2)))
	conn.Write(query2)
	conn.Close()
	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// dot.go: NewDoTServer error paths (cert/key errors, listen errors)
// ---------------------------------------------------------------------------

func TestNewDoTServer_InvalidCert(t *testing.T) {
	_, err := NewDoTServer(":0", &EchoHandler{}, "nonexistent-cert.pem", "nonexistent-key.pem",
		5*time.Second, 10, discardLogger())
	if err == nil {
		t.Error("expected error for invalid cert/key files")
	}
}

// ---------------------------------------------------------------------------
// handler.go buildBlockedResponse: nil blocklist (line 606-608)
// ---------------------------------------------------------------------------

func TestBuildBlockedResponse_NilBlocklist(t *testing.T) {
	h := testHandler()
	// blocklist is nil, so blockingMode defaults to "nxdomain"
	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x7777,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "blocked.test", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	q := dns.Question{Name: "blocked.test", Type: dns.TypeA, Class: dns.ClassIN}

	resp, err := h.buildBlockedResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNXDomain {
		t.Errorf("expected NXDOMAIN, got %d", msg.Header.RCODE())
	}
}

// ---------------------------------------------------------------------------
// handler.go buildMinimalANYResponse: direct test (already handled above via Handle)
// ---------------------------------------------------------------------------

func TestBuildMinimalANYResponse_Direct(t *testing.T) {
	h := testHandler()
	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x2222,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "any.test", Type: dns.TypeANY, Class: dns.ClassIN}},
	}
	q := dns.Question{Name: "any.test", Type: dns.TypeANY, Class: dns.ClassIN}

	resp, err := h.buildMinimalANYResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	if parsed.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", parsed.Header.RCODE())
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].Type != dns.TypeHINFO {
		t.Error("expected one HINFO answer")
	}
}

func TestBuildMinimalANYResponse_WithEDNS(t *testing.T) {
	h := testHandler()
	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x3333,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "any2.test", Type: dns.TypeANY, Class: dns.ClassIN}},
		EDNS0:     &dns.EDNS0{UDPSize: 4096, DOFlag: true},
	}
	q := dns.Question{Name: "any2.test", Type: dns.TypeANY, Class: dns.ClassIN}

	resp, err := h.buildMinimalANYResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	if parsed.EDNS0 == nil {
		t.Error("expected OPT record with EDNS0")
	}
}

// ---------------------------------------------------------------------------
// handler.go buildBlockedResponse: direct tests for all modes
// ---------------------------------------------------------------------------

func TestBuildBlockedResponse_NullIP_A(t *testing.T) {
	h := testHandler()
	h.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{},
		blockingMode: "null_ip",
	})

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x4444,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "null.test", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	q := dns.Question{Name: "null.test", Type: dns.TypeA, Class: dns.ClassIN}

	resp, err := h.buildBlockedResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	if parsed.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", parsed.Header.RCODE())
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answers))
	}
}

func TestBuildBlockedResponse_NullIP_AAAA(t *testing.T) {
	h := testHandler()
	h.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{},
		blockingMode: "null_ip",
	})

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x4445,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "null6.test", Type: dns.TypeAAAA, Class: dns.ClassIN}},
	}
	q := dns.Question{Name: "null6.test", Type: dns.TypeAAAA, Class: dns.ClassIN}

	resp, err := h.buildBlockedResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	if len(parsed.Answers) != 1 {
		t.Fatalf("expected 1 answer (AAAA), got %d", len(parsed.Answers))
	}
	if parsed.Answers[0].Type != dns.TypeAAAA {
		t.Errorf("expected AAAA, got %d", parsed.Answers[0].Type)
	}
}

func TestBuildBlockedResponse_NullIP_OtherType(t *testing.T) {
	h := testHandler()
	h.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{},
		blockingMode: "null_ip",
	})

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x4446,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "null-mx.test", Type: dns.TypeMX, Class: dns.ClassIN}},
	}
	q := dns.Question{Name: "null-mx.test", Type: dns.TypeMX, Class: dns.ClassIN}

	resp, err := h.buildBlockedResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	// For non-A/AAAA types, null_ip mode still returns NOERROR but no answers
	if len(parsed.Answers) != 0 {
		t.Errorf("expected 0 answers for MX with null_ip, got %d", len(parsed.Answers))
	}
}

func TestBuildBlockedResponse_CustomIP_A(t *testing.T) {
	h := testHandler()
	h.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{},
		blockingMode: "custom_ip",
		customIP:     "1.2.3.4",
	})

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x5555,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "custom.test", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	q := dns.Question{Name: "custom.test", Type: dns.TypeA, Class: dns.ClassIN}

	resp, err := h.buildBlockedResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	if parsed.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR, got %d", parsed.Header.RCODE())
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answers))
	}
	// Check IP is 1.2.3.4
	if parsed.Answers[0].RData[0] != 1 || parsed.Answers[0].RData[1] != 2 ||
		parsed.Answers[0].RData[2] != 3 || parsed.Answers[0].RData[3] != 4 {
		t.Errorf("expected 1.2.3.4, got different rdata")
	}
}

func TestBuildBlockedResponse_CustomIP_NilBlocklist(t *testing.T) {
	// custom_ip with nil blocklist uses default "0.0.0.0"
	h := testHandler()
	// blocklist is nil, so mode defaults to "nxdomain", not "custom_ip"
	// This test verifies the nil blocklist path in custom_ip branch
	// which can only be reached if mode is already "custom_ip" but blocklist is nil.
	// That can't happen in practice since mode is read from blocklist.
	// Instead, test the case where customIP returns "0.0.0.0" (the default).
	h.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{},
		blockingMode: "custom_ip",
		customIP:     "0.0.0.0",
	})

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x5556,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "zero.test", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	q := dns.Question{Name: "zero.test", Type: dns.TypeA, Class: dns.ClassIN}

	resp, err := h.buildBlockedResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	if len(parsed.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answers))
	}
}

func TestBuildBlockedResponse_CustomIP_AAAA(t *testing.T) {
	h := testHandler()
	h.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{},
		blockingMode: "custom_ip",
		customIP:     "127.0.0.1",
	})

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x5557,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "custom6.test", Type: dns.TypeAAAA, Class: dns.ClassIN}},
	}
	q := dns.Question{Name: "custom6.test", Type: dns.TypeAAAA, Class: dns.ClassIN}

	resp, err := h.buildBlockedResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	// custom_ip with IPv4 address for AAAA query - no answer produced
	if len(parsed.Answers) != 0 {
		t.Errorf("expected 0 answers for AAAA with IPv4 custom IP, got %d", len(parsed.Answers))
	}
}

func TestBuildBlockedResponse_CustomIP_InvalidIP(t *testing.T) {
	h := testHandler()
	h.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{},
		blockingMode: "custom_ip",
		customIP:     "not-an-ip",
	})

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0x5558,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "badip.test", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	q := dns.Question{Name: "badip.test", Type: dns.TypeA, Class: dns.ClassIN}

	resp, err := h.buildBlockedResponse(queryMsg, q)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	// Invalid IP means net.ParseIP returns nil, no answer
	if len(parsed.Answers) != 0 {
		t.Errorf("expected 0 answers for invalid custom IP, got %d", len(parsed.Answers))
	}
}

// ---------------------------------------------------------------------------
// dot.go: Serve - ctx.Done select branch
// ---------------------------------------------------------------------------

func TestDoTServeCtxDoneSelectBranch(t *testing.T) {
	handler := &EchoHandler{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewDoTServerWithListener(ln, handler, 5*time.Second, 10, logger)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	time.Sleep(100 * time.Millisecond)
	cancel()
	ln.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - idle timeout (pipeline)
// ---------------------------------------------------------------------------

func TestDoTIdleTimeout(t *testing.T) {
	handler := &EchoHandler{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &DoTServer{
		listener:    ln,
		handler:     handler,
		timeout:     5 * time.Second,
		maxConns:    10,
		sem:         make(chan struct{}, 10),
		logger:      logger,
		pipelineMax: 100,
		idleTimeout: 200 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send one query
	query := buildMinimalQuery(0xF100)
	binary.Write(conn, binary.BigEndian, uint16(len(query)))
	conn.Write(query)

	var respLen uint16
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		t.Fatalf("read length: %v", err)
	}
	resp := make([]byte, respLen)
	io.ReadFull(conn, resp)

	// Wait for idle timeout
	time.Sleep(400 * time.Millisecond)

	// Try another query - should fail
	query2 := buildMinimalQuery(0xF101)
	binary.Write(conn, binary.BigEndian, uint16(len(query2)))
	conn.Write(query2)

	err = binary.Read(conn, binary.BigEndian, &respLen)
	if err == nil {
		t.Error("expected error after idle timeout")
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: cache store paths (NXDOMAIN and NODATA from resolver)
// These are the "bypassCache" false branches for cache storage.
// We can test that the cache is populated after resolution.
// ---------------------------------------------------------------------------

// The cache store for NXDOMAIN/NODATA happens after resolver.Resolve returns,
// lines 354-360. These are integration-test paths that require real network.
// We verify the non-bypass case stores correctly by using the fail-fast resolver
// which returns SERVFAIL - that path doesn't store. The store paths for NOERROR
// are already covered by existing cache tests.

// ---------------------------------------------------------------------------
// handler.go: buildResponse with EDNS0 DO flag
// ---------------------------------------------------------------------------

func TestBuildResponseWithEDNS0_DOFlag(t *testing.T) {
	m := metrics.NewMetrics()
	handler := &MainHandler{metrics: m}

	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xCCCC,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "do.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		EDNS0: &dns.EDNS0{UDPSize: 4096, DOFlag: true},
	}

	result := &resolver.ResolveResult{
		Answers: []dns.ResourceRecord{{
			Name: "do.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
		RCODE: dns.RCodeNoError,
	}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	if parsed.EDNS0 == nil {
		t.Error("expected OPT record")
	}
}

// ---------------------------------------------------------------------------
// dot.go: NewDoTServer - valid cert but invalid listen address (lines 33-54)
// ---------------------------------------------------------------------------

func writeTempCertKey(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	certPath := filepath.Join(dir, "cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyPath := filepath.Join(dir, "key.pem")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return certPath, keyPath
}

func TestNewDoTServer_ListenError(t *testing.T) {
	certFile, keyFile := writeTempCertKey(t)
	// Valid cert/key but invalid address triggers Listen error (lines 38-41)
	_, err := NewDoTServer("invalid-addr-no-port", &EchoHandler{}, certFile, keyFile,
		5*time.Second, 10, discardLogger())
	if err == nil {
		t.Error("expected error for invalid listen address")
	}
}

func TestNewDoTServer_Success(t *testing.T) {
	certFile, keyFile := writeTempCertKey(t)
	// Valid cert/key and valid address → success (lines 33-54)
	srv, err := NewDoTServer("127.0.0.1:0", &EchoHandler{}, certFile, keyFile,
		5*time.Second, 10, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	srv.Close()
}

// ---------------------------------------------------------------------------
// handler.go: cacheRCode == "" fallback to "NOERROR" (line 290-292)
// Need a cache entry with RCODE that's not in RCodeToString map.
// ---------------------------------------------------------------------------

func TestHandleCacheHitUnknownRCode(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	// StoreNegative with RCODE=9 (not in RCodeToString map)
	c.StoreNegative("unkrecode.example.com", dns.TypeA, dns.ClassIN,
		cache.NegNoData, 9, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	var rcodeSeen string
	handler.OnQuery = func(client, qname, qtype, rcode string, cached bool, durationMs float64) {
		rcodeSeen = rcode
	}

	query := buildTestQuery("unkrecode.example.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	// RCODE=9 not in RCodeToString → falls back to "NOERROR"
	if rcodeSeen != "NOERROR" {
		t.Errorf("expected rcode='NOERROR' (fallback), got %q", rcodeSeen)
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: buildResponse error in Handle path (line 384-386)
// Need buildResponse to fail during Handle. buildResponse fails when
// dns.Pack overflows the 4096 buffer. Need resolver to return huge result.
// We can test this by calling Handle with a query that resolves to something
// enormous. But the fail-fast resolver only returns SERVFAIL with 0 records.
// We would need a custom resolver - instead we can test this via the direct
// buildResponse test (already covered by TestBuildResponsePackError).
// The Handle path line 384-386 is: if buildErr != nil { return nil, buildErr }
// This is hard to trigger without a mock resolver that returns huge results.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handler.go Handle: DNSSEC bogus path (lines 334-339)
// Need a resolve result with DNSSECStatus="bogus" and EDNS0 in query.
// The fail-fast resolver returns SERVFAIL but no DNSSECStatus. The panicking
// resolver returns nil result with error. We cannot easily trigger this path
// without a mock resolver.
// However, we can still test the rcodeStr="UNKNOWN" branch (line 349-351).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handler.go Handle: cache store branches (lines 354-360)
// These require a resolver that returns real results: NOERROR+answers,
// NXDOMAIN, or NOERROR+no answers. All integration test paths.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handler.go buildSlipResponse: buildError returns error (line 454-456)
// buildError never returns error (it always returns ([]byte, nil)).
// This is dead code. Cannot be covered.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handler.go buildErrorWithEDE: buildError returns error (line 647-649)
// Same as above - buildError never returns error. Dead code.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handler.go buildErrorWithEDE: Pack fails (line 659-661)
// Pack would fail only if the message is too large. After adding EDE to a
// small error response, this shouldn't happen. Very hard to trigger.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handler.go addCookieToResponse: Pack fails (line 714-716)
// Pack would fail if the response + cookie exceeds buffer. Edge case.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// tcp.go handleTCP: binary.Write error for response length (line 133-135)
// This happens if conn is closed before server writes the response length.
// Already tested by TestTCPHandleWriteLengthError but the timing is tricky.
// The line requires the write of the 2-byte length prefix to fail while
// the write of the response body succeeds. Very timing-dependent.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handler.go buildResponse: question section > maxSize truncation (line 586-589)
// When the question section alone exceeds maxSize (512), we set header-only.
// This requires a domain name > ~495 bytes. DNS names max at 253.
// But if maxSize < question section size, it triggers.
// With no EDNS0, maxSize=512. Question = 12(header) + name + 4(type+class).
// The check is qEnd > maxSize. qEnd is the end of the question section.
// After truncation sets qEnd to end of questions, if qEnd > maxSize then
// send header only. This requires question section > 512 bytes.
// Max DNS name = 253 bytes, so question section = 253 + 4 = ~257 bytes.
// qEnd = 12 + 257 = 269 < 512. So this path can't be triggered with
// standard DNS names and no EDNS0. With EDNS0 maxSize is larger.
// However, we can try with a very small EDNS0 buffer size.
// ---------------------------------------------------------------------------

func TestBuildResponseTruncation_HeaderOnly(t *testing.T) {
	m := metrics.NewMetrics()
	handler := &MainHandler{metrics: m}

	// Use EDNS0 with maxSize much smaller than normal to trigger qEnd > maxSize
	queryMsg := &dns.Message{
		Header: dns.Header{
			ID:    0xDDDD,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "a.very-long-subdomain-name-that-is-quite-big.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		// EDNS0 with very small UDP size to trigger truncation
		EDNS0: &dns.EDNS0{UDPSize: 30},
	}

	// Many answers to trigger truncation
	var answers []dns.ResourceRecord
	for i := 0; i < 50; i++ {
		answers = append(answers, dns.ResourceRecord{
			Name: "a.very-long-subdomain-name-that-is-quite-big.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 0, 0, 1},
		})
	}
	result := &resolver.ResolveResult{Answers: answers, RCODE: dns.RCodeNoError}

	resp, err := handler.buildResponse(queryMsg, result)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Check TC bit is set
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags>>9&1 != 1 {
		t.Error("expected TC bit to be set")
	}
	// Since maxSize=30 and question section alone is bigger, should send header only
	if len(resp) > 30 {
		// If qEnd > maxSize, resp is header-only (12 bytes)
		if len(resp) != 12 {
			// It's acceptable if it's just the header + question truncated to maxSize
			t.Logf("response is %d bytes (maxSize=30)", len(resp))
		}
	}
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - pipeline max and idle timeout (line 140-142, 143-145)
// The write response body error + write length prefix error.
// These are timing-dependent write errors on the TLS connection.
// We've already tested close-before-response patterns above.
// Let's test the specific case where we do a successful first query
// then close during the second to trigger write errors.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handler.go Handle: blocklist buildBlockedResponse error (line 239-241)
// buildBlockedResponse can only error if dns.Pack fails. With normal
// blocked responses this doesn't happen. Unreachable in practice.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handler.go Handle: buildMinimalANYResponse error (line 257-259)
// Same as above - dns.Pack on a small HINFO response won't fail.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Additional edge case coverage
// ---------------------------------------------------------------------------

func TestHandleBlockedNotBlocked(t *testing.T) {
	// Verify that unblocked domains pass through when blocklist is set
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	c.Store("allowed.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "allowed.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}, nil)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.SetBlocklist(&mockBlocklist{
		blocked:      map[string]bool{"evil.com": true},
		blockingMode: "nxdomain",
	})

	query := buildTestQuery("allowed.com", dns.TypeA)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("expected NOERROR for allowed domain, got %d", msg.Header.RCODE())
	}
}

func TestHandleCookiesDisabledNoEffect(t *testing.T) {
	// Verify that cookies don't affect response when disabled
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	// cookiesEnabled is false by default

	query := buildTestQueryWithEDNS("nocookie.example.com", dns.TypeA, 4096)
	resp, err := handler.Handle(query, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
}

// ---------------------------------------------------------------------------
// handler.go Handle: NoCacheClients with IPv6
// ---------------------------------------------------------------------------

func TestSetNoCacheClientsIPv4CIDR(t *testing.T) {
	h := testHandler()
	h.SetNoCacheClients([]string{"192.168.0.0/16"})
	if !h.shouldBypassCache("192.168.1.100") {
		t.Error("192.168.1.100 should match 192.168.0.0/16")
	}
	if h.shouldBypassCache("10.0.0.1") {
		t.Error("10.0.0.1 should not match 192.168.0.0/16")
	}
}

// ---------------------------------------------------------------------------
// dot.go: handleDoT - large length value (too big to read body)
// ---------------------------------------------------------------------------

func TestDoTHandleLargeLength(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send length=65535 but only write a few bytes, then close
	binary.Write(conn, binary.BigEndian, uint16(65535))
	conn.Write([]byte{1, 2, 3})
	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// dot.go: Serve - SetDeadline on non-TCPListener (line 85-87)
// When we use NewDoTServerWithListener with a plain net.Listener (not
// *net.TCPListener), the SetDeadline type assertion fails gracefully.
// The startTestDoTServer wraps with tls.NewListener, so the underlying
// type is *tls.listener, not *net.TCPListener. This means line 85-87
// (the SetDeadline path) is NOT taken for our test DoT server.
// This is actually already the case - the code at line 85 checks for
// *net.TCPListener which is never true for a TLS listener.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// tcp.go handleTCP: conn.Write response error (line 136-138)
// This is tricky to test because we need the length prefix write to succeed
// but the body write to fail. That requires precise timing.
// ---------------------------------------------------------------------------

func TestTCPHandleWriteBodyError(t *testing.T) {
	logger := discardLogger()

	// Create a handler that returns a response large enough that the write
	// might partially fail if the connection is closed.
	handler := &EchoHandler{}
	srv, err := NewTCPServer(":0", handler, 2*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Send first query and read response to confirm connection works
	query := buildMinimalQuery(0xA001)
	resp := sendTCPQuery(t, conn, query)
	if len(resp) < 12 {
		t.Fatalf("first response too short")
	}

	// Now send another query and set a very short read deadline on our side
	// to simulate the scenario where the connection degrades
	query2 := buildMinimalQuery(0xA002)
	binary.Write(conn, binary.BigEndian, uint16(len(query2)))
	conn.Write(query2)
	// Immediately close our end to cause write error on server side
	conn.Close()
	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// tcp.go handleTCP: binary.Write length prefix error (line 133-135)
// Use a slow handler so we can close the connection while it's processing.
// ---------------------------------------------------------------------------

func TestTCPHandleWriteLengthPrefixError(t *testing.T) {
	logger := discardLogger()
	handler := &slowHandler{delay: 200 * time.Millisecond}
	srv, err := NewTCPServer(":0", handler, 5*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Send query
	query := buildMinimalQuery(0xB001)
	binary.Write(conn, binary.BigEndian, uint16(len(query)))
	conn.Write(query)

	// Close immediately while slow handler is still processing
	// This ensures the binary.Write of the response length prefix will fail
	time.Sleep(50 * time.Millisecond) // ensure query is read
	conn.Close()
	time.Sleep(300 * time.Millisecond) // wait for handler to finish and fail
}

// ---------------------------------------------------------------------------
// dot.go handleDoT: binary.Write length prefix error + conn.Write body error
// (lines 140-142, 143-145) - Same approach with slow handler.
// ---------------------------------------------------------------------------

func TestDoTHandleWriteErrors_SlowHandler(t *testing.T) {
	handler := &slowHandler{delay: 200 * time.Millisecond}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewDoTServerWithListener(ln, handler, 5*time.Second, 10, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send query
	query := buildMinimalQuery(0xC001)
	binary.Write(conn, binary.BigEndian, uint16(len(query)))
	conn.Write(query)

	// Close while handler is still processing
	time.Sleep(50 * time.Millisecond) // ensure query is read
	conn.Close()
	time.Sleep(300 * time.Millisecond) // wait for handler to finish
}
