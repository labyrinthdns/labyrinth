package security

import (
	"context"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestInZone(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		expected bool
	}{
		{"google.com", "google.com", true},
		{"ns1.google.com", "google.com", true},
		{"a.b.c.google.com", "google.com", true},
		{"evil.com", "google.com", false},
		{"notgoogle.com", "google.com", false},
		{"anything", "", true}, // root zone — everything in zone
		{"com", "com", true},
		{"google.com", "com", true},
	}

	for _, tt := range tests {
		result := InZone(tt.name, tt.zone)
		if result != tt.expected {
			t.Errorf("InZone(%q, %q) = %v, want %v", tt.name, tt.zone, result, tt.expected)
		}
	}
}

func TestACLCheck(t *testing.T) {
	acl, err := NewACL([]string{"192.168.0.0/16"}, nil)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	if !acl.Check("192.168.1.1") {
		t.Error("192.168.1.1 should be allowed")
	}
	if acl.Check("10.0.0.1") {
		t.Error("10.0.0.1 should be denied")
	}
}

func TestACLDenyOverridesAllow(t *testing.T) {
	acl, err := NewACL(
		[]string{"192.168.0.0/16"},
		[]string{"192.168.1.0/24"},
	)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	if acl.Check("192.168.1.1") {
		t.Error("192.168.1.1 should be denied (deny overrides allow)")
	}
	if !acl.Check("192.168.2.1") {
		t.Error("192.168.2.1 should be allowed")
	}
}

func TestACLEmptyAllow(t *testing.T) {
	acl, err := NewACL(nil, nil)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	if !acl.Check("192.168.1.1") {
		t.Error("empty allow list should allow all")
	}
	if !acl.Check("10.0.0.1") {
		t.Error("empty allow list should allow all")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10, 3)

	// First 3 should be allowed (burst=3)
	for i := 0; i < 3; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 4th should be rejected
	if rl.Allow("1.2.3.4") {
		t.Error("4th request should be rejected (burst exceeded)")
	}
}

// encodePlainName encodes a domain name as uncompressed wire-format label sequence (for test use).
func encodePlainName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0x00}
	}
	var buf []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
			start = i + 1
		}
	}
	buf = append(buf, 0x00)
	return buf
}

func TestSanitizeBailiwick(t *testing.T) {
	// Build NS RDATA: wire-format encoded name for "ns1.example.com"
	nsRData := encodePlainName("ns1.example.com")

	msg := &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4}},
			{Name: "evil.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{6, 6, 6, 6}},
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData},
			{Name: "evil.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600, RDLength: 4, RData: encodePlainName("ns1.evil.com")},
		},
		Additional: []dns.ResourceRecord{
			{Name: "ns1.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1}},
			{Name: "ns1.evil.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{6, 6, 6, 6}},
			{Name: "", Type: dns.TypeOPT, Class: 4096, TTL: 0, RDLength: 0, RData: nil},
		},
	}

	SanitizeBailiwick(msg, "example.com")

	// Answers: only example.com should remain
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}
	if msg.Answers[0].Name != "example.com" {
		t.Errorf("expected answer name 'example.com', got %q", msg.Answers[0].Name)
	}

	// Authority: only example.com NS should remain
	if len(msg.Authority) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(msg.Authority))
	}
	if msg.Authority[0].Name != "example.com" {
		t.Errorf("expected authority name 'example.com', got %q", msg.Authority[0].Name)
	}

	// Additional: OPT + ns1.example.com glue should remain, ns1.evil.com removed
	if len(msg.Additional) != 2 {
		t.Fatalf("expected 2 additional (OPT + glue), got %d", len(msg.Additional))
	}
	hasOPT := false
	hasGlue := false
	for _, rr := range msg.Additional {
		if rr.Type == dns.TypeOPT {
			hasOPT = true
		}
		if rr.Name == "ns1.example.com" {
			hasGlue = true
		}
	}
	if !hasOPT {
		t.Error("OPT record should be preserved")
	}
	if !hasGlue {
		t.Error("glue record for ns1.example.com should be preserved")
	}
}

// TestSanitizeBailiwick_OutOfBailiwickGlue exercises the cache-poisoning
// defense for the classic Kashpureff-style attack: a parent-zone server
// (here ".com") delegates child.example with NS pointing to an attacker-
// controlled host in a sibling zone, and tries to slip A glue for that
// host into Additional. The NS record itself is in-bailiwick (example.com
// is below ".com") so it survives the Authority filter — the glue must
// nonetheless be rejected because the responder has no authority over
// "ns.evil.org".
func TestSanitizeBailiwick_OutOfBailiwickGlue(t *testing.T) {
	// ".com" server returning a delegation for example.com with two NS:
	//   - ns2.example.com (in-bailiwick of .com, glue should survive)
	//   - ns.evil.org    (out-of-bailiwick of .com, glue must be dropped)
	nsLegit := encodePlainName("ns2.example.com")
	nsEvil := encodePlainName("ns.evil.org")

	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600, RDLength: uint16(len(nsLegit)), RData: nsLegit},
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600, RDLength: uint16(len(nsEvil)), RData: nsEvil},
		},
		Additional: []dns.ResourceRecord{
			// Legit in-bailiwick glue — must survive.
			{Name: "ns2.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 2}},
			// Poisoning attempt — out-of-bailiwick glue, must be dropped.
			{Name: "ns.evil.org", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{6, 6, 6, 6}},
		},
	}

	SanitizeBailiwick(msg, "com")

	// Both NS records are valid below .com so both Authority entries survive.
	if len(msg.Authority) != 2 {
		t.Fatalf("expected 2 authority records, got %d", len(msg.Authority))
	}

	// Only the in-bailiwick glue should be kept.
	if len(msg.Additional) != 1 {
		t.Fatalf("expected 1 surviving glue record, got %d (%+v)", len(msg.Additional), msg.Additional)
	}
	if msg.Additional[0].Name != "ns2.example.com" {
		t.Errorf("unexpected surviving glue: %q", msg.Additional[0].Name)
	}
	for _, rr := range msg.Additional {
		if rr.Name == "ns.evil.org" {
			t.Error("out-of-bailiwick glue for ns.evil.org must be rejected")
		}
	}
}

// TestSanitizeBailiwick_RootIsPermissive verifies that priming queries
// (zone="") keep all glue. The root zone is allowed to publish glue for
// any TLD nameserver — that is its job.
func TestSanitizeBailiwick_RootIsPermissive(t *testing.T) {
	nsCom := encodePlainName("a.gtld-servers.net")

	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600, RDLength: uint16(len(nsCom)), RData: nsCom},
		},
		Additional: []dns.ResourceRecord{
			{Name: "a.gtld-servers.net", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600, RDLength: 4, RData: []byte{192, 5, 6, 30}},
		},
	}

	SanitizeBailiwick(msg, "")

	if len(msg.Additional) != 1 {
		t.Fatalf("priming/root case must keep glue, got %d records", len(msg.Additional))
	}
	if msg.Additional[0].Name != "a.gtld-servers.net" {
		t.Errorf("expected gtld-servers glue preserved, got %q", msg.Additional[0].Name)
	}
}

// TestSanitizeBailiwick_NSNotMatchingGlueIsDropped covers the
// pre-existing "name not in nsNames" path: even an in-bailiwick record
// in Additional is dropped if no NS in Authority pointed at it. This
// guards against responders padding the Additional section with
// unsolicited records.
func TestSanitizeBailiwick_NSNotMatchingGlueIsDropped(t *testing.T) {
	nsRData := encodePlainName("ns1.example.com")

	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600, RDLength: uint16(len(nsRData)), RData: nsRData},
		},
		Additional: []dns.ResourceRecord{
			// Matches NS in Authority — kept.
			{Name: "ns1.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1}},
			// In-bailiwick of example.com but NOT named by any NS — dropped.
			{Name: "extra.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 99}},
		},
	}

	SanitizeBailiwick(msg, "example.com")

	if len(msg.Additional) != 1 {
		t.Fatalf("expected 1 surviving record, got %d", len(msg.Additional))
	}
	if msg.Additional[0].Name != "ns1.example.com" {
		t.Errorf("expected only ns1.example.com glue kept, got %q", msg.Additional[0].Name)
	}
}

func TestFilterInZoneEmptyZone(t *testing.T) {
	// Cover filterInZone with zone="" (root zone, everything passes)
	records := []dns.ResourceRecord{
		{Name: "anything.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300},
		{Name: "other.org", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300},
	}

	result := filterInZone(records, "")
	if len(result) != 2 {
		t.Errorf("empty zone should pass all records, got %d", len(result))
	}
}

func TestFilterInZoneRemovesOutOfZone(t *testing.T) {
	// Cover filterInZone directly with records that should be removed
	records := []dns.ResourceRecord{
		{Name: "sub.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300},
		{Name: "evil.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300},
		{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300},
	}

	result := filterInZone(records, "example.com")
	if len(result) != 2 {
		t.Fatalf("expected 2 in-zone records, got %d", len(result))
	}
	for _, rr := range result {
		if rr.Name == "evil.com" {
			t.Error("evil.com should have been filtered out")
		}
	}
}

func TestRateLimiterStartCleanup(t *testing.T) {
	// Cover StartCleanup: add a client, start cleanup, verify client removed
	rl := NewRateLimiter(10, 3)
	rl.cleanup = 100 * time.Millisecond // short cleanup interval for testing

	// Add a client with a lastTime in the past
	rl.mu.Lock()
	rl.clients["1.2.3.4"] = &tokenBucket{
		tokens:   3,
		lastTime: time.Now().Add(-10 * time.Minute),
	}
	rl.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rl.StartCleanup(ctx)
		close(done)
	}()

	// Wait for at least one cleanup tick
	time.Sleep(300 * time.Millisecond)

	rl.mu.Lock()
	count := len(rl.clients)
	rl.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 clients after cleanup, got %d", count)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("StartCleanup did not stop after cancel")
	}
}

func TestACLNewACLInvalidCIDR(t *testing.T) {
	// Cover the error path in NewACL with invalid allow CIDR
	_, err := NewACL([]string{"not-a-cidr"}, nil)
	if err == nil {
		t.Error("expected error for invalid allow CIDR")
	}

	// Cover the error path in NewACL with invalid deny CIDR
	_, err = NewACL(nil, []string{"also-not-valid"})
	if err == nil {
		t.Error("expected error for invalid deny CIDR")
	}
}

func TestACLCheckIPv6(t *testing.T) {
	// Cover ACL Check with IPv6 addresses
	acl, err := NewACL([]string{"fd00::/8"}, nil)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	if !acl.Check("fd00::1") {
		t.Error("fd00::1 should be allowed")
	}
	if acl.Check("2001:db8::1") {
		t.Error("2001:db8::1 should be denied")
	}
}

func TestACLCheckInvalidIP(t *testing.T) {
	// Cover the ip == nil path in Check
	acl, err := NewACL(nil, nil)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	if acl.Check("not-an-ip") {
		t.Error("invalid IP should return false")
	}
}

func TestRateLimiterTokenRefillCap(t *testing.T) {
	// Cover the tb.tokens > float64(rl.burst) cap branch in Allow
	rl := NewRateLimiter(1000, 3) // high rate so tokens refill quickly

	rl.Allow("1.2.3.4") // create the bucket, tokens = burst-1 = 2

	// Wait so tokens refill well beyond burst
	time.Sleep(100 * time.Millisecond)

	// This call should trigger the token cap (tokens > burst -> cap to burst)
	if !rl.Allow("1.2.3.4") {
		t.Error("should be allowed after token refill")
	}
}

func TestRateLimiterRefillAllowsAfterWait(t *testing.T) {
	// Cover the refill path in Allow: exhaust tokens, wait, then verify refill works
	rl := NewRateLimiter(100, 2) // rate=100 tokens/sec, burst=2

	// Exhaust all tokens
	rl.Allow("5.5.5.5") // tokens = burst-1 = 1
	rl.Allow("5.5.5.5") // tokens = 0 (refill is negligible)
	if rl.Allow("5.5.5.5") {
		t.Error("should be denied after exhausting tokens")
	}

	// Wait for refill (100 tokens/sec = 1 token per 10ms)
	time.Sleep(50 * time.Millisecond)

	// Should now be allowed due to token refill
	if !rl.Allow("5.5.5.5") {
		t.Error("should be allowed after token refill wait")
	}
}
