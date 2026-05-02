package resolver

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestRandomTXID(t *testing.T) {
	const count = 10000
	seen := make(map[uint16]struct{}, count)

	for i := 0; i < count; i++ {
		id, err := randomTXID()
		if err != nil {
			t.Fatalf("randomTXID error: %v", err)
		}
		seen[id] = struct{}{}
	}

	// With 65536 possible values and 10000 samples,
	// collisions are expected but unique count should be high (>9900)
	if len(seen) < 9000 {
		t.Errorf("expected >9000 unique IDs out of %d, got %d (possible weak randomness)", count, len(seen))
	}
}

func TestRandomTXIDNotZero(t *testing.T) {
	// Generate many IDs — none should all be zero (basic sanity)
	allZero := true
	for i := 0; i < 100; i++ {
		id, err := randomTXID()
		if err != nil {
			t.Fatalf("randomTXID error: %v", err)
		}
		if id != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("all 100 IDs were zero — randomness is broken")
	}
}

// --- 0x20 case randomization tests ---

func TestRandomizeCase_PreservesLength(t *testing.T) {
	names := []string{"example.com", "EXAMPLE.COM", "a.b.c.d.e", "123.456"}
	for _, name := range names {
		result := randomizeCase(name)
		if len(result) != len(name) {
			t.Errorf("randomizeCase(%q) changed length: %d → %d", name, len(name), len(result))
		}
	}
}

func TestRandomizeCase_PreservesNonAlpha(t *testing.T) {
	name := "123.456-789"
	result := randomizeCase(name)
	if result != name {
		t.Errorf("randomizeCase should not change non-alpha chars: %q → %q", name, result)
	}
}

func TestRandomizeCase_EmptyAndDot(t *testing.T) {
	if randomizeCase("") != "" {
		t.Error("empty string should pass through")
	}
	if randomizeCase(".") != "." {
		t.Error("root dot should pass through")
	}
}

func TestRandomizeCase_CaseInsensitiveEqual(t *testing.T) {
	name := "Example.Com"
	for i := 0; i < 100; i++ {
		result := randomizeCase(name)
		if strings.ToLower(result) != strings.ToLower(name) {
			t.Errorf("randomizeCase broke the domain: %q → %q", name, result)
		}
	}
}

func TestRandomizeCase_ProducesVariation(t *testing.T) {
	name := "abcdefghijklmnopqrstuvwxyz"
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		seen[randomizeCase(name)] = struct{}{}
	}
	// With 26 letters, the odds of getting the same output 100 times is negligible
	if len(seen) < 5 {
		t.Errorf("expected variation in randomizeCase, only got %d unique results", len(seen))
	}
}

func TestValidateResponseQuestionEx_CaseSensitive(t *testing.T) {
	msg := &dns.Message{
		Questions: []dns.Question{{Name: "ExAmPlE.CoM", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	// Case-sensitive match
	if err := validateResponseQuestionEx(msg, "ExAmPlE.CoM", dns.TypeA, dns.ClassIN, true); err != nil {
		t.Errorf("exact case should match: %v", err)
	}
	// Case-sensitive mismatch
	if err := validateResponseQuestionEx(msg, "example.com", dns.TypeA, dns.ClassIN, true); err == nil {
		t.Error("case-sensitive should reject different case")
	}
	// Case-insensitive still works
	if err := validateResponseQuestionEx(msg, "example.com", dns.TypeA, dns.ClassIN, false); err != nil {
		t.Errorf("case-insensitive should accept: %v", err)
	}
}

// --- EDNS0 advertised UDP buffer size (DNS Flag Day 2020 / RFC 9018) ---

func TestAdvertisedUDPBufferSize_DefaultsTo1232WhenZero(t *testing.T) {
	r := &Resolver{config: ResolverConfig{}}
	if got := r.advertisedUDPBufferSize(); got != 1232 {
		t.Errorf("zero config must fall back to 1232, got %d", got)
	}
}

func TestAdvertisedUDPBufferSize_HonorsConfiguredValue(t *testing.T) {
	cases := []struct {
		configured int
		want       uint16
	}{
		{512, 512},     // RFC 6891 mandated minimum
		{1232, 1232},   // DNS Flag Day 2020 default
		{4096, 4096},   // legacy default — operator may still want it
		{65535, 65535}, // max valid uint16
	}
	for _, c := range cases {
		r := &Resolver{config: ResolverConfig{UpstreamUDPBufferSize: c.configured}}
		if got := r.advertisedUDPBufferSize(); got != c.want {
			t.Errorf("UpstreamUDPBufferSize=%d: got %d, want %d", c.configured, got, c.want)
		}
	}
}

func TestAdvertisedUDPBufferSize_RejectsOutOfRange(t *testing.T) {
	// Pathological values must fall back to the safe 1232 default rather
	// than be propagated into outgoing OPT records.
	cases := []int{-1, 0, 1, 511, 65536, 1 << 30}
	for _, v := range cases {
		r := &Resolver{config: ResolverConfig{UpstreamUDPBufferSize: v}}
		if got := r.advertisedUDPBufferSize(); got != 1232 {
			t.Errorf("UpstreamUDPBufferSize=%d should fall back to 1232, got %d", v, got)
		}
	}
}

// TestSendQueryAdvertisesConfiguredBuffer verifies that the EDNS0 OPT
// record on the wire carries the configured UDP buffer size in its
// Class field — the actual security-relevant property.
func TestSendQueryAdvertisesConfiguredBuffer(t *testing.T) {
	var capturedBuf atomic.Uint32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		for _, rr := range q.Additional {
			if rr.Type == dns.TypeOPT {
				capturedBuf.Store(uint32(rr.Class))
			}
		}
		return &dns.Message{
			Header: dns.Header{
				Flags: dns.NewFlagBuilder().SetQR(true).Build(),
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 60, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	r.config.UpstreamUDPBufferSize = 1232

	if _, err := r.queryUpstream(mock.ip, "buf.example.com", dns.TypeA, dns.ClassIN); err != nil {
		t.Fatalf("queryUpstream error: %v", err)
	}
	if got := capturedBuf.Load(); got != 1232 {
		t.Errorf("OPT.Class on wire: got %d, want 1232", got)
	}
}

// TestSendQueryAdvertisesDefaultBufferWhenUnset verifies that an
// unconfigured resolver still sends the safe 1232-byte buffer rather
// than the legacy 4096 default.
func TestSendQueryAdvertisesDefaultBufferWhenUnset(t *testing.T) {
	var capturedBuf atomic.Uint32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		for _, rr := range q.Additional {
			if rr.Type == dns.TypeOPT {
				capturedBuf.Store(uint32(rr.Class))
			}
		}
		return &dns.Message{
			Header: dns.Header{
				Flags: dns.NewFlagBuilder().SetQR(true).Build(),
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 60, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	})
	defer mock.close()

	// Construct a resolver without setting UpstreamUDPBufferSize.
	r := testResolver(t, mock)
	r.config.UpstreamUDPBufferSize = 0

	if _, err := r.queryUpstream(mock.ip, "default.example.com", dns.TypeA, dns.ClassIN); err != nil {
		t.Fatalf("queryUpstream error: %v", err)
	}
	if got := capturedBuf.Load(); got != 1232 {
		t.Errorf("unset config should yield 1232 on wire, got %d", got)
	}
}
