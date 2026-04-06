package resolver

import (
	"strings"
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
