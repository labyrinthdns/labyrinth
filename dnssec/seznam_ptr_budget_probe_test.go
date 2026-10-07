//go:build live

package dnssec

import (
	"log/slog"
	"os"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestLive_SeznamIPv6PTR_NotBogus pins the deep-reverse crypto-budget floor:
// seznam.cz IPv6 PTRs under 0.0.a.8.4.6.0.0.8.9.5.0.2.0.a.2.ip6.arpa require
// more than the old maxCryptoVerifyPerResponse=32 signature checks (NSEC
// covers under RIPE + NSEC3 ENTs under the seznam parent). Cap exhaustion
// used to yield Bogus→fallback while public resolvers returned Secure.
func TestLive_SeznamIPv6PTR_NotBogus(t *testing.T) {
	if testing.Short() {
		t.Skip("live")
	}
	name := "3.4.3.0.2.0.3.0.0.0.0.0.0.0.0.0.0.0.a.8.4.6.0.0.8.9.5.0.2.0.a.2.ip6.arpa."
	resp, err := fetchAuth(name, dns.TypePTR)
	if err != nil {
		t.Skip(err)
	}
	v := NewValidator(udpRecurseQuerier{addr: "1.1.1.1:53"}, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	verdict, steps := v.ValidateResponseDetailed(resp, name, dns.TypePTR)
	t.Logf("verdict=%v cryptoCap=%d", verdict, maxCryptoVerifyPerResponse)
	for _, s := range steps {
		t.Logf("  stage=%s outcome=%s detail=%s", s.Stage, s.Outcome, s.Detail)
	}
	if verdict == Bogus {
		t.Fatalf("seznam ipv6 PTR marked Bogus (public resolvers Secure it)")
	}
	if verdict != Secure {
		t.Fatalf("want Secure, got %v", verdict)
	}
}
