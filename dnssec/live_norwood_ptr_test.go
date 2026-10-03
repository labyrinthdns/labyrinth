package dnssec

import (
	"log/slog"
	"os"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestLive_NorwoodPTR_SignedCNAME_NotBogus(t *testing.T) {
	if testing.Short() {
		t.Skip("live")
	}
	name := "205.123.59.199.in-addr.arpa"
	resp, err := fetchAuth(name, dns.TypePTR)
	if err != nil {
		t.Skip(err)
	}
	v := NewValidator(udpRecurseQuerier{addr: "1.1.1.1:53"}, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	verdict, steps := v.ValidateResponseDetailed(resp, name, dns.TypeCNAME)
	t.Logf("TypeCNAME verdict=%v answers=%d", verdict, len(resp.Answers))
	for _, s := range steps {
		t.Logf("  stage=%s outcome=%s detail=%s alg=%d key=%d owner=%s",
			s.Stage, s.Outcome, s.Detail, s.Algorithm, s.KeyTag, s.Owner)
	}
	if verdict == Bogus {
		t.Fatalf("signed CNAME + unsigned cross-zone follow marked Bogus")
	}
}
