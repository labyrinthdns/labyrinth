package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestQueryFallback_TransportErrorHasNoResponseRCODE(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint8
		port string
	}{
		{"servfail-control", dns.RCodeServFail, ""},
		{"transport-overflow", dns.RCodeServFail, "70000"},
		{"transport-negative", dns.RCodeServFail, "-1"},
		{"noerror", dns.RCodeNoError, ""},
		{"nxdomain", dns.RCodeNXDomain, ""},
		{"refused", dns.RCodeRefused, ""},
		{"notimp", dns.RCodeNotImp, ""},
		{"repeated-transport", dns.RCodeServFail, "70000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
				return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(tc.code).Build(), QDCount: 1}, Questions: q.Questions}
			})
			defer mock.close()
			r := testResolver(t, mock)
			r.config.FallbackResolvers = []string{mock.ip}
			path := filepath.Join(t.TempDir(), "fallback.jsonl")
			r.fallbackLog = newFallbackFileLog(path)
			t.Cleanup(func() {
				if r.fallbackLog.f != nil {
					_ = r.fallbackLog.f.Close()
				}
			})
			if tc.port != "" {
				r.config.UpstreamPort = tc.port
			}
			result := r.queryFallback("example.com", dns.TypeA, dns.ClassIN, "SERVFAIL")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var rec fallbackLogRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatal(err)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			wantRCODE := rcodeName(tc.code)
			wantRecovery := tc.port == "" && (tc.code == dns.RCodeNoError || tc.code == dns.RCodeNXDomain)
			if tc.port != "" {
				wantRCODE = ""
				if rec.FallbackError == "" {
					t.Fatal("transport error missing")
				}
				if _, exists := raw["fallback_rcode"]; exists {
					t.Error("absent response code must be omitted")
				}
			} else if rec.FallbackError != "" {
				t.Errorf("unexpected transport error: %s", rec.FallbackError)
			}
			t.Logf("EXPECTED: RCODE=%q recovery=%v ACTUAL: RCODE=%q recovery=%v", wantRCODE, wantRecovery, rec.FallbackRCODE, rec.Recovered)
			if rec.FallbackRCODE != wantRCODE || rec.Recovered != wantRecovery || (result != nil) != wantRecovery || rec.FallbackTried != 1 {
				t.Fatalf("PROBLEM CONFIRMED: %+v", rec)
			}
		})
	}
	if !t.Failed() {
		t.Log("FIX VERIFIED")
	}
}
