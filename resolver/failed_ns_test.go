package resolver

import "testing"

func TestVisitedSet_FailedIP(t *testing.T) {
	v := newVisitedSet()
	if v.IsFailedIP("1.2.3.4") {
		t.Fatal("unexpected failed IP before mark")
	}
	v.MarkFailedIP("1.2.3.4")
	if !v.IsFailedIP("1.2.3.4") {
		t.Fatal("expected failed IP after mark")
	}
	if v.IsFailedIP("8.8.8.8") {
		t.Fatal("other IP should not be failed")
	}
}

func TestExcludeNSIP_ClearsGlueKeepsHostname(t *testing.T) {
	in := []nsEntry{
		{hostname: "ns1.example.", ipv4: "203.0.113.1"},
		{hostname: "ns2.example.", ipv4: "203.0.113.2", ipv6: "2001:db8::2"},
	}
	out := excludeNSIP(in, "203.0.113.1")
	if len(out) != 2 {
		t.Fatalf("len=%d want 2", len(out))
	}
	if out[0].hostname != "ns1.example." || out[0].ipv4 != "" {
		t.Fatalf("ns1 not cleared: %+v", out[0])
	}
	if out[1].ipv4 != "203.0.113.2" {
		t.Fatalf("ns2 altered: %+v", out[1])
	}
}
