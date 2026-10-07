package blocklist

import "testing"

func TestManager_CheckDomainRPZ(t *testing.T) {
	m := NewManager(ManagerConfig{}, newTestLogger())
	m.matcher.Load().AddExact("ordinary.example")
	m.rpzMatcher.Load().AddRule(RPZRule{Name: "rpz.example", Action: RPZAction{Type: RPZActionNXDomain}})
	m.rpzMatcher.Load().AddRule(RPZRule{Name: "allowed.example", Action: RPZAction{Type: RPZActionPassthru}})
	for _, tc := range []struct {
		name    string
		blocked bool
	}{{"rpz.example", true}, {"RPZ.Example.", true}, {"ordinary.example", true}, {"allowed.example", false}, {"safe.example", false}, {"", false}} {
		if got := m.CheckDomain(tc.name); got != tc.blocked {
			t.Errorf("CheckDomain(%q)=%v, want %v", tc.name, got, tc.blocked)
		}
	}
	if got := m.blockedTotal.Load(); got != 0 {
		t.Fatalf("read-only checks changed counter to %d", got)
	}
}
