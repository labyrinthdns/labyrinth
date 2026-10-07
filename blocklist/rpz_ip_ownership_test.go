package blocklist

import (
	"net"
	"testing"
)

func rpzGatedMutation(mutate func()) {
	release := make(chan struct{})
	done := make(chan struct{})
	go func() { <-release; mutate(); close(done) }()
	close(release)
	<-done
}
func TestRPZMatcher_IPOwnership(t *testing.T) {
	cases := []struct {
		name     string
		wildcard bool
		ip       net.IP
		action   RPZActionType
	}{
		{"exact_ipv4", false, net.IP{192, 0, 2, 1}, RPZActionLocalA},
		{"wildcard_ipv4", true, net.IP{192, 0, 2, 1}, RPZActionLocalA},
		{"exact_ipv6", false, net.ParseIP("2001:db8::1"), RPZActionLocalAAAA},
		{"wildcard_ipv6", true, net.ParseIP("2001:db8::1"), RPZActionLocalAAAA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewRPZMatcher()
			want := tc.ip.String()
			query := "redirect.example"
			if tc.wildcard {
				query = "sub.redirect.example"
			}
			m.AddRule(RPZRule{Name: "redirect.example", IsWildcard: tc.wildcard, Action: RPZAction{Type: tc.action, IP: tc.ip}})
			rpzGatedMutation(func() { tc.ip[len(tc.ip)-1] = 9 })
			first := m.Match(query)
			if first == nil || first.IP.String() != want {
				t.Fatalf("input mutation changed result: %+v, want %s", first, want)
			}
			rpzGatedMutation(func() { first.IP[len(first.IP)-1] = 7 })
			second := m.Match(query)
			if second == nil || second.IP.String() != want {
				t.Fatalf("output mutation changed result: %+v, want %s", second, want)
			}
		})
	}
	m := NewRPZMatcher()
	m.AddRule(RPZRule{Name: "blocked.example", Action: RPZAction{Type: RPZActionNXDomain}})
	if got := m.Match("blocked.example"); got == nil || got.IP != nil || got.Type != RPZActionNXDomain {
		t.Fatalf("non-IP action changed: %+v", got)
	}
	m.AddRule(RPZRule{Name: "allowed.example", Action: RPZAction{Type: RPZActionPassthru}})
	if m.Match("allowed.example") != nil || m.Match("") != nil {
		t.Fatal("passthru/empty behavior changed")
	}
}
