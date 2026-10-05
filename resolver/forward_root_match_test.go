package resolver

import "testing"

func TestForwardTableMatchRoot(t *testing.T) {
	for _, root := range []string{".", ""} {
		ft := NewForwardTable([]ForwardZone{
			{Name: root, Addrs: []string{"192.0.2.53"}},
			{Name: "EXAMPLE.TEST.", Addrs: []string{"192.0.2.54"}},
		})
		for _, tc := range []struct{ name, want string }{
			{"other.test", ""},
			{"OTHER.TEST.", ""},
			{"test", ""},
			{".", ""},
			{"example.test", "example.test"},
			{"a.example.test", "example.test"},
		} {
			z := ft.Match(tc.name)
			if z == nil || z.Name != tc.want {
				t.Errorf("root %q, Match(%q) = %+v, want %q", root, tc.name, z, tc.want)
			}
		}
	}
	ft := NewForwardTable([]ForwardZone{{Name: "example.test"}})
	if z := ft.Match("other.test"); z != nil {
		t.Errorf("unconfigured root matched: %+v", z)
	}
}
