package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestLocalZoneTable_FindZoneExact(t *testing.T) {
	table := NewLocalZoneTable([]LocalZone{
		{Name: "example.local", Type: LocalRefuse},
		{Name: "sub.example.local", Type: LocalDeny},
	})
	for _, tc := range []struct {
		name string
		want string
	}{
		{"example.local", "example.local"},
		{"EXAMPLE.LOCAL.", "example.local"},
		{"sub.example.local", "sub.example.local"},
		{"missing.example.local", ""},
		{"host.sub.example.local", ""},
		{"outside.local", ""},
		{"", ""},
	} {
		got := table.FindZone(tc.name)
		if tc.want == "" {
			if got != nil {
				t.Errorf("FindZone(%q) = %q, want nil", tc.name, got.Name)
			}
		} else if got == nil || got.Name != tc.want {
			t.Errorf("FindZone(%q) = %v, want %q", tc.name, got, tc.want)
		}
	}
	var nilTable *LocalZoneTable
	if nilTable.FindZone("example.local") != nil || NewLocalZoneTable(nil).FindZone("example.local") != nil {
		t.Fatal("nil and empty tables must not return a zone")
	}
	result := table.Lookup("host.sub.example.local", dns.TypeA, dns.ClassIN)
	if result == nil || result.DNSSECStatus != "local-deny" {
		t.Fatalf("Lookup must retain longest-suffix matching: %v", result)
	}
}
