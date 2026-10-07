package resolver

import "testing"

func TestInfraCache_LameZoneIdentity(t *testing.T) {
	ic := NewInfraCache()
	forms := []string{"Example.COM.", "example.com", "EXAMPLE.COM"}
	for _, name := range forms {
		ic.RecordLame("192.0.2.1", name)
	}
	for _, name := range forms {
		if !ic.IsLame("192.0.2.1", name) {
			t.Errorf("same zone %q not recognized", name)
		}
	}
	if got := len(ic.entries["192.0.2.1"].LameZones); got != 1 {
		t.Errorf("duplicate identities: %d, want 1", got)
	}
	if ic.IsLame("192.0.2.1", "other.example") || ic.IsLame("192.0.2.2", "example.com") || NewInfraCache().IsLame("192.0.2.1", "example.com") {
		t.Fatal("unrelated NS/zone was marked lame")
	}
}
