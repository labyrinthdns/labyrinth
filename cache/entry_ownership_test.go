package cache

import (
	"github.com/labyrinthdns/labyrinth/dns"
	"testing"
)

func TestEntrySnapshotsOwnMutableData(t *testing.T) {
	source := &Entry{Records: []dns.ResourceRecord{{Name: "original", RData: []byte{1}}}, Authority: []dns.ResourceRecord{{RData: []byte{2}}}, SOA: &dns.ResourceRecord{Name: "original-soa", RData: []byte{3}}}
	snapshot := source.WithDecayedTTL(10)
	snapshot.Records[0].Name = "changed"
	if source.Records[0].Name != "original" {
		t.Fatal("unaffected struct-copy control failed")
	}
	gate, done := make(chan struct{}), make(chan struct{})
	go func() {
		<-gate
		snapshot.Records[0].RData[0] = 9
		snapshot.Authority[0].RData[0] = 9
		snapshot.SOA.Name = "changed-soa"
		snapshot.SOA.RData[0] = 9
		close(done)
	}()
	replacementSnapshot := source.WithDecayedTTL(5)
	close(gate)
	<-done
	t.Logf("EXPECTED: source/sibling bytes=1,2,3 SOA=original-soa ACTUAL: %d,%d,%d SOA=%s sibling=%d", source.Records[0].RData[0], source.Authority[0].RData[0], source.SOA.RData[0], source.SOA.Name, replacementSnapshot.Records[0].RData[0])
	bad := source.Records[0].RData[0] != 1 || source.Authority[0].RData[0] != 2 || source.SOA.RData[0] != 3 || source.SOA.Name != "original-soa" || replacementSnapshot.Records[0].RData[0] != 1
	auth := []dns.ResourceRecord{soaForZone("example.com", 300, 300)}
	c := NewCache(1000, 1, 86400, 3600, nil)
	c.StoreNegative("missing.example.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, auth)
	auth[0].Name = "caller-mutated"
	got, ok := c.Get("missing.example.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("negative control absent")
	}
	t.Logf("EXPECTED: stored SOA=example.com ACTUAL: SOA=%s authority=%s", got.SOA.Name, got.Authority[0].Name)
	if got.Authority[0].Name != "example.com" {
		t.Fatal("authority clone control failed")
	}
	if bad || got.SOA.Name != "example.com" {
		t.Fatal("PROBLEM CONFIRMED")
	}
	empty := (&Entry{}).WithDecayedTTL(0)
	if len(empty.Records) != 0 || len(empty.Authority) != 0 || empty.SOA != nil {
		t.Fatal("empty edge failed")
	}
	repeated := source.WithDecayedTTL(0)
	repeated.Records[0].RData[0] = 8
	if source.Records[0].RData[0] != 1 {
		t.Fatal("repeat edge failed")
	}
	t.Log("FIX VERIFIED")
}
