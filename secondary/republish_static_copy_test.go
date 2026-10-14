package secondary

import (
	"sync"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// TestRepublishDoesNotWriteSharedStaticRecords pins that republish hands
// resolver.NewLocalZoneTable copies of the static records. That constructor
// normalises record names in place, and the static record arrays are shared
// with the live table (main.go builds it from the same zones) and with every
// concurrent republish, so writing them raced with queries on each transfer.
func TestRepublishDoesNotWriteSharedStaticRecords(t *testing.T) {
	static := []resolver.LocalZone{{Name: "Static.Example.", Type: resolver.LocalStatic, Records: []resolver.LocalRecord{
		{Name: "WWW.Static.Example.", Type: dns.TypeA, RData: []byte{192, 0, 2, 9}, TTL: 60},
	}}}
	m := NewManager(testResolver(t), static, nil, nil, discardLogger())

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			m.republish()
		}()
	}
	close(start)
	wg.Wait()

	if got := static[0].Records[0].Name; got != "WWW.Static.Example." {
		t.Fatalf("republish rewrote the caller's static record in place: %q", got)
	}
	if got := m.res.LocalZones().Lookup("www.static.example", dns.TypeA, dns.ClassIN); got == nil || len(got.Answers) != 1 {
		t.Fatal("static zone not served after republish")
	}
}
