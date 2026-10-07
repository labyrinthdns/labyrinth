package xfr

import (
	"fmt"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestXFR_IXFREmptyFullFallback(t *testing.T) {
	soa := testSOA(t, "example.com", 3)
	for split := 0; split <= 2; split++ {
		t.Run(fmt.Sprintf("split_%d", split), func(t *testing.T) {
			records := []dns.ResourceRecord{soa, soa}
			parts := [][]dns.ResourceRecord{records}
			if split == 1 {
				parts = [][]dns.ResourceRecord{records[:split], records[split:]}
			}
			got, err := readMemoryIXFR(t, parts, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got.Incremental || got.UpToDate || len(got.Records) != 1 || len(got.Deltas) != 0 || got.Serial != 3 {
				t.Fatalf("empty full fallback = %+v, want one SOA and no deltas", got)
			}
		})
	}
}
