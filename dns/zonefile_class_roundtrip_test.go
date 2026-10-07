package dns

import (
	"bytes"
	"fmt"
	"testing"
)

func TestFormatZone_ClassRoundTrip(t *testing.T) {
	for _, class := range []uint16{ClassIN, 3, 4, 254, 255} {
		t.Run(fmt.Sprintf("class %d", class), func(t *testing.T) {
			source := []ResourceRecord{
				{Name: "example.", Type: TypeSOA, Class: class, TTL: 300, RData: buildSOA(t, "ns.example.", "hostmaster.example.", 1, 2, 3, 4, 5)},
				{Name: "www.example.", Type: TypeA, Class: class, TTL: 300, RData: []byte{192, 0, 2, 1}},
				{Name: "example.", Type: TypeNS, Class: class, TTL: 300, RData: buildName(t, "ns.example.")},
			}
			text, err := FormatZone("example.", source)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseZone("example.", text)
			if err != nil || len(got) != len(source) {
				t.Fatalf("round trip: %v, count=%d", err, len(got))
			}
			for _, want := range source {
				found := false
				for _, record := range got {
					if record.Name == want.Name && record.Type == want.Type {
						found = true
						if record.Class != want.Class || record.TTL != want.TTL || !bytes.Equal(record.RData, want.RData) {
							t.Errorf("got %+v, want %+v", record, want)
						}
					}
				}
				if !found {
					t.Errorf("record missing: %+v", want)
				}
			}
		})
	}
}
