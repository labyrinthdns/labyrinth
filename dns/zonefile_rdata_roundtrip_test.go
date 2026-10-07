package dns

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestFormatRData_MappedAAAARoundTrip(t *testing.T) {
	for _, address := range []string{
		"2001:db8::1",
		"::",
		"::1",
		"::192.0.2.1",
		"::ffff:0:192.0.2.1",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"::ffff:192.0.2.1",
		"::ffff:0.0.0.0",
		"::ffff:0.0.0.1",
		"::ffff:255.255.255.255",
	} {
		t.Run(address, func(t *testing.T) {
			data := []byte(net.ParseIP(address).To16())
			record := ResourceRecord{Name: "address.example.", Type: TypeAAAA, Class: ClassIN, TTL: 300, RData: data}
			text, err := FormatRData(record)
			if err != nil || !strings.Contains(text, ":") {
				t.Fatalf("AAAA presentation = %q, err=%v; want IPv6 text", text, err)
			}
			if !bytes.Equal(net.ParseIP(text).To16(), data) {
				t.Fatalf("presentation %q changed address bytes %x", text, data)
			}
			zone, err := FormatZone("example.", []ResourceRecord{
				{Name: "example.", Type: TypeSOA, Class: ClassIN, TTL: 300,
					RData: buildSOA(t, "ns.example.", "hostmaster.example.", 1, 2, 3, 4, 5)},
				record,
			})
			if err != nil {
				t.Fatalf("FormatZone: %v", err)
			}
			parsed, err := ParseZone("example.", zone)
			if err != nil || len(parsed) != 2 {
				t.Fatalf("ParseZone: count=%d err=%v; zone=%s", len(parsed), err, zone)
			}
			var got *ResourceRecord
			for i := range parsed {
				if parsed[i].Type == TypeAAAA {
					got = &parsed[i]
				}
			}
			if got == nil || got.Name != record.Name || got.TTL != record.TTL || got.Class != record.Class || !bytes.Equal(got.RData, data) {
				t.Fatalf("AAAA round trip = %+v, want %+v", got, record)
			}
		})
	}
	for _, size := range []int{0, 4, 15, 17} {
		t.Run(fmt.Sprintf("invalid length %d", size), func(t *testing.T) {
			if _, err := FormatRData(ResourceRecord{Type: TypeAAAA, RData: make([]byte, size)}); err == nil {
				t.Fatalf("AAAA RDATA length %d accepted", size)
			}
		})
	}
	if got, err := FormatRData(ResourceRecord{Type: TypeA, RData: []byte{192, 0, 2, 1}}); err != nil || got != "192.0.2.1" {
		t.Fatalf("A presentation = %q, err=%v", got, err)
	}
}
