package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// testNegativeSOA returns an authority section holding an SOA for zone with
// a 300 s negative TTL. The cache does not store a NODATA without an SOA
// (RFC 2308 §5), so negative-cache fixtures need one.
func testNegativeSOA(t *testing.T, zone string) []dns.ResourceRecord {
	t.Helper()
	mname, err := dns.EncodeNameToBytes("ns1." + zone)
	if err != nil {
		t.Fatalf("encode mname: %v", err)
	}
	rname, err := dns.EncodeNameToBytes("admin." + zone)
	if err != nil {
		t.Fatalf("encode rname: %v", err)
	}
	rdata := append(append([]byte(nil), mname...), rname...)
	for _, v := range []uint32{1, 3600, 900, 604800, 300} {
		rdata = binary.BigEndian.AppendUint32(rdata, v)
	}
	return []dns.ResourceRecord{{
		Name: zone, Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300,
		RDLength: uint16(len(rdata)), RData: rdata,
	}}
}
