package cache

import (
	"bytes"
	"sort"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// Aggressive NXDOMAIN synthesis needs a full denial proof, not one covering
// interval (RFC 4035 §5.4, RFC 5155 §8.4, RFC 8198 §5.2/§5.3). With coverage
// alone, one seeding query let the cache answer AD=1 NXDOMAIN for every name
// in a delegated child zone, for empty non-terminals, and for names a
// wildcard synthesises.

func proofNSEC(owner, next string, types []uint16) dns.ResourceRecord {
	rdata := append(nameToDNSWire(next), serialiseTypeBitmap(types)...)
	return dns.ResourceRecord{Name: owner, Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 300, RData: rdata, RDLength: uint16(len(rdata))}
}

type proofNSEC3Name struct {
	name  string
	types []uint16
}

// proofNSEC3Chain builds a zone's complete, non-opt-out NSEC3 chain.
func proofNSEC3Chain(zone string, names []proofNSEC3Name) []dns.ResourceRecord {
	type link struct {
		hash  []byte
		types []uint16
	}
	links := make([]link, 0, len(names))
	for _, n := range names {
		links = append(links, link{nsec3Hash(n.name), n.types})
	}
	sort.Slice(links, func(i, j int) bool { return bytes.Compare(links[i].hash, links[j].hash) < 0 })
	out := []dns.ResourceRecord{soaForZone(zone, 300, 300)}
	for i, l := range links {
		next := links[(i+1)%len(links)].hash
		rdata := append([]byte{1, 0, 0, 0, 0, byte(len(next))}, next...)
		rdata = append(rdata, serialiseTypeBitmap(l.types)...)
		out = append(out, dns.ResourceRecord{Name: nsec3Base32.EncodeToString(l.hash) + "." + zone, Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: rdata, RDLength: uint16(len(rdata))})
	}
	return out
}

func TestRFC8198_NSECNXDOMAINNeedsFullProof(t *testing.T) {
	apexToChild := proofNSEC("example.com", "child.example.com", []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC})
	for _, tc := range []struct {
		name            string
		nsecs           []dns.ResourceRecord
		provable, wrong string
	}{
		{"below a delegation", []dns.ResourceRecord{apexToChild, proofNSEC("child.example.com", "www.example.com", []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC})}, "d.example.com", "host.child.example.com"},
		{"empty non-terminal", []dns.ResourceRecord{proofNSEC("example.com", "a.b.example.com", []uint16{dns.TypeSOA, dns.TypeNS}), proofNSEC("a.b.example.com", "www.example.com", []uint16{dns.TypeA})}, "aa.example.com", "b.example.com"},
		{"wildcard not denied", []dns.ResourceRecord{proofNSEC("sub.example.com", "www.example.com", []uint16{dns.TypeA})}, "y.sub.example.com", "t.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(1024, 60, 86400, 3600, nil)
			c.RegisterNSECInterval("example.com", 300, append([]dns.ResourceRecord{soaForZone("example.com", 300, 300)}, tc.nsecs...))
			if e, ok := c.LookupNSECCoversTyped(tc.provable, dns.TypeA, dns.ClassIN); !ok || e.RCODE != dns.RCodeNXDomain {
				t.Fatalf("%s has a full proof but was not synthesised", tc.provable)
			}
			if e, ok := c.LookupNSECCoversTyped(tc.wrong, dns.TypeA, dns.ClassIN); ok && e.RCODE == dns.RCodeNXDomain {
				t.Fatalf("%s synthesised as NXDOMAIN without a proof of nonexistence", tc.wrong)
			}
		})
	}
}

func TestRFC8198_NSEC3NXDOMAINNeedsClosestEncloserProof(t *testing.T) {
	apex := proofNSEC3Name{"example.com", []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3PARAM}}
	for _, tc := range []struct {
		name            string
		names           []proofNSEC3Name
		provable, wrong string
	}{
		{"below a delegation", []proofNSEC3Name{apex, {"child.example.com", []uint16{dns.TypeNS}}}, "nx.example.com", "www.child.example.com"},
		{"wildcard exists", []proofNSEC3Name{apex, {"*.example.com", []uint16{dns.TypeA}}, {"sub.example.com", []uint16{dns.TypeA}}}, "y.sub.example.com", "t.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(1024, 60, 86400, 3600, nil)
			c.RegisterNSEC3Interval("example.com", 300, proofNSEC3Chain("example.com", tc.names))
			if e, ok := c.LookupNSEC3CoversTyped(tc.provable, dns.TypeA, dns.ClassIN); !ok || e.RCODE != dns.RCodeNXDomain {
				t.Fatalf("%s has a closest-encloser proof but was not synthesised", tc.provable)
			}
			if e, ok := c.LookupNSEC3CoversTyped(tc.wrong, dns.TypeA, dns.ClassIN); ok && e.RCODE == dns.RCodeNXDomain {
				t.Fatalf("%s synthesised as NXDOMAIN without a closest-encloser proof", tc.wrong)
			}
		})
	}
}
