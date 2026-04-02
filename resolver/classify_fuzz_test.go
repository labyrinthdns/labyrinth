package resolver

import (
	"testing"

	"github.com/labyrinth-dns/labyrinth/dns"
)

func FuzzClassifyResponse(f *testing.F) {
	// Seed: simple NOERROR response with 1 answer
	f.Add(
		uint16(0x8180), // flags: QR=1, RD=1, RA=1, RCODE=0
		uint8(1),       // answer count
		uint8(0),       // authority count
		uint16(dns.TypeA),
		uint16(dns.TypeCNAME),
		uint16(dns.TypeNS),
		uint16(dns.TypeSOA),
	)
	// Seed: NXDOMAIN
	f.Add(
		uint16(0x8183), // RCODE=3
		uint8(0),
		uint8(1),
		uint16(dns.TypeA),
		uint16(0),
		uint16(0),
		uint16(dns.TypeSOA),
	)
	// Seed: referral (NS in authority, no SOA)
	f.Add(
		uint16(0x8100), // RCODE=0, no answers
		uint8(0),
		uint8(1),
		uint16(dns.TypeA),
		uint16(0),
		uint16(dns.TypeNS),
		uint16(0),
	)
	// Seed: SERVFAIL
	f.Add(
		uint16(0x8182), // RCODE=2
		uint8(0),
		uint8(0),
		uint16(dns.TypeA),
		uint16(0),
		uint16(0),
		uint16(0),
	)

	f.Fuzz(func(t *testing.T, flags uint16, anCount, nsCount uint8,
		ansType, ansCnameType, authType, authSoaType uint16) {

		// Build answers
		var answers []dns.ResourceRecord
		for i := 0; i < int(anCount%8); i++ {
			rr := dns.ResourceRecord{
				Name:  "example.com",
				Class: dns.ClassIN,
				TTL:   300,
			}
			if i == 0 {
				rr.Type = ansType
			} else {
				rr.Type = ansCnameType
			}
			answers = append(answers, rr)
		}

		// Build authority
		var authority []dns.ResourceRecord
		for i := 0; i < int(nsCount%8); i++ {
			rr := dns.ResourceRecord{
				Name:  "example.com",
				Class: dns.ClassIN,
				TTL:   300,
			}
			if i == 0 {
				rr.Type = authType
			} else {
				rr.Type = authSoaType
			}
			authority = append(authority, rr)
		}

		msg := &dns.Message{
			Header: dns.Header{
				Flags:   flags,
				QDCount: 1,
				ANCount: uint16(len(answers)),
				NSCount: uint16(len(authority)),
			},
			Questions: []dns.Question{{
				Name:  "example.com",
				Type:  dns.TypeA,
				Class: dns.ClassIN,
			}},
			Answers:   answers,
			Authority: authority,
		}

		result := classifyResponse(msg, "example.com", dns.TypeA)

		// Verify result is a valid responseType (0 through 5).
		if result < responseAnswer || result > responseServFail {
			t.Fatalf("classifyResponse returned invalid responseType: %d", result)
		}
	})
}
