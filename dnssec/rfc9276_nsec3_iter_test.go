package dnssec

import (
	"errors"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestVerifyNSEC3Denial5155_MixedIterations_RejectAllAtCap pins RFC
// 9276 §3.2: the iteration cap (MaxNSEC3Iterations = 100) MUST apply
// to every NSEC3 record in the denial proof, not just records[0].
// An attacker who controls one record in the bundle could otherwise
// slip a 1000-iteration NSEC3 past the gate by ordering a low-iter
// record first — and force the validator into a CPU-amplified hash
// walk for every NXDOMAIN proof against that zone (RFC 9276 §2.1's
// "Hash Calculations" DoS).
//
// The cap behaviour is: VerifyNSEC3Denial5155 returns errTooManyIterations,
// validator.go:1450 maps that to Indeterminate, and the resolver in turn
// reports DNSSECStatus="insecure" (RFC 9276 §3.2: "validating resolvers
// SHOULD return an insecure response when processing NSEC3 records with
// iterations larger than 100" — insecure, not bogus).
//
// We pin three positions of the offending record (first / middle / last)
// to make the order-independence explicit.
func TestVerifyNSEC3Denial5155_MixedIterations_RejectAllAtCap(t *testing.T) {
	const highIter uint16 = MaxNSEC3Iterations + 1

	mkRecord := func(iter uint16) NSEC3RecordWithOwner {
		return NSEC3RecordWithOwner{
			OwnerHash: []byte{0xAB, 0xCD},
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1,
				Iterations:    iter,
				Salt:          nil,
				NextHash:      []byte{0x01},
			},
		}
	}

	cases := []struct {
		name    string
		records []NSEC3RecordWithOwner
	}{
		{"high-iter first", []NSEC3RecordWithOwner{
			mkRecord(highIter), mkRecord(10), mkRecord(20),
		}},
		{"high-iter middle", []NSEC3RecordWithOwner{
			mkRecord(10), mkRecord(highIter), mkRecord(20),
		}},
		{"high-iter last", []NSEC3RecordWithOwner{
			mkRecord(10), mkRecord(20), mkRecord(highIter),
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := VerifyNSEC3Denial5155("missing.example.com",
				dns.TypeA, dns.RCodeNXDomain, c.records)
			if !errors.Is(err, errTooManyIterations) {
				t.Errorf("err = %v, want errTooManyIterations — RFC 9276 §3.2 iteration cap must reject regardless of position", err)
			}
			if ok {
				t.Errorf("denial proof accepted despite over-cap iteration count — RFC 9276 §3.2 violation")
			}
		})
	}
}

// TestVerifyNSEC3Denial5155_AtCap_StillProcessed pins the boundary
// case: exactly MaxNSEC3Iterations (100) is the documented hard
// ceiling — records AT the cap must still be processed (the rejection
// is `> MaxNSEC3Iterations`, not `>=`). If a refactor swapped the
// operator, every legitimately-signed zone at the BIND 9.18+ /
// Unbound 1.16+ default of 100 iterations would suddenly fall over.
//
// We only need to reach past the iteration gate; the proof itself
// won't validate (we feed garbage records) — what matters is that
// the rejection mode is NOT errTooManyIterations.
func TestVerifyNSEC3Denial5155_AtCap_StillProcessed(t *testing.T) {
	records := []NSEC3RecordWithOwner{{
		OwnerHash: []byte{0xAB, 0xCD},
		NSEC3Record: dns.NSEC3Record{
			HashAlgorithm: 1,
			Iterations:    MaxNSEC3Iterations, // exactly at the cap
			Salt:          nil,
			NextHash:      []byte{0x01},
		},
	}}

	_, err := VerifyNSEC3Denial5155("missing.example.com",
		dns.TypeA, dns.RCodeNXDomain, records)
	if errors.Is(err, errTooManyIterations) {
		t.Errorf("iteration count == MaxNSEC3Iterations rejected as too-many — cap boundary is inclusive (RFC 9276 §3.2 / BIND 9.18 default)")
	}
}
