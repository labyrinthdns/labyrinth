package server

import (
	"fmt"
	"sync"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/resolver"
)

func f001Result(t *testing.T, nAdditional int) *resolver.ResolveResult {
	m := &dns.Message{
		Header:    dns.Header{ID: 1, Flags: dns.NewFlagBuilder().SetQR(true).Build()},
		Questions: []dns.Question{{Name: "x.test", Type: dns.TypeA, Class: dns.ClassIN}},
		Answers:   []dns.ResourceRecord{{Name: "x.test", Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RDLength: 4, RData: []byte{192, 0, 2, 1}}},
	}
	for i := 0; i < nAdditional; i++ {
		m.Additional = append(m.Additional, dns.ResourceRecord{Name: fmt.Sprintf("ns%d.x.test", i), Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RDLength: 4, RData: []byte{192, 0, 2, byte(10 + i)}})
	}
	packed, err := dns.Pack(m, make([]byte, 4096))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	u, err := dns.Unpack(packed)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return &resolver.ResolveResult{RCODE: dns.RCodeNoError, Answers: u.Answers, Additional: u.Additional}
}

func f001Query(size uint16) *dns.Message {
	return &dns.Message{
		Header:    dns.Header{ID: 7, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
		Questions: []dns.Question{{Name: "x.test", Type: dns.TypeA, Class: dns.ClassIN}},
		EDNS0:     &dns.EDNS0{UDPSize: size, DOFlag: true},
	}
}

// TestBuildResponse_DoesNotMutateSharedAdditional pins that buildResponse never
// writes into the backing array of result.Additional. Coalesced waiters in the
// resolver share one *ResolveResult, so such a write races between clients.
func TestBuildResponse_DoesNotMutateSharedAdditional(t *testing.T) {
	h := testHandler()

	t.Run("spare capacity untouched", func(t *testing.T) {
		for _, n := range []int{0, 1, 3, 5} {
			res := f001Result(t, n)
			l, c := len(res.Additional), cap(res.Additional)
			if _, err := h.buildResponse(f001Query(4096), res); err != nil {
				t.Fatal(err)
			}
			if len(res.Additional) != l {
				t.Fatalf("n=%d: len changed %d -> %d", n, l, len(res.Additional))
			}
			for i := l; i < c; i++ {
				if typ := res.Additional[:c][i].Type; typ != 0 {
					t.Fatalf("n=%d: spare slot %d written (Type=%d)", n, i, typ)
				}
			}
		}
	})

	t.Run("repeated calls keep the shared result intact", func(t *testing.T) {
		res := f001Result(t, 3)
		for i := 0; i < 3; i++ {
			if _, err := h.buildResponse(f001Query(4096), res); err != nil {
				t.Fatal(err)
			}
		}
		if len(res.Additional) != 3 || res.Additional[:cap(res.Additional)][3].Type != 0 {
			t.Fatalf("shared result mutated: %+v", res.Additional)
		}
	})

	t.Run("concurrent waiters each get their own OPT", func(t *testing.T) {
		res := f001Result(t, 3)
		sizes := []uint16{1232, 4096}
		start := make(chan struct{})
		out := make([][]byte, len(sizes))
		var wg sync.WaitGroup
		for i, s := range sizes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				b, err := h.buildResponse(f001Query(s), res)
				if err != nil {
					t.Errorf("build: %v", err)
				}
				out[i] = b
			}()
		}
		close(start)
		wg.Wait()
		for i, s := range sizes {
			msg, err := dns.Unpack(out[i])
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if msg.EDNS0 == nil || msg.EDNS0.UDPSize != h.advertisedUDPBufferSize() {
				t.Fatalf("size %d: missing/incorrect OPT: %+v", s, msg.EDNS0)
			}
		}
	})
	fmt.Println("FIX VERIFIED")
}
