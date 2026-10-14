package resolver

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestSendQuery_Caps0x20FallbackForCaseFoldingServer pins the 0x20 fallback.
// Some authoritatives lowercase the question instead of echoing it (live:
// ns0/ns1.easynet.co.uk), so every answer failed the 0x20 check and their
// zones were SERVFAIL while public resolvers answered. The mismatching
// answer is still dropped; the query is asked again without 0x20 and the
// server is then remembered, so later queries go out without 0x20 at once.
func TestSendQuery_Caps0x20FallbackForCaseFoldingServer(t *testing.T) {
	var queries atomic.Int32
	var mixedCase atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queries.Add(1)
		name := q.Questions[0].Name
		if name != strings.ToLower(name) {
			mixedCase.Add(1)
		}
		qs := []dns.Question{{Name: strings.ToLower(name), Type: q.Questions[0].Type, Class: q.Questions[0].Class}}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(), QDCount: 1, ANCount: 1},
			Questions: qs,
			Answers: []dns.ResourceRecord{{
				Name: qs[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RDLength: 4, RData: []byte{192, 0, 2, 1},
			}},
		}
	})
	defer mock.close()
	r := testResolver(t, mock)
	r.config.Caps0x20Enabled = true

	// A name with enough letters that randomizeCase almost surely mixes it.
	const name = "case-folding-authoritative.example.com"
	msg, err := r.sendQuery(mock.ip, name, dns.TypeA, dns.ClassIN, true, nil, nil)
	if err != nil || msg == nil || len(msg.Answers) != 1 {
		t.Fatalf("first query: msg=%v err=%v, want the answer after the no-0x20 retry", msg, err)
	}
	if !r.noCapsServers.Has(mock.ip) {
		t.Fatal("case-folding server was not remembered")
	}
	before := queries.Load()
	mixedBefore := mixedCase.Load()
	if _, err := r.sendQuery(mock.ip, name, dns.TypeA, dns.ClassIN, true, nil, nil); err != nil {
		t.Fatalf("second query: %v", err)
	}
	if n := queries.Load() - before; n != 1 {
		t.Errorf("second query sent %d packets, want 1", n)
	}
	if mixedCase.Load() != mixedBefore {
		t.Error("second query still used 0x20 case")
	}
}

// TestSendQuery_Caps0x20WrongNameNotRetried: only a case-only difference is
// retried. A different name is a plain mismatch and the server is not
// marked.
func TestSendQuery_Caps0x20WrongNameNotRetried(t *testing.T) {
	var queries atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queries.Add(1)
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(), QDCount: 1},
			Questions: []dns.Question{{Name: "other.example.com", Type: q.Questions[0].Type, Class: q.Questions[0].Class}},
		}
	})
	defer mock.close()
	r := testResolver(t, mock)
	r.config.Caps0x20Enabled = true

	_, err := r.sendQuery(mock.ip, "asked.example.com", dns.TypeA, dns.ClassIN, true, nil, nil)
	if err == nil || errors.Is(err, errCaseMismatch) {
		t.Fatalf("err=%v, want a plain question mismatch", err)
	}
	if n := queries.Load(); n != 1 {
		t.Errorf("sent %d packets, want 1 (no retry)", n)
	}
	if r.noCapsServers.Has(mock.ip) {
		t.Error("server marked case-folding after a different-name answer")
	}
}

// TestQueryUpstream_Caps0x20TimeoutRetriedLowercase pins the timeout side of
// the 0x20 fallback. Two of the isnet.net.tr NS sit behind a balancer that
// silently drops most mixed-case spellings and never a lowercase one, so
// both 0x20 attempts timed out and the zone needed the public fallback.
// After a 0x20 timeout the last retry goes out lowercase (as Unbound's
// capsforid fallback does on timeouts); the server loses 0x20 only after
// this happens twice.
func TestQueryUpstream_Caps0x20TimeoutRetriedLowercase(t *testing.T) {
	var mixedCase atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		name := q.Questions[0].Name
		if name != strings.ToLower(name) {
			mixedCase.Add(1)
			return nil // dropped, like the balancer
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(), QDCount: 1, ANCount: 1},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RDLength: 4, RData: []byte{192, 0, 2, 1},
			}},
		}
	})
	defer mock.close()
	r := testResolver(t, mock)
	r.config.Caps0x20Enabled = true
	r.config.UpstreamTimeout = 200 * time.Millisecond

	const name = "ns1.atlpdns30.isnet-balancer.example.net"
	for i := 1; i <= 2; i++ {
		msg, err := r.queryUpstream(mock.ip, name, dns.TypeA, dns.ClassIN)
		if err != nil || msg == nil || len(msg.Answers) != 1 {
			t.Fatalf("query %d: msg=%v err=%v, want the answer from the lowercase retry", i, msg, err)
		}
		if got, want := r.noCapsServers.Has(mock.ip), i == 2; got != want {
			t.Fatalf("after query %d: noCaps=%v, want %v (only the second recovery disables 0x20)", i, got, want)
		}
	}

	// Now remembered: the next query goes out lowercase at once.
	before := mixedCase.Load()
	if _, err := r.queryUpstream(mock.ip, name, dns.TypeA, dns.ClassIN); err != nil {
		t.Fatalf("third query: %v", err)
	}
	if mixedCase.Load() != before {
		t.Error("0x20 spelling sent to a server remembered as dropping them")
	}
}

// TestQueryUpstream_DeadServerNotMarkedNoCaps: a server that answers
// nothing at all must not be moved off 0x20 by the timeout fallback.
func TestQueryUpstream_DeadServerNotMarkedNoCaps(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message { return nil })
	defer mock.close()
	r := testResolver(t, mock)
	r.config.Caps0x20Enabled = true
	r.config.UpstreamTimeout = 100 * time.Millisecond

	for i := 0; i < 3; i++ {
		if _, err := r.queryUpstream(mock.ip, "dead.example.net", dns.TypeA, dns.ClassIN); err == nil {
			t.Fatal("dead server answered")
		}
	}
	if r.noCapsServers.Has(mock.ip) || r.capsTimeoutSuspects.Has(mock.ip) {
		t.Error("dead server was marked as dropping 0x20")
	}
}
