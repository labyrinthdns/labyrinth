package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestMinimalANY_HINFOFormat_RFC8482 pins RFC 8482 §4.5: the synthetic
// response to an ANY query MUST be a single HINFO RR with the CPU field
// set to "RFC8482" (so any DNS-debug tool can immediately tell why the
// answer looks weird) and an empty OS field. The purpose is to refuse
// the amplification surface ANY exposes — a real ANY response can carry
// hundreds of bytes per query, making it a favourite reflector for
// DDoS spoofed-source attacks. The HINFO is intentionally tiny (~25
// bytes total response) so the amplification factor drops to ≤ 1.
//
// A refactor that lost the "RFC8482" CPU label would silently strip the
// self-documenting hint and make the response indistinguishable from a
// real (and confusing) HINFO record served from the zone — leading to
// hours of debugging when an operator wonders why example.com appears
// to be running an obscure CPU architecture.
//
// We pin: (1) RCODE=NOERROR; (2) exactly one Answer; (3) Type=HINFO;
// (4) Class=IN; (5) TTL=0 (per §4.5: "This response is not cacheable");
// (6) RDATA layout = <7> "RFC8482" <0>.
func TestMinimalANY_HINFOFormat_RFC8482(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	query := buildTestQueryWithEDNS("y62-any.example.com", dns.TypeANY, 1232)
	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	if parsed.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("RCODE = %d, want NOERROR — RFC 8482 §4.5 mandates a successful synth response", parsed.Header.RCODE())
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("answers = %d, want 1 — minimal ANY response carries exactly one HINFO", len(parsed.Answers))
	}
	a := parsed.Answers[0]
	if a.Type != dns.TypeHINFO {
		t.Errorf("answer.Type = %d, want HINFO (%d) — RFC 8482 §4.5", a.Type, dns.TypeHINFO)
	}
	if a.Class != dns.ClassIN {
		t.Errorf("answer.Class = %d, want IN (1)", a.Class)
	}
	if a.TTL != 0 {
		t.Errorf("answer.TTL = %d, want 0 — §4.5 'this response is not cacheable'", a.TTL)
	}

	// RDATA layout: <CPU-len=7> "RFC8482" <OS-len=0>. 9 bytes total.
	want := []byte{7, 'R', 'F', 'C', '8', '4', '8', '2', 0}
	if string(a.RData) != string(want) {
		t.Errorf("RDATA = %v, want %v — §4.5 CPU label must be the literal string 'RFC8482' so operators can identify the synthetic answer at a glance", a.RData, want)
	}
}

// TestMinimalANY_NotANY_NotIntercepted pins the negation: a non-ANY
// query type MUST NOT trigger the minimal-ANY path. The intercept is
// gated by `q.Type == dns.TypeANY` at handler.go:702 — a regression
// that loosened this (say, to TypeMAILA or some other rarely-used
// legacy type) would synthesise nonsense HINFO responses for unrelated
// queries. We verify with TypeA which goes through the normal resolver
// path (and the broken resolver here surfaces as SERVFAIL — which is
// fine; what matters is that it is NOT a synthesised HINFO).
func TestMinimalANY_NotANY_NotIntercepted(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	query := buildTestQueryWithEDNS("y62-not-any.example.com", dns.TypeA, 1232)
	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	for _, a := range parsed.Answers {
		if a.Type == dns.TypeHINFO && len(a.RData) >= 8 && string(a.RData[1:8]) == "RFC8482" {
			t.Errorf("TypeA query received an RFC8482 minimal-ANY synth — intercept gate must be exactly Type==ANY")
		}
	}
}
