package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestHandle_RecoversFromPanic_ReturnsServfail pins the defence-in-depth
// behaviour added in v0.7.27: any panic that escapes from the resolver,
// cache, validator, or a third-party transport must NOT propagate out
// of MainHandler.Handle. Instead the panic must be caught, logged, and
// turned into a clean SERVFAIL response that the client can actually
// see.
//
// Why it matters: on UDP a panicking goroutine silently drops the
// client request, and a deterministic panic creates a feedback loop —
// the client re-queries, panics again, and we have a DoS that looks
// like upstream packet loss. On TCP it tears down the connection
// (visible) but still hands the client zero diagnostic information.
// Catching the panic and returning SERVFAIL lets clients move on and
// keeps the resolver running.
//
// The test triggers the panic via a nil cache: with testHandler() the
// cache field is nil but the resolver code reaches h.cache.Get, which
// nil-derefs. That's a real, naturally-occurring panic site — not a
// synthetic one — so the test pins recovery behaviour for the path an
// operator misconfiguration could actually take.
func TestHandle_RecoversFromPanic_ReturnsServfail(t *testing.T) {
	h := &MainHandler{
		metrics: metrics.NewMetrics(),
		// resolver, cache, logger all deliberately nil — the first
		// nil-deref happens inside h.cache.Get on the lookup path.
	}

	query := buildTestQuery("example.test", dns.TypeA)

	// Must not panic out of this call. Pre-recovery, this line would
	// crash the goroutine with "runtime error: invalid memory address
	// or nil pointer dereference".
	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle returned error instead of SERVFAIL response: %v", err)
	}
	if len(resp) < 12 {
		t.Fatalf("response too short: got %d bytes", len(resp))
	}

	flags := binary.BigEndian.Uint16(resp[2:4])
	if rcode := uint8(flags & 0xF); rcode != dns.RCodeServFail {
		t.Errorf("RCODE: expected SERVFAIL(%d), got %d", dns.RCodeServFail, rcode)
	}
	if qr := flags >> 15 & 1; qr != 1 {
		t.Error("QR should be 1 on the recovery response")
	}
}

// TestHandle_RecoversFromPanic_IncrementsServfailCounter pins the
// metrics-side effect: a recovered panic must bump the SERVFAIL
// response counter so operators have a signal in Prometheus
// (labyrinth_responses_total{rcode="SERVFAIL"}) when a resolver bug
// starts panicking. Without this hook the panic would be silent at the
// metrics layer and only show up in logs.
func TestHandle_RecoversFromPanic_IncrementsServfailCounter(t *testing.T) {
	m := metrics.NewMetrics()
	h := &MainHandler{metrics: m}

	before := m.Snapshot().ResponsesByRCode["SERVFAIL"]
	_, _ = h.Handle(buildTestQuery("example.test", dns.TypeA), nil)
	after := m.Snapshot().ResponsesByRCode["SERVFAIL"]

	if after <= before {
		t.Errorf("SERVFAIL counter did not increment on recovered panic: before=%d after=%d",
			before, after)
	}
}
