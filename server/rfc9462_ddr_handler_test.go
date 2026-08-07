package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// The handler half of RFC 9462. The wire-format details are pinned in
// dns/rfc9462_ddr_test.go; what matters here is that the query is intercepted
// before it can reach resolution at all.
//
// `_dns.resolver.arpa` has no delegation in the global DNS. Letting it fall
// through to the resolver would leak the client's discovery attempt upstream
// to the root servers and come back NXDOMAIN — the client would then conclude
// this resolver offers no encrypted transport and stay on plaintext, which is
// precisely the outcome DDR exists to prevent.

func ddrTestHandler(t *testing.T, cfg dns.DDRConfig) *MainHandler {
	t.Helper()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, metrics.NewMetrics())
	// newPanickingResolver has nil metrics and panics if resolution is
	// reached — which makes it the right harness here: if the DDR intercept
	// ever regresses, this test does not silently pass with a SERVFAIL.
	h := NewMainHandler(newPanickingResolver(ca), ca, nil, nil, nil, metrics.NewMetrics(), discardLogger())
	h.SetDDR(cfg)
	return h
}

func ddrQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x9462,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions:  []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{dns.BuildOPT(1232, false)},
	}
	packed, err := dns.Pack(msg, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return packed
}

// TestRFC9462_HandlerAnswersDiscoveryLocally is the core pin: the designation
// comes back without resolution ever running.
func TestRFC9462_HandlerAnswersDiscoveryLocally(t *testing.T) {
	h := ddrTestHandler(t, dns.DDRConfig{
		TargetName: "dns.example.net",
		DoTEnabled: true, DoTPort: 853,
		DoHEnabled: true, DoHPort: 443,
	})

	resp, err := h.Handle(ddrQuery(t, dns.DDRQueryName, dns.TypeSVCB), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Fatalf("rcode = %d, want NOERROR", msg.Header.RCODE())
	}
	if len(msg.Answers) != 2 {
		t.Fatalf("got %d answers, want 2 (DoH + DoT)", len(msg.Answers))
	}
	for _, rr := range msg.Answers {
		if rr.Type != dns.TypeSVCB {
			t.Errorf("answer type = %d, want SVCB", rr.Type)
		}
		if rr.Name != dns.DDRQueryName {
			t.Errorf("answer owner = %q, want %q", rr.Name, dns.DDRQueryName)
		}
	}
	// RFC 9462 §4: the resolver is authoritative for this special-use name.
	if !msg.Header.AA() {
		t.Error("AA bit not set on a locally-authoritative special-use answer")
	}
}

// TestRFC9462_UnconfiguredReturnsNodataNotNXDomain pins the distinction that
// matters when DDR is off. resolver.arpa exists as a special-use name whether
// or not this resolver designates anything; NXDOMAIN would tell the client
// the name itself is bogus, which is a different and wrong statement — and
// one a client could cache against every resolver it later talks to.
func TestRFC9462_UnconfiguredReturnsNodataNotNXDomain(t *testing.T) {
	h := ddrTestHandler(t, dns.DDRConfig{}) // no target name

	resp, err := h.Handle(ddrQuery(t, dns.DDRQueryName, dns.TypeSVCB), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Fatalf("rcode = %d, want NOERROR (NODATA), not NXDOMAIN", msg.Header.RCODE())
	}
	if len(msg.Answers) != 0 {
		t.Errorf("got %d answers with DDR unconfigured, want 0", len(msg.Answers))
	}
}

// TestRFC9462_NonSVCBQueryNotIntercepted pins the narrowness of the
// intercept. An A query for the same name is not a discovery query, and
// swallowing it here would mean the handler answers questions it was never
// asked.
func TestRFC9462_NonSVCBQueryNotIntercepted(t *testing.T) {
	h := ddrTestHandler(t, dns.DDRConfig{TargetName: "dns.example.net", DoTEnabled: true})

	// The panicking resolver turns "reached resolution" into SERVFAIL via
	// the panic-recovery path, which is exactly the signal we want: this
	// query must NOT have been answered by the DDR branch.
	resp, err := h.Handle(ddrQuery(t, dns.DDRQueryName, dns.TypeA), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(msg.Answers) != 0 {
		t.Errorf("an A query for %s was answered by the DDR branch", dns.DDRQueryName)
	}
}

// TestRFC9462_LookalikeNameNotIntercepted pins that the match is exact.
// A name merely ending in the discovery name — which an attacker controls
// under their own zone — must not draw a designation out of us.
func TestRFC9462_LookalikeNameNotIntercepted(t *testing.T) {
	h := ddrTestHandler(t, dns.DDRConfig{TargetName: "dns.example.net", DoTEnabled: true})

	resp, err := h.Handle(ddrQuery(t, "_dns.resolver.arpa.attacker.example", dns.TypeSVCB), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(msg.Answers) != 0 {
		t.Errorf("a lookalike name drew %d designation records", len(msg.Answers))
	}
}

// TestRFC9462_CaseInsensitiveMatch pins RFC 4343. A client that randomises
// query-name case (as 0x20 encoding does) must still get its designation.
func TestRFC9462_CaseInsensitiveMatch(t *testing.T) {
	h := ddrTestHandler(t, dns.DDRConfig{TargetName: "dns.example.net", DoTEnabled: true, DoTPort: 853})

	resp, err := h.Handle(ddrQuery(t, "_DnS.ReSoLvEr.ArPa", dns.TypeSVCB), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("got %d answers for a case-varied query name, want 1", len(msg.Answers))
	}
}

// TestRFC9606_RESINFOServedForOwnName pins the RFC 9606 loop. A client that
// just learned our name from a DDR designation asks it "what will you do to
// my queries?", and the answer must come from us rather than from a lookup.
func TestRFC9606_RESINFOServedForOwnName(t *testing.T) {
	h := ddrTestHandler(t, dns.DDRConfig{TargetName: "dns.example.net", DoTEnabled: true})
	h.SetResolverInfo(dns.ResolverInfo{
		QnameMinimisation: true,
		ExtendedErrors:    []uint16{dns.EDECodeFiltered},
		InfoURL:           "https://resolver.example/policy",
	})

	resp, err := h.Handle(ddrQuery(t, "dns.example.net", dns.TypeRESINFO), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("got %d answers, want 1 RESINFO record", len(msg.Answers))
	}
	if msg.Answers[0].Type != dns.TypeRESINFO {
		t.Errorf("answer type = %d, want RESINFO (261)", msg.Answers[0].Type)
	}

	strs, err := dns.ParseTXT(msg.Answers[0].RData)
	if err != nil {
		t.Fatalf("ParseTXT: %v", err)
	}
	if len(strs) == 0 || strs[0] != "qnamemin" {
		t.Errorf("RESINFO strings = %v, want qnamemin first", strs)
	}
}

// TestRFC9606_RESINFONotServedForOtherNames pins the scope. RESINFO describes
// *this* resolver; synthesising it for an arbitrary queried name would assert
// our policy over someone else's zone.
func TestRFC9606_RESINFONotServedForOtherNames(t *testing.T) {
	h := ddrTestHandler(t, dns.DDRConfig{TargetName: "dns.example.net", DoTEnabled: true})
	h.SetResolverInfo(dns.ResolverInfo{QnameMinimisation: true})

	resp, err := h.Handle(ddrQuery(t, "someone-else.example", dns.TypeRESINFO), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(msg.Answers) != 0 {
		t.Errorf("served %d RESINFO records for a name that is not ours", len(msg.Answers))
	}
}

// TestRFC9606_UndeclaredResolverServesNodata pins that a resolver which has
// declared nothing publishes nothing. An empty RESINFO record would be a
// cacheable assertion that we considered the question and had no answer.
func TestRFC9606_UndeclaredResolverServesNodata(t *testing.T) {
	h := ddrTestHandler(t, dns.DDRConfig{TargetName: "dns.example.net", DoTEnabled: true})
	// No SetResolverInfo call.

	resp, err := h.Handle(ddrQuery(t, "dns.example.net", dns.TypeRESINFO), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if msg.Header.RCODE() != dns.RCodeNoError {
		t.Errorf("rcode = %d, want NOERROR (NODATA)", msg.Header.RCODE())
	}
	if len(msg.Answers) != 0 {
		t.Errorf("got %d answers from an undeclared resolver, want 0", len(msg.Answers))
	}
}
