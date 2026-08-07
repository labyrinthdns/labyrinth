package resolver

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// The resolver half of RFC 9567 is mostly about restraint. Reports fire on
// failure, and failures arrive in correlated bursts: one expired signature on
// a popular zone fails every client query at once. Without bounds, the
// resolver would answer a zone's outage by pointing a query flood at whatever
// host that zone named as its agent domain — an amplifier built out of a
// diagnostic feature, aimed by the same authoritative server whose answers we
// just decided not to trust.
//
// These tests pin the bounds, not the happy path (the name construction is
// pinned in dns/rfc9567_error_report_test.go).

// TestRFC9567_DisabledByDefault pins the opt-in. RFC 9567 §8 notes a report
// tells a third party that this resolver looked up a particular name and got
// a particular error, so an operator must choose to send them.
func TestRFC9567_DisabledByDefault(t *testing.T) {
	r := &Resolver{}
	if r.errorReporter.Load() != nil {
		t.Fatal("error reporting active on a fresh resolver — RFC 9567 §8 " +
			"privacy exposure must be opt-in")
	}

	// reportError on a disabled resolver must be a no-op, not a panic: it
	// is called from every DNSSEC failure path.
	r.reportError(&dns.Message{}, "broken.test", dns.TypeA, dns.EDECodeDNSSECBogus)
}

// TestRFC9567_ToggleLifecycle pins that enabling and disabling at runtime
// (config hot-reload) works in both directions, and that re-enabling does not
// discard the dedup table — otherwise a reload storm would let a suppressed
// report through on every reload.
func TestRFC9567_ToggleLifecycle(t *testing.T) {
	r := &Resolver{}

	r.SetErrorReporting(true)
	first := r.errorReporter.Load()
	if first == nil {
		t.Fatal("SetErrorReporting(true) did not install a reporter")
	}

	r.SetErrorReporting(true) // idempotent re-apply, as a hot-reload does
	if r.errorReporter.Load() != first {
		t.Error("re-enabling replaced the reporter, discarding the dedup table — " +
			"a reload loop would then defeat suppression entirely")
	}

	r.SetErrorReporting(false)
	if r.errorReporter.Load() != nil {
		t.Error("SetErrorReporting(false) left reporting active")
	}
}

// TestRFC9567_DedupWindow pins the suppression window. The scenario is the
// one that matters: a zone's signature expires, and every client query for
// that name fails in the same second.
func TestRFC9567_DedupWindow(t *testing.T) {
	er := newErrorReporter(nil)
	now := time.Now()
	const key = "_er.1.broken.test.6._er.a.example"

	if !er.shouldSend(key, now) {
		t.Fatal("first report suppressed — the operator would never be told at all")
	}

	// The burst: a thousand client queries for the same broken name.
	for i := 0; i < 1000; i++ {
		if er.shouldSend(key, now.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatalf("duplicate report allowed through at iteration %d — one "+
				"zone outage would become a query flood at the agent domain", i)
		}
	}

	// After the window, the operator is reminded the problem is ongoing.
	if !er.shouldSend(key, now.Add(reportDedupWindow+time.Second)) {
		t.Error("report still suppressed after the dedup window expired — an " +
			"ongoing outage would look like a single transient blip")
	}
}

// TestRFC9567_DistinctFailuresReportedSeparately pins that dedup is per
// failure, not global. Two different names, or the same name failing two
// different ways, are two things an operator needs to see.
func TestRFC9567_DistinctFailuresReportedSeparately(t *testing.T) {
	er := newErrorReporter(nil)
	now := time.Now()

	keys := []string{
		"_er.1.a.zone.test.6._er.agent.example",  // A / bogus
		"_er.28.a.zone.test.6._er.agent.example", // AAAA / bogus
		"_er.1.a.zone.test.7._er.agent.example",  // A / signature expired
		"_er.1.b.zone.test.6._er.agent.example",  // different name
	}
	for _, k := range keys {
		if !er.shouldSend(k, now) {
			t.Errorf("distinct failure %q was suppressed", k)
		}
	}
}

// TestRFC9567_DedupTableBounded pins the cap. The dedup key contains the
// qname, so a random-subdomain flood against a zone that publishes a
// Report-Channel writes an unbounded number of distinct keys. The table must
// not be a memory-exhaustion vector handed to an attacker by a diagnostic
// feature.
func TestRFC9567_DedupTableBounded(t *testing.T) {
	er := newErrorReporter(nil)
	now := time.Now()

	for i := 0; i < reportDedupCap*3; i++ {
		key := "_er.1." + randomishLabel(i) + ".zone.test.6._er.agent.example"
		er.shouldSend(key, now)
	}

	er.mu.Lock()
	size := len(er.recent)
	er.mu.Unlock()

	if size > reportDedupCap {
		t.Fatalf("dedup table holds %d entries, cap is %d — a random-subdomain "+
			"flood would grow it without bound", size, reportDedupCap)
	}
}

// randomishLabel produces a distinct DNS label per index without needing a
// RNG, so the test stays deterministic.
func randomishLabel(i int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, 0, 8)
	for n := i; ; n /= len(alphabet) {
		buf = append(buf, alphabet[n%len(alphabet)])
		if n < len(alphabet) {
			break
		}
	}
	return string(buf)
}

// TestRFC9567_NoReportWithoutAgentDomain pins that the common case costs
// nothing. The overwhelming majority of zones do not publish a
// Report-Channel, and a response without one must not produce an outbound
// query — nor consume a dedup slot, which would let ordinary traffic evict
// the entries that matter.
func TestRFC9567_NoReportWithoutAgentDomain(t *testing.T) {
	r := &Resolver{}
	r.SetErrorReporting(true)
	er := r.errorReporter.Load()

	// A response with EDNS but no Report-Channel option.
	response := &dns.Message{
		EDNS0: &dns.EDNS0{Options: []dns.EDNSOption{
			{Code: dns.EDNSOptionCodeCookie, Data: make([]byte, 8)},
		}},
	}
	r.reportError(response, "broken.test", dns.TypeA, dns.EDECodeDNSSECBogus)

	er.mu.Lock()
	size := len(er.recent)
	er.mu.Unlock()
	if size != 0 {
		t.Fatalf("dedup table grew to %d for a zone with no agent domain — "+
			"ordinary failures must not consume suppression slots", size)
	}
}

// TestRFC9567_ReportBogusUsesSharedEDEMapping pins that the code sent
// upstream in a report is the same one the server sends downstream to the
// client for the identical failure. If the two diverged, an operator
// correlating their agent-domain logs against a user's reported error would
// be comparing two different numbers for one event.
func TestRFC9567_ReportBogusUsesSharedEDEMapping(t *testing.T) {
	cases := map[string]uint16{
		"signature-expired":       dns.EDECodeSignatureExpired,
		"signature-not-yet-valid": dns.EDECodeSignatureNotYetValid,
		"dnskey-missing":          dns.EDECodeDNSKEYMissing,
		"rrsigs-missing":          dns.EDECodeRRSIGsMissing,
		"":                        dns.EDECodeDNSSECBogus, // unclassified
		"something-new":           dns.EDECodeDNSSECBogus, // unknown token
	}
	for reason, want := range cases {
		if got, _ := dns.BogusReasonToEDE(reason); got != want {
			t.Errorf("BogusReasonToEDE(%q) = %d, want %d", reason, got, want)
		}
	}
}
