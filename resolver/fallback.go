package resolver

import (
	"math/rand/v2"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// queryFallback walks configured fallback resolvers (shuffled) until one
// returns NOERROR/NXDOMAIN. Returns nil if fallback is not configured or
// every backup also fails. fbReason describes why primary resolver failed.
func (r *Resolver) queryFallback(name string, qtype uint16, qclass uint16, fbReason string) *ResolveResult {
	return r.queryFallbackWithPrimary(name, qtype, qclass, fbReason, nil)
}

func (r *Resolver) queryFallbackWithPrimary(name string, qtype uint16, qclass uint16, fbReason string, primary *ResolveResult) *ResolveResult {
	return r.queryFallbackWithContext(name, qtype, qclass, fbReason, primary, nil, false)
}

func (r *Resolver) queryFallbackWithContext(name string, qtype uint16, qclass uint16, fbReason string, primary *ResolveResult, clientECS *dns.ECSOption, cd bool) *ResolveResult {
	if len(r.config.FallbackResolvers) == 0 {
		return nil
	}

	addrs := append([]string(nil), r.config.FallbackResolvers...)
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })

	r.metrics.IncFallbackQueries()
	if r.metrics.RecordFallbackFunc != nil {
		r.metrics.RecordFallbackFunc(1, 0)
	}
	r.logger.Debug("trying fallback resolvers", "addrs", addrs, "name", name, "qtype", qtype)

	dnssecStatus, dnssecReason, failReason, primaryRcode := primaryFallbackFields(primary)
	var primaryAttempts []string
	if primary != nil {
		primaryAttempts = primary.Attempts
	}
	tried := 0
	var lastEvent metrics.FallbackEvent
	for _, addr := range addrs {
		tried++
		event := metrics.FallbackEvent{
			Timestamp:            time.Now(),
			QueryName:            name,
			QType:                qtype,
			QClass:               qclass,
			PrimaryFailureReason: fbReason,
			ResolverAddr:         addr,
		}

		msg, err := r.sendForwardQueryOnceECSCD(addr, name, qtype, qclass, clientECS, cd, nil)
		if err != nil {
			event.Error = err.Error()
			// Leave RCODE unset (0) out of the JSONL line — rcodeName(0) is
			// "NOERROR" and would mislabel timeouts as successful answers.
			lastEvent = event
			r.logger.Debug("fallback resolver failed", "addr", addr, "error", err)
			continue
		}

		// Only accept successful responses (NOERROR or NXDOMAIN).
		// SERVFAIL from fallback means try the next backup; if all fail
		// the domain genuinely has issues (or all backups are down).
		rcode := msg.Header.RCODE()
		if rcode != dns.RCodeNoError && rcode != dns.RCodeNXDomain {
			event.RCODE = rcode
			lastEvent = event
			continue
		}

		event.Recovered = true
		event.RCODE = rcode
		r.metrics.FallbackEventRing().Add(event)

		if r.metrics.RecordFallbackFunc != nil {
			r.metrics.RecordFallbackFunc(0, 1)
		}

		r.metrics.IncFallbackRecoveries()
		r.logger.Info("fallback resolver recovered query", "addr", addr, "name", name, "rcode", rcode)

		r.fallbackLog.write(fallbackLogRecord{
			Name:            name,
			QType:           qtype,
			QTypeName:       qtypeName(qtype),
			Reason:          fbReason,
			DNSSECStatus:    dnssecStatus,
			DNSSECReason:    dnssecReason,
			FailureReason:   failReason,
			PrimaryRCODE:    primaryRcode,
			Recovered:       true,
			FallbackAddr:    addr,
			FallbackRCODE:   rcodeName(rcode),
			FallbackTried:   tried,
			PrimaryAttempts: primaryAttempts,
		})

		status := ""
		if r.config.DNSSECEnabled && msg.Header.AD() {
			status = "secure"
		}
		// Under CD=1 the backup skips validation too (RFC 4035 §3.2.2), so
		// its answer is the same unvalidated data our validator just ruled
		// Bogus. Keep that verdict: laundered to "" it was cached and served
		// to every later CD=0 client, bypassing DNSSEC for all of them.
		if cd && primary != nil && primary.DNSSECStatus == "bogus" {
			status = "bogus"
		}
		return &ResolveResult{
			Answers:      msg.Answers,
			Authority:    msg.Authority,
			Additional:   msg.Additional,
			RCODE:        rcode,
			DNSSECStatus: status,
			UpstreamECS:  extractResponseECS(msg),
		}
	}

	r.metrics.FallbackEventRing().Add(lastEvent)
	r.fallbackLog.write(fallbackLogRecord{
		Name:            name,
		QType:           qtype,
		QTypeName:       qtypeName(qtype),
		Reason:          fbReason,
		DNSSECStatus:    dnssecStatus,
		DNSSECReason:    dnssecReason,
		FailureReason:   failReason,
		PrimaryRCODE:    primaryRcode,
		Recovered:       false,
		FallbackAddr:    lastEvent.ResolverAddr,
		FallbackRCODE:   rcodeNameForEvent(lastEvent.RCODE, lastEvent.Error),
		FallbackError:   lastEvent.Error,
		FallbackTried:   tried,
		PrimaryAttempts: primaryAttempts,
	})
	return nil
}

// fallbackReason describes why fallback was triggered.
type fallbackReason struct {
	triggered bool
	reason    string
}

// shouldFallback returns whether fallback is warranted and the reason for it:
// SERVFAIL (including DNSSEC bogus), upstream error, or nil result.
// queryFallback still rejects SERVFAIL from the backup resolver, so names
// that public resolvers also fail (e.g. dnssec-failed.org) stay failed.
func shouldFallback(qtype uint16, result *ResolveResult, err error) fallbackReason {
	// PTR almost never recovers via a public resolver: broken reverse
	// delegations (REFUSED / soft SERVFAIL from every NS) fail at 1.1.1.1
	// and 8.8.8.8 the same way, so the fallback only adds a round trip
	// and fills fallback.jsonl. Forward types stay eligible.
	if qtype == dns.TypePTR {
		return fallbackReason{triggered: false, reason: ""}
	}
	// An exhausted request budget (query cap or RequestTimeout) is not
	// worth a fallback: the client has given up by the deadline, and the
	// query cap is what an NXNS-style amplification hits.
	//
	// "no-reachable-authority" does engage the fallback. Every NS of the
	// delegation failed *for us*, which is exactly the case the fallback
	// exists for: live, toksan.com.tr's only nameserver dropped every query
	// carrying an EDNS option it did not know, so it was EDE 22 here while
	// 1.1.1.1 and 8.8.8.8 answered. When the public resolvers hit the same
	// dead servers, queryFallback rejects their SERVFAIL and the client
	// still gets EDE 22. Stub and forward zones are excluded by the caller
	// so internal names are never sent to a public resolver.
	if result != nil && result.FailureReason == "query-budget-exceeded" {
		return fallbackReason{triggered: false, reason: ""}
	}
	// Prefer result.Error over err since resolveIterativeFrom preserves
	// the underlying upstream error even when returning SERVFAIL.
	if result != nil && result.Error != nil {
		return fallbackReason{triggered: true, reason: result.Error.Error()}
	}
	if err != nil {
		return fallbackReason{triggered: true, reason: err.Error()}
	}
	if result == nil {
		return fallbackReason{triggered: true, reason: "nil result"}
	}
	if result.RCODE != dns.RCodeServFail {
		return fallbackReason{triggered: false, reason: ""}
	}
	// DNSSEC Bogus previously skipped fallback so a local validator bug
	// (or a zone the public resolvers accept) pinned clients on SERVFAIL
	// forever. queryFallback still rejects SERVFAIL from the backup, so
	// genuinely broken names (dnssec-failed.org) stay failed — but names
	// that 1.1.1.1/8.8.8.8 can answer are recovered.
	if result.DNSSECStatus == "bogus" {
		return fallbackReason{triggered: true, reason: "DNSSEC bogus"}
	}
	return fallbackReason{triggered: true, reason: "SERVFAIL"}
}

// shouldFallbackForZone is shouldFallback for a name that may belong to a
// stub or forward zone. A configured zone whose own servers are unreachable
// stays out of the fallback: its names are usually internal, and public
// resolvers would either leak them or answer with the public view. Resolve
// and Trace share it so a trace never takes a fallback production refuses.
func shouldFallbackForZone(name string, qtype uint16, result *ResolveResult, err error, configuredZone bool) fallbackReason {
	if publicResolverBlockedZone(name) {
		return fallbackReason{}
	}
	fb := shouldFallback(qtype, result, err)
	if fb.triggered && configuredZone && result != nil && result.FailureReason == "no-reachable-authority" {
		fb.triggered = false
	}
	return fb
}

// fallbackBlockedSuffixes are DNSBL zones whose operators refuse queries
// from large public resolvers and answer them with a policy code instead of
// the listing (checked 2026-10-15 with the zones' own test records):
// Spamhaus gives 127.255.255.254 at 1.1.1.1 and nothing at 8.8.8.8,
// URIBL gives 127.0.0.1 ("query refused") at both, and SURBL nothing at
// 1.1.1.1. Sent through the fallback such an answer reaches a mail server
// as a listing or an error, which is worse than SERVFAIL, so these names
// never use it. spamhaus.net covers the Data Query Service (dq.spamhaus.net).
var fallbackBlockedSuffixes = []string{
	"spamhaus.org",
	"spamhaus.net",
	"uribl.com",
	"surbl.org",
}

// publicResolverBlockedZone reports whether name is at or below one of the
// fallbackBlockedSuffixes.
func publicResolverBlockedZone(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, z := range fallbackBlockedSuffixes {
		if name == z || strings.HasSuffix(name, "."+z) {
			return true
		}
	}
	return false
}
