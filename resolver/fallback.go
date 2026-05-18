package resolver

import (
	"math/rand/v2"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// queryFallback picks one random fallback resolver and sends a single
// recursive (RD=1) query. Returns nil if fallback is not configured or
// the fallback also fails. fbReason describes why primary resolver failed.
func (r *Resolver) queryFallback(name string, qtype uint16, qclass uint16, fbReason string) *ResolveResult {
	if len(r.config.FallbackResolvers) == 0 {
		return nil
	}

	addr := r.config.FallbackResolvers[rand.IntN(len(r.config.FallbackResolvers))]
	r.metrics.IncFallbackQueries()
	if r.metrics.RecordFallbackFunc != nil {
		r.metrics.RecordFallbackFunc(1, 0)
	}
	r.logger.Debug("trying fallback resolver", "addr", addr, "name", name, "qtype", qtype)

	event := metrics.FallbackEvent{
		Timestamp:            time.Now(),
		QueryName:           name,
		QType:               qtype,
		QClass:              qclass,
		PrimaryFailureReason: fbReason,
		ResolverAddr:         addr,
	}

	msg, err := r.sendForwardQueryOnce(addr, name, qtype, qclass)
	if err != nil {
		event.Error = err.Error()
		r.metrics.FallbackEventRing().Add(event)
		r.logger.Debug("fallback resolver failed", "addr", addr, "error", err)
		return nil
	}

	// Only accept successful responses (NOERROR or NXDOMAIN).
	// SERVFAIL from fallback means the domain genuinely has issues.
	rcode := msg.Header.RCODE()
	if rcode == dns.RCodeServFail {
		event.RCODE = rcode
		r.metrics.FallbackEventRing().Add(event)
		return nil
	}

	event.Recovered = true
	event.RCODE = rcode
	r.metrics.FallbackEventRing().Add(event)

	if r.metrics.RecordFallbackFunc != nil {
		r.metrics.RecordFallbackFunc(0, 1)
	}

	r.metrics.IncFallbackRecoveries()
	r.logger.Info("fallback resolver recovered query", "addr", addr, "name", name, "rcode", rcode)

	status := ""
	if r.config.DNSSECEnabled && msg.Header.AD() {
		status = "secure"
	}
	return &ResolveResult{
		Answers:      msg.Answers,
		Authority:    msg.Authority,
		Additional:   msg.Additional,
		RCODE:        rcode,
		DNSSECStatus: status,
	}
}

// fallbackReason describes why fallback was triggered.
type fallbackReason struct {
	triggered bool
	reason    string
}

// shouldFallback returns whether fallback is warranted and the reason for it:
// SERVFAIL, upstream error, or nil result (not DNSSEC bogus).
func shouldFallback(result *ResolveResult, err error) fallbackReason {
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
	// Don't bypass DNSSEC validation failures — those are intentional.
	if result.DNSSECStatus == "bogus" {
		return fallbackReason{triggered: false, reason: ""}
	}
	return fallbackReason{triggered: true, reason: "SERVFAIL"}
}
