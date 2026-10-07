package resolver

import (
	"math/rand/v2"
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
			Name:          name,
			QType:         qtype,
			QTypeName:     qtypeName(qtype),
			Reason:        fbReason,
			DNSSECStatus:  dnssecStatus,
			DNSSECReason:  dnssecReason,
			FailureReason: failReason,
			PrimaryRCODE:  primaryRcode,
			Recovered:     true,
			FallbackAddr:  addr,
			FallbackRCODE: rcodeName(rcode),
			FallbackTried: tried,
		})

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
			UpstreamECS:  extractResponseECS(msg),
		}
	}

	r.metrics.FallbackEventRing().Add(lastEvent)
	fallbackRCODE := ""
	if lastEvent.Error == "" {
		fallbackRCODE = rcodeName(lastEvent.RCODE)
	}
	r.fallbackLog.write(fallbackLogRecord{
		Name:          name,
		QType:         qtype,
		QTypeName:     qtypeName(qtype),
		Reason:        fbReason,
		DNSSECStatus:  dnssecStatus,
		DNSSECReason:  dnssecReason,
		FailureReason: failReason,
		PrimaryRCODE:  primaryRcode,
		Recovered:     false,
		FallbackAddr:  lastEvent.ResolverAddr,
		FallbackRCODE: fallbackRCODE,
		FallbackError: lastEvent.Error,
		FallbackTried: tried,
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
func shouldFallback(result *ResolveResult, err error) fallbackReason {
	// Exhausted the delegation or the request budget: public recursive
	// resolvers typically SERVFAIL the same names. Do not count those
	// as fallback engagements (they cannot be "recovered").
	if result != nil {
		switch result.FailureReason {
		case "no-reachable-authority", "query-budget-exceeded":
			return fallbackReason{triggered: false, reason: ""}
		}
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
