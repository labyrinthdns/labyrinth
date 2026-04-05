package resolver

import (
	"math/rand/v2"

	"github.com/labyrinthdns/labyrinth/dns"
)

// queryFallback picks one random fallback resolver and sends a single
// recursive (RD=1) query. Returns nil if fallback is not configured or
// the fallback also fails.
func (r *Resolver) queryFallback(name string, qtype uint16, qclass uint16) *ResolveResult {
	if len(r.config.FallbackResolvers) == 0 {
		return nil
	}

	addr := r.config.FallbackResolvers[rand.IntN(len(r.config.FallbackResolvers))]
	r.metrics.IncFallbackQueries()
	r.logger.Debug("trying fallback resolver", "addr", addr, "name", name, "qtype", qtype)

	msg, err := r.sendForwardQueryOnce(addr, name, qtype, qclass)
	if err != nil {
		r.logger.Debug("fallback resolver failed", "addr", addr, "error", err)
		return nil
	}

	// Only accept successful responses (NOERROR or NXDOMAIN).
	// SERVFAIL from fallback means the domain genuinely has issues.
	rcode := msg.Header.RCODE()
	if rcode == dns.RCodeServFail {
		return nil
	}

	r.metrics.IncFallbackRecoveries()
	r.logger.Info("fallback resolver recovered query", "addr", addr, "name", name, "rcode", rcode)

	return &ResolveResult{
		Answers:    msg.Answers,
		Authority:  msg.Authority,
		Additional: msg.Additional,
		RCODE:      rcode,
	}
}

// shouldFallback returns true if the resolution result warrants a
// fallback attempt: SERVFAIL that isn't caused by DNSSEC validation.
func shouldFallback(result *ResolveResult, err error) bool {
	if err != nil {
		return true
	}
	if result == nil {
		return true
	}
	if result.RCODE != dns.RCodeServFail {
		return false
	}
	// Don't bypass DNSSEC validation failures — those are intentional.
	if result.DNSSECStatus == "bogus" {
		return false
	}
	return true
}
