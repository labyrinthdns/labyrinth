package resolver

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// RFC 9567 error reporting, resolver side. See dns/errorreport.go for what
// the mechanism is and why it exists; this file is about not letting it hurt
// us.
//
// The risk profile of outbound reporting is unusual: the trigger is a
// *failure*, and failures arrive in correlated bursts. A single expired
// DNSSEC signature on a popular zone makes every client query fail at once,
// and a naive implementation would answer that by firing one outbound query
// per client query — turning a zone's outage into a traffic amplifier
// pointed at whatever host the zone operator named as their agent domain.
// The agent domain is also attacker-influenceable: it comes from the same
// authoritative server whose answers we just decided not to trust.
//
// Three bounds keep that in check, all enforced here rather than at the call
// sites:
//
//	dedup window     one report per (qname, qtype, EDE) per 5 minutes
//	dedup table cap  bounded, so a random-subdomain flood cannot grow it
//	inflight cap     at most 8 report queries in flight at any moment
//
// Reporting is opt-in (resolver.error_reporting) and off by default. It is
// genuinely useful, but it discloses to a third party that this resolver
// queried a particular name and got a particular error — a privacy cost the
// operator should choose deliberately (RFC 9567 §8).

const (
	// reportDedupWindow is how long a given failure stays suppressed. Long
	// enough that a zone-wide outage produces a trickle rather than a
	// flood; short enough that an operator watching their agent domain
	// sees the problem is ongoing rather than a one-off.
	reportDedupWindow = 5 * time.Minute

	// reportDedupCap bounds the dedup table. The table is keyed partly by
	// qname, so a random-subdomain attack against a zone with a
	// Report-Channel would otherwise grow it without limit. On overflow
	// the table is cleared rather than evicted one-by-one: the loss is
	// only that some reports get sent twice, which is harmless, and it
	// avoids carrying an LRU for a cache whose entries all expire anyway.
	reportDedupCap = 4096

	// maxInflightReports caps concurrent outbound report queries. Reports
	// are best-effort diagnostics; they must never compete with real
	// client resolution for the outbound query budget.
	maxInflightReports = 8
)

// errorReporter tracks which failures have already been reported and bounds
// how many reports are in flight.
type errorReporter struct {
	mu     sync.Mutex
	recent map[string]time.Time

	inflight atomic.Int32
	logger   *slog.Logger
}

func newErrorReporter(logger *slog.Logger) *errorReporter {
	return &errorReporter{
		recent: make(map[string]time.Time),
		logger: logger,
	}
}

// shouldSend reports whether `key` is due for a report, and records it as
// sent when it is. A nil receiver returns false so callers do not need to
// nil-check before asking.
func (er *errorReporter) shouldSend(key string, now time.Time) bool {
	if er == nil {
		return false
	}
	er.mu.Lock()
	defer er.mu.Unlock()

	if last, ok := er.recent[key]; ok && now.Sub(last) < reportDedupWindow {
		return false
	}
	if len(er.recent) >= reportDedupCap {
		er.recent = make(map[string]time.Time)
	}
	er.recent[key] = now
	return true
}

// SetErrorReporting turns RFC 9567 outbound error reporting on or off at
// runtime. Called from startup and from the /api/config/raw hot-reload path.
func (r *Resolver) SetErrorReporting(enabled bool) {
	if !enabled {
		r.errorReporter.Store(nil)
		return
	}
	if r.errorReporter.Load() == nil {
		r.errorReporter.Store(newErrorReporter(r.logger))
	}
}

// reportError sends an RFC 9567 error report for a failed response, when the
// responding server advertised a Report-Channel and reporting is enabled.
//
// `response` is the upstream message we just rejected — it carries both the
// agent domain (in its OPT record) and, implicitly, the authority that wants
// to hear about this. `name` and `qtype` are what the client asked for, and
// `edeCode` is the RFC 8914 Extended DNS Error we concluded.
//
// Everything about this call is best-effort and non-blocking: it must never
// delay the client's answer, and its own failures are not worth logging at
// anything above debug. The one thing it must not do is get in the way, so
// each bound below returns early rather than waiting.
func (r *Resolver) reportError(response *dns.Message, name string, qtype uint16, edeCode uint16) {
	er := r.errorReporter.Load()
	if er == nil || response == nil {
		return
	}

	agent := dns.ExtractReportChannel(response.EDNS0)
	if agent == "" {
		return // this zone did not ask to be told
	}

	reportName, ok := dns.BuildReportQName(agent, name, qtype, edeCode)
	if !ok {
		return // report name too long, or a report about a report (§6.3)
	}

	if !er.shouldSend(reportName, time.Now()) {
		return
	}

	if er.inflight.Add(1) > maxInflightReports {
		er.inflight.Add(-1)
		return
	}

	go func() {
		defer er.inflight.Add(-1)
		// RFC 9567 §6.2: the query IS the report. Whatever comes back —
		// an answer, NXDOMAIN, SERVFAIL, nothing at all — is discarded.
		// A failure to deliver the report is not a resolution failure and
		// must not surface anywhere near the client's result.
		if _, err := r.Resolve(reportName, dns.TypeTXT, dns.ClassIN); err != nil && r.logger != nil {
			r.logger.Debug("RFC 9567 error report not delivered",
				"report_qname", reportName,
				"agent_domain", agent,
				"error", err,
			)
		}
	}()
}
