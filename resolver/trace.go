package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/dnssec"
	"github.com/labyrinthdns/labyrinth/security"
)

// TraceStatus classifies an emitted event for UI rendering.
type TraceStatus string

const (
	TraceStatusInfo  TraceStatus = "info"
	TraceStatusOK    TraceStatus = "ok"
	TraceStatusWarn  TraceStatus = "warn"
	TraceStatusError TraceStatus = "error"
)

// TraceEvent is a single point of progress emitted by Trace.
//
// Stage names are stable and form the "pipeline" the UI renders:
//
//	start, local-zones, forward-zones, cache, iterative-step,
//	upstream, classify, cname, dname, delegation, dnssec, fallback, finish.
//
// Details is free-form per-stage context (e.g. NS IP, response counts).
type TraceEvent struct {
	Seq       uint64         `json:"seq"`
	Stage     string         `json:"stage"`
	Status    TraceStatus    `json:"status"`
	Time      time.Time      `json:"time"`
	ElapsedMs int64          `json:"elapsed_ms"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
}

// TraceOptions controls Trace behaviour.
type TraceOptions struct {
	// BypassCache makes the trace ignore the resolver cache for the queried
	// name. Glue / DNSKEY caching is unaffected so the trace stays fast.
	BypassCache bool
	// SkipDNSSEC turns off the DNSSEC validator for this trace even if the
	// resolver has it enabled. Useful when diagnosing whether a SERVFAIL is
	// upstream-related or validation-related.
	SkipDNSSEC bool
	// MaxDepth caps the number of iterative steps; 0 falls back to resolver
	// MaxDepth.
	MaxDepth int
	// MaxCNAMEDepth caps CNAME chasing; 0 falls back to resolver setting.
	MaxCNAMEDepth int
}

// Trace performs a diagnostic resolution that emits one TraceEvent per
// pipeline stage. The function returns when the channel reader has consumed
// all events or ctx is cancelled. Events are guaranteed to be ordered by
// Seq. The caller is expected to read events promptly — the channel is
// unbuffered to give back-pressure when the UI cannot keep up. Trace closes
// `events` before it returns.
//
// Trace does NOT use the inflight coalescer (so each call is independent of
// concurrent production resolutions for the same name) and bypasses the
// answer cache when opts.BypassCache is set. It still reads glue and
// delegation cache to avoid hammering the roots on every diagnostic.
func (r *Resolver) Trace(
	ctx context.Context,
	name string,
	qtype uint16,
	qclass uint16,
	opts TraceOptions,
	events chan<- TraceEvent,
) (*ResolveResult, error) {
	defer close(events)

	t := newTracer(ctx, events)
	defer t.finish()

	name = strings.ToLower(strings.TrimSuffix(name, "."))
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = r.config.MaxDepth
	}
	maxCNAME := opts.MaxCNAMEDepth
	if maxCNAME <= 0 {
		maxCNAME = r.config.MaxCNAMEDepth
	}

	t.emit("start", TraceStatusInfo, fmt.Sprintf("resolving %s %s", name, typeName(qtype)), map[string]any{
		"name":            name,
		"qtype":           qtype,
		"qtype_name":      typeName(qtype),
		"qclass":          qclass,
		"bypass_cache":    opts.BypassCache,
		"skip_dnssec":     opts.SkipDNSSEC,
		"qmin_enabled":    r.config.QMinEnabled,
		"dnssec_enabled":  r.config.DNSSECEnabled && !opts.SkipDNSSEC && r.dnssecValidator != nil,
		"max_depth":       maxDepth,
		"max_cname_depth": maxCNAME,
		"resolver_ready":  r.IsReady(),
	})

	// 1. Local zones (operator-configured authoritative data wins over the
	// RFC 6761 short-circuit).
	if r.localZones != nil {
		if result := r.localZones.Lookup(name, qtype, qclass); result != nil {
			t.emit("local-zones", TraceStatusOK, "answered from local zone", map[string]any{
				"rcode":   rcodeName(result.RCODE),
				"answers": len(result.Answers),
			})
			t.emit("finish", TraceStatusOK, "done (local zone)", nil)
			return result, nil
		}
		t.emit("local-zones", TraceStatusInfo, "no local zone match", nil)
	} else {
		t.emit("local-zones", TraceStatusInfo, "local zones disabled", nil)
	}

	// 1.5 RFC 6761 / 7686 / 8375 special-use names — short-circuit AFTER
	// local-zone lookup so admins can override (e.g. operator-defined
	// .test or .local zones still resolve).
	if result := specialUseResponse(name, qtype, qclass); result != nil {
		t.emit("local-zones", TraceStatusOK, "answered from special-use short-circuit (RFC 6761/7686/8375)", map[string]any{
			"rcode": rcodeName(result.RCODE),
		})
		t.emit("finish", TraceStatusOK, "done (special-use)", nil)
		return result, nil
	}

	// 2. Cache short-circuit (unless bypassed).
	if !opts.BypassCache {
		if entry, ok := r.cache.Get(name, qtype, qclass); ok {
			t.emit("cache", TraceStatusOK, "answer cache hit", map[string]any{
				"rcode":   rcodeName(entry.RCODE),
				"records": len(entry.Records),
			})
			result := &ResolveResult{
				Answers:   entry.Records,
				Authority: entry.Authority,
				RCODE:     entry.RCODE,
			}
			t.emit("finish", TraceStatusOK, "done (cache hit)", nil)
			return result, nil
		}
		t.emit("cache", TraceStatusInfo, "answer cache miss", nil)
	} else {
		t.emit("cache", TraceStatusInfo, "cache bypassed", nil)
	}

	// 3. Forward / stub.
	if fz := r.forwardTable.Match(name); fz != nil {
		t.emit("forward-zones", TraceStatusInfo, fmt.Sprintf("zone %q matched (stub=%v)", fz.Name, fz.IsStub), map[string]any{
			"zone":  fz.Name,
			"stub":  fz.IsStub,
			"addrs": fz.Addrs,
		})
		var (
			result *ResolveResult
			err    error
		)
		if !fz.IsStub {
			result, err = r.traceForward(t, fz.Addrs, name, qtype, qclass)
		} else {
			result, err = r.traceIterative(t, name, qtype, qclass, fz.Addrs, fz.Name, 0, maxDepth, maxCNAME, opts, newVisitedSet())
		}
		return r.traceFinishWithFallback(t, result, err, name, qtype, qclass, opts)
	}
	t.emit("forward-zones", TraceStatusInfo, "no forward/stub zone match", nil)

	// 4. Iterative resolution from roots.
	rootAddrs := make([]string, 0, len(r.rootServers))
	for _, ns := range r.rootServers {
		if ns.IPv4 != "" {
			rootAddrs = append(rootAddrs, ns.IPv4)
		}
	}
	t.emit("iterative-step", TraceStatusInfo, fmt.Sprintf("starting iterative resolution from %d root servers", len(rootAddrs)), map[string]any{
		"root_count": len(rootAddrs),
	})

	result, err := r.traceIterative(t, name, qtype, qclass, rootAddrs, "", 0, maxDepth, maxCNAME, opts, newVisitedSet())
	return r.traceFinishWithFallback(t, result, err, name, qtype, qclass, opts)
}

// traceFinishWithFallback runs the same fallback-resolver hook that prod
// Resolve uses, then emits the terminal event.
func (r *Resolver) traceFinishWithFallback(
	t *tracer,
	result *ResolveResult,
	err error,
	name string,
	qtype uint16,
	qclass uint16,
	opts TraceOptions,
) (*ResolveResult, error) {
	if fb := shouldFallback(result, err); fb.triggered {
		t.emit("fallback", TraceStatusWarn, fmt.Sprintf("primary failed (%s) — trying fallback resolver", fb.reason), map[string]any{
			"reason":    fb.reason,
			"resolvers": r.config.FallbackResolvers,
		})
		if fbResult := r.queryFallback(name, qtype, qclass, fb.reason); fbResult != nil {
			t.emit("fallback", TraceStatusOK, "fallback resolver answered", map[string]any{
				"rcode":         rcodeName(fbResult.RCODE),
				"answers":       len(fbResult.Answers),
				"dnssec_status": fbResult.DNSSECStatus,
			})
			t.emit("finish", TraceStatusOK, "done (fallback)", nil)
			return fbResult, nil
		}
		t.emit("fallback", TraceStatusError, "fallback resolver did not produce an answer", nil)
	}

	if err != nil {
		t.emit("finish", TraceStatusError, fmt.Sprintf("resolution failed: %v", err), nil)
		return result, err
	}
	if result == nil {
		t.emit("finish", TraceStatusError, "resolution returned no result", nil)
		return nil, errors.New("trace: empty result")
	}
	status := TraceStatusOK
	switch result.RCODE {
	case dns.RCodeServFail, dns.RCodeRefused:
		status = TraceStatusError
	case dns.RCodeNXDomain:
		status = TraceStatusWarn
	}
	t.emit("finish", status, fmt.Sprintf("rcode=%s answers=%d dnssec=%s", rcodeName(result.RCODE), len(result.Answers), nzs(result.DNSSECStatus)), map[string]any{
		"rcode":         rcodeName(result.RCODE),
		"answers":       len(result.Answers),
		"authority":     len(result.Authority),
		"additional":    len(result.Additional),
		"dnssec_status": result.DNSSECStatus,
	})
	return result, nil
}

// traceForward issues an RD=1 forward query and emits one upstream event per
// address attempted.
func (r *Resolver) traceForward(t *tracer, addrs []string, name string, qtype uint16, qclass uint16) (*ResolveResult, error) {
	var lastErr error
	for _, addr := range addrs {
		start := time.Now()
		msg, err := r.sendForwardQuery(addr, name, qtype, qclass)
		dur := time.Since(start)
		if err != nil {
			lastErr = err
			t.emit("upstream", TraceStatusWarn, fmt.Sprintf("forward query to %s failed: %v", addr, err), map[string]any{
				"ns":     addr,
				"name":   name,
				"qtype":  typeName(qtype),
				"error":  err.Error(),
				"rtt_ms": dur.Milliseconds(),
				"mode":   "forward",
			})
			continue
		}
		t.emit("upstream", TraceStatusOK, fmt.Sprintf("forward %s answered in %dms", addr, dur.Milliseconds()), map[string]any{
			"ns":      addr,
			"name":    name,
			"qtype":   typeName(qtype),
			"rcode":   rcodeName(msg.Header.RCODE()),
			"answers": len(msg.Answers),
			"rtt_ms":  dur.Milliseconds(),
			"ad":      msg.Header.AD(),
			"mode":    "forward",
		})
		status := ""
		if r.config.DNSSECEnabled && msg.Header.AD() {
			status = "secure"
		}
		return &ResolveResult{
			Answers:      msg.Answers,
			Authority:    msg.Authority,
			Additional:   msg.Additional,
			RCODE:        msg.Header.RCODE(),
			DNSSECStatus: status,
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("forward: all upstreams unreachable")
	}
	return &ResolveResult{RCODE: dns.RCodeServFail, Error: lastErr}, lastErr
}

// traceIterative mirrors resolveIterativeFromInner but emits per-step events.
// It re-uses queryUpstream, classifyResponse, the DNSSEC validator, and the
// security/bailiwick sanitizer so the trace reflects production semantics.
func (r *Resolver) traceIterative(
	t *tracer,
	name string,
	qtype uint16,
	qclass uint16,
	initialNS []string,
	initialZone string,
	cnameDepth int,
	maxDepth int,
	maxCNAME int,
	opts TraceOptions,
	visited *visitedSet,
) (*ResolveResult, error) {
	if cnameDepth > maxCNAME {
		t.emit("cname", TraceStatusError, fmt.Sprintf("CNAME chain longer than %d — aborting", maxCNAME), nil)
		return &ResolveResult{RCODE: dns.RCodeServFail}, errors.New("CNAME chain too long")
	}

	currentZone := initialZone
	nameservers := initialNS
	var lastErr error

	for depth := 0; depth < maxDepth; depth++ {
		if err := t.ctxErr(); err != nil {
			return nil, err
		}

		if len(nameservers) == 0 {
			t.emit("iterative-step", TraceStatusError, "no reachable nameserver", map[string]any{
				"zone":  currentZone,
				"depth": depth,
			})
			return &ResolveResult{RCODE: dns.RCodeServFail, Error: errors.New("no reachable nameserver")}, nil
		}

		nsIP := nameservers[0]

		queryName := name
		queryType := qtype
		if r.config.QMinEnabled {
			queryName, queryType = r.minimizeQName(name, qtype, currentZone)
		}

		t.emit("iterative-step", TraceStatusInfo, fmt.Sprintf("step %d: querying %s for %s %s (zone=%q)", depth, nsIP, queryName, typeName(queryType), currentZone), map[string]any{
			"depth":      depth,
			"ns":         nsIP,
			"zone":       currentZone,
			"query_name": queryName,
			"query_type": typeName(queryType),
			"qmin":       queryName != name || queryType != qtype,
		})

		start := time.Now()
		response, err := r.queryUpstream(nsIP, queryName, queryType, qclass)
		rtt := time.Since(start)
		if err != nil {
			r.infraCache.RecordFailure(nsIP)
			t.emit("upstream", TraceStatusWarn, fmt.Sprintf("ns %s: %v", nsIP, err), map[string]any{
				"ns":     nsIP,
				"error":  err.Error(),
				"rtt_ms": rtt.Milliseconds(),
			})
			lastErr = err
			nameservers = nameservers[1:]
			continue
		}
		r.infraCache.RecordRTT(nsIP, rtt)
		t.emit("upstream", TraceStatusOK, fmt.Sprintf("ns %s answered in %dms rcode=%s answers=%d", nsIP, rtt.Milliseconds(), rcodeName(response.Header.RCODE()), len(response.Answers)), map[string]any{
			"ns":         nsIP,
			"rtt_ms":     rtt.Milliseconds(),
			"rcode":      rcodeName(response.Header.RCODE()),
			"answers":    len(response.Answers),
			"authority":  len(response.Authority),
			"additional": len(response.Additional),
			"ad":         response.Header.AD(),
		})

		security.SanitizeBailiwick(response, currentZone)
		rtype := classifyResponse(response, queryName, queryType)

		// QNAME minimisation: retry full query if minimised attempt didn't
		// yield a referral. Same semantics as resolveIterativeFromInner.
		minimised := queryName != name || queryType != qtype
		if r.config.QMinEnabled && minimised && rtype != responseReferral {
			t.emit("classify", TraceStatusInfo, "qmin: minimised query did not yield a referral, re-asking full question", map[string]any{
				"minimised_type": typeName(queryType),
				"full_name":      name,
				"full_type":      typeName(qtype),
			})
			start = time.Now()
			response, err = r.queryUpstream(nsIP, name, qtype, qclass)
			rtt = time.Since(start)
			if err != nil {
				t.emit("upstream", TraceStatusWarn, fmt.Sprintf("qmin fallback to %s failed: %v", nsIP, err), map[string]any{
					"ns": nsIP, "error": err.Error(), "rtt_ms": rtt.Milliseconds(),
				})
				lastErr = err
				nameservers = nameservers[1:]
				continue
			}
			security.SanitizeBailiwick(response, currentZone)
			rtype = classifyResponse(response, name, qtype)
		}

		t.emit("classify", TraceStatusInfo, fmt.Sprintf("classified as %s", classifyName(rtype)), map[string]any{
			"type": classifyName(rtype),
		})

		switch rtype {
		case responseAnswer:
			result := &ResolveResult{
				Answers:    response.Answers,
				Authority:  response.Authority,
				Additional: response.Additional,
				RCODE:      dns.RCodeNoError,
			}
			r.traceDNSSEC(t, response, name, qtype, opts, result)
			return result, nil

		case responseCNAME:
			target := extractCNAMETarget(response, name)
			if target == "" {
				t.emit("cname", TraceStatusError, "CNAME response with no target", nil)
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			if visited.HasCNAME(target) {
				t.emit("cname", TraceStatusError, fmt.Sprintf("CNAME loop detected at %s", target), nil)
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			visited.AddCNAME(target)
			t.emit("cname", TraceStatusInfo, fmt.Sprintf("CNAME %s → %s — restarting from roots", name, target), map[string]any{
				"from":  name,
				"to":    target,
				"depth": cnameDepth + 1,
			})

			cnameVerdict := dnssec.Insecure
			if r.dnssecValidator != nil && !opts.SkipDNSSEC {
				var steps []dnssec.ValidationStep
				cnameVerdict, steps = r.dnssecValidator.ValidateResponseDetailed(response, name, dns.TypeCNAME)
				emitValidationSteps(t, steps, "cname")
				st := verdictStatus(cnameVerdict)
				t.emit("dnssec", st, fmt.Sprintf("CNAME hop %s → %s: %s", name, target, cnameVerdict), map[string]any{
					"hop":     "cname",
					"verdict": cnameVerdict.String(),
					"steps":   len(steps),
				})
				if cnameVerdict == dnssec.Bogus {
					return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
				}
			}

			rootAddrs := make([]string, 0, len(r.rootServers))
			for _, ns := range r.rootServers {
				if ns.IPv4 != "" {
					rootAddrs = append(rootAddrs, ns.IPv4)
				}
			}
			sub, err := r.traceIterative(t, target, qtype, qclass, rootAddrs, "", cnameDepth+1, maxDepth, maxCNAME, opts, visited)
			if err != nil {
				return sub, err
			}
			cnameRRs := extractCNAMERecords(response, name)
			sub.Answers = append(cnameRRs, sub.Answers...)
			sub.DNSSECStatus = combineDNSSECStatus(verdictToStatus(cnameVerdict), sub.DNSSECStatus)
			return sub, nil

		case responseReferral:
			newNS, zone := extractDelegation(response)
			if len(newNS) == 0 {
				t.emit("delegation", TraceStatusError, "referral has no usable NS records", nil)
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			validateReferralNS(newNS, zone, r.logger)

			nsIPs := make([]string, 0, len(newNS))
			nsNames := make([]string, 0, len(newNS))
			for _, d := range newNS {
				nsNames = append(nsNames, d.Hostname)
				if d.IPv4 != "" {
					// Glue IPv4 in the delegation table is already a printable
					// dotted-quad string, not a 4-byte slice.
					nsIPs = append(nsIPs, d.IPv4)
				}
			}
			// If no glue, resolve at least one NS via cache/recursion so
			// we have an IP to query next iteration.
			if len(nsIPs) == 0 {
				for _, ns := range newNS {
					if res, err := r.resolveNSAddr(ns.Hostname, dns.TypeA); err == nil {
						for _, rr := range res.Answers {
							if rr.Type == dns.TypeA {
								if ip, perr := dns.ParseA(rr.RData); perr == nil {
									nsIPs = append(nsIPs, ip.String())
								}
							}
						}
						if len(nsIPs) > 0 {
							break
						}
					}
				}
			}

			t.emit("delegation", TraceStatusOK, fmt.Sprintf("referred to zone %q with %d NS (%d glue)", zone, len(newNS), len(nsIPs)), map[string]any{
				"zone":     zone,
				"ns_names": nsNames,
				"ns_ips":   nsIPs,
			})

			r.cacheDelegation(response, zone)
			nameservers = nsIPs
			currentZone = zone
			continue

		case responseNXDomain:
			result := &ResolveResult{
				Authority: response.Authority,
				RCODE:     dns.RCodeNXDomain,
			}
			if r.dnssecValidator != nil && !opts.SkipDNSSEC {
				status := r.validateDenialIfEnabled(response, name, qtype, false)
				result.DNSSECStatus = status
				t.emit("dnssec", denialStatus(status), fmt.Sprintf("NXDOMAIN denial proof: %s", nzs(status)), map[string]any{
					"verdict": status,
				})
				if status == "bogus" {
					return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
				}
			}
			r.cache.StoreNegative(name, qtype, qclass, cache.NegNXDomain, dns.RCodeNXDomain, response.Authority)
			return result, nil

		case responseNoData:
			result := &ResolveResult{
				Authority: response.Authority,
				RCODE:     dns.RCodeNoError,
			}
			if r.dnssecValidator != nil && !opts.SkipDNSSEC {
				status := r.validateDenialIfEnabled(response, name, qtype, false)
				result.DNSSECStatus = status
				t.emit("dnssec", denialStatus(status), fmt.Sprintf("NODATA denial proof: %s", nzs(status)), map[string]any{
					"verdict": status,
				})
				if status == "bogus" {
					return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
				}
			}
			r.cache.StoreNegative(name, qtype, qclass, cache.NegNoData, dns.RCodeNoError, response.Authority)
			return result, nil

		case responseDNAME:
			target := extractDNAMETarget(response, name)
			if target == "" {
				t.emit("dname", TraceStatusError, "DNAME response with no usable target", nil)
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			t.emit("dname", TraceStatusInfo, fmt.Sprintf("DNAME substitution: %s → %s", name, target), map[string]any{
				"from": name, "to": target,
			})
			rootAddrs := make([]string, 0, len(r.rootServers))
			for _, ns := range r.rootServers {
				if ns.IPv4 != "" {
					rootAddrs = append(rootAddrs, ns.IPv4)
				}
			}
			return r.traceIterative(t, target, qtype, qclass, rootAddrs, "", cnameDepth+1, maxDepth, maxCNAME, opts, visited)

		case responseServFail:
			t.emit("classify", TraceStatusWarn, fmt.Sprintf("ns %s returned ServFail/Refused — trying next", nsIP), map[string]any{
				"ns":    nsIP,
				"rcode": rcodeName(response.Header.RCODE()),
			})
			nameservers = nameservers[1:]
			continue
		}
	}

	t.emit("iterative-step", TraceStatusError, "max iterative depth reached", map[string]any{
		"max_depth": maxDepth,
	})
	return &ResolveResult{RCODE: dns.RCodeServFail, Error: lastErr}, nil
}

func (r *Resolver) traceDNSSEC(t *tracer, response *dns.Message, name string, qtype uint16, opts TraceOptions, result *ResolveResult) {
	if r.dnssecValidator == nil || opts.SkipDNSSEC {
		t.emit("dnssec", TraceStatusInfo, "DNSSEC validation skipped", map[string]any{
			"reason": dnssecSkipReason(r.dnssecValidator == nil, opts.SkipDNSSEC),
		})
		return
	}
	verdict, steps := r.dnssecValidator.ValidateResponseDetailed(response, name, qtype)
	emitValidationSteps(t, steps, "answer")
	st := verdictStatus(verdict)
	t.emit("dnssec", st, fmt.Sprintf("validator verdict: %s", verdict), map[string]any{
		"verdict": verdict.String(),
		"steps":   len(steps),
	})
	switch verdict {
	case dnssec.Secure:
		result.DNSSECStatus = "secure"
	case dnssec.Insecure:
		result.DNSSECStatus = "insecure"
	case dnssec.Bogus:
		result.DNSSECStatus = "bogus"
		result.RCODE = dns.RCodeServFail
	}
}

// emitValidationSteps surfaces each per-RRSIG decision the DNSSEC validator
// took as its own trace event. This is the difference between "Bogus" (which
// tells you nothing) and "this specific RRSIG over CNAME under signer X with
// key tag Y failed crypto verification" — which tells you what to fix.
func emitValidationSteps(t *tracer, steps []dnssec.ValidationStep, hop string) {
	for _, s := range steps {
		status := TraceStatusInfo
		switch s.Outcome {
		case "ok":
			status = TraceStatusOK
		case "bogus":
			status = TraceStatusError
		case "indeterminate":
			status = TraceStatusWarn
		case "insecure":
			status = TraceStatusInfo
		case "skipped":
			status = TraceStatusInfo
		}
		msg := fmt.Sprintf("[%s] %s (%s) signer=%s key_tag=%d alg=%d labels=%d",
			s.Stage, s.Outcome, typeName(s.TypeCovered), s.Signer, s.KeyTag, s.Algorithm, s.Labels)
		if s.Detail != "" {
			msg = msg + " — " + s.Detail
		}
		t.emit("dnssec", status, msg, map[string]any{
			"hop":          hop,
			"stage":        s.Stage,
			"outcome":      s.Outcome,
			"signer":       s.Signer,
			"owner":        s.Owner,
			"key_tag":      s.KeyTag,
			"algorithm":    s.Algorithm,
			"type_covered": typeName(s.TypeCovered),
			"labels":       s.Labels,
			"detail":       s.Detail,
		})
	}
}

// --- helpers ---

type tracer struct {
	ctx    context.Context
	out    chan<- TraceEvent
	start  time.Time
	seq    uint64
	closed bool
}

func newTracer(ctx context.Context, out chan<- TraceEvent) *tracer {
	return &tracer{ctx: ctx, out: out, start: time.Now()}
}

func (t *tracer) emit(stage string, status TraceStatus, message string, details map[string]any) {
	if t.closed {
		return
	}
	t.seq++
	ev := TraceEvent{
		Seq:       t.seq,
		Stage:     stage,
		Status:    status,
		Time:      time.Now(),
		ElapsedMs: time.Since(t.start).Milliseconds(),
		Message:   message,
		Details:   details,
	}
	select {
	case t.out <- ev:
	case <-t.ctx.Done():
		t.closed = true
	}
}

func (t *tracer) ctxErr() error {
	return t.ctx.Err()
}

func (t *tracer) finish() {
	t.closed = true
}

func verdictStatus(v dnssec.ValidationResult) TraceStatus {
	switch v {
	case dnssec.Secure:
		return TraceStatusOK
	case dnssec.Bogus:
		return TraceStatusError
	default:
		return TraceStatusInfo
	}
}

func denialStatus(s string) TraceStatus {
	switch s {
	case "secure":
		return TraceStatusOK
	case "bogus":
		return TraceStatusError
	default:
		return TraceStatusInfo
	}
}

func nzs(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

func dnssecSkipReason(noValidator, skip bool) string {
	switch {
	case noValidator && skip:
		return "no validator and skip requested"
	case noValidator:
		return "no validator configured"
	case skip:
		return "trace requested skip"
	}
	return ""
}

func rcodeName(code uint8) string {
	switch code {
	case dns.RCodeNoError:
		return "NOERROR"
	case dns.RCodeFormErr:
		return "FORMERR"
	case dns.RCodeServFail:
		return "SERVFAIL"
	case dns.RCodeNXDomain:
		return "NXDOMAIN"
	case dns.RCodeNotImp:
		return "NOTIMP"
	case dns.RCodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", code)
}

func classifyName(rt responseType) string {
	switch rt {
	case responseAnswer:
		return "answer"
	case responseCNAME:
		return "cname"
	case responseDNAME:
		return "dname"
	case responseReferral:
		return "referral"
	case responseNXDomain:
		return "nxdomain"
	case responseNoData:
		return "nodata"
	case responseServFail:
		return "servfail"
	}
	return "unknown"
}

func typeName(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeCNAME:
		return "CNAME"
	case dns.TypeMX:
		return "MX"
	case dns.TypeNS:
		return "NS"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeSOA:
		return "SOA"
	case dns.TypePTR:
		return "PTR"
	case dns.TypeSRV:
		return "SRV"
	case dns.TypeDNSKEY:
		return "DNSKEY"
	case dns.TypeDS:
		return "DS"
	case dns.TypeRRSIG:
		return "RRSIG"
	case dns.TypeNSEC:
		return "NSEC"
	case dns.TypeNSEC3:
		return "NSEC3"
	case dns.TypeDNAME:
		return "DNAME"
	case dns.TypeNSEC3PARAM:
		return "NSEC3PARAM"
	case dns.TypeANY:
		return "ANY"
	}
	if s, ok := dns.TypeToString[qtype]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", qtype)
}
