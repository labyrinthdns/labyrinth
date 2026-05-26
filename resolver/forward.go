package resolver

import (
	"errors"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

var errTXIDMismatch = errors.New("transaction ID mismatch")

// ForwardZone represents a configured forwarding or stub zone.
type ForwardZone struct {
	Name   string   // zone name (lowercase, no trailing dot)
	Addrs  []string // upstream IP addresses
	IsStub bool     // false = forward (RD=1), true = stub (RD=0, iterative from addrs)
}

// ForwardTable stores forward/stub zones and provides longest-suffix matching.
type ForwardTable struct {
	zones []ForwardZone
}

// NewForwardTable creates a ForwardTable from the given zone list.
// Zone names are normalised to lowercase with no trailing dot.
func NewForwardTable(zones []ForwardZone) *ForwardTable {
	normalised := make([]ForwardZone, len(zones))
	for i, z := range zones {
		normalised[i] = ForwardZone{
			Name:   strings.ToLower(strings.TrimSuffix(z.Name, ".")),
			Addrs:  z.Addrs,
			IsStub: z.IsStub,
		}
	}
	return &ForwardTable{zones: normalised}
}

// Match finds the ForwardZone whose name is the longest suffix of qname.
// Returns nil if no zone matches.
func (ft *ForwardTable) Match(qname string) *ForwardZone {
	if ft == nil || len(ft.zones) == 0 {
		return nil
	}
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))

	var best *ForwardZone
	bestLen := -1

	for i := range ft.zones {
		z := &ft.zones[i]
		if z.Name == qname || (len(qname) > len(z.Name) && strings.HasSuffix(qname, "."+z.Name)) {
			if len(z.Name) > bestLen {
				best = z
				bestLen = len(z.Name)
			}
		}
	}
	return best
}

// resolveStub performs iterative resolution starting from the stub zone's
// configured nameserver addresses instead of the root servers.
func (r *Resolver) resolveStub(name string, qtype uint16, qclass uint16, fz *ForwardZone) (*ResolveResult, error) {
	return r.resolveStubECS(name, qtype, qclass, fz, nil)
}

// resolveStubECS is the ECS-aware variant: the client's subnet is propagated
// to every upstream stub query so authoritative servers can geo-tailor.
func (r *Resolver) resolveStubECS(name string, qtype uint16, qclass uint16, fz *ForwardZone, clientECS *dns.ECSOption) (*ResolveResult, error) {
	stubNS := make([]nsEntry, len(fz.Addrs))
	for i, addr := range fz.Addrs {
		stubNS[i] = nsEntry{
			hostname: "stub-ns-" + addr,
			ipv4:     addr,
		}
	}
	return r.resolveIterativeFromInner(name, qtype, qclass, 0, newVisitedSet(), stubNS, fz.Name, false, clientECS)
}

// queryForward sends a recursive (RD=1) query to the forward zone upstreams.
// It tries each address in order and returns the first successful result.
//
// Forward zones are configured to point at trusted validating resolvers
// (RFC 8499 §6 forwarder). When the upstream signals validation success via
// the AD bit AND we ourselves sent DO=1 (so the upstream understood we want
// DNSSEC), we propagate that verdict to our caller so the eventual response
// to the client carries AD=1. The upstream's AD is otherwise ignored: an
// unsigned channel to an unauthenticated server cannot prove anything, but
// forward-zone upstreams are operator-trusted by configuration.
func (r *Resolver) queryForward(addrs []string, name string, qtype uint16, qclass uint16) (*ResolveResult, error) {
	return r.queryForwardECS(addrs, name, qtype, qclass, nil)
}

func (r *Resolver) queryForwardECS(addrs []string, name string, qtype uint16, qclass uint16, clientECS *dns.ECSOption) (*ResolveResult, error) {
	var lastErr error
	for _, addr := range addrs {
		msg, err := r.sendForwardQueryECS(addr, name, qtype, qclass, clientECS)
		if err != nil {
			lastErr = err
			r.logger.Debug("forward query error", "addr", addr, "name", name, "error", err)
			continue
		}
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
			UpstreamECS:  extractResponseECS(msg),
		}, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return &ResolveResult{RCODE: dns.RCodeServFail}, nil
}

// sendForwardQuery builds and sends a single DNS query with RD=1.
func (r *Resolver) sendForwardQuery(nsIP string, name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	return r.sendForwardQueryECS(nsIP, name, qtype, qclass, nil)
}

func (r *Resolver) sendForwardQueryECS(nsIP string, name string, qtype uint16, qclass uint16, clientECS *dns.ECSOption) (*dns.Message, error) {
	r.metrics.IncUpstreamQueries()

	retries := r.config.UpstreamRetries
	if retries < 1 {
		retries = 1
	}

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		msg, err := r.sendForwardQueryOnceECS(nsIP, name, qtype, qclass, clientECS)
		if err != nil {
			lastErr = err
			r.metrics.IncUpstreamErrors()
			continue
		}
		return msg, nil
	}
	return nil, lastErr
}

// sendForwardQueryOnce sends a single forward query with RD=1 and EDNS0.
func (r *Resolver) sendForwardQueryOnce(nsIP string, name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	return r.sendForwardQueryOnceECS(nsIP, name, qtype, qclass, nil)
}

func (r *Resolver) sendForwardQueryOnceECS(nsIP string, name string, qtype uint16, qclass uint16, clientECS *dns.ECSOption) (*dns.Message, error) {
	msg, err := r.sendQueryWithRDECS(nsIP, name, qtype, qclass, true, true, clientECS)
	if err != nil {
		return nil, err
	}

	// If the server returns FORMERR (doesn't understand EDNS0),
	// retry without the OPT record (and without ECS — a server that can't
	// parse EDNS0 won't accept nested ECS options either).
	if msg.Header.RCODE() == dns.RCodeFormErr {
		msg, err = r.sendQueryWithRDECS(nsIP, name, qtype, qclass, true, false, nil)
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// sendQueryWithRD is the legacy no-ECS wrapper retained for tests and for
// internal paths that do not carry a client subnet (e.g. trace).
func (r *Resolver) sendQueryWithRD(nsIP string, name string, qtype uint16, qclass uint16, rd bool, withEDNS0 bool) (*dns.Message, error) {
	return r.sendQueryWithRDECS(nsIP, name, qtype, qclass, rd, withEDNS0, nil)
}

// sendQueryWithRDECS builds, sends and validates a DNS query with a configurable
// RD flag. clientECS, when non-nil and withEDNS0 is true, is included as an
// EDNS Client Subnet option (RFC 7871) in the outgoing OPT record.
func (r *Resolver) sendQueryWithRDECS(nsIP string, name string, qtype uint16, qclass uint16, rd bool, withEDNS0 bool, clientECS *dns.ECSOption) (*dns.Message, error) {
	txID, err := randTXIDFunc()
	if err != nil {
		return nil, err
	}

	query := &dns.Message{
		Header: dns.Header{
			ID: txID,
			Flags: dns.NewFlagBuilder().
				SetRD(rd).
				Build(),
			QDCount: 1,
		},
		Questions: []dns.Question{{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		}},
	}
	if withEDNS0 {
		var ecsOptions []dns.EDNSOption
		if r.config.ECSEnabled && clientECS != nil {
			outgoing := *clientECS
			outgoing.ScopePrefixLen = 0
			ecsOptions = append(ecsOptions, dns.BuildECS(&outgoing))
		}
		if len(ecsOptions) > 0 {
			query.Additional = []dns.ResourceRecord{
				dns.BuildOPTWithOptions(r.advertisedUDPBufferSize(), r.config.DNSSECEnabled, ecsOptions),
			}
		} else {
			query.Additional = []dns.ResourceRecord{
				dns.BuildOPT(r.advertisedUDPBufferSize(), r.config.DNSSECEnabled),
			}
		}
	}

	buf := make([]byte, 4096)
	packed, err := dns.Pack(query, buf)
	if err != nil {
		return nil, err
	}

	// Try UDP first
	response, err := r.queryUDP(nsIP, packed)
	if err != nil {
		return nil, err
	}

	msg, err := dns.Unpack(response)
	if err != nil {
		return nil, err
	}

	// Validate transaction ID
	if msg.Header.ID != txID {
		return nil, errTXIDMismatch
	}
	// Validate question section
	if err := validateResponseQuestion(msg, name, qtype, qclass); err != nil {
		return nil, err
	}

	// TC bit set -> retry over TCP
	if msg.Header.TC() {
		response, err = r.queryTCP(nsIP, packed)
		if err != nil {
			return nil, err
		}
		msg, err = dns.Unpack(response)
		if err != nil {
			return nil, err
		}
		if msg.Header.ID != txID {
			return nil, errTXIDMismatch
		}
		if err := validateResponseQuestion(msg, name, qtype, qclass); err != nil {
			return nil, err
		}
	}

	return msg, nil
}
