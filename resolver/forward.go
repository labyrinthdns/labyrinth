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
	// Build initial nameserver list from stub zone addresses.
	stubNS := make([]nsEntry, len(fz.Addrs))
	for i, addr := range fz.Addrs {
		stubNS[i] = nsEntry{
			hostname: "stub-ns-" + addr,
			ipv4:     addr,
		}
	}

	return r.resolveIterativeFrom(name, qtype, qclass, 0, newVisitedSet(), stubNS, fz.Name)
}

// queryForward sends a recursive (RD=1) query to the forward zone upstreams.
// It tries each address in order and returns the first successful result.
func (r *Resolver) queryForward(addrs []string, name string, qtype uint16, qclass uint16) (*ResolveResult, error) {
	var lastErr error
	for _, addr := range addrs {
		msg, err := r.sendForwardQuery(addr, name, qtype, qclass)
		if err != nil {
			lastErr = err
			r.logger.Debug("forward query error", "addr", addr, "name", name, "error", err)
			continue
		}
		return &ResolveResult{
			Answers:    msg.Answers,
			Authority:  msg.Authority,
			Additional: msg.Additional,
			RCODE:      msg.Header.RCODE(),
		}, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return &ResolveResult{RCODE: dns.RCodeServFail}, nil
}

// sendForwardQuery builds and sends a single DNS query with RD=1.
func (r *Resolver) sendForwardQuery(nsIP string, name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	r.metrics.IncUpstreamQueries()

	retries := r.config.UpstreamRetries
	if retries < 1 {
		retries = 1
	}

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		msg, err := r.sendForwardQueryOnce(nsIP, name, qtype, qclass)
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
	msg, err := r.sendQueryWithRD(nsIP, name, qtype, qclass, true, true)
	if err != nil {
		return nil, err
	}

	// If the server returns FORMERR (doesn't understand EDNS0),
	// retry without the OPT record.
	if msg.Header.RCODE() == dns.RCodeFormErr {
		msg, err = r.sendQueryWithRD(nsIP, name, qtype, qclass, true, false)
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// sendQueryWithRD builds, sends and validates a DNS query with a configurable RD flag.
func (r *Resolver) sendQueryWithRD(nsIP string, name string, qtype uint16, qclass uint16, rd bool, withEDNS0 bool) (*dns.Message, error) {
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
		query.Additional = []dns.ResourceRecord{
			dns.BuildOPT(4096, r.config.DNSSECEnabled),
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
