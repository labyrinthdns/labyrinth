package blocklist

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
)

// RPZActionType defines the action an RPZ rule specifies.
type RPZActionType int

const (
	// RPZActionNXDomain returns NXDOMAIN for the matched domain.
	RPZActionNXDomain RPZActionType = iota
	// RPZActionNODATA returns NODATA (empty answer, NOERROR) for the matched domain.
	RPZActionNODATA
	// RPZActionPassthru allows the query through (whitelist).
	RPZActionPassthru
	// RPZActionDrop silently drops the query.
	RPZActionDrop
	// RPZActionLocalA redirects to a custom IPv4 address.
	RPZActionLocalA
	// RPZActionLocalAAAA redirects to a custom IPv6 address.
	RPZActionLocalAAAA
)

// RPZRule represents a single parsed RPZ rule.
type RPZRule struct {
	// Name is the domain pattern (e.g., "example.com" or "*.example.com").
	Name string
	// IsWildcard is true if the rule applies to all subdomains of the domain.
	IsWildcard bool
	// Action describes what to do when the rule matches.
	Action RPZAction
}

// RPZAction holds the action type and optional data (e.g., redirect IP).
type RPZAction struct {
	Type RPZActionType
	IP   net.IP // set for LocalA / LocalAAAA
}

// ParseRPZ parses RPZ zone file content and returns a list of rules.
// Each line should be in the format:
//
//	<owner> <TTL?> <CLASS?> <RRTYPE> <RDATA>
//
// Supported rule patterns:
//   - `example.com CNAME .`          → NXDOMAIN
//   - `example.com CNAME *.`         → NODATA
//   - `example.com CNAME rpz-passthru.` → PASSTHRU (whitelist)
//   - `example.com CNAME rpz-drop.`  → DROP
//   - `example.com A 10.0.0.1`       → redirect to IPv4
//   - `example.com AAAA ::1`         → redirect to IPv6
//   - `*.example.com CNAME .`        → NXDOMAIN for all subdomains
func ParseRPZ(r io.Reader) ([]RPZRule, error) {
	var rules []RPZRule
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and blank lines.
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		// Skip SOA, NS, and $-directives.
		if line[0] == '$' {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		owner := strings.ToLower(strings.TrimSuffix(fields[0], "."))
		if owner == "" {
			continue
		}

		// Determine if this is a wildcard rule.
		isWildcard := false
		if strings.HasPrefix(owner, "*.") {
			isWildcard = true
			owner = owner[2:] // strip the "*." prefix
		}

		// Find the RRTYPE and RDATA. Skip optional TTL and CLASS fields.
		// fields[1..] may be: [TTL] [CLASS] RRTYPE RDATA
		idx := 1
		// Skip numeric TTL
		if idx < len(fields) && isNumeric(fields[idx]) {
			idx++
		}
		// Skip class (IN, CH, etc.)
		if idx < len(fields) && isClass(fields[idx]) {
			idx++
		}

		if idx+1 >= len(fields)+1 {
			continue // not enough fields for type + rdata
		}

		rrtype := strings.ToUpper(fields[idx])
		rdata := ""
		if idx+1 < len(fields) {
			rdata = strings.ToLower(fields[idx+1])
		}

		var action RPZAction

		switch rrtype {
		case "CNAME":
			rdata = strings.TrimSuffix(rdata, ".")
			switch rdata {
			case "":
				// "CNAME ." → NXDOMAIN
				action = RPZAction{Type: RPZActionNXDomain}
			case "*":
				// "CNAME *." → NODATA
				action = RPZAction{Type: RPZActionNODATA}
			case "rpz-passthru":
				action = RPZAction{Type: RPZActionPassthru}
			case "rpz-drop":
				action = RPZAction{Type: RPZActionDrop}
			default:
				// Unknown CNAME target, skip
				continue
			}
		case "A":
			if rdata == "" {
				continue
			}
			ip := net.ParseIP(rdata)
			if ip == nil {
				continue
			}
			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}
			action = RPZAction{Type: RPZActionLocalA, IP: ipv4}
		case "AAAA":
			if rdata == "" {
				continue
			}
			ip := net.ParseIP(rdata)
			if ip == nil {
				continue
			}
			action = RPZAction{Type: RPZActionLocalAAAA, IP: ip.To16()}
		default:
			// Skip unsupported types (SOA, NS, etc.)
			continue
		}

		rules = append(rules, RPZRule{
			Name:       owner,
			IsWildcard: isWildcard,
			Action:     action,
		})
	}

	return rules, scanner.Err()
}

// isNumeric returns true if s consists only of digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isClass returns true if s is a DNS class name.
func isClass(s string) bool {
	upper := strings.ToUpper(s)
	return upper == "IN" || upper == "CH" || upper == "HS" || upper == "ANY"
}

// RPZMatcher is a concurrent-safe matcher for RPZ rules. It supports exact
// domain matches and wildcard (subdomain) matches. Passthru (whitelist)
// rules are checked first.
type RPZMatcher struct {
	mu              sync.RWMutex
	exact           map[string]RPZAction
	wildcards       map[string]RPZAction
	exactPassthru   map[string]struct{}
	wildcardPassthru map[string]struct{}
}

// NewRPZMatcher creates an empty RPZMatcher.
func NewRPZMatcher() *RPZMatcher {
	return &RPZMatcher{
		exact:            make(map[string]RPZAction),
		wildcards:        make(map[string]RPZAction),
		exactPassthru:    make(map[string]struct{}),
		wildcardPassthru: make(map[string]struct{}),
	}
}

// AddRule adds a parsed RPZ rule to the matcher.
func (m *RPZMatcher) AddRule(rule RPZRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := normalize(rule.Name)
	if name == "" {
		return
	}

	if rule.Action.Type == RPZActionPassthru {
		if rule.IsWildcard {
			m.wildcardPassthru[name] = struct{}{}
		} else {
			m.exactPassthru[name] = struct{}{}
		}
		return
	}

	if rule.IsWildcard {
		m.wildcards[name] = rule.Action
	} else {
		m.exact[name] = rule.Action
	}
}

// Match checks if qname matches any RPZ rule and returns the corresponding
// action. Passthru rules are checked first; if the domain is whitelisted,
// nil is returned. Returns nil if no rule matches.
func (m *RPZMatcher) Match(qname string) *RPZAction {
	qname = normalize(qname)
	if qname == "" {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check passthru (whitelist) first.
	if _, ok := m.exactPassthru[qname]; ok {
		return nil
	}
	d := qname
	for {
		if _, ok := m.wildcardPassthru[d]; ok {
			return nil
		}
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			break
		}
		d = d[idx+1:]
	}

	// Check exact match.
	if action, ok := m.exact[qname]; ok {
		return &action
	}

	// Check wildcard match (walk up labels).
	d = qname
	for {
		if action, ok := m.wildcards[d]; ok {
			return &action
		}
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			break
		}
		d = d[idx+1:]
	}

	return nil
}

// Stats returns the number of exact rules, wildcard rules, and passthru rules.
func (m *RPZMatcher) Stats() (exact, wildcards, passthru int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.exact), len(m.wildcards), len(m.exactPassthru) + len(m.wildcardPassthru)
}
