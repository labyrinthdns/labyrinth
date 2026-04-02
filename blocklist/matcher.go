package blocklist

import (
	"strings"
	"sync"
)

// Matcher is a concurrent-safe domain matching engine that supports exact
// domain blocking, wildcard blocking (domain + all subdomains), and
// whitelist overrides. Lookups are O(1) for exact matches and O(k) for
// wildcard walks where k is the number of labels in the queried domain.
type Matcher struct {
	mu                sync.RWMutex
	exact             map[string]struct{}
	wildcards         map[string]struct{}
	whitelist         map[string]struct{}
	wildcardWhitelist map[string]struct{}
}

// NewMatcher creates an empty Matcher ready for use.
func NewMatcher() *Matcher {
	return &Matcher{
		exact:             make(map[string]struct{}),
		wildcards:         make(map[string]struct{}),
		whitelist:         make(map[string]struct{}),
		wildcardWhitelist: make(map[string]struct{}),
	}
}

// normalize lowercases the domain and trims a trailing dot so that
// "Example.COM." and "example.com" are treated identically.
func normalize(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

// Match returns true if the domain should be blocked.
//
// The evaluation order is:
//  1. Normalize the domain.
//  2. Check the whitelist (exact match, then wildcard walk). If the domain
//     is whitelisted, return false immediately.
//  3. Check for an exact block match.
//  4. Walk up the domain labels checking for wildcard block matches.
func (m *Matcher) Match(domain string) bool {
	domain = normalize(domain)
	if domain == "" {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// --- whitelist check ---
	if _, ok := m.whitelist[domain]; ok {
		return false
	}
	// wildcard whitelist walk
	d := domain
	for {
		if _, ok := m.wildcardWhitelist[d]; ok {
			return false
		}
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			break
		}
		d = d[idx+1:]
	}

	// --- block check ---
	if _, ok := m.exact[domain]; ok {
		return true
	}
	// wildcard block walk
	d = domain
	for {
		if _, ok := m.wildcards[d]; ok {
			return true
		}
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			break
		}
		d = d[idx+1:]
	}

	return false
}

// AddExact adds an exact domain block rule.
func (m *Matcher) AddExact(domain string) {
	domain = normalize(domain)
	if domain == "" {
		return
	}
	m.mu.Lock()
	m.exact[domain] = struct{}{}
	m.mu.Unlock()
}

// AddWildcard adds a wildcard block rule that matches the domain itself
// and all of its subdomains.
func (m *Matcher) AddWildcard(domain string) {
	domain = normalize(domain)
	if domain == "" {
		return
	}
	m.mu.Lock()
	m.wildcards[domain] = struct{}{}
	m.mu.Unlock()
}

// AddWhitelist adds an exact whitelist rule. A whitelisted domain is never
// reported as blocked.
func (m *Matcher) AddWhitelist(domain string) {
	domain = normalize(domain)
	if domain == "" {
		return
	}
	m.mu.Lock()
	m.whitelist[domain] = struct{}{}
	m.mu.Unlock()
}

// AddWildcardWhitelist adds a wildcard whitelist rule that exempts the
// domain and all of its subdomains from blocking.
func (m *Matcher) AddWildcardWhitelist(domain string) {
	domain = normalize(domain)
	if domain == "" {
		return
	}
	m.mu.Lock()
	m.wildcardWhitelist[domain] = struct{}{}
	m.mu.Unlock()
}

// Remove removes a domain from all block lists (exact and wildcard) but
// does not touch the whitelist.
func (m *Matcher) Remove(domain string) {
	domain = normalize(domain)
	if domain == "" {
		return
	}
	m.mu.Lock()
	delete(m.exact, domain)
	delete(m.wildcards, domain)
	m.mu.Unlock()
}

// Reset clears all rules (blocks and whitelists).
func (m *Matcher) Reset() {
	m.mu.Lock()
	m.exact = make(map[string]struct{})
	m.wildcards = make(map[string]struct{})
	m.whitelist = make(map[string]struct{})
	m.wildcardWhitelist = make(map[string]struct{})
	m.mu.Unlock()
}

// Stats returns the number of exact block rules, wildcard block rules,
// and whitelist rules (exact + wildcard combined).
func (m *Matcher) Stats() (exact, wildcards, whitelist int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.exact), len(m.wildcards), len(m.whitelist) + len(m.wildcardWhitelist)
}
