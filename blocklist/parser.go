package blocklist

import (
	"bufio"
	"io"
	"strings"
)

// skipDomains contains hostnames that should be ignored when parsing hosts
// files because they are local machine entries, not advertising domains.
var skipDomains = map[string]struct{}{
	"localhost":              {},
	"localhost.localdomain":  {},
	"local":                  {},
	"broadcasthost":          {},
	"ip6-localhost":          {},
	"ip6-loopback":           {},
	"ip6-localnet":           {},
	"ip6-mcastprefix":        {},
	"ip6-allnodes":           {},
	"ip6-allrouters":         {},
	"ip6-allhosts":           {},
}

// ParseHostsFile parses a hosts-format blocklist where each line maps an
// IP address to a domain (e.g. "0.0.0.0 ads.example.com"). Only lines
// whose first field is "0.0.0.0" or "127.0.0.1" are considered. Standard
// local entries (localhost, broadcasthost, etc.) are skipped.
func ParseHostsFile(r io.Reader) []string {
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}

		// Strip inline comments.
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := fields[0]
		if ip != "0.0.0.0" && ip != "127.0.0.1" {
			continue
		}

		domain := strings.ToLower(fields[1])
		if _, skip := skipDomains[domain]; skip {
			continue
		}

		domains = append(domains, domain)
	}
	return domains
}

// ParseDomainList parses a plain domain list with one domain per line.
// Blank lines and lines starting with '#' or '!' are skipped.
func ParseDomainList(r io.Reader) []string {
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}

		// Strip inline comments.
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		domains = append(domains, strings.ToLower(line))
	}
	return domains
}

// ParseABP parses an AdBlock Plus format blocklist. It extracts domains
// from rules of the form "||ads.example.com^". Other ABP rule types
// (element hiding, exceptions, etc.) are ignored.
func ParseABP(r io.Reader) []string {
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '!' || line[0] == '#' {
			continue
		}
		// ABP header line.
		if strings.HasPrefix(line, "[") {
			continue
		}

		if !strings.HasPrefix(line, "||") {
			continue
		}
		if !strings.HasSuffix(line, "^") {
			continue
		}

		// Extract domain between "||" and "^".
		domain := line[2 : len(line)-1]
		domain = strings.ToLower(domain)
		if domain == "" {
			continue
		}
		// Skip entries that contain path separators or wildcards -- they
		// are URL patterns, not pure domain rules.
		if strings.ContainsAny(domain, "/*") {
			continue
		}

		domains = append(domains, domain)
	}
	return domains
}
