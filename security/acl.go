package security

import (
	"net"
	"strings"
)

// ACL implements access control list based on CIDR ranges, with optional
// per-zone overrides.
type ACL struct {
	allow []*net.IPNet
	deny  []*net.IPNet
	zones []ZoneACL
}

// ZoneACL defines access control rules scoped to a specific DNS zone.
// When a query matches a zone, these rules are evaluated instead of the
// global allow/deny lists.
type ZoneACL struct {
	Zone      string
	AllowNets []*net.IPNet
	DenyNets  []*net.IPNet
}

// ZoneACLConfig is the configuration input for a per-zone ACL rule.
type ZoneACLConfig struct {
	Zone  string
	Allow []string
	Deny  []string
}

// NewACL creates an ACL from allow and deny CIDR lists.
func NewACL(allow, deny []string) (*ACL, error) {
	acl := &ACL{}

	for _, cidr := range allow {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		acl.allow = append(acl.allow, ipNet)
	}

	for _, cidr := range deny {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		acl.deny = append(acl.deny, ipNet)
	}

	return acl, nil
}

// AddZoneACL adds a per-zone access control rule. Zone-specific rules are
// checked before global rules when using CheckWithZone.
func (acl *ACL) AddZoneACL(cfg ZoneACLConfig) error {
	za := ZoneACL{
		Zone: strings.ToLower(strings.TrimSuffix(cfg.Zone, ".")),
	}

	for _, cidr := range cfg.Allow {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		za.AllowNets = append(za.AllowNets, ipNet)
	}

	for _, cidr := range cfg.Deny {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		za.DenyNets = append(za.DenyNets, ipNet)
	}

	acl.zones = append(acl.zones, za)
	return nil
}

// Check returns true if the IP is allowed by the global ACL rules.
func (acl *ACL) Check(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return acl.checkGlobal(ip)
}

// CheckWithZone returns true if the IP is allowed for queries to the given
// qname. It first looks for a matching zone-specific rule. If one is found,
// only that zone's allow/deny lists are evaluated. If no zone matches, the
// global rules are used.
func (acl *ACL) CheckWithZone(ipStr string, qname string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	qname = strings.ToLower(strings.TrimSuffix(qname, "."))

	// Check zone-specific rules (most specific match).
	if za, ok := acl.matchZone(qname); ok {
		return checkNets(ip, za.AllowNets, za.DenyNets)
	}

	// Fall back to global rules.
	return acl.checkGlobal(ip)
}

// matchZone finds the most specific (longest) zone that is a suffix of qname.
func (acl *ACL) matchZone(qname string) (ZoneACL, bool) {
	var best ZoneACL
	bestLen := -1

	for _, za := range acl.zones {
		if !inZoneOrEqual(qname, za.Zone) {
			continue
		}
		if len(za.Zone) > bestLen {
			best = za
			bestLen = len(za.Zone)
		}
	}

	return best, bestLen >= 0
}

// inZoneOrEqual returns true if qname equals zone or is a subdomain of zone.
func inZoneOrEqual(qname, zone string) bool {
	if qname == zone {
		return true
	}
	// qname must end with ".zone"
	if len(qname) > len(zone) && qname[len(qname)-len(zone)-1] == '.' && strings.HasSuffix(qname, zone) {
		return true
	}
	return false
}

// checkGlobal evaluates the global allow/deny lists.
func (acl *ACL) checkGlobal(ip net.IP) bool {
	return checkNets(ip, acl.allow, acl.deny)
}

// checkNets evaluates allow/deny lists for an IP. Deny is checked first.
// If the allow list is empty, all non-denied IPs are allowed.
func checkNets(ip net.IP, allow, deny []*net.IPNet) bool {
	// Deny list checked first
	for _, denied := range deny {
		if denied.Contains(ip) {
			return false
		}
	}

	// Empty allow list = allow all
	if len(allow) == 0 {
		return true
	}

	// Check allow list
	for _, allowed := range allow {
		if allowed.Contains(ip) {
			return true
		}
	}

	return false
}
