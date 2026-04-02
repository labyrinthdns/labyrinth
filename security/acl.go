package security

import "net"

// ACL implements access control list based on CIDR ranges.
type ACL struct {
	allow []*net.IPNet
	deny  []*net.IPNet
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

// Check returns true if the IP is allowed by the ACL.
func (acl *ACL) Check(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Deny list checked first
	for _, denied := range acl.deny {
		if denied.Contains(ip) {
			return false
		}
	}

	// Empty allow list = allow all
	if len(acl.allow) == 0 {
		return true
	}

	// Check allow list
	for _, allowed := range acl.allow {
		if allowed.Contains(ip) {
			return true
		}
	}

	return false
}
