//go:build linux

package resolver

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// udpSocketControl sets IP_PMTUDISC_OMIT (and the IPv6 equivalent) on the raw
// UDP socket before connect, so the kernel maintains no per-destination PMTU
// exception for this flow and ignores ICMP "fragmentation needed" messages for
// it. This closes the SAD-DNS PMTU side channel (CVE-2021-20322).
//
// Both setsockopts are best-effort: a kernel that rejects an option, or an
// IPv4-only socket rejecting the IPv6 option (and vice versa), still yields a
// working connected UDP socket. The callback always returns nil so this
// hardening can never fail a dial — resolution must not depend on it.
func udpSocketControl(network, address string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_OMIT)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_OMIT)
	})
	return nil
}
