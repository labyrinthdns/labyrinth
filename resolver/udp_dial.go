package resolver

import (
	"net"
	"time"
)

// dialUDP opens a CONNECTED UDP socket to addr with the given timeout. Two
// SAD-DNS hardening properties (CVE-2020-25705 / CVE-2021-20322):
//
//   - Connected (Dial, not ListenPacket): the kernel filters inbound datagrams
//     by the full 4-tuple, so off-path spoofers must match our random source
//     port, not just the destination.
//   - On platforms that support it (Linux), udpSocketControl sets
//     IP_PMTUDISC_OMIT on the socket so the kernel keeps no per-destination
//     PMTU exception for this flow and ignores ICMP "fragmentation needed"
//     for it. That removes the side channel SAD-DNS uses (probing the global
//     ICMP rate limit / per-socket PMTU cache) to infer the source port and
//     collapse the spoofing entropy back toward the 16-bit TXID.
//
// The socket option is best-effort and never blocks the dial — on a kernel or
// platform that lacks it, resolution proceeds on the plain connected socket,
// still protected by the 0x20 / DNS-cookie / TXID / port-entropy / DNSSEC stack.
func dialUDP(addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		Timeout: timeout,
		Control: udpSocketControl,
	}
	return d.Dial("udp", addr)
}
