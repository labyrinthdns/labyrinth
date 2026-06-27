//go:build !linux

package resolver

import "syscall"

// udpSocketControl is a no-op on platforms without the Linux PMTU-discovery
// socket option (Windows, macOS, the BSDs). The connected UDP socket plus the
// 0x20 / DNS-cookie / TXID / source-port-entropy / DNSSEC stack still apply;
// only the IP_PMTUDISC_OMIT side-channel mitigation is Linux-specific.
func udpSocketControl(network, address string, c syscall.RawConn) error {
	return nil
}
