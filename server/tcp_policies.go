package server

import (
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// applyTCPTransportPolicies applies stateful-transport EDNS policies to
// a wire-format response based on what the client signalled in its query:
//
//   - RFC 7828 (edns-tcp-keepalive): if the client carried a KEEPALIVE
//     option, attach our idle timeout so the client can hold the
//     connection open across queries.
//   - RFC 7830 + RFC 8467 (PADDING): if the client carried a PADDING
//     option AND the transport is encrypted, pad the response to the
//     next 468-byte boundary. RFC 8467 §6 explicitly disallows padding
//     on plaintext TCP (the privacy gain is zero on a wire an observer
//     already sees in full, and the bytes are pure waste).
//
// Unknown encoding or non-EDNS queries are passed through unchanged —
// padding/keepalive only matter when the client opted in.
func applyTCPTransportPolicies(query, response []byte, idleTimeout time.Duration, encrypted bool) []byte {
	qmsg, err := dns.Unpack(query)
	if err != nil || qmsg.EDNS0 == nil {
		return response
	}
	if encrypted && dns.HasPaddingOption(qmsg.EDNS0) {
		response = dns.PadRawResponse(response, dns.PaddingBlockSize)
	}
	if dns.HasTCPKeepaliveOption(qmsg.EDNS0) {
		units := uint16(idleTimeout / (100 * time.Millisecond))
		if units == 0 {
			// Floor to a single 100ms tick — a zero would tell the
			// client to close immediately, which defeats the purpose
			// of even signalling keepalive.
			units = 1
		}
		response = dns.AddTCPKeepaliveToRawResponse(response, units)
	}
	return response
}
