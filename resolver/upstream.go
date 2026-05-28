package resolver

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// queryUpstream is the legacy entry point used by code paths that have no
// client context (root priming, glue resolution, DNSSEC chain fetches,
// trace/fallback). It forwards no ECS option upstream.
func (r *Resolver) queryUpstream(nsIP string, name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	return r.queryUpstreamECS(nsIP, name, qtype, qclass, nil)
}

// queryUpstreamECS is the ECS-aware variant. clientECS, when non-nil and
// the operator policy enables ECS forwarding, is included as an EDNS Client
// Subnet option (RFC 7871) in the outgoing OPT record so the authoritative
// server can geo-tailor its response.
func (r *Resolver) queryUpstreamECS(nsIP string, name string, qtype uint16, qclass uint16, clientECS *dns.ECSOption) (*dns.Message, error) {
	r.metrics.IncUpstreamQueries()

	retries := r.config.UpstreamRetries
	if retries < 1 {
		retries = 1
	}

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		msg, err := r.queryUpstreamOnceECS(nsIP, name, qtype, qclass, clientECS)
		if err == nil {
			return msg, nil
		}
		lastErr = err
		r.metrics.IncUpstreamErrors()
	}
	return nil, lastErr
}

// randTXIDFunc is the function used to generate transaction IDs.
// Overridden in tests to simulate crypto/rand failures.
var randTXIDFunc = randomTXID

func (r *Resolver) queryUpstreamOnce(nsIP string, name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	return r.queryUpstreamOnceECS(nsIP, name, qtype, qclass, nil)
}

func (r *Resolver) queryUpstreamOnceECS(nsIP string, name string, qtype uint16, qclass uint16, clientECS *dns.ECSOption) (*dns.Message, error) {
	// RFC 7873 §5.3 — pre-load the server cookie cached from a prior
	// exchange with this auth (if any) so the FIRST query already
	// carries client||server cookie. Saves the BADCOOKIE round-trip on
	// every query after the cache is warm.
	cachedSC := r.serverCookieCache.Get(nsIP)
	if r.metrics != nil {
		if len(cachedSC) > 0 {
			r.metrics.IncServerCookieCacheHits()
		} else {
			r.metrics.IncServerCookieCacheMisses()
		}
	}
	msg, err := r.sendQuery(nsIP, name, qtype, qclass, true, clientECS, cachedSC)
	if err != nil {
		return nil, err
	}

	// RFC 7873 §5.4 BADCOOKIE handling: when an auth requires DNS cookies
	// it rejects the first query (which carried only our client cookie)
	// with extended RCODE 23 and includes a freshly-minted server cookie
	// in the OPT COOKIE option. We are required to re-issue the query
	// with `client_cookie || server_cookie` so the auth recognises us as
	// the same client. Without this retry we never get past auths that
	// enforce cookies — they will reply BADCOOKIE forever. We retry once
	// only: a second BADCOOKIE is bogus and is surfaced as the answer.
	if extendedRCODE(msg) == dns.RCodeBadCookie {
		if sc := extractServerCookie(msg); len(sc) > 0 {
			if r.metrics != nil {
				r.metrics.IncOutboundBadCookieRetries()
			}
			retried, retryErr := r.sendQuery(nsIP, name, qtype, qclass, true, clientECS, sc)
			if retryErr == nil {
				msg = retried
				// Cache the cookie we negotiated through the BADCOOKIE
				// round-trip so the next query skips it.
				r.serverCookieCache.Put(nsIP, sc)
			}
		}
	} else if sc := extractServerCookie(msg); len(sc) > 0 {
		// Friendly auth that included a server cookie on a successful
		// response — record it for future queries (RFC 7873 §5.3).
		r.serverCookieCache.Put(nsIP, sc)
	}

	// RFC 5452 §6.1 hardening: a FORMERR from an EDNS-bearing query was
	// historically interpreted (per RFC 6891 §7) as "this server hates EDNS,
	// retry without OPT." Modern reality is the opposite — DNS Flag Day
	// 2020 made EDNS mandatory for any auth server that participates in
	// the public DNS, and an EDNS-hostile server is effectively extinct.
	// What does still happen: an off-path attacker who wins the TXID/0x20
	// race for a single forged packet can inject a FORMERR and trigger our
	// silent downgrade to a non-EDNS query that drops DNSSEC OK / ECS /
	// the 1232-byte buffer ceiling — a one-packet downgrade vector against
	// DNSSEC validation. We surface the FORMERR as a server failure
	// instead; the iterative loop's classifyResponse moves to a sibling
	// NS, and no spoofed FORMERR can strip the DO bit off subsequent
	// queries. If an operator ever encounters a legitimately broken EDNS
	// server they should bypass it via the forward-zone configuration
	// rather than have the resolver silently strip protocol features.
	return msg, nil
}

// extendedRCODE returns the 12-bit RCODE per RFC 6891 §6.1.3 — the high
// 8 bits live in the OPT RR's TTL byte 0 (parsed as EDNS0.ExtRCODE) and
// the low 4 bits are in the header Flags field. Without composing them
// a resolver that only looks at Header.RCODE() sees BADCOOKIE (23) as a
// plain "7" (a reserved low-RCODE value) and never triggers the cookie
// retry path.
func extendedRCODE(msg *dns.Message) uint8 {
	if msg == nil {
		return 0
	}
	rc := msg.Header.RCODE()
	if msg.EDNS0 != nil && msg.EDNS0.ExtRCODE != 0 {
		return (msg.EDNS0.ExtRCODE << 4) | rc
	}
	return rc
}

// extractServerCookie returns the server-supplied portion of a COOKIE
// option in the response (bytes 8..end of the option payload, per
// RFC 7873 §4). Returns nil when no cookie or no server cookie portion
// is present.
func extractServerCookie(msg *dns.Message) []byte {
	if msg == nil || msg.EDNS0 == nil {
		return nil
	}
	for _, opt := range msg.EDNS0.Options {
		if opt.Code != dns.EDNSOptionCodeCookie {
			continue
		}
		if len(opt.Data) < 16 {
			return nil
		}
		sc := make([]byte, len(opt.Data)-8)
		copy(sc, opt.Data[8:])
		return sc
	}
	return nil
}

// sendQuery builds, sends and validates a single upstream DNS query.
// When clientECS is non-nil and withEDNS0 is true, the OPT record carries
// an EDNS Client Subnet option (RFC 7871). The outgoing ECS always has
// SCOPE PREFIX-LENGTH = 0 — only authoritative answers set that field.
func (r *Resolver) sendQuery(nsIP string, name string, qtype uint16, qclass uint16, withEDNS0 bool, clientECS *dns.ECSOption, serverCookie []byte) (*dns.Message, error) {
	txID, err := randTXIDFunc()
	if err != nil {
		return nil, err
	}

	// Apply 0x20 case randomization (RFC 5452 anti-spoofing measure).
	queryName := name
	if r.config.Caps0x20Enabled {
		queryName = randomizeCase(name)
	}

	query := &dns.Message{
		Header: dns.Header{
			ID: txID,
			Flags: dns.NewFlagBuilder().
				SetRD(false).
				Build(),
			QDCount: 1,
		},
		Questions: []dns.Question{{
			Name:  queryName,
			Type:  qtype,
			Class: qclass,
		}},
	}
	if withEDNS0 {
		// Per-query ECS, taken from the caller's clientECS argument rather
		// than from global state. This is the fix for the previous
		// activeECS atomic.Pointer design which leaked one client's subnet
		// onto another's outbound query under concurrency.
		var ednsOpts []dns.EDNSOption
		if r.config.ECSEnabled && clientECS != nil {
			// RFC 7871 §6: outgoing queries set SCOPE PREFIX-LENGTH = 0.
			outgoing := *clientECS
			outgoing.ScopePrefixLen = 0
			ednsOpts = append(ednsOpts, dns.BuildECS(&outgoing))
		}
		// RFC 6975: advertise the DNSSEC algorithms / DS digest types /
		// NSEC3 hash algorithms this resolver can validate. Multi-signed
		// zones (key rollovers, dual-algorithm publishing) use this to
		// pick which signature to ship — without DAU they must include
		// every signature, inflating both the response and the resolver's
		// amplification footprint. Only emitted when DNSSEC is enabled
		// (DO bit set), since RFC 6975 §2 ties the option to validating
		// queries.
		if r.config.DNSSECEnabled {
			ednsOpts = append(ednsOpts,
				dns.BuildDAUOption(r.supportedDNSSECAlgorithms()),
				dns.BuildDHUOption(r.supportedDSDigests()),
				dns.BuildN3UOption(r.supportedNSEC3Hashes()),
			)
		}
		// RFC 7873 §5.4 outbound DNS cookies: present our stable 8-byte
		// client cookie on every EDNS-bearing query. An off-path spoofer
		// trying to forge a response now has to guess this 64-bit value in
		// addition to the TXID (16 bits) and the source port (~15 bits of
		// entropy on commodity OS RNGs) — multiplying the brute-force
		// window by ~10^19. Compliant auths echo the cookie back in the
		// COOKIE option; we verify the echo and drop on mismatch (see
		// validateResponseCookie). Auths that don't support cookies just
		// ignore the option, so this is fully back-compatible.
		if len(r.outboundClientCookie) == 8 {
			cookieData := append([]byte(nil), r.outboundClientCookie...)
			// RFC 7873 §5.3: a known server cookie (received from this
			// same auth in a prior BADCOOKIE response) is appended after
			// the client cookie so the server recognises us as the same
			// client across the BADCOOKIE round trip.
			if len(serverCookie) > 0 {
				cookieData = append(cookieData, serverCookie...)
			}
			cookieOpt := dns.EDNSOption{
				Code: dns.EDNSOptionCodeCookie,
				Data: cookieData,
			}
			ednsOpts = append(ednsOpts, cookieOpt)
		}
		if len(ednsOpts) > 0 {
			query.Additional = []dns.ResourceRecord{
				dns.BuildOPTWithOptions(r.advertisedUDPBufferSize(), r.config.DNSSECEnabled, ednsOpts),
			}
		} else {
			query.Additional = []dns.ResourceRecord{
				dns.BuildOPT(r.advertisedUDPBufferSize(), r.config.DNSSECEnabled),
			}
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
	// Validate question section matches what we asked.
	// When 0x20 is active, compare case-sensitively against the randomized name.
	if err := validateResponseQuestionEx(msg, queryName, qtype, qclass, r.config.Caps0x20Enabled); err != nil {
		return nil, err
	}
	// RFC 7873 §5.4 outbound cookie echo check: if the response carries a
	// COOKIE option, the first 8 bytes MUST equal the client cookie we
	// sent. A mismatch is positive evidence of off-path forgery (the
	// spoofer could not have observed our random cookie), so drop the
	// response. Auths that did not include a cookie at all are accepted
	// (RFC 7873 §5.4: "...the resolver MUST NOT discard responses that
	// do not include a COOKIE option.").
	if !r.validateResponseCookie(msg) {
		return nil, errors.New("response cookie mismatch")
	}

	// TC bit set → retry over TCP
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
		if err := validateResponseQuestionEx(msg, queryName, qtype, qclass, r.config.Caps0x20Enabled); err != nil {
			return nil, err
		}
		// RFC 7873 §5.4 cookie echo applies to EVERY response, not just
		// the UDP one. The earlier check on the truncated UDP message
		// does not cover the TCP fallback — without this line a bug
		// (or a man-in-the-middle who can intercept TCP) could inject
		// a wrong-cookie response on the TCP retry that the resolver
		// would accept. TCP makes blind spoofing harder due to the
		// three-way handshake, but RFC 7873 is unambiguous that the
		// check applies regardless of transport.
		if !r.validateResponseCookie(msg) {
			return nil, errors.New("TCP response cookie mismatch")
		}
		// RFC 7766 §4 — "The TC flag SHOULD NOT be set ... for responses
		// arriving over TCP." A TCP response with TC=1 indicates a
		// confused authoritative; treat as a malformed answer rather
		// than re-recursing into TCP (which would loop).
		if msg.Header.TC() {
			return nil, errors.New("TCP response carries TC=1 (RFC 7766 §4 violation)")
		}
	}

	return msg, nil
}

func (r *Resolver) queryUDP(nsIP string, query []byte) ([]byte, error) {
	addr := net.JoinHostPort(nsIP, r.dnsPort())
	conn, err := net.DialTimeout("udp", addr, r.config.UpstreamTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(r.config.UpstreamTimeout))

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	// The read buffer must be at least as large as the EDNS UDP buffer
	// size we advertised in the outbound query. A smaller read buffer
	// silently truncates the response — net.UDPConn.Read returns only
	// what fits and discards the rest, leaving the caller with a
	// half-message that `dns.Unpack` then mis-parses. The default
	// advertised size is 1232 (DNS Flag Day 2020), but operators can
	// raise UpstreamUDPBufferSize as high as 65535. We size the read
	// buffer to match so we never silently lose response bytes.
	bufSize := int(r.advertisedUDPBufferSize())
	if bufSize < 4096 {
		// 4096 is the legacy default and remains a safe floor — most
		// auths cap their UDP response at this even when we advertise
		// less. Keeping the floor avoids a regression for the common
		// path while still respecting larger advertised sizes.
		bufSize = 4096
	}
	buf := make([]byte, bufSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

func (r *Resolver) queryTCP(nsIP string, query []byte) ([]byte, error) {
	addr := net.JoinHostPort(nsIP, r.dnsPort())
	conn, err := net.DialTimeout("tcp", addr, r.config.UpstreamTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(r.config.UpstreamTimeout))

	// Length-prefixed write
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))
	if _, err := conn.Write(lenBuf); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	// Length-prefixed read
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf)

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// validateResponseCookie enforces the outbound-cookie integrity check
// (RFC 7873 §5.4). The check is one-sided:
//
//   - No COOKIE option in the response → accept (back-compat with auths
//     that don't implement RFC 7873).
//   - COOKIE option present whose first 8 bytes echo our client cookie
//     → accept (server confirmed it saw our query as we sent it).
//   - COOKIE option present whose first 8 bytes do NOT match → reject.
//     This is the spoofer-eject case: an off-path attacker who guessed
//     TXID + port + 0x20 caps but did not observe our random client
//     cookie cannot echo it back, so the mismatch positively identifies
//     a forgery.
//
// We do NOT store any server cookie returned by the auth — full RFC 7873
// state tracking (per-IP server-cookie cache + retry on BADCOOKIE) is a
// follow-up. Even without it, the client-cookie echo check provides ~64
// bits of additional entropy against blind off-path spoofing.
func (r *Resolver) validateResponseCookie(msg *dns.Message) bool {
	if len(r.outboundClientCookie) != 8 {
		return true // cookie disabled at startup; nothing to verify against
	}
	if msg == nil || msg.EDNS0 == nil {
		return true
	}
	for _, opt := range msg.EDNS0.Options {
		if opt.Code != dns.EDNSOptionCodeCookie {
			continue
		}
		// RFC 7873 §4: COOKIE option payload is exactly 8 bytes (client
		// cookie only) OR 16-40 bytes (client + server cookie). Any
		// other length is malformed; treat as no-cookie rather than as
		// a positive forgery signal — a buggy implementation should not
		// look like an attacker.
		if len(opt.Data) < 8 {
			return true
		}
		// Constant-time compare to deny timing-side-channel inference of
		// the cookie value across many probes.
		if subtle.ConstantTimeCompare(opt.Data[:8], r.outboundClientCookie) != 1 {
			return false
		}
		return true
	}
	return true
}

// extractResponseECS parses the OPT record from a DNS response message and
// returns the EDNS Client Subnet option if the authoritative server included
// one. The returned option's SCOPE PREFIX-LENGTH is the authoritative cache
// key shape per RFC 7871 §7.3 (scope=0 means global, scope>0 means subnet
// specific). Returns nil when the response has no OPT or no ECS option.
func extractResponseECS(msg *dns.Message) *dns.ECSOption {
	if msg == nil {
		return nil
	}
	for i := range msg.Additional {
		rr := &msg.Additional[i]
		if rr.Type != dns.TypeOPT {
			continue
		}
		opt, err := dns.ParseOPT(rr)
		if err != nil || opt == nil {
			return nil
		}
		ecs, err := dns.ExtractECSFromOPT(opt)
		if err != nil {
			return nil
		}
		return ecs
	}
	return nil
}

// validateResponseQuestion checks that the response carries exactly the
// question we asked (case-insensitive).
func validateResponseQuestion(msg *dns.Message, name string, qtype uint16, qclass uint16) error {
	return validateResponseQuestionEx(msg, name, qtype, qclass, false)
}

// validateResponseQuestionEx validates the response question section.
// When caseSensitive is true (0x20 encoding), the name comparison preserves case.
func validateResponseQuestionEx(msg *dns.Message, name string, qtype uint16, qclass uint16, caseSensitive bool) error {
	if len(msg.Questions) == 0 {
		return errors.New("response has no question section")
	}
	q := msg.Questions[0]
	// Normalize root zone: "." and "" are equivalent after wire decode.
	var qn, nm string
	if caseSensitive {
		qn = strings.TrimSuffix(q.Name, ".")
		nm = strings.TrimSuffix(name, ".")
	} else {
		qn = strings.TrimSuffix(strings.ToLower(q.Name), ".")
		nm = strings.TrimSuffix(strings.ToLower(name), ".")
	}
	if qn != nm || q.Type != qtype || q.Class != qclass {
		return errors.New("response question mismatch")
	}
	return nil
}

// randomizeCase applies DNS 0x20 encoding by randomly flipping the case of
// each ASCII letter in the domain name (RFC 5452 anti-spoofing measure).
func randomizeCase(name string) string {
	if name == "" || name == "." {
		return name
	}
	result := []byte(name)
	var randBuf [1]byte
	bitPos := 0
	var randByte byte
	for i := range result {
		c := result[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			if bitPos == 0 {
				rand.Read(randBuf[:])
				randByte = randBuf[0]
				bitPos = 8
			}
			if randByte&1 != 0 {
				result[i] ^= 0x20 // flip case
			}
			randByte >>= 1
			bitPos--
		}
	}
	return string(result)
}

func randomTXID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// advertisedUDPBufferSize returns the EDNS0 UDP payload size to advertise
// in outgoing OPT records. DNS Flag Day 2020 (RFC 9018, RFC 8906) recommends
// 1232 bytes — small enough to avoid IP fragmentation on most paths, which
// shuts down off-path fragment-injection cache poisoning (Brandt et al,
// USENIX 2018). Larger buffers (the legacy 4096 default) let an attacker
// race a forged second IP fragment ahead of the legitimate response and
// stitch it into the resolver's reassembly buffer.
//
// If the operator configured an out-of-range or zero value we fall back
// to 1232 rather than honoring obviously broken settings. The minimum
// 512 bound is RFC 6891's mandated DNS payload floor.
func (r *Resolver) advertisedUDPBufferSize() uint16 {
	const (
		defaultSize = 1232
		minSize     = 512
		maxSize     = 65535
	)
	v := r.config.UpstreamUDPBufferSize
	if v < minSize || v > maxSize {
		return defaultSize
	}
	return uint16(v)
}
