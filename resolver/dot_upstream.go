package resolver

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"time"
)

// Upstream DNS-over-TLS for forward zones (RFC 7858), authenticated per
// RFC 8310.
//
// Labyrinth has served DoT, DoH and DoQ to its clients for some time, but its
// own outbound queries were plaintext on every path. For an iterative
// resolver talking to authoritative servers that is the status quo of the
// DNS and hard to avoid. For a *forward* zone it is a straightforward gap:
// the operator has deliberately pointed a zone at a specific upstream
// resolver they trust, which is exactly the relationship RFC 7858 was written
// for. Leaving that hop in cleartext means every query for the forwarded zone
// is visible to the path between here and the upstream, and the encrypted
// front door the operator configured for their clients ends at this process.
//
// # Why authentication is mandatory here
//
// RFC 8310 defines two usage profiles: Opportunistic Privacy, which encrypts
// without authenticating, and Strict Privacy, which authenticates the server
// and fails closed. Labyrinth implements only Strict.
//
// Opportunistic is not offered because of what it would mean in this
// codebase. A forward zone is a configuration statement — "for this zone,
// trust this resolver's answers" — and the forward path already honours the
// upstream's AD bit on that basis (see queryForwardECSCD). An unauthenticated
// TLS session gives an on-path attacker a free hand to be that trusted
// upstream, while the config file and the dashboard would both report the
// zone as encrypted. That combination — a security claim in the UI backed by
// nothing on the wire — is worse than the honest plaintext it replaced.
//
// So enabling TLS on a forward zone requires an authentication domain name
// (RFC 8310 §6.1), an SPKI pinset (§8.1), or both. The config layer rejects
// the zone outright otherwise rather than quietly downgrading.

const (
	// defaultDoTPort is the DoT port from RFC 7858 §3.1.
	defaultDoTPort = "853"

	// dotHandshakeTimeout bounds the TLS handshake separately from the
	// query deadline. A handshake that stalls must not consume the whole
	// upstream timeout and leave nothing for the exchange itself.
	dotHandshakeTimeout = 5 * time.Second
)

var (
	errDoTNoAuth   = errors.New("dot: TLS enabled without an authentication domain name or SPKI pin")
	errDoTPinMatch = errors.New("dot: server SPKI does not match any configured pin")
)

// DoTPolicy is the resolved TLS policy for one forward zone.
type DoTPolicy struct {
	// AuthName is the RFC 8310 §6.1 authentication domain name. When set,
	// the server certificate is verified against it with ordinary PKIX
	// rules — chain to a system root, name match, validity dates.
	AuthName string

	// Pins holds RFC 8310 §8.1 SPKI pins: base64-encoded SHA-256 digests
	// of the server's SubjectPublicKeyInfo. When non-empty, the server's
	// SPKI must match one of them.
	//
	// A pin authenticates the key rather than the name, so it works for an
	// upstream with no PKIX-valid certificate — a resolver on an internal
	// network, or one whose operator publishes a pin instead of a name.
	Pins []string
}

// authenticated reports whether this config can authenticate the peer at all.
// A zone that reaches the dialer without one is a configuration bug, and the
// dialer refuses rather than connecting.
func (c DoTPolicy) authenticated() bool {
	return c.AuthName != "" || len(c.Pins) > 0
}

// dialDoT establishes an authenticated TLS session to a DoT upstream.
//
// addr is the upstream's IP (with an optional port; 853 is assumed). The
// certificate is verified against cfg.AuthName when set, and against the SPKI
// pinset when set. With both, both must pass — a pin is a constraint added to
// PKIX, not a replacement for it.
func dialDoT(addr string, cfg DoTPolicy, timeout time.Duration) (net.Conn, error) {
	if !cfg.authenticated() {
		return nil, errDoTNoAuth
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, defaultDoTPort)
	}

	handshakeTimeout := dotHandshakeTimeout
	if timeout > 0 && timeout < handshakeTimeout {
		handshakeTimeout = timeout
	}

	raw, err := net.DialTimeout("tcp", addr, handshakeTimeout)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		// RFC 8310 §5 requires TLS 1.2 as a floor. We ask for 1.3 as the
		// preferred version but do not require it: unlike the XFR client
		// (RFC 9103 mandates 1.3), RFC 7858/8310 do not, and refusing 1.2
		// would cut off upstreams that are otherwise correctly configured.
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.AuthName,
	}

	if cfg.AuthName == "" {
		// Pin-only authentication. PKIX verification is disabled because
		// there is no name to verify against — the pin IS the
		// authentication, and it is checked below before the connection is
		// handed back. This is the one place InsecureSkipVerify is correct:
		// turning it off here would make a pin-authenticated upstream
		// impossible to configure, and the connection is never used unless
		// verifyPin succeeds.
		tlsCfg.InsecureSkipVerify = true
	}

	conn := tls.Client(raw, tlsCfg)
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		raw.Close()
		return nil, err
	}
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("dot: handshake with %s: %w", addr, err)
	}

	if len(cfg.Pins) > 0 {
		if err := verifyPin(conn.ConnectionState().PeerCertificates, cfg.Pins); err != nil {
			conn.Close()
			return nil, err
		}
	}

	// Clear the handshake deadline; the caller sets a per-exchange one.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// verifyPin checks the peer's SubjectPublicKeyInfo against an RFC 8310 §8.1
// pinset.
//
// The pin covers the public key rather than the certificate, which is what
// makes it survive certificate renewal: an operator who rotates their cert
// but keeps the key does not break every resolver that pinned them. Only the
// leaf certificate is checked — pinning an intermediate would authenticate
// "someone this CA signed" rather than "this server".
func verifyPin(chain []*x509.Certificate, pins []string) error {
	if len(chain) == 0 {
		return errors.New("dot: peer presented no certificate")
	}
	spki := sha256.Sum256(chain[0].RawSubjectPublicKeyInfo)
	got := base64.StdEncoding.EncodeToString(spki[:])
	for _, want := range pins {
		if got == want {
			return nil
		}
	}
	return fmt.Errorf("%w (server presented %s)", errDoTPinMatch, got)
}

// queryDoT performs a single DNS exchange over an authenticated TLS session,
// reusing a pooled connection when one is available.
//
// Reuse matters more here than it does for plain TCP: a cold DoT query pays a
// TCP handshake plus a TLS handshake — two extra round trips, and an
// asymmetric crypto operation on both ends. Without pooling, encrypting the
// forward path would be a visible latency regression, and the honest
// engineering answer to "should I turn this on?" would be "no".
//
// The stale-connection retry is the same as queryTCP's and exists for the
// same reason: the peer may have closed an idle session, and that must not
// surface as a client-visible failure.
func (r *Resolver) queryDoT(addr string, cfg DoTPolicy, query []byte) ([]byte, error) {
	// The pool key includes the auth name so two zones pointing at the same
	// IP under different authentication policies never share a session.
	key := "dot|" + addr + "|" + cfg.AuthName

	if conn := r.tcpPool.get(key); conn != nil {
		resp, err := r.tcpExchange(conn, query)
		if err == nil {
			r.tcpPool.put(key, conn)
			return resp, nil
		}
		conn.Close()
	}

	conn, err := dialDoT(addr, cfg, r.config.UpstreamTimeout)
	if err != nil {
		return nil, err
	}

	resp, err := r.tcpExchange(conn, query)
	if err != nil {
		conn.Close()
		return nil, err
	}
	r.tcpPool.put(key, conn)
	return resp, nil
}
