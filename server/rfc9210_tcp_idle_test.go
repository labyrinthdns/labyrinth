package server

import (
	"net"
	"testing"
	"time"
)

// y44nopHandler is a minimal Handler that returns nothing — TCP timeout
// tests never actually feed it a query. Scoped to this file so it doesn't
// collide with similarly-named fixtures elsewhere in the package.
type y44nopHandler struct{}

func (y44nopHandler) Handle(_ []byte, _ net.Addr) ([]byte, error) {
	return nil, nil
}

// TestTCPServer_DefaultIdleTimeout pins Y44/a: RFC 9210 §3.7 says a TCP
// idle timeout MUST exist and SHOULD be configurable. RFC 7766 §6.2.3
// recommends a default in the 10-second range; we ship 5 s which is the
// shorter end of the operational window but still well above the 1 s
// floor §3.7 specifies. The point of this pin: a refactor that wipes
// out the field default (or sets it to 0, disabling the timeout entirely)
// would let a single misbehaving client hold a TCP connection forever.
//
// We don't pin the exact value because tuning it is a legitimate ops
// decision; we DO pin "> 0 and ≤ 30 s" so the safety property survives.
func TestTCPServer_DefaultIdleTimeout(t *testing.T) {
	s, err := NewTCPServer("127.0.0.1:0", y44nopHandler{}, 5*time.Second, 10, discardLogger())
	if err != nil {
		t.Fatalf("NewTCPServer: %v", err)
	}
	defer s.Close()

	if s.idleTimeout <= 0 {
		t.Errorf("default idleTimeout = %v, must be > 0 (RFC 9210 §3.7 — no idle timeout = DoS surface)", s.idleTimeout)
	}
	if s.idleTimeout > 30*time.Second {
		t.Errorf("default idleTimeout = %v, must be ≤ 30 s (RFC 7766 §6.2.3 — over-generous defaults are still DoS surface)", s.idleTimeout)
	}
}

// TestTCPServer_WithIdleTimeoutOverride pins Y44/b: the WithIdleTimeout
// option must actually take effect — a positive override replaces the
// default, and a non-positive value falls back (RFC 9210 §3.7 forbids
// disabling the timeout). Without this pin, a refactor of the option
// helper could turn it into a no-op and the operator-configured value
// would be silently ignored.
func TestTCPServer_WithIdleTimeoutOverride(t *testing.T) {
	s, err := NewTCPServer("127.0.0.1:0", y44nopHandler{}, 5*time.Second, 10,
		discardLogger(), WithIdleTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("NewTCPServer: %v", err)
	}
	defer s.Close()
	if s.idleTimeout != 2*time.Second {
		t.Errorf("WithIdleTimeout(2s) did not apply: got %v", s.idleTimeout)
	}

	// Non-positive override must NOT clobber the default — the safety
	// property is "always > 0", and a zero override would violate it.
	s2, _ := NewTCPServer("127.0.0.1:0", y44nopHandler{}, 5*time.Second, 10,
		discardLogger(), WithIdleTimeout(0))
	defer s2.Close()
	if s2.idleTimeout <= 0 {
		t.Errorf("WithIdleTimeout(0) clobbered the default to %v (must keep > 0)", s2.idleTimeout)
	}
}

// TestTCPServer_DefaultPipelineMax pins Y44/c: RFC 7766 §6.2.1 mandates
// support for query pipelining (multiple queries on a single TCP
// connection). The implementation MUST bound the number of queries per
// connection to defend against a malicious client that opens one
// connection and sends an infinite stream. Default 100 is well above
// the practical browser/forwarder use case while still capped.
func TestTCPServer_DefaultPipelineMax(t *testing.T) {
	s, err := NewTCPServer("127.0.0.1:0", y44nopHandler{}, 5*time.Second, 10, discardLogger())
	if err != nil {
		t.Fatalf("NewTCPServer: %v", err)
	}
	defer s.Close()

	if s.pipelineMax <= 0 {
		t.Errorf("pipelineMax = %d, must be > 0 (RFC 7766 §6.2.1)", s.pipelineMax)
	}
	if s.pipelineMax > 10000 {
		t.Errorf("pipelineMax = %d, must be bounded for DoS resilience", s.pipelineMax)
	}
}

// TestTCPServer_WithPipelineMaxOverride pins that the option helper
// applies a positive override and rejects non-positive ones the same
// way the idle-timeout helper does — symmetric defense.
func TestTCPServer_WithPipelineMaxOverride(t *testing.T) {
	s, err := NewTCPServer("127.0.0.1:0", y44nopHandler{}, 5*time.Second, 10,
		discardLogger(), WithPipelineMax(42))
	if err != nil {
		t.Fatalf("NewTCPServer: %v", err)
	}
	defer s.Close()
	if s.pipelineMax != 42 {
		t.Errorf("WithPipelineMax(42) did not apply: got %d", s.pipelineMax)
	}

	s2, _ := NewTCPServer("127.0.0.1:0", y44nopHandler{}, 5*time.Second, 10,
		discardLogger(), WithPipelineMax(0))
	defer s2.Close()
	if s2.pipelineMax <= 0 {
		t.Errorf("WithPipelineMax(0) clobbered default to %d (must keep > 0)", s2.pipelineMax)
	}
}
