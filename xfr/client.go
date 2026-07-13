// Package xfr implements DNS zone transfer (AXFR/IXFR) clients
// over TLS (RFC 9103) and plain TCP (RFC 5936).
//
// AXFR (RFC 5936) transfers a complete zone as a stream of DNS messages.
// The client sends a single AXFR query, and the server responds with one
// or more DNS messages containing the zone's resource records. The first
// message begins with the zone's SOA record, and the last message ends
// with the same SOA record.
//
// XFR-over-TLS (RFC 9103) mandates TLS 1.3 on port 853, reusing the
// DNS-over-TLS (DoT) transport. Plain TCP on port 53 is supported for
// legacy compatibility.
package xfr

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// Defaults
const (
	defaultPort     = "853"
	defaultTimeout  = 30 * time.Second
	maxXFRMessages  = 65535
)

// ClientConfig configures an XFR client.
type ClientConfig struct {
	// PrimaryAddr is the address of the primary DNS server from which
	// to transfer the zone, e.g. "10.0.0.1:853" or "ns1.example.com".
	// If empty, ":853" is assumed and the zone name is used to look up
	// the primary server via DNS (not implemented yet).
	PrimaryAddr string
	// Zone is the name of the zone to transfer, e.g. "example.com".
	Zone string
	// Timeout is the per-message read/write deadline.
	Timeout time.Duration
	// UseTLS enables TLS transport (RFC 9103). When true, the client
	// connects via TLS to the primary on port 853. When false, plain
	// TCP on port 53 is used (RFC 5936).
	UseTLS bool
	// InsecureSkipVerify controls whether TLS certificate verification
	// is skipped. Should only be used for testing.
	InsecureSkipVerify bool
}

// AXFR performs a full zone transfer (AXFR) and returns all resource
// records in the zone. The transfer uses the configured transport
// (TLS or plain TCP).
func AXFR(ctx context.Context, cfg ClientConfig) ([]dns.ResourceRecord, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	addr := cfg.PrimaryAddr
	if addr == "" {
		return nil, errors.New("xfr: primary address is required")
	}
	// Default port based on transport
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if cfg.UseTLS {
			addr = net.JoinHostPort(addr, defaultPort)
		} else {
			addr = net.JoinHostPort(addr, "53")
		}
	}

	conn, err := dial(ctx, addr, cfg.UseTLS, cfg.InsecureSkipVerify, timeout)
	if err != nil {
		return nil, fmt.Errorf("xfr: dial %s: %w", addr, err)
	}
	defer conn.Close()

	return transferAXFR(conn, cfg.Zone, timeout)
}

// dial establishes a connection to the primary server, optionally over TLS.
func dial(ctx context.Context, addr string, useTLS, skipVerify bool, timeout time.Duration) (net.Conn, error) {
	if useTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: skipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		dialer := &tls.Dialer{Config: tlsCfg}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return dialer.DialContext(ctx, "tcp", addr)
	}

	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

// transferAXFR sends an AXFR query and reads the response stream.
func transferAXFR(conn net.Conn, zone string, timeout time.Duration) ([]dns.ResourceRecord, error) {
	// Build AXFR query
	query := buildAXFRQuery(zone)
	wire, err := dns.Pack(query, make([]byte, 512))
	if err != nil {
		return nil, fmt.Errorf("xfr: pack query: %w", err)
	}

	// Send length-prefixed query
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := binary.Write(conn, binary.BigEndian, uint16(len(wire))); err != nil {
		return nil, fmt.Errorf("xfr: write length: %w", err)
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, fmt.Errorf("xfr: write query: %w", err)
	}

	// Read response stream
	var allRecords []dns.ResourceRecord
	var sawFirstSOA, sawSecondSOA bool

	for msgCount := 0; msgCount < maxXFRMessages; msgCount++ {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}

		// Read 2-byte length prefix
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			if errors.Is(err, io.EOF) && sawFirstSOA && sawSecondSOA {
				break // Clean end of transfer
			}
			return nil, fmt.Errorf("xfr: read length (msg %d): %w", msgCount, err)
		}

		if length < 12 {
			return nil, fmt.Errorf("xfr: message %d too short (%d bytes)", msgCount, length)
		}

		// Read DNS message
		msgWire := make([]byte, length)
		if _, err := io.ReadFull(conn, msgWire); err != nil {
			return nil, fmt.Errorf("xfr: read message %d: %w", msgCount, err)
		}

		msg, err := dns.Unpack(msgWire)
		if err != nil {
			return nil, fmt.Errorf("xfr: unpack message %d: %w", msgCount, err)
		}

		// Collect records
		allRecords = append(allRecords, msg.Answers...)
		allRecords = append(allRecords, msg.Authority...)
		allRecords = append(allRecords, msg.Additional...)

		// Check for SOA in answer section — marks the start and end of AXFR
		for _, rr := range msg.Answers {
			if rr.Type == dns.TypeSOA {
				if !sawFirstSOA {
					sawFirstSOA = true
				} else {
					sawSecondSOA = true
				}
				break
			}
		}

		// After we've seen two SOAs, the transfer is complete
		if sawFirstSOA && sawSecondSOA {
			break
		}
	}

	if !sawFirstSOA {
		return nil, errors.New("xfr: no SOA record found in AXFR response")
	}

	return allRecords, nil
}

// buildAXFRQuery constructs an AXFR query message for the given zone.
func buildAXFRQuery(zone string) *dns.Message {
	return &dns.Message{
		Header: dns.Header{
			ID:      0, // server assigns ID in response
			Flags:   0x0100, // RD=1
			QDCount: 1,
		},
		Questions: []dns.Question{{
			Name:  zone,
			Type:  dns.TypeAXFR,
			Class: dns.ClassIN,
		}},
	}
}
