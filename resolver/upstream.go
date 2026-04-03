package resolver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func (r *Resolver) queryUpstream(nsIP string, name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	r.metrics.IncUpstreamQueries()

	retries := r.config.UpstreamRetries
	if retries < 1 {
		retries = 1
	}

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		msg, err := r.queryUpstreamOnce(nsIP, name, qtype, qclass)
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
	msg, err := r.sendQuery(nsIP, name, qtype, qclass, true)
	if err != nil {
		return nil, err
	}

	// RFC 6891 §7: If the server returns FORMERR (doesn't understand EDNS0),
	// retry without the OPT record.
	if msg.Header.RCODE() == dns.RCodeFormErr {
		msg, err = r.sendQuery(nsIP, name, qtype, qclass, false)
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// sendQuery builds, sends and validates a single upstream DNS query.
func (r *Resolver) sendQuery(nsIP string, name string, qtype uint16, qclass uint16, withEDNS0 bool) (*dns.Message, error) {
	txID, err := randTXIDFunc()
	if err != nil {
		return nil, err
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
			Name:  name,
			Type:  qtype,
			Class: qclass,
		}},
	}
	if withEDNS0 {
		query.Additional = []dns.ResourceRecord{
			dns.BuildOPT(4096, r.config.DNSSECEnabled),
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
	// Validate question section matches what we asked
	if err := validateResponseQuestion(msg, name, qtype, qclass); err != nil {
		return nil, err
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
		if err := validateResponseQuestion(msg, name, qtype, qclass); err != nil {
			return nil, err
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

	buf := make([]byte, 4096)
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

// validateResponseQuestion checks that the response carries exactly the
// question we asked. This prevents an off-path attacker who guesses the
// TX ID from injecting records for a different domain.
func validateResponseQuestion(msg *dns.Message, name string, qtype uint16, qclass uint16) error {
	if len(msg.Questions) == 0 {
		return errors.New("response has no question section")
	}
	q := msg.Questions[0]
	// Normalize root zone: "." and "" are equivalent after wire decode.
	qn := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	nm := strings.TrimSuffix(strings.ToLower(name), ".")
	if qn != nm || q.Type != qtype || q.Class != qclass {
		return errors.New("response question mismatch")
	}
	return nil
}

func randomTXID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
