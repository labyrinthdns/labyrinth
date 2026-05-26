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
	msg, err := r.sendQuery(nsIP, name, qtype, qclass, true, clientECS)
	if err != nil {
		return nil, err
	}

	// RFC 6891 §7: If the server returns FORMERR (doesn't understand EDNS0),
	// retry without the OPT record. This also drops any ECS option we may
	// have sent — a server that FORMERRs on plain EDNS0 will certainly
	// reject an OPT carrying ECS sub-options.
	if msg.Header.RCODE() == dns.RCodeFormErr {
		msg, err = r.sendQuery(nsIP, name, qtype, qclass, false, nil)
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// sendQuery builds, sends and validates a single upstream DNS query.
// When clientECS is non-nil and withEDNS0 is true, the OPT record carries
// an EDNS Client Subnet option (RFC 7871). The outgoing ECS always has
// SCOPE PREFIX-LENGTH = 0 — only authoritative answers set that field.
func (r *Resolver) sendQuery(nsIP string, name string, qtype uint16, qclass uint16, withEDNS0 bool, clientECS *dns.ECSOption) (*dns.Message, error) {
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
		var ecsOptions []dns.EDNSOption
		if r.config.ECSEnabled && clientECS != nil {
			// RFC 7871 §6: outgoing queries set SCOPE PREFIX-LENGTH = 0.
			outgoing := *clientECS
			outgoing.ScopePrefixLen = 0
			ecsOptions = append(ecsOptions, dns.BuildECS(&outgoing))
		}
		if len(ecsOptions) > 0 {
			query.Additional = []dns.ResourceRecord{
				dns.BuildOPTWithOptions(r.advertisedUDPBufferSize(), r.config.DNSSECEnabled, ecsOptions),
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
