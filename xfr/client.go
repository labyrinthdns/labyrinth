// Package xfr implements DNS zone transfer clients: AXFR (RFC 5936), IXFR
// (RFC 1995), over plain TCP or TLS (RFC 9103), authenticated with TSIG
// (RFC 8945).
//
// # AXFR
//
// A full transfer is a stream of DNS messages over one TCP connection. It
// opens with the zone's SOA and closes with the same SOA repeated; everything
// between is the zone. The repeated SOA is the only end-of-stream marker —
// there is no length, no count, and no terminator — so a client that does not
// track it correctly either truncates a zone silently or hangs waiting for
// data that will never come.
//
// # IXFR
//
// An incremental transfer (RFC 1995) asks "what changed since serial N?" and
// carries only the difference. The server may answer three different ways to
// the same query, distinguishable only by inspecting the record stream:
//
//	up to date   a single SOA whose serial equals the client's
//	incremental  SOA(new), then alternating delete/add sections per version
//	full         an ordinary AXFR-shaped response, when the server has no
//	             history far enough back to answer incrementally
//
// The third case is not an error and not signalled anywhere in the header. A
// client that assumes its IXFR query produced an IXFR-shaped answer will
// misparse a perfectly valid full transfer as a nonsensical delta.
//
// # TSIG
//
// Zone data is not public in the way ordinary DNS answers are, and a transfer
// carries the entire contents of a zone. TSIG authenticates both the request
// (so a primary can refuse strangers) and every message of the response
// stream, chained so the stream cannot be truncated or reordered mid-flight.
package xfr

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

const (
	defaultTLSPort = "853" // RFC 9103 §9.3
	defaultTCPPort = "53"
	defaultTimeout = 30 * time.Second

	// maxXFRMessages bounds the stream. A primary that never sends the
	// closing SOA would otherwise hold this client in the read loop for as
	// long as it kept dribbling messages.
	maxXFRMessages = 65535

	// maxXFRRecords bounds total records accepted from one transfer.
	// Without it, a hostile or runaway primary can drive this process out
	// of memory with a stream that is individually well-formed at every
	// step. Large real zones (a ccTLD) are comfortably under this.
	maxXFRRecords = 5_000_000
)

var (
	ErrNoPrimary     = errors.New("xfr: primary address is required")
	ErrNoSOA         = errors.New("xfr: no SOA record in transfer response")
	ErrTXIDMismatch  = errors.New("xfr: response transaction ID does not match the query")
	ErrQuestionMatch = errors.New("xfr: response question does not match the query")
	ErrTooManyRecs   = errors.New("xfr: transfer exceeded the record limit")
	ErrRcode         = errors.New("xfr: primary refused the transfer")
)

// ClientConfig configures a zone transfer.
type ClientConfig struct {
	// PrimaryAddr is the primary server, e.g. "10.0.0.1" or "10.0.0.1:853".
	// The port defaults to 853 with TLS and 53 without.
	PrimaryAddr string
	// Zone is the zone to transfer, e.g. "example.com".
	Zone string
	// Timeout is the per-message read/write deadline.
	Timeout time.Duration
	// UseTLS enables XFR-over-TLS (RFC 9103).
	UseTLS bool
	// TLSServerName is the name to verify the primary's certificate
	// against. Required when UseTLS is set and InsecureSkipVerify is not:
	// a bare IP address has nothing to verify against.
	TLSServerName string
	// InsecureSkipVerify disables certificate verification. Test use only;
	// it turns RFC 9103's transport security into transport obfuscation.
	InsecureSkipVerify bool
	// TSIGKey authenticates the transfer (RFC 8945). Zero value disables
	// TSIG, which is appropriate only when the primary restricts transfers
	// by source address instead.
	TSIGKey dns.TSIGKey
	// TSIGFudge is the permitted clock skew in seconds. 0 uses the RFC 8945
	// recommended 300.
	TSIGFudge uint16
}

// tsigEnabled reports whether the transfer should be signed.
func (c ClientConfig) tsigEnabled() bool {
	return c.TSIGKey.Name != "" && len(c.TSIGKey.Secret) > 0
}

func (c ClientConfig) timeout() time.Duration {
	if c.Timeout <= 0 {
		return defaultTimeout
	}
	return c.Timeout
}

// Delta is one version step of an incremental transfer: the records removed
// and added between two serials (RFC 1995 §2).
type Delta struct {
	FromSerial uint32
	ToSerial   uint32
	Deleted    []dns.ResourceRecord
	Added      []dns.ResourceRecord
}

// Result is the outcome of a transfer.
type Result struct {
	// Incremental reports whether the server answered with deltas. A false
	// value after an IXFR request is normal and means the server fell back
	// to a full transfer (RFC 1995 §2) — Records then holds the whole zone.
	Incremental bool
	// UpToDate reports that the client's serial was already current, so
	// there is nothing to apply. RFC 1995 §2 signals this with a response
	// containing only the SOA.
	UpToDate bool
	// Records is the complete zone, set for a full transfer.
	Records []dns.ResourceRecord
	// Deltas holds the version steps, set for an incremental transfer.
	Deltas []Delta
	// Serial is the zone serial after applying the transfer.
	Serial uint32
}

// AXFR performs a full zone transfer.
func AXFR(ctx context.Context, cfg ClientConfig) ([]dns.ResourceRecord, error) {
	res, err := transfer(ctx, cfg, dns.TypeAXFR, 0)
	if err != nil {
		return nil, err
	}
	return res.Records, nil
}

// IXFR requests the changes since `serial` (RFC 1995).
//
// The caller must handle all three shapes the server may answer with — see
// Result. In particular a non-incremental Result is not a failure: it is the
// server saying "I cannot go back that far, here is everything", which is the
// normal outcome when a secondary has been offline longer than the primary
// keeps history for.
func IXFR(ctx context.Context, cfg ClientConfig, serial uint32) (*Result, error) {
	return transfer(ctx, cfg, dns.TypeIXFR, serial)
}

func transfer(ctx context.Context, cfg ClientConfig, qtype uint16, serial uint32) (*Result, error) {
	if cfg.PrimaryAddr == "" {
		return nil, ErrNoPrimary
	}
	addr := cfg.PrimaryAddr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if cfg.UseTLS {
			addr = net.JoinHostPort(addr, defaultTLSPort)
		} else {
			addr = net.JoinHostPort(addr, defaultTCPPort)
		}
	}

	conn, err := dial(ctx, addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("xfr: dial %s: %w", addr, err)
	}
	defer conn.Close()

	return runTransfer(conn, cfg, qtype, serial)
}

// dial connects to the primary, over TLS when configured.
func dial(ctx context.Context, addr string, cfg ClientConfig) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()

	if !cfg.UseTLS {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, "tcp", addr)
	}

	// RFC 9103 §9.3.1 mandates TLS 1.3 for XFR-over-TLS. Unlike DoT
	// (RFC 8310, where 1.2 is still permitted), there is no interop
	// argument for accepting less here: XoT is new enough that every
	// implementation offering it speaks 1.3.
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         cfg.TLSServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	dialer := &tls.Dialer{Config: tlsCfg}
	return dialer.DialContext(ctx, "tcp", addr)
}

// runTransfer sends the query and consumes the response stream.
func runTransfer(conn net.Conn, cfg ClientConfig, qtype uint16, serial uint32) (*Result, error) {
	txID, err := randomTXID()
	if err != nil {
		return nil, err
	}

	query, err := buildQuery(txID, cfg.Zone, qtype, serial)
	if err != nil {
		return nil, err
	}

	// TSIG signs the request so the primary can tell us apart from anyone
	// else who can reach its port. The request MAC is then folded into the
	// verification of every response message, binding the stream to this
	// specific request.
	var requestMAC []byte
	if cfg.tsigEnabled() {
		query, requestMAC, err = dns.TSIGSign(query, cfg.TSIGKey, time.Now(), cfg.TSIGFudge, nil)
		if err != nil {
			return nil, fmt.Errorf("xfr: sign query: %w", err)
		}
	}

	if err := writeMessage(conn, query, cfg.timeout()); err != nil {
		return nil, err
	}
	return readStream(conn, cfg, txID, qtype, serial, requestMAC)
}

// readStream consumes response messages until the transfer is complete.
//
// `askedSerial` is the serial an IXFR query carried, and is what makes the
// "already up to date" response detectable. That response is a single SOA
// (RFC 1995 §2) — the same shape as the opening SOA of a real transfer, so
// there is no structural way to tell them apart. The serial is: when it
// matches what we asked with, the server is telling us there is nothing to
// send, and waiting for a closing SOA that will never arrive would stall the
// transfer until the read deadline.
func readStream(conn net.Conn, cfg ClientConfig, txID uint16, qtype uint16, askedSerial uint32, requestMAC []byte) (*Result, error) {
	var (
		records  []dns.ResourceRecord
		soaSeen  int
		priorMAC = requestMAC
		firstMsg = true
	)

	for msgCount := 0; msgCount < maxXFRMessages; msgCount++ {
		wire, err := readMessage(conn, cfg.timeout())
		if err != nil {
			// A primary that closes the connection after a complete
			// response has ended the transfer, not failed it. RFC 9103
			// encourages connection reuse so this is not the usual path,
			// but plain-TCP primaries commonly hang up.
			if errors.Is(err, io.EOF) && soaSeen >= 2 {
				break
			}
			if errors.Is(err, io.EOF) && qtype == dns.TypeIXFR && soaSeen == 1 {
				break // single-SOA "up to date", server hung up
			}
			return nil, fmt.Errorf("xfr: read message %d: %w", msgCount, err)
		}

		// TSIG verification happens on the raw wire bytes, before anything
		// is parsed out of the message — an unauthenticated message must
		// not get the chance to influence parsing at all.
		if cfg.tsigEnabled() {
			var mac []byte
			if firstMsg {
				// The first response is verified against the request MAC
				// (RFC 8945 §5.3).
				_, mac, err = dns.TSIGVerify(wire, staticKeyring(cfg.TSIGKey), priorMAC, time.Now())
			} else {
				// Later messages chain off the previous message's MAC
				// (§5.3.1), which is what makes the stream untruncatable.
				_, mac, err = dns.TSIGVerifyStream(wire, cfg.TSIGKey, priorMAC, time.Now())
			}
			if err != nil {
				// RFC 8945 §5.3.1 lets a primary sign only every Nth
				// message of a long stream. An unsigned intermediate
				// message is therefore not a failure — but the chain MAC
				// carries forward unchanged, so the next signed message
				// still covers it.
				if errors.Is(err, dns.ErrTSIGNotSigned) && !firstMsg {
					mac = priorMAC
				} else {
					return nil, fmt.Errorf("xfr: message %d: %w", msgCount, err)
				}
			}
			priorMAC = mac
		}

		msg, err := dns.Unpack(wire)
		if err != nil {
			return nil, fmt.Errorf("xfr: unpack message %d: %w", msgCount, err)
		}

		if firstMsg {
			if msg.Header.ID != txID {
				return nil, ErrTXIDMismatch
			}
			if rcode := msg.Header.RCODE(); rcode != dns.RCodeNoError {
				return nil, fmt.Errorf("%w: rcode %d", ErrRcode, rcode)
			}
			if len(msg.Questions) != 1 || !equalName(msg.Questions[0].Name, cfg.Zone) ||
				msg.Questions[0].Type != qtype {
				return nil, ErrQuestionMatch
			}
			firstMsg = false
		}

		// Only the answer section carries zone data. The authority and
		// additional sections hold OPT and TSIG records, which are message
		// metadata — folding them in (as this code previously did) would
		// insert the transfer's own TSIG into the zone.
		for _, rr := range msg.Answers {
			if rr.Type == dns.TypeSOA {
				soaSeen++
			}
			records = append(records, rr)
			if len(records) > maxXFRRecords {
				return nil, ErrTooManyRecs
			}
		}

		if soaSeen >= 2 {
			break
		}
		// "Already up to date" (RFC 1995 §2): a lone SOA whose serial is the
		// one we asked with. Structurally identical to the opening SOA of a
		// real transfer, so the serial is the only way to tell — and without
		// this check the client would block waiting for a closing SOA the
		// server has no intention of sending.
		if qtype == dns.TypeIXFR && soaSeen == 1 && len(records) == 1 {
			if s, serr := soaSerial(records[0]); serr == nil && s == askedSerial {
				break
			}
		}
	}

	if soaSeen == 0 {
		return nil, ErrNoSOA
	}
	if qtype == dns.TypeIXFR {
		return parseIXFR(records)
	}
	return parseAXFR(records)
}

// parseAXFR validates the SOA bracketing of a full transfer.
func parseAXFR(records []dns.ResourceRecord) (*Result, error) {
	if len(records) < 2 || records[0].Type != dns.TypeSOA {
		return nil, ErrNoSOA
	}
	serial, err := soaSerial(records[0])
	if err != nil {
		return nil, err
	}
	// Drop the closing SOA so the caller gets the zone once, not with a
	// duplicated apex record.
	body := records
	if last := records[len(records)-1]; last.Type == dns.TypeSOA {
		body = records[:len(records)-1]
	}
	return &Result{Records: body, Serial: serial}, nil
}

// parseIXFR sorts out which of the three RFC 1995 §2 response shapes arrived.
//
// The distinction is made from the record stream alone, because nothing in
// the header says which one the server chose:
//
//   - one record only            → the client was already up to date
//   - second record is not SOA   → the server sent a full zone instead
//   - second record is SOA       → a real incremental, alternating
//     delete-section / add-section per version step
func parseIXFR(records []dns.ResourceRecord) (*Result, error) {
	if len(records) == 0 || records[0].Type != dns.TypeSOA {
		return nil, ErrNoSOA
	}
	finalSerial, err := soaSerial(records[0])
	if err != nil {
		return nil, err
	}

	if len(records) == 1 {
		return &Result{UpToDate: true, Serial: finalSerial}, nil
	}

	// A second record that is not an SOA means the server could not answer
	// incrementally and sent the whole zone (RFC 1995 §2). This is a normal
	// outcome, not an error.
	if records[1].Type != dns.TypeSOA {
		return parseAXFR(records)
	}

	// Incremental. The stream is:
	//   SOA(new) [ SOA(from) deleted... SOA(to) added... ]... SOA(new)
	var (
		deltas  []Delta
		current *Delta
		inAdd   bool
	)
	body := records[1:]
	if last := body[len(body)-1]; last.Type == dns.TypeSOA {
		if s, err := soaSerial(last); err == nil && s == finalSerial && len(body) > 1 {
			body = body[:len(body)-1]
		}
	}

	for _, rr := range body {
		if rr.Type == dns.TypeSOA {
			serial, serr := soaSerial(rr)
			if serr != nil {
				return nil, serr
			}
			if current == nil || inAdd {
				// Opening a new version step: this SOA names the serial
				// the deletions are being removed *from*.
				deltas = append(deltas, Delta{FromSerial: serial})
				current = &deltas[len(deltas)-1]
				inAdd = false
			} else {
				// Switching from the delete section to the add section:
				// this SOA names the serial being moved *to*.
				current.ToSerial = serial
				inAdd = true
			}
			continue
		}
		if current == nil {
			return nil, errors.New("xfr: IXFR record outside any version step")
		}
		if inAdd {
			current.Added = append(current.Added, rr)
		} else {
			current.Deleted = append(current.Deleted, rr)
		}
	}

	return &Result{Incremental: true, Deltas: deltas, Serial: finalSerial}, nil
}

// buildQuery constructs the AXFR or IXFR query.
//
// An IXFR query carries the client's current SOA in the authority section
// (RFC 1995 §3), which is how the server learns which serial to diff from.
func buildQuery(txID uint16, zone string, qtype uint16, serial uint32) ([]byte, error) {
	msg := &dns.Message{
		Header: dns.Header{
			ID:      txID,
			Flags:   0, // RD is meaningless for a transfer; the primary is authoritative
			QDCount: 1,
		},
		Questions: []dns.Question{{Name: zone, Type: qtype, Class: dns.ClassIN}},
	}

	if qtype == dns.TypeIXFR {
		rdata, err := minimalSOARData(zone, serial)
		if err != nil {
			return nil, err
		}
		msg.Authority = []dns.ResourceRecord{{
			Name:     zone,
			Type:     dns.TypeSOA,
			Class:    dns.ClassIN,
			TTL:      0,
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		}}
	}

	packed, err := dns.Pack(msg, make([]byte, 1024))
	if err != nil {
		return nil, fmt.Errorf("xfr: pack query: %w", err)
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out, nil
}

// minimalSOARData builds the SOA RDATA for an IXFR query. Only the serial is
// meaningful — RFC 1995 §3 says the other fields are ignored by the server —
// so MNAME and RNAME are the zone apex and the timers are zero.
func minimalSOARData(zone string, serial uint32) ([]byte, error) {
	mname := dns.BuildPlainName(zone)
	rname := dns.BuildPlainName(zone)
	timers := make([]byte, 20)
	binary.BigEndian.PutUint32(timers[0:4], serial)

	out := append([]byte{}, mname...)
	out = append(out, rname...)
	return append(out, timers...), nil
}

func soaSerial(rr dns.ResourceRecord) (uint32, error) {
	soa, err := dns.ParseSOA(rr.RData, 0)
	if err != nil || soa == nil {
		return 0, fmt.Errorf("xfr: parse SOA: %w", err)
	}
	return soa.Serial, nil
}

// staticKeyring adapts a single key to the lookup function TSIGVerify takes.
// A transfer client knows exactly which key it used, so any other name in the
// response is a mismatch rather than a lookup miss.
func staticKeyring(key dns.TSIGKey) func(string) (dns.TSIGKey, bool) {
	return func(name string) (dns.TSIGKey, bool) {
		if equalName(name, key.Name) {
			return key, true
		}
		return dns.TSIGKey{}, false
	}
}

func equalName(a, b string) bool {
	return normaliseName(a) == normaliseName(b)
}

func normaliseName(n string) string {
	if len(n) > 0 && n[len(n)-1] == '.' {
		n = n[:len(n)-1]
	}
	// ASCII lowercase per RFC 4343.
	buf := []byte(n)
	for i, c := range buf {
		if c >= 'A' && c <= 'Z' {
			buf[i] = c + 32
		}
	}
	return string(buf)
}

func randomTXID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("xfr: transaction ID: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func writeMessage(conn net.Conn, wire []byte, timeout time.Duration) error {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	buf := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(wire)))
	copy(buf[2:], wire)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("xfr: write query: %w", err)
	}
	return nil
}

func readMessage(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])
	if length < 12 {
		return nil, fmt.Errorf("xfr: message too short (%d octets)", length)
	}
	wire := make([]byte, length)
	if _, err := io.ReadFull(conn, wire); err != nil {
		return nil, err
	}
	return wire, nil
}
