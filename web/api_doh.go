package web

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/server"
)

// handleDoH implements DNS-over-HTTPS (RFC 8484).
// It accepts both GET (with base64url-encoded "dns" query parameter) and POST
// (with raw DNS message body and Content-Type: application/dns-message).
func (s *AdminServer) handleDoH(w http.ResponseWriter, r *http.Request) {
	// Default every response — including every error path below — to
	// Cache-Control: no-store. Without this an http.Error reply (DoH
	// not enabled, bad media type, malformed query, internal error)
	// is left with the Go default of "no cache directive", and a CDN
	// or browser cache is free to store it. A brief upstream failure
	// would then persist as a cached 5xx well beyond its real
	// duration, leaving the DoH endpoint silently broken for any
	// client behind that intermediary. The success path overrides
	// this header with the TTL-derived max-age below.
	w.Header().Set("Cache-Control", "no-store")
	if s.dohHandler == nil {
		http.Error(w, "DoH not enabled", http.StatusNotFound)
		return
	}

	var query []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		query, err = s.dohDecodeGet(r)
	case http.MethodPost:
		query, err = s.dohDecodePost(r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		switch err.(type) {
		case *dohUnsupportedMediaType:
			http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		case *dohRequestTooLarge:
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	if len(query) < 12 {
		http.Error(w, "dns message too short", http.StatusBadRequest)
		return
	}

	// Build a fake client address from the HTTP request's remote address.
	clientAddr := dohClientAddr(r)

	response, handleErr := s.dohHandler.Handle(query, clientAddr)
	if handleErr != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if response == nil {
		http.Error(w, "no response", http.StatusInternalServerError)
		return
	}

	// RFC 7830 + RFC 8467 — DoH is encrypted, so if the client carried
	// a PADDING option we pad the response to the next 468-byte block
	// to hide length-based fingerprinting on the wire. TCP-keepalive
	// (RFC 7828) does not apply here: HTTP/2 manages connection state
	// at its own layer.
	if qmsg, qerr := dns.Unpack(query); qerr == nil && dns.HasPaddingOption(qmsg.EDNS0) {
		response = dns.PadRawResponse(response, dns.PaddingBlockSize)
	}

	// Compute Cache-Control max-age from the minimum TTL of answer records.
	maxAge := dohMinTTL(response)

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", maxAge))
	// RFC 8484 §5.1 / RFC 7234 §4.1: an intermediate cache that varies
	// its response on Accept must be told to do so explicitly.
	// Without `Vary: Accept` a shared cache can serve a stored
	// application/dns-message body to a downstream client that asked
	// for application/dns-json (or vice versa) and the client will
	// reject the payload as malformed. We only support dns-message
	// today, but emitting Vary now makes the contract correct for
	// every intermediary and future-proofs against adding dns-json.
	w.Header().Set("Vary", "Accept")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

const dohMaxPostBodyBytes = 65536

// dohMaxGetParamBytes caps the base64url-encoded "dns" GET parameter
// length. The POST path is capped at 65536 raw bytes; without a matching cap
// on the GET path an attacker can
// POST-equivalent abuse through ?dns=… with a megabytes-long encoded
// payload that the base64 decoder would happily expand to ~75% of
// that size in RAM before the DNS parser even runs. A 65536-byte cap
// matches the POST surface (the encoded form is ~4/3 of the raw, so
// this still fits any RFC 8484-sized DNS message comfortably).
const dohMaxGetParamBytes = 65536

// dohDecodeGet extracts the DNS query from a GET request's "dns" query parameter.
// The parameter value is base64url-encoded without padding (RFC 4648 Section 5).
func (s *AdminServer) dohDecodeGet(r *http.Request) ([]byte, error) {
	param := r.URL.Query().Get("dns")
	if param == "" {
		return nil, fmt.Errorf("missing 'dns' query parameter")
	}
	if len(param) > dohMaxGetParamBytes {
		return nil, fmt.Errorf("'dns' parameter exceeds %d-byte cap", dohMaxGetParamBytes)
	}
	query, err := base64.RawURLEncoding.DecodeString(param)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url encoding: %w", err)
	}
	return query, nil
}

// dohDecodePost reads the DNS query from a POST request body.
// The Content-Type must be "application/dns-message".
func (s *AdminServer) dohDecodePost(r *http.Request) ([]byte, error) {
	ct := r.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		return nil, &dohUnsupportedMediaType{contentType: ct}
	}
	if r.ContentLength > dohMaxPostBodyBytes {
		return nil, &dohRequestTooLarge{}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, dohMaxPostBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if len(body) > dohMaxPostBodyBytes {
		return nil, &dohRequestTooLarge{}
	}
	return body, nil
}

type dohRequestTooLarge struct{}

func (*dohRequestTooLarge) Error() string {
	return fmt.Sprintf("dns message exceeds %d-byte cap", dohMaxPostBodyBytes)
}

// dohUnsupportedMediaType is an error type for wrong Content-Type on POST.
type dohUnsupportedMediaType struct {
	contentType string
}

func (e *dohUnsupportedMediaType) Error() string {
	return fmt.Sprintf("unsupported content type: %s", e.contentType)
}

// dohClientAddr extracts the remote address from an HTTP request and returns
// it as a net.Addr suitable for passing to the DNS handler.
func dohClientAddr(r *http.Request) net.Addr {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Fallback: use the raw remote address
		host = r.RemoteAddr
		port = "0"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	}
	p := 0
	fmt.Sscanf(port, "%d", &p)
	return &net.TCPAddr{IP: ip, Port: p}
}

// dohMinTTL extracts the minimum TTL from DNS answer records in a wire-format
// response. Returns 0 if no answer records are found or the response is too short.
func dohMinTTL(response []byte) uint32 {
	if len(response) < 12 {
		return 0
	}
	anCount := binary.BigEndian.Uint16(response[6:8])
	if anCount == 0 {
		return 0
	}

	// Skip header (12 bytes) and question section.
	offset := 12
	qdCount := binary.BigEndian.Uint16(response[4:6])
	for i := 0; i < int(qdCount); i++ {
		offset = skipDNSName(response, offset)
		if offset < 0 || offset+4 > len(response) {
			return 0
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answer records to find the minimum TTL.
	var minTTL uint32
	first := true
	for i := 0; i < int(anCount); i++ {
		offset = skipDNSName(response, offset)
		if offset < 0 || offset+10 > len(response) {
			break
		}
		ttl := binary.BigEndian.Uint32(response[offset+4 : offset+8])
		rdlen := binary.BigEndian.Uint16(response[offset+8 : offset+10])
		offset += 10 + int(rdlen)
		if offset > len(response) {
			break
		}
		if first || ttl < minTTL {
			minTTL = ttl
			first = false
		}
	}
	return minTTL
}

// skipDNSName advances past a DNS name in wire format (handling compression).
// Returns the new offset, or -1 on error.
func skipDNSName(buf []byte, offset int) int {
	if offset < 0 || offset >= len(buf) {
		return -1
	}
	for {
		if offset >= len(buf) {
			return -1
		}
		length := int(buf[offset])
		if length == 0 {
			return offset + 1
		}
		if length&0xC0 == 0xC0 {
			// Compression pointer — 2 bytes total
			return offset + 2
		}
		offset += 1 + length
	}
}

// SetDoHHandler sets the DNS handler used for DoH requests.
func (s *AdminServer) SetDoHHandler(h server.Handler) {
	s.dohHandler = h
}

// SetDoHEnabled enables or disables the DoH endpoint.
func (s *AdminServer) SetDoHEnabled(enabled bool) {
	s.dohEnabled = enabled
}
