package dns

import (
	"encoding/binary"
	"fmt"
)

// EDNS0 represents parsed EDNS0 extension data.
type EDNS0 struct {
	UDPSize  uint16
	ExtRCODE uint8
	Version  uint8
	DOFlag   bool
	Options  []EDNSOption
}

// EDNSOption represents a single EDNS0 option.
type EDNSOption struct {
	Code uint16
	Data []byte
}

// ParseOPT extracts EDNS0 information from an OPT pseudo-record.
func ParseOPT(rr *ResourceRecord) (*EDNS0, error) {
	if rr.Type != TypeOPT {
		return nil, fmt.Errorf("dns: not an OPT record (type %d)", rr.Type)
	}

	edns := &EDNS0{
		UDPSize:  rr.Class,
		ExtRCODE: uint8(rr.TTL >> 24),
		Version:  uint8(rr.TTL >> 16 & 0xFF),
		DOFlag:   rr.TTL>>15&1 == 1,
	}

	// Parse RDATA options
	offset := 0
	for offset+4 <= int(rr.RDLength) {
		code := binary.BigEndian.Uint16(rr.RData[offset:])
		optLen := binary.BigEndian.Uint16(rr.RData[offset+2:])
		offset += 4

		if offset+int(optLen) > int(rr.RDLength) {
			break
		}

		data := make([]byte, optLen)
		copy(data, rr.RData[offset:offset+int(optLen)])
		edns.Options = append(edns.Options, EDNSOption{Code: code, Data: data})
		offset += int(optLen)
	}

	return edns, nil
}

// BuildOPT creates an OPT pseudo-record for outgoing queries.
func BuildOPT(udpSize uint16, doFlag bool) ResourceRecord {
	var ttl uint32
	if doFlag {
		ttl |= 1 << 15
	}

	return ResourceRecord{
		Name:     "",
		Type:     TypeOPT,
		Class:    udpSize,
		TTL:      ttl,
		RDLength: 0,
		RData:    nil,
	}
}

// BuildOPTWithOptions creates an OPT pseudo-record with EDNS0 options.
func BuildOPTWithOptions(udpSize uint16, doFlag bool, options []EDNSOption) ResourceRecord {
	rr := BuildOPT(udpSize, doFlag)
	if len(options) == 0 {
		return rr
	}

	var rdata []byte
	for _, opt := range options {
		buf := make([]byte, 4+len(opt.Data))
		binary.BigEndian.PutUint16(buf[0:2], opt.Code)
		binary.BigEndian.PutUint16(buf[2:4], uint16(len(opt.Data)))
		copy(buf[4:], opt.Data)
		rdata = append(rdata, buf...)
	}
	rr.RData = rdata
	rr.RDLength = uint16(len(rdata))
	return rr
}

// EDE info codes (RFC 8914).
const (
	EDECodeOtherError              uint16 = 0
	EDECodeUnsupportedDNSKEYAlgo   uint16 = 1
	EDECodeUnsupportedDSDigestType uint16 = 2
	EDECodeStaleAnswer             uint16 = 3
	EDECodeForgedAnswer            uint16 = 4
	EDECodeDNSSECIndeterminate     uint16 = 5
	EDECodeDNSSECBogus             uint16 = 6
	EDECodeSignatureExpired        uint16 = 7
	EDECodeSignatureNotYetValid    uint16 = 8
	EDECodeDNSKEYMissing           uint16 = 9
	EDECodeRRSIGsMissing           uint16 = 10
	EDECodeNoZoneKeyBitSet         uint16 = 11
	EDECodeNSECMissing             uint16 = 12
	EDECodeCachedError             uint16 = 13
	EDECodeNotReady                uint16 = 14
	EDECodeBlocked                 uint16 = 15
	EDECodeCensored                uint16 = 16
	EDECodeFiltered                uint16 = 17
	EDECodeProhibited              uint16 = 18
	EDECodeStaleNXDOMAINAnswer     uint16 = 19
	EDECodeNotAuthoritative        uint16 = 20
	EDECodeNotSupported            uint16 = 21
	EDECodeNoReachableAuthority    uint16 = 22
	EDECodeNetworkError            uint16 = 23
	EDECodeInvalidData             uint16 = 24
	// EDECodeSignatureExpiredBeforeValid — RFC 9606. The signer
	// produced an RRSIG whose Expiration timestamp is earlier than
	// its Inception timestamp; under no clock could it ever validate.
	// Distinct from a normal "expired" (7) because this is a signer
	// bug rather than a clock-skew situation.
	EDECodeSignatureExpiredBeforeValid uint16 = 25
	// EDECodeTooEarly — RFC 9539. Used by upstreams that observed
	// the resolver send a 0-RTT query before the TLS handshake
	// completed in a way they could not safely replay. Lets the
	// client know to retry once handshake completes.
	EDECodeTooEarly uint16 = 26
	// EDECodeUnsupportedNSEC3IterationsValue — RFC 9276 §3.2. The
	// resolver refused to walk an NSEC3 chain because its iteration
	// count exceeded the local cap (MaxNSEC3Iterations); the response
	// is reported Insecure rather than Bogus so the client knows to
	// trust it for non-DNSSEC purposes.
	EDECodeUnsupportedNSEC3IterationsValue uint16 = 27
	// EDECodeUnableToConformToPolicy — IANA EDE 28. Signals that the
	// upstream did not return an answer the resolver considers
	// policy-acceptable (e.g. an unsigned answer when the operator
	// requires DO=1 + AD=1). Distinct from "filtered" (17) which is
	// the resolver's OWN policy refusing to forward; code 28 covers
	// the case where the upstream's response itself violates a local
	// policy gate the resolver enforces post-receipt.
	EDECodeUnableToConformToPolicy uint16 = 28
	// EDECodeSynthesized — IANA EDE 29. Signals that the answer was
	// synthesized by the resolver (DNS64 AAAA synthesis, RFC 8198
	// aggressive NSEC NXDOMAIN/NODATA, NSEC3-aggressive synthesis)
	// rather than fetched as-is from the authoritative. Clients that
	// need a verifiable upstream answer can re-query with synthesis
	// disabled or take corrective action.
	EDECodeSynthesized uint16 = 29
)

// EDNS option codes, as assigned in the IANA "DNS EDNS0 Option Codes
// (OPT)" registry. Codes are listed here even when Labyrinth does not act
// on them: an unrecognised option in a query is silently ignored per
// RFC 6891 §6.1.2, and having the constant means a log line or a metric
// can name the option instead of printing a bare integer.
const (
	// EDNSOptionCodeNSID is the Name Server Identifier option (RFC 5001).
	// A client sends it with zero-length data to ask "which instance am I
	// actually talking to?"; the server answers with an opaque identifier.
	// On an anycast deployment this is the only in-band way to tell which
	// node served a query, which is why it is the first thing an operator
	// reaches for when one node in a cluster misbehaves.
	EDNSOptionCodeNSID uint16 = 3
	EDNSOptionCodeECS  uint16 = 8
	// EDNSOptionCodeEXPIRE is the EDNS EXPIRE option (RFC 7314). A
	// secondary uses it to learn the remaining lifetime of the zone it
	// holds, so a zone can expire consistently across a chain of
	// secondaries rather than each restarting the clock. Not acted on:
	// Labyrinth has no secondary-zone role yet (see RFC 9103 in
	// docs/rfc-compliance-matrix.md).
	EDNSOptionCodeEXPIRE       uint16 = 9
	EDNSOptionCodeCookie       uint16 = 10
	EDNSOptionCodeTCPKeepalive uint16 = 11
	EDNSOptionCodePadding      uint16 = 12
	// EDNSOptionCodeCHAIN is the CHAIN query option (RFC 7901), by which a
	// validating client asks for the whole DNSSEC chain in one response.
	// Not acted on: Labyrinth validates on the client's behalf, so the
	// chain-shipping case only arises for stubs that validate themselves.
	EDNSOptionCodeCHAIN uint16 = 13
	// EDNSOptionCodeKeyTag is edns-key-tag (RFC 8145 §4), by which a
	// validator reports which trust anchors it holds. It is the mechanism
	// that made the 2018 root KSK rollover measurable. Not acted on:
	// Labyrinth tracks anchors via RFC 5011 but does not report them.
	EDNSOptionCodeKeyTag uint16 = 14
	EDNSOptionCodeEDE    uint16 = 15
	// EDNSOptionCodeReportChannel is the Report-Channel option (RFC 9567
	// §6.1). An authoritative server attaches it to advertise an agent
	// domain that resolvers should send error reports to. See
	// errorreport.go.
	EDNSOptionCodeReportChannel uint16 = 18
	// EDNSOptionCodeZoneVersion is the ZONEVERSION option (RFC 9660), by
	// which an authoritative server discloses which version of a zone
	// produced an answer. Not acted on: useful to zone operators
	// debugging propagation, not to a recursive resolver.
	EDNSOptionCodeZoneVersion uint16 = 19
	// EDNSOptionCodeDAU is the "DNSSEC Algorithm Understood" option
	// (RFC 6975 §3). The option data is the list of DNSKEY/RRSIG
	// algorithm numbers the resolver can validate. Multi-signed zones
	// (a zone published with multiple algorithms during a rollover)
	// use this to decide which signature to return; without DAU they
	// must send all signatures, wasting bandwidth and amplification.
	EDNSOptionCodeDAU uint16 = 5
	// EDNSOptionCodeDHU is the "DS Hash Understood" option. Same idea
	// but for DS digest types (RFC 6975 §3, option code 6).
	EDNSOptionCodeDHU uint16 = 6
	// EDNSOptionCodeN3U is the "NSEC3 Hash Understood" option. NSEC3
	// hash algorithms — only SHA-1 (algorithm 1) is currently defined
	// (RFC 6975 §3, option code 7).
	EDNSOptionCodeN3U uint16 = 7
)

// PaddingBlockSize is the recommended response padding block (RFC 8467
// §4.1: "the server SHOULD pad the response packet to a multiple of
// 468 bytes"). The number is empirical: it avoids most common MTUs
// while still being a single power-of-two-friendly value that hides
// most short answers in the same length bucket as longer ones.
const PaddingBlockSize = 468

// BuildPaddingOption constructs an EDNS(0) PADDING option (RFC 7830,
// option code 12) carrying `n` zero bytes. The option SHOULD be the
// last option in the OPT RR per RFC 7830 §3 so receivers can ignore
// trailing zeros without parsing the rest. Only meaningful on
// encrypted transports (DoT/DoH) — RFC 8467 §6 explicitly disallows
// padding on plain UDP/TCP since it gives no privacy benefit and
// wastes bandwidth.
func BuildPaddingOption(n int) EDNSOption {
	if n < 0 {
		n = 0
	}
	return EDNSOption{Code: EDNSOptionCodePadding, Data: make([]byte, n)}
}

// BuildTCPKeepaliveOption constructs an EDNS(0) edns-tcp-keepalive
// option (RFC 7828, option code 11). `timeoutUnits100ms` is the idle
// timeout the server is willing to keep the connection open, expressed
// in 100-millisecond units (RFC 7828 §3.1). A zero-length data field
// (length=0) is the client form ("I want to use keepalive"); the
// server response form MUST carry the 2-byte timeout. This builder
// produces the server form.
func BuildTCPKeepaliveOption(timeoutUnits100ms uint16) EDNSOption {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, timeoutUnits100ms)
	return EDNSOption{Code: EDNSOptionCodeTCPKeepalive, Data: data}
}

// HasPaddingOption reports whether the parsed EDNS0 record carries a
// PADDING option (used as the client's signal that it wants the
// response padded — RFC 8467 §4).
func HasPaddingOption(e *EDNS0) bool {
	if e == nil {
		return false
	}
	for _, opt := range e.Options {
		if opt.Code == EDNSOptionCodePadding {
			return true
		}
	}
	return false
}

// HasTCPKeepaliveOption reports whether the parsed EDNS0 record
// carries an edns-tcp-keepalive option — the client's signal that
// it wants to negotiate a TCP idle timeout (RFC 7828 §3.2). Per the
// RFC the client form has zero-length data; we accept any length and
// treat the option's presence alone as the signal.
func HasTCPKeepaliveOption(e *EDNS0) bool {
	if e == nil {
		return false
	}
	for _, opt := range e.Options {
		if opt.Code == EDNSOptionCodeTCPKeepalive {
			return true
		}
	}
	return false
}

// MaxNSIDLength bounds the identifier a server will emit. RFC 5001 puts no
// ceiling on NSID length, but the option travels in every response to a
// client that asked for it, and an operator who pastes a long string into
// the config should not silently start pushing responses over the UDP
// buffer into TCP fallback. 64 bytes is comfortably more than the
// hostname-or-site-code that real deployments use.
const MaxNSIDLength = 64

// HasNSIDOption reports whether the parsed EDNS0 record carries an NSID
// option — the client's request for the server's identity (RFC 5001 §2.1).
// The request form has zero-length data; we treat presence alone as the
// signal, since a client that sent data is still unambiguously asking.
func HasNSIDOption(e *EDNS0) bool {
	if e == nil {
		return false
	}
	for _, opt := range e.Options {
		if opt.Code == EDNSOptionCodeNSID {
			return true
		}
	}
	return false
}

// BuildNSIDOption constructs an NSID option (RFC 5001 §2.3) carrying the
// server's identifier. RFC 5001 §2.3 is explicit that the payload is an
// opaque byte string with no imposed structure or encoding — so the
// identifier is emitted verbatim rather than being hex-encoded or
// null-terminated. Identifiers longer than MaxNSIDLength are truncated.
func BuildNSIDOption(id []byte) EDNSOption {
	if len(id) > MaxNSIDLength {
		id = id[:MaxNSIDLength]
	}
	data := make([]byte, len(id))
	copy(data, id)
	return EDNSOption{Code: EDNSOptionCodeNSID, Data: data}
}

// AddNSIDToRawResponse parses a wire-format response and attaches an NSID
// option carrying `id` (RFC 5001 §2.3). Used by every transport rather than
// just the stateful ones: an operator debugging an anycast cluster is most
// often doing it over UDP, which is where the misrouting happens.
//
// Idempotent — a response that already carries NSID is returned unchanged,
// since RFC 6891 §6.1.1 allows each option code to appear only once.
// Returns the original bytes on any parse/pack error or for an empty id.
//
// Like AddTCPKeepaliveToRawResponse, this appends to the existing OPT RR's
// RData rather than rebuilding the record, so ExtRCODE/Version/DO bits set
// by earlier stages survive.
func AddNSIDToRawResponse(resp []byte, id []byte) []byte {
	if len(id) == 0 {
		return resp
	}
	if len(id) > MaxNSIDLength {
		id = id[:MaxNSIDLength]
	}

	msg, err := Unpack(resp)
	if err != nil {
		return resp
	}

	optIdx := -1
	for i, rr := range msg.Additional {
		if rr.Type == TypeOPT {
			optIdx = i
			break
		}
	}

	if optIdx < 0 {
		msg.Additional = append(msg.Additional,
			BuildOPTWithOptions(1232, false, []EDNSOption{BuildNSIDOption(id)}))
	} else {
		if edns, perr := ParseOPT(&msg.Additional[optIdx]); perr == nil {
			for _, o := range edns.Options {
				if o.Code == EDNSOptionCodeNSID {
					return resp
				}
			}
		}
		hdr := make([]byte, 4+len(id))
		binary.BigEndian.PutUint16(hdr[0:2], EDNSOptionCodeNSID)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(id)))
		copy(hdr[4:], id)
		msg.Additional[optIdx].RData = append(msg.Additional[optIdx].RData, hdr...)
		msg.Additional[optIdx].RDLength = uint16(len(msg.Additional[optIdx].RData))
	}

	packed, err := Pack(msg, make([]byte, len(resp)+MaxNSIDLength+32))
	if err != nil {
		return resp
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out
}

// BuildDAUOption constructs the DNSSEC Algorithm Understood option
// (RFC 6975) carrying the list of DNSKEY/RRSIG algorithm numbers this
// resolver can validate. Algorithms we deliberately refuse (RSASHA1
// when allowSHA1=false, ED448 until we ship a verifier) are omitted —
// the spec is explicit that DAU advertises ONLY algorithms the resolver
// will actually accept.
func BuildDAUOption(algorithms []uint8) EDNSOption {
	data := make([]byte, len(algorithms))
	copy(data, algorithms)
	return EDNSOption{Code: EDNSOptionCodeDAU, Data: data}
}

// BuildDHUOption is the DS-hash counterpart of BuildDAUOption.
func BuildDHUOption(digests []uint8) EDNSOption {
	data := make([]byte, len(digests))
	copy(data, digests)
	return EDNSOption{Code: EDNSOptionCodeDHU, Data: data}
}

// BuildN3UOption is the NSEC3-hash counterpart of BuildDAUOption.
func BuildN3UOption(hashes []uint8) EDNSOption {
	data := make([]byte, len(hashes))
	copy(data, hashes)
	return EDNSOption{Code: EDNSOptionCodeN3U, Data: data}
}

// BuildEDEOption constructs an Extended DNS Error option (RFC 8914, option code 15).
// infoCode is the EDE info code, extraText is an optional UTF-8 string.
func BuildEDEOption(infoCode uint16, extraText string) EDNSOption {
	data := make([]byte, 2+len(extraText))
	binary.BigEndian.PutUint16(data[0:2], infoCode)
	if len(extraText) > 0 {
		copy(data[2:], extraText)
	}
	return EDNSOption{
		Code: EDNSOptionCodeEDE,
		Data: data,
	}
}

// ParseEDEOption parses an Extended DNS Error option from EDNS0 option data.
// Returns the info code and extra text.
func ParseEDEOption(data []byte) (infoCode uint16, extraText string, err error) {
	if len(data) < 2 {
		return 0, "", fmt.Errorf("dns: EDE option data too short: %d bytes", len(data))
	}
	infoCode = binary.BigEndian.Uint16(data[0:2])
	if len(data) > 2 {
		extraText = string(data[2:])
	}
	return infoCode, extraText, nil
}

// PadRawResponse parses a wire-format response and adds an EDNS PADDING
// option (RFC 7830 §3) sized so that the total wire length becomes the
// next multiple of `block` bytes (RFC 8467 §4.1 recommends 468). Used
// by DoT/DoH servers when the client signalled padding interest, so a
// passive observer cannot infer the queried name from response length
// alone. Returns the original bytes unchanged on any parse/pack error
// or when `block <= 0`.
//
// Implementation note: we deliberately mutate the existing OPT RR's
// RData (rather than rebuilding via BuildOPTWithOptions) so OPT TTL
// bits — ExtRCODE, Version, DO-flag — are preserved verbatim. The
// caller's resolver may have set ExtRCODE for BADVERS/BADKEY signalling
// and we must not lose it.
func PadRawResponse(resp []byte, block int) []byte {
	if block <= 0 {
		return resp
	}
	msg, err := Unpack(resp)
	if err != nil {
		return resp
	}

	optIdx := -1
	for i, rr := range msg.Additional {
		if rr.Type == TypeOPT {
			optIdx = i
			break
		}
	}

	if optIdx < 0 {
		newOpt := BuildOPTWithOptions(1232, false, []EDNSOption{{Code: EDNSOptionCodePadding}})
		msg.Additional = append(msg.Additional, newOpt)
		optIdx = len(msg.Additional) - 1
	} else {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], EDNSOptionCodePadding)
		binary.BigEndian.PutUint16(hdr[2:4], 0)
		msg.Additional[optIdx].RData = append(msg.Additional[optIdx].RData, hdr...)
		msg.Additional[optIdx].RDLength = uint16(len(msg.Additional[optIdx].RData))
	}

	packed, err := Pack(msg, make([]byte, len(resp)+block+512))
	if err != nil {
		return resp
	}
	L1 := len(packed)
	target := ((L1 + block - 1) / block) * block
	need := target - L1
	if need <= 0 {
		out := make([]byte, len(packed))
		copy(out, packed)
		return out
	}

	optRR := &msg.Additional[optIdx]
	binary.BigEndian.PutUint16(optRR.RData[len(optRR.RData)-2:], uint16(need))
	optRR.RData = append(optRR.RData, make([]byte, need)...)
	optRR.RDLength = uint16(len(optRR.RData))

	packed2, err := Pack(msg, make([]byte, target+512))
	if err != nil {
		return resp
	}
	out := make([]byte, len(packed2))
	copy(out, packed2)
	return out
}

// AddTCPKeepaliveToRawResponse parses a wire-format response and adds
// an edns-tcp-keepalive option (RFC 7828 §3.1) carrying the server's
// idle timeout in 100ms units. Used by TCP/DoT/DoH servers when the
// client signalled keepalive interest. Idempotent — if the response
// already carries a keepalive option, the original bytes are returned
// unchanged. Returns the original bytes on any parse/pack error.
func AddTCPKeepaliveToRawResponse(resp []byte, timeoutUnits100ms uint16) []byte {
	msg, err := Unpack(resp)
	if err != nil {
		return resp
	}

	optIdx := -1
	for i, rr := range msg.Additional {
		if rr.Type == TypeOPT {
			optIdx = i
			break
		}
	}

	keepaliveHdr := make([]byte, 4+2)
	binary.BigEndian.PutUint16(keepaliveHdr[0:2], EDNSOptionCodeTCPKeepalive)
	binary.BigEndian.PutUint16(keepaliveHdr[2:4], 2)
	binary.BigEndian.PutUint16(keepaliveHdr[4:6], timeoutUnits100ms)

	if optIdx < 0 {
		newOpt := BuildOPTWithOptions(1232, false, []EDNSOption{BuildTCPKeepaliveOption(timeoutUnits100ms)})
		msg.Additional = append(msg.Additional, newOpt)
	} else {
		// Skip if KEEPALIVE option already present.
		if edns, perr := ParseOPT(&msg.Additional[optIdx]); perr == nil {
			for _, o := range edns.Options {
				if o.Code == EDNSOptionCodeTCPKeepalive {
					return resp
				}
			}
		}
		msg.Additional[optIdx].RData = append(msg.Additional[optIdx].RData, keepaliveHdr...)
		msg.Additional[optIdx].RDLength = uint16(len(msg.Additional[optIdx].RData))
	}

	packed, err := Pack(msg, make([]byte, len(resp)+32))
	if err != nil {
		return resp
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out
}

// ParseCookieOption parses a DNS Cookie option (RFC 7873, option code 10).
// Returns the client cookie (8 bytes) and optional server cookie (8-32 bytes).
func ParseCookieOption(data []byte) (clientCookie []byte, serverCookie []byte) {
	if len(data) < 8 {
		return nil, nil
	}
	clientCookie = make([]byte, 8)
	copy(clientCookie, data[:8])
	if len(data) > 8 {
		serverCookie = make([]byte, len(data)-8)
		copy(serverCookie, data[8:])
	}
	return clientCookie, serverCookie
}
