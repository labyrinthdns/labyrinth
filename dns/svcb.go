package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"sort"
)

// SVCB RDATA construction (RFC 9460 §2.2), used to answer the RFC 9462
// Discovery of Designated Resolvers query.
//
// Labyrinth has always passed SVCB and HTTPS records through opaquely, which
// is the correct behaviour for a resolver forwarding someone else's records
// (RFC 3597 — never reinterpret RDATA you did not author, or the signatures
// over it stop verifying). Building one is a different job, and it only
// arises because DDR requires the resolver to describe *itself*.

// SvcParamKey values from the IANA "Service Parameter Keys (SvcParamKeys)"
// registry (RFC 9460 §14.3.2).
const (
	SvcParamMandatory     uint16 = 0
	SvcParamALPN          uint16 = 1
	SvcParamNoDefaultALPN uint16 = 2
	SvcParamPort          uint16 = 3
	SvcParamIPv4Hint      uint16 = 4
	SvcParamECH           uint16 = 5
	SvcParamIPv6Hint      uint16 = 6
	// SvcParamDoHPath is the "dohpath" key (RFC 9461 §5): the URI template
	// of a DoH endpoint, e.g. "/dns-query{?dns}". Required for a DoH
	// designation, since unlike DoT and DoQ a DoH endpoint is not fully
	// identified by a host and port.
	SvcParamDoHPath uint16 = 7
)

// SvcParam is one key/value pair in an SVCB record's parameter list.
type SvcParam struct {
	Key   uint16
	Value []byte
}

var errSvcParamTooLong = errors.New("dns: SVCB parameter value exceeds 65535 octets")

// BuildSVCBRData assembles SVCB/HTTPS RDATA: a 2-octet priority, an
// uncompressed target name, and the parameter list.
//
// Parameters are sorted by key before encoding. RFC 9460 §2.2 requires them
// to appear in strictly increasing key order, and a receiver is entitled to
// reject a record that violates it — sorting here means a caller cannot
// produce an invalid record by listing parameters in a natural reading order
// rather than a numeric one.
//
// A priority of 0 marks AliasMode, in which §2.4.2 forbids any parameters;
// callers building DDR records always use ServiceMode (priority >= 1).
func BuildSVCBRData(priority uint16, target string, params []SvcParam) ([]byte, error) {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, priority)
	out = append(out, BuildPlainName(target)...)

	sorted := make([]SvcParam, len(params))
	copy(sorted, params)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })

	var prevKey uint16
	for i, p := range sorted {
		if len(p.Value) > 0xFFFF {
			return nil, errSvcParamTooLong
		}
		// RFC 9460 §2.2: keys MUST NOT be repeated. A duplicate is a caller
		// bug rather than untrusted input, but silently emitting both would
		// produce a record some resolvers accept and others reject —
		// the worst kind of interop failure to debug.
		if i > 0 && p.Key == prevKey {
			return nil, errors.New("dns: duplicate SVCB parameter key")
		}
		prevKey = p.Key

		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], p.Key)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(p.Value)))
		out = append(out, hdr...)
		out = append(out, p.Value...)
	}
	return out, nil
}

// SvcParamALPNValue encodes an "alpn" parameter value (RFC 9460 §7.1.1): a
// sequence of length-prefixed protocol identifiers, e.g. {"h2", "h3"}.
//
// The one-octet length prefix is per protocol id, not for the whole list —
// a detail worth stating because the encoding otherwise looks like it could
// be a simple concatenation, and a receiver reading a mis-encoded value gets
// garbage protocol names rather than a parse error.
func SvcParamALPNValue(protocols ...string) SvcParam {
	var v []byte
	for _, p := range protocols {
		if p == "" || len(p) > 255 {
			continue
		}
		v = append(v, byte(len(p)))
		v = append(v, p...)
	}
	return SvcParam{Key: SvcParamALPN, Value: v}
}

// SvcParamPortValue encodes a "port" parameter (RFC 9460 §7.2).
func SvcParamPortValue(port uint16) SvcParam {
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, port)
	return SvcParam{Key: SvcParamPort, Value: v}
}

// SvcParamDoHPathValue encodes a "dohpath" parameter (RFC 9461 §5). The value
// is the raw UTF-8 URI template with no length prefix — the parameter's own
// length field delimits it.
func SvcParamDoHPathValue(path string) SvcParam {
	return SvcParam{Key: SvcParamDoHPath, Value: []byte(path)}
}

// SvcParamIPv4HintValue encodes an "ipv4hint" parameter (RFC 9460 §7.3) as a
// concatenation of 4-octet addresses. Non-IPv4 entries are skipped rather
// than encoded as something the receiver would misread.
func SvcParamIPv4HintValue(ips []net.IP) SvcParam {
	var v []byte
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			v = append(v, ip4...)
		}
	}
	return SvcParam{Key: SvcParamIPv4Hint, Value: v}
}

// SvcParamIPv6HintValue encodes an "ipv6hint" parameter (RFC 9460 §7.3) as a
// concatenation of 16-octet addresses. IPv4 addresses are skipped: an
// IPv4-mapped IPv6 address here would tell the client to open an IPv6
// connection to an address that only exists in v4.
func SvcParamIPv6HintValue(ips []net.IP) SvcParam {
	var v []byte
	for _, ip := range ips {
		if ip.To4() != nil {
			continue
		}
		if ip16 := ip.To16(); ip16 != nil {
			v = append(v, ip16...)
		}
	}
	return SvcParam{Key: SvcParamIPv6Hint, Value: v}
}

// ParseSVCBParams reads the parameter list out of SVCB RDATA, skipping the
// priority and target name. Used by tests and by the dashboard to show what a
// designation actually advertises.
//
// It is strict about the ordering rule so a malformed record is reported
// rather than silently half-read.
func ParseSVCBParams(rdata []byte) ([]SvcParam, error) {
	if len(rdata) < 2 {
		return nil, errTruncated
	}
	_, off, err := DecodeName(rdata, 2)
	if err != nil {
		return nil, err
	}

	var params []SvcParam
	var prevKey uint16
	first := true
	for off < len(rdata) {
		if off+4 > len(rdata) {
			return nil, errTruncated
		}
		key := binary.BigEndian.Uint16(rdata[off : off+2])
		length := int(binary.BigEndian.Uint16(rdata[off+2 : off+4]))
		off += 4
		if off+length > len(rdata) {
			return nil, errTruncated
		}
		if !first && key <= prevKey {
			return nil, errors.New("dns: SVCB parameters not in strictly increasing key order")
		}
		first = false
		prevKey = key

		value := make([]byte, length)
		copy(value, rdata[off:off+length])
		params = append(params, SvcParam{Key: key, Value: value})
		off += length
	}
	return params, nil
}
