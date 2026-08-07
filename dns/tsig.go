package dns

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

// TSIG — Secret Key Transaction Authentication for DNS (RFC 8945).
//
// TSIG authenticates a DNS message between two parties that already share a
// secret. It is not a general-purpose signature scheme like DNSSEC: there is
// no chain of trust and no third-party verification, just an HMAC over the
// message computed with a key both ends were configured with out of band.
// That narrowness is the point — it makes TSIG cheap enough to put on every
// message of a zone transfer, which is what it is overwhelmingly used for.
//
// # Where the difficulty is
//
// The MAC does not cover the message as it appears on the wire. It covers the
// message *without* the TSIG record, with ARCOUNT decremented to match, plus a
// synthetic block of "TSIG variables" that is not laid out the same way as the
// TSIG RDATA it comes from. Get any of that wrong and you produce a MAC that
// is self-consistent — sign and verify agree with yourself — while every other
// implementation rejects it. So the digest construction is written out
// step-by-step below against the section numbers rather than condensed.
//
// # What is deliberately not here
//
// HMAC-MD5 (`hmac-md5.sig-alg.reg.int`) is a MAY in RFC 8945 §6 and is the
// historical default from RFC 2845. It is not implemented. MD5's collision
// resistance is long gone (RFC 6151), and while HMAC-MD5 is not broken in the
// same way, offering it invites an operator to pick it from a config file
// without understanding the distinction. Every peer worth transferring a zone
// with supports HMAC-SHA256.

// TSIG error codes (RFC 8945 §4.3 / §5.2). These live in the TSIG RDATA's
// Error field, which is a distinct registry from the DNS RCODE and the EDNS
// extended RCODE — value 16 is BADSIG here and BADVERS in the EDNS space.
const (
	TSIGErrorNoError  uint16 = 0
	TSIGErrorBadSig   uint16 = 16
	TSIGErrorBadKey   uint16 = 17
	TSIGErrorBadTime  uint16 = 18
	TSIGErrorBadTrunc uint16 = 22
)

// TSIG algorithm names, as they appear on the wire (RFC 8945 §6). They are
// domain names, compared case-insensitively.
const (
	TSIGHMACSHA1   = "hmac-sha1"
	TSIGHMACSHA224 = "hmac-sha224"
	TSIGHMACSHA256 = "hmac-sha256"
	TSIGHMACSHA384 = "hmac-sha384"
	TSIGHMACSHA512 = "hmac-sha512"
)

// DefaultTSIGAlgorithm is what a configuration that does not say gets.
// RFC 8945 §6 lists HMAC-SHA256 as mandatory to implement, and it is the
// de-facto default across BIND, Knot and PowerDNS.
const DefaultTSIGAlgorithm = TSIGHMACSHA256

// DefaultTSIGFudge is the permitted clock skew in seconds (RFC 8945 §5.2.3
// recommends 300). It bounds how far apart the two clocks may be before
// signatures start failing, and equally how long a captured message stays
// replayable.
const DefaultTSIGFudge uint16 = 300

var (
	ErrTSIGNotSigned       = errors.New("tsig: message carries no TSIG record")
	ErrTSIGNotLast         = errors.New("tsig: TSIG record is not the last record in the additional section")
	ErrTSIGBadKey          = errors.New("tsig: unknown key name")
	ErrTSIGBadAlgorithm    = errors.New("tsig: unsupported algorithm")
	ErrTSIGBadSig          = errors.New("tsig: MAC verification failed")
	ErrTSIGBadTime         = errors.New("tsig: time signed outside the fudge window")
	ErrTSIGBadTrunc        = errors.New("tsig: MAC truncated below the permitted minimum")
	ErrTSIGMalformed       = errors.New("tsig: malformed TSIG record")
	ErrTSIGWrongClassOrTTL = errors.New("tsig: TSIG record must have class ANY and TTL 0")
)

// TSIGKey is a shared secret and the algorithm it is used with.
type TSIGKey struct {
	// Name is the key name, which travels as the TSIG record's owner name.
	// Both parties must use the same name; it is how the receiver selects
	// which secret to verify against.
	Name string
	// Algorithm is one of the TSIGHMAC* constants. Empty means
	// DefaultTSIGAlgorithm.
	Algorithm string
	// Secret is the raw shared secret. Configuration usually carries it
	// base64-encoded; decoding happens at the config boundary so a secret
	// never sits in memory in two representations.
	Secret []byte
}

// algorithm returns the normalised algorithm name.
func (k TSIGKey) algorithm() string {
	if k.Algorithm == "" {
		return DefaultTSIGAlgorithm
	}
	return strings.ToLower(strings.TrimSuffix(k.Algorithm, "."))
}

// newHash returns the HMAC constructor for a TSIG algorithm name.
//
// HMAC-MD5 is absent on purpose; see the package comment.
func newHash(algorithm string) (func() hash.Hash, error) {
	switch strings.ToLower(strings.TrimSuffix(algorithm, ".")) {
	case TSIGHMACSHA1:
		return sha1.New, nil
	case TSIGHMACSHA224:
		return sha256.New224, nil
	case TSIGHMACSHA256:
		return sha256.New, nil
	case TSIGHMACSHA384:
		return sha512.New384, nil
	case TSIGHMACSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrTSIGBadAlgorithm, algorithm)
	}
}

// TSIGRecord is a parsed TSIG RDATA (RFC 8945 §4.2).
type TSIGRecord struct {
	KeyName    string
	Algorithm  string
	TimeSigned uint64 // 48-bit seconds since the Unix epoch
	Fudge      uint16
	MAC        []byte
	OriginalID uint16
	Error      uint16
	OtherData  []byte
}

// TSIGSign appends a TSIG record to a packed DNS message and returns the new
// message together with the MAC it carries.
//
// requestMAC is empty when signing a request. When signing a *response*, it
// must be the MAC from the request being answered: RFC 8945 §5.3 folds it into
// the digest so a response cannot be lifted from one exchange and replayed
// into another. Omitting it produces a signature the peer will reject, which
// is the correct failure — but it is silent on this side, so callers signing
// responses must thread it through.
func TSIGSign(msg []byte, key TSIGKey, timeSigned time.Time, fudge uint16, requestMAC []byte) ([]byte, []byte, error) {
	if len(msg) < 12 {
		return nil, nil, ErrTSIGMalformed
	}
	newH, err := newHash(key.algorithm())
	if err != nil {
		return nil, nil, err
	}
	if fudge == 0 {
		fudge = DefaultTSIGFudge
	}

	signedTime := uint64(timeSigned.Unix())
	originalID := binary.BigEndian.Uint16(msg[0:2])

	mac := computeTSIGMAC(newH, key, msg, requestMAC, tsigVariables{
		keyName:    key.Name,
		algorithm:  key.algorithm(),
		timeSigned: signedTime,
		fudge:      fudge,
		errCode:    TSIGErrorNoError,
		otherData:  nil,
	}, false)

	rdata := buildTSIGRData(TSIGRecord{
		Algorithm:  key.algorithm(),
		TimeSigned: signedTime,
		Fudge:      fudge,
		MAC:        mac,
		OriginalID: originalID,
		Error:      TSIGErrorNoError,
	})

	out := appendTSIGRR(msg, key.Name, rdata)
	return out, mac, nil
}

// TSIGVerify checks the TSIG record on a packed message and returns its MAC,
// which the caller needs in order to sign the response (or the next message of
// a multi-message stream).
//
// keyFor resolves a key name to its secret. Taking a lookup function rather
// than a single key is what lets a server hold several keys and select by the
// name the client presented — the normal deployment, where each peer has its
// own secret.
//
// `now` is passed in rather than read from the clock so the fudge-window check
// is testable; production callers pass time.Now().
func TSIGVerify(msg []byte, keyFor func(name string) (TSIGKey, bool), requestMAC []byte, now time.Time) (*TSIGRecord, []byte, error) {
	rec, rrStart, err := extractTSIG(msg)
	if err != nil {
		return nil, nil, err
	}

	key, ok := keyFor(rec.KeyName)
	if !ok {
		return rec, nil, fmt.Errorf("%w: %q", ErrTSIGBadKey, rec.KeyName)
	}
	// The algorithm is chosen by the sender, so it is attacker-controlled
	// input on an unauthenticated message. Verify against the algorithm the
	// *record* names rather than the one the local key is configured with —
	// but only after confirming we support it, so an unknown name is a clean
	// rejection instead of a nil dereference.
	newH, err := newHash(rec.Algorithm)
	if err != nil {
		return rec, nil, err
	}
	if !strings.EqualFold(rec.Algorithm, key.algorithm()) {
		return rec, nil, fmt.Errorf("%w: message uses %q, key %q is configured for %q",
			ErrTSIGBadAlgorithm, rec.Algorithm, rec.KeyName, key.algorithm())
	}

	// RFC 8945 §5.2.2.1: a truncated MAC must be at least half the full
	// digest length and at least 10 octets. Without the floor, a peer could
	// negotiate the MAC down to a length brute-forceable offline.
	full := newH().Size()
	if len(rec.MAC) < full/2 || len(rec.MAC) < 10 {
		return rec, nil, fmt.Errorf("%w: %d octets, minimum %d",
			ErrTSIGBadTrunc, len(rec.MAC), maxInt(full/2, 10))
	}
	if len(rec.MAC) > full {
		return rec, nil, fmt.Errorf("%w: MAC longer than the algorithm's digest", ErrTSIGMalformed)
	}

	// Reconstruct the message the sender digested: everything before the
	// TSIG record, with ARCOUNT decremented and the original ID restored.
	stripped := stripTSIG(msg, rrStart, rec.OriginalID)

	want := computeTSIGMAC(newH, key, stripped, requestMAC, tsigVariables{
		keyName:    rec.KeyName,
		algorithm:  rec.Algorithm,
		timeSigned: rec.TimeSigned,
		fudge:      rec.Fudge,
		errCode:    rec.Error,
		otherData:  rec.OtherData,
	}, false)

	// Compare only as many octets as the sender sent, per the truncation
	// rules — but through hmac.Equal, so the comparison stays constant-time
	// and a MAC cannot be recovered one byte at a time by timing.
	if !hmac.Equal(rec.MAC, want[:len(rec.MAC)]) {
		return rec, nil, ErrTSIGBadSig
	}

	// Time check comes last. RFC 8945 §5.2.3 orders the checks so that a
	// message failing on time has already proved it holds the key —
	// otherwise BADTIME would be a probing oracle telling an attacker
	// without the secret whether their guessed key name exists.
	if !withinFudge(rec.TimeSigned, rec.Fudge, now) {
		return rec, nil, fmt.Errorf("%w: signed at %d, now %d, fudge %d",
			ErrTSIGBadTime, rec.TimeSigned, now.Unix(), rec.Fudge)
	}

	return rec, rec.MAC, nil
}

// TSIGSignStream signs a subsequent message of a multi-message stream, such
// as the second and later messages of an AXFR (RFC 8945 §5.3.1).
//
// The digest for these is deliberately different: it covers the *previous*
// message's MAC, then the message, then only the Time Signed and Fudge fields
// rather than the full TSIG variables block. That is what chains the messages
// together — a stream cannot be reordered or have messages dropped from the
// middle without the chain breaking.
func TSIGSignStream(msg []byte, key TSIGKey, timeSigned time.Time, fudge uint16, priorMAC []byte) ([]byte, []byte, error) {
	if len(msg) < 12 {
		return nil, nil, ErrTSIGMalformed
	}
	newH, err := newHash(key.algorithm())
	if err != nil {
		return nil, nil, err
	}
	if fudge == 0 {
		fudge = DefaultTSIGFudge
	}

	signedTime := uint64(timeSigned.Unix())
	originalID := binary.BigEndian.Uint16(msg[0:2])

	mac := computeTSIGMAC(newH, key, msg, priorMAC, tsigVariables{
		timeSigned: signedTime,
		fudge:      fudge,
	}, true)

	rdata := buildTSIGRData(TSIGRecord{
		Algorithm:  key.algorithm(),
		TimeSigned: signedTime,
		Fudge:      fudge,
		MAC:        mac,
		OriginalID: originalID,
		Error:      TSIGErrorNoError,
	})
	return appendTSIGRR(msg, key.Name, rdata), mac, nil
}

// TSIGVerifyStream is the verification counterpart of TSIGSignStream.
func TSIGVerifyStream(msg []byte, key TSIGKey, priorMAC []byte, now time.Time) (*TSIGRecord, []byte, error) {
	rec, rrStart, err := extractTSIG(msg)
	if err != nil {
		return nil, nil, err
	}
	newH, err := newHash(rec.Algorithm)
	if err != nil {
		return rec, nil, err
	}

	stripped := stripTSIG(msg, rrStart, rec.OriginalID)
	want := computeTSIGMAC(newH, key, stripped, priorMAC, tsigVariables{
		timeSigned: rec.TimeSigned,
		fudge:      rec.Fudge,
	}, true)

	if len(rec.MAC) == 0 || len(rec.MAC) > len(want) {
		return rec, nil, ErrTSIGMalformed
	}
	if !hmac.Equal(rec.MAC, want[:len(rec.MAC)]) {
		return rec, nil, ErrTSIGBadSig
	}
	if !withinFudge(rec.TimeSigned, rec.Fudge, now) {
		return rec, nil, ErrTSIGBadTime
	}
	return rec, rec.MAC, nil
}

// tsigVariables is the synthetic block RFC 8945 §4.3.3 appends to the message
// before hashing. It is NOT the TSIG RDATA: MAC Size and MAC are excluded
// (they are the output), and the owner name, class and TTL are folded in from
// the record header.
type tsigVariables struct {
	keyName    string
	algorithm  string
	timeSigned uint64
	fudge      uint16
	errCode    uint16
	otherData  []byte
}

// computeTSIGMAC builds the digest input and returns the full-length MAC.
//
// The order is fixed by RFC 8945 §4.3:
//
//  1. the request MAC, length-prefixed  (§4.3.1, responses and stream continuations only)
//  2. the DNS message, sans TSIG        (§4.3.2)
//  3. the TSIG variables                (§4.3.3)
//
// streamContinuation selects the reduced variables block of §5.3.1, which
// carries only Time Signed and Fudge.
func computeTSIGMAC(newH func() hash.Hash, key TSIGKey, msg, priorMAC []byte, v tsigVariables, streamContinuation bool) []byte {
	mac := hmac.New(newH, key.Secret)

	// (1) Request/prior MAC, prefixed with its 2-octet length.
	if len(priorMAC) > 0 {
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(priorMAC)))
		mac.Write(lenBuf[:])
		mac.Write(priorMAC)
	}

	// (2) The message itself.
	mac.Write(msg)

	// (3) TSIG variables.
	if streamContinuation {
		mac.Write(encodeTimeSigned(v.timeSigned))
		var fudge [2]byte
		binary.BigEndian.PutUint16(fudge[:], v.fudge)
		mac.Write(fudge[:])
		return mac.Sum(nil)
	}

	// Names go in canonical form — uncompressed and lowercased (RFC 4034
	// §6.1, applied by RFC 8945 §4.3.3). Case-preserving here would make a
	// key name typed as "KEY.example" fail against a peer that wrote
	// "key.example", for no reason the operator could see.
	mac.Write(BuildPlainName(strings.ToLower(strings.TrimSuffix(v.keyName, "."))))

	var classTTL [6]byte
	binary.BigEndian.PutUint16(classTTL[0:2], 255) // CLASS ANY
	binary.BigEndian.PutUint32(classTTL[2:6], 0)   // TTL 0
	mac.Write(classTTL[:])

	mac.Write(BuildPlainName(strings.ToLower(strings.TrimSuffix(v.algorithm, "."))))
	mac.Write(encodeTimeSigned(v.timeSigned))

	var tail [6]byte
	binary.BigEndian.PutUint16(tail[0:2], v.fudge)
	binary.BigEndian.PutUint16(tail[2:4], v.errCode)
	binary.BigEndian.PutUint16(tail[4:6], uint16(len(v.otherData)))
	mac.Write(tail[:])
	mac.Write(v.otherData)

	return mac.Sum(nil)
}

// encodeTimeSigned renders the 48-bit Time Signed field.
func encodeTimeSigned(t uint64) []byte {
	return []byte{
		byte(t >> 40), byte(t >> 32), byte(t >> 24),
		byte(t >> 16), byte(t >> 8), byte(t),
	}
}

// withinFudge reports whether a Time Signed value is acceptable now
// (RFC 8945 §5.2.3). The window is symmetric: a signature from the future is
// as suspect as one from the past, since a skewed peer can err either way.
func withinFudge(timeSigned uint64, fudge uint16, now time.Time) bool {
	nowSecs := now.Unix()
	if nowSecs < 0 {
		return false
	}
	signed := int64(timeSigned)
	delta := nowSecs - signed
	if delta < 0 {
		delta = -delta
	}
	return delta <= int64(fudge)
}

// buildTSIGRData serialises TSIG RDATA (RFC 8945 §4.2).
func buildTSIGRData(rec TSIGRecord) []byte {
	out := BuildPlainName(rec.Algorithm)
	out = append(out, encodeTimeSigned(rec.TimeSigned)...)

	var buf [4]byte
	binary.BigEndian.PutUint16(buf[0:2], rec.Fudge)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(rec.MAC)))
	out = append(out, buf[:]...)
	out = append(out, rec.MAC...)

	var tail [6]byte
	binary.BigEndian.PutUint16(tail[0:2], rec.OriginalID)
	binary.BigEndian.PutUint16(tail[2:4], rec.Error)
	binary.BigEndian.PutUint16(tail[4:6], uint16(len(rec.OtherData)))
	out = append(out, tail[:]...)
	out = append(out, rec.OtherData...)
	return out
}

// appendTSIGRR appends a TSIG resource record to a packed message and bumps
// ARCOUNT.
//
// The record is written directly rather than via Pack because TSIG must be
// byte-exact: the owner name is uncompressed (RFC 8945 §4.2 forbids
// compression here, and a compression pointer would make the MAC depend on
// where in the message the name happened to land).
func appendTSIGRR(msg []byte, keyName string, rdata []byte) []byte {
	out := make([]byte, len(msg), len(msg)+len(rdata)+len(keyName)+16)
	copy(out, msg)

	out = append(out, BuildPlainName(keyName)...)

	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], TypeTSIG)
	binary.BigEndian.PutUint16(hdr[2:4], 255) // CLASS ANY
	binary.BigEndian.PutUint32(hdr[4:8], 0)   // TTL 0
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rdata)))
	out = append(out, hdr[:]...)
	out = append(out, rdata...)

	// ARCOUNT += 1
	arcount := binary.BigEndian.Uint16(out[10:12])
	binary.BigEndian.PutUint16(out[10:12], arcount+1)
	return out
}

// stripTSIG returns the message as the signer digested it: truncated before
// the TSIG record, with ARCOUNT decremented and the original transaction ID
// restored.
//
// The ID restoration matters for forwarded messages. A forwarder rewrites the
// transaction ID, and RFC 8945 §4.2 keeps the pre-rewrite value in the TSIG's
// Original ID field precisely so the MAC still verifies afterwards. Skipping
// it works fine in a direct exchange and breaks the moment anything sits in
// between.
func stripTSIG(msg []byte, rrStart int, originalID uint16) []byte {
	stripped := make([]byte, rrStart)
	copy(stripped, msg[:rrStart])

	arcount := binary.BigEndian.Uint16(stripped[10:12])
	if arcount > 0 {
		binary.BigEndian.PutUint16(stripped[10:12], arcount-1)
	}
	binary.BigEndian.PutUint16(stripped[0:2], originalID)
	return stripped
}

// extractTSIG locates and parses the TSIG record, returning it along with the
// offset at which its owner name begins.
//
// RFC 8945 §5.1 requires TSIG to be the last record in the additional
// section, and this enforces it rather than merely searching for one. A
// message with a TSIG somewhere in the middle would let an attacker append
// records after a validly-signed record and have them accepted as
// authenticated — the MAC covers everything before the TSIG, and nothing
// after it.
func extractTSIG(msg []byte) (*TSIGRecord, int, error) {
	if len(msg) < 12 {
		return nil, 0, ErrTSIGMalformed
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))
	if ar == 0 {
		return nil, 0, ErrTSIGNotSigned
	}

	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := DecodeName(msg, off)
		if err != nil {
			return nil, 0, ErrTSIGMalformed
		}
		off = next + 4 // QTYPE + QCLASS
		if off > len(msg) {
			return nil, 0, ErrTSIGMalformed
		}
	}

	total := an + ns + ar
	var (
		rrStart  int
		found    bool
		keyName  string
		rdStart  int
		rdLength int
	)
	for i := 0; i < total; i++ {
		start := off
		name, next, err := DecodeName(msg, off)
		if err != nil {
			return nil, 0, ErrTSIGMalformed
		}
		if next+10 > len(msg) {
			return nil, 0, ErrTSIGMalformed
		}
		rrType := binary.BigEndian.Uint16(msg[next : next+2])
		rrClass := binary.BigEndian.Uint16(msg[next+2 : next+4])
		rrTTL := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		off = next + 10 + rdLen
		if off > len(msg) {
			return nil, 0, ErrTSIGMalformed
		}

		if rrType == TypeTSIG {
			// A TSIG anywhere but last means records follow it that the MAC
			// does not cover.
			if i != total-1 {
				return nil, 0, ErrTSIGNotLast
			}
			if rrClass != 255 || rrTTL != 0 {
				return nil, 0, ErrTSIGWrongClassOrTTL
			}
			rrStart, found, keyName = start, true, name
			rdStart, rdLength = next+10, rdLen
		}
	}
	if !found {
		return nil, 0, ErrTSIGNotSigned
	}

	rec, err := parseTSIGRData(msg, rdStart, rdLength)
	if err != nil {
		return nil, 0, err
	}
	rec.KeyName = keyName
	return rec, rrStart, nil
}

// parseTSIGRData decodes TSIG RDATA in place from the message buffer.
func parseTSIGRData(msg []byte, off, length int) (*TSIGRecord, error) {
	end := off + length
	if end > len(msg) {
		return nil, ErrTSIGMalformed
	}

	algorithm, next, err := DecodeName(msg, off)
	if err != nil {
		return nil, ErrTSIGMalformed
	}
	if next+10 > end {
		return nil, ErrTSIGMalformed
	}

	var rec TSIGRecord
	rec.Algorithm = algorithm
	rec.TimeSigned = uint64(msg[next])<<40 | uint64(msg[next+1])<<32 |
		uint64(msg[next+2])<<24 | uint64(msg[next+3])<<16 |
		uint64(msg[next+4])<<8 | uint64(msg[next+5])
	rec.Fudge = binary.BigEndian.Uint16(msg[next+6 : next+8])
	macSize := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
	next += 10

	if next+macSize+6 > end {
		return nil, ErrTSIGMalformed
	}
	rec.MAC = make([]byte, macSize)
	copy(rec.MAC, msg[next:next+macSize])
	next += macSize

	rec.OriginalID = binary.BigEndian.Uint16(msg[next : next+2])
	rec.Error = binary.BigEndian.Uint16(msg[next+2 : next+4])
	otherLen := int(binary.BigEndian.Uint16(msg[next+4 : next+6]))
	next += 6

	if next+otherLen > end {
		return nil, ErrTSIGMalformed
	}
	rec.OtherData = make([]byte, otherLen)
	copy(rec.OtherData, msg[next:next+otherLen])

	return &rec, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
