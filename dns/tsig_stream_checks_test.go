package dns

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// tsigForgeStream appends a TSIG carrying an arbitrary MAC, as an attacker
// without the secret would.
func tsigForgeStream(msg []byte, key TSIGKey, ts time.Time, mac []byte) []byte {
	rdata := buildTSIGRData(TSIGRecord{
		Algorithm:  key.algorithm(),
		TimeSigned: uint64(ts.Unix()),
		Fudge:      DefaultTSIGFudge,
		MAC:        mac,
		OriginalID: binary.BigEndian.Uint16(msg[0:2]),
	})
	return appendTSIGRR(msg, key.Name, rdata)
}

// TestRFC8945_StreamTruncationFloor pins §5.2.2.1 for continuation messages.
// TSIGVerifyStream used to accept any MAC of one octet or more, so a forged
// continuation needed at most 256 guesses.
func TestRFC8945_StreamTruncationFloor(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	_, prior, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, full, err := TSIGSignStream(tsigTestMessage(t), key, now, DefaultTSIGFudge, prior)
	if err != nil {
		t.Fatal(err)
	}

	for b := 0; b < 256; b++ {
		forged := tsigForgeStream(tsigTestMessage(t), key, now, []byte{byte(b)})
		if _, _, err := TSIGVerifyStream(forged, key, prior, now); !errors.Is(err, ErrTSIGBadTrunc) {
			t.Fatalf("1-octet MAC %#02x: error = %v, want ErrTSIGBadTrunc", b, err)
		}
	}
	if _, _, err := TSIGVerifyStream(tsigForgeStream(tsigTestMessage(t), key, now, full[:15]), key, prior, now); !errors.Is(err, ErrTSIGBadTrunc) {
		t.Fatalf("15-octet MAC: error = %v, want ErrTSIGBadTrunc", err)
	}
	if _, _, err := TSIGVerifyStream(tsigForgeStream(tsigTestMessage(t), key, now, full[:16]), key, prior, now); err != nil {
		t.Fatalf("16-octet MAC (half the digest) must verify: %v", err)
	}
}

// TestRFC8945_StreamAlgorithmMustMatchKey pins that a continuation message
// cannot pick a different algorithm than the key is configured for.
func TestRFC8945_StreamAlgorithmMustMatchKey(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	_, prior, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatal(err)
	}
	sha1Key := key
	sha1Key.Algorithm = TSIGHMACSHA1
	downgraded, _, err := TSIGSignStream(tsigTestMessage(t), sha1Key, now, DefaultTSIGFudge, prior)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := TSIGVerifyStream(downgraded, key, prior, now); !errors.Is(err, ErrTSIGBadAlgorithm) {
		t.Fatalf("error = %v, want ErrTSIGBadAlgorithm", err)
	}
}

// TestRFC8945_StreamDigestCoversUnsignedMessages pins the §5.3.1 digest when
// a sender signs only every Nth message: prior MAC, then every unsigned
// message since the last TSIG, then this message, then the timers. It is
// checked against an HMAC computed here independently, since sign and verify
// agreeing with each other proves nothing about interoperability.
func TestRFC8945_StreamDigestCoversUnsignedMessages(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	prior := bytes.Repeat([]byte{7}, sha256.Size)
	u1 := tsigTestMessage(t)
	u2 := tsigTestMessage(t)
	u2[0] = 0x01 // distinct from u1, so their order matters
	msg := tsigTestMessage(t)

	signed, _, err := TSIGSignStream(msg, key, now, DefaultTSIGFudge, prior, u1, u2)
	if err != nil {
		t.Fatal(err)
	}

	h := hmac.New(sha256.New, key.Secret)
	h.Write([]byte{0, sha256.Size})
	h.Write(prior)
	h.Write(u1)
	h.Write(u2)
	h.Write(msg)
	h.Write(encodeTimeSigned(uint64(now.Unix())))
	h.Write(binary.BigEndian.AppendUint16(nil, DefaultTSIGFudge))
	rec, _, err := extractTSIG(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(rec.MAC, h.Sum(nil)) {
		t.Fatal("TSIGSignStream MAC differs from the RFC 8945 §5.3.1 digest")
	}

	if _, _, err := TSIGVerifyStream(signed, key, prior, now, u1, u2); err != nil {
		t.Fatalf("verify with the unsigned messages: %v", err)
	}
	for name, unsigned := range map[string][][]byte{
		"none":     nil,
		"dropped":  {u1},
		"reversed": {u2, u1},
	} {
		if _, _, err := TSIGVerifyStream(signed, key, prior, now, unsigned...); !errors.Is(err, ErrTSIGBadSig) {
			t.Fatalf("%s: error = %v, want ErrTSIGBadSig", name, err)
		}
	}
}
