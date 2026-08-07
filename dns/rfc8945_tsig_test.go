package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// TSIG (RFC 8945).
//
// The trap in TSIG is that the MAC does not cover the message as it appears on
// the wire. It covers the message *without* the TSIG record, with ARCOUNT
// decremented, the transaction ID restored to Original ID, plus a synthetic
// "TSIG variables" block laid out differently from the RDATA it derives from.
// An implementation that gets any of that wrong is perfectly self-consistent —
// it signs and verifies its own messages fine — and rejected by every other
// implementation on the internet.
//
// Round-trip tests therefore prove very little on their own. The tests that
// carry weight here are the ones that tamper: change a byte the MAC should
// cover and require the verification to fail.

func tsigTestKey() TSIGKey {
	return TSIGKey{
		Name:      "test-key.example",
		Algorithm: TSIGHMACSHA256,
		Secret:    []byte("a shared secret of no particular length"),
	}
}

func tsigKeyring(k TSIGKey) func(string) (TSIGKey, bool) {
	return func(name string) (TSIGKey, bool) {
		if name == k.Name {
			return k, true
		}
		return TSIGKey{}, false
	}
}

// tsigTestMessage packs an ordinary query to sign.
func tsigTestMessage(t *testing.T) []byte {
	t.Helper()
	msg := &Message{
		Header:    Header{ID: 0x8945, Flags: NewFlagBuilder().SetRD(true).Build()},
		Questions: []Question{{Name: "zone.example", Type: TypeAXFR, Class: ClassIN}},
	}
	packed, err := Pack(msg, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out
}

// TestRFC8945_SignVerifyRoundTrip is the baseline. It also pins the message
// shape after signing: ARCOUNT must have grown, and the TSIG must be parseable
// by the ordinary message parser.
func TestRFC8945_SignVerifyRoundTrip(t *testing.T) {
	key := tsigTestKey()
	msg := tsigTestMessage(t)
	now := time.Unix(1_700_000_000, 0)

	signed, mac, err := TSIGSign(msg, key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}
	if len(mac) != 32 {
		t.Errorf("MAC length = %d, want 32 for HMAC-SHA256", len(mac))
	}

	// ARCOUNT must reflect the added record, or every other implementation
	// will fail to find it.
	if before, after := binary.BigEndian.Uint16(msg[10:12]), binary.BigEndian.Uint16(signed[10:12]); after != before+1 {
		t.Errorf("ARCOUNT went %d -> %d, want +1", before, after)
	}

	rec, gotMAC, err := TSIGVerify(signed, tsigKeyring(key), nil, now)
	if err != nil {
		t.Fatalf("TSIGVerify: %v", err)
	}
	if rec.KeyName != key.Name {
		t.Errorf("key name = %q, want %q", rec.KeyName, key.Name)
	}
	if rec.Algorithm != TSIGHMACSHA256 {
		t.Errorf("algorithm = %q, want %q", rec.Algorithm, TSIGHMACSHA256)
	}
	if !bytes.Equal(gotMAC, mac) {
		t.Error("verified MAC differs from the signed MAC")
	}
	if rec.OriginalID != 0x8945 {
		t.Errorf("original ID = %#x, want 0x8945", rec.OriginalID)
	}
}

// TestRFC8945_TamperedMessageRejected is the test that actually proves the
// digest covers the message. Flip a byte in the question section — which no
// sane implementation would notice by other means — and the MAC must fail.
func TestRFC8945_TamperedMessageRejected(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	signed, _, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}

	tampered := make([]byte, len(signed))
	copy(tampered, signed)
	tampered[14] ^= 0x20 // a byte inside the QNAME

	if _, _, err := TSIGVerify(tampered, tsigKeyring(key), nil, now); !errors.Is(err, ErrTSIGBadSig) {
		t.Fatalf("error = %v, want ErrTSIGBadSig for a tampered message", err)
	}
}

// TestRFC8945_WrongSecretRejected pins the obvious case, which is worth having
// because a digest built over the wrong input can accidentally be
// key-independent.
func TestRFC8945_WrongSecretRejected(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	signed, _, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}

	wrong := key
	wrong.Secret = []byte("a different secret entirely")
	if _, _, err := TSIGVerify(signed, tsigKeyring(wrong), nil, now); !errors.Is(err, ErrTSIGBadSig) {
		t.Fatalf("error = %v, want ErrTSIGBadSig under the wrong secret", err)
	}
}

// TestRFC8945_UnknownKeyRejected pins BADKEY (RFC 8945 §5.2.1).
func TestRFC8945_UnknownKeyRejected(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	signed, _, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}

	empty := func(string) (TSIGKey, bool) { return TSIGKey{}, false }
	if _, _, err := TSIGVerify(signed, empty, nil, now); !errors.Is(err, ErrTSIGBadKey) {
		t.Fatalf("error = %v, want ErrTSIGBadKey", err)
	}
}

// TestRFC8945_ClockSkewWindow pins the BADTIME window of §5.2.3, including
// that it is symmetric — a signature from the future is as suspect as one from
// the past, because a skewed peer errs in both directions.
func TestRFC8945_ClockSkewWindow(t *testing.T) {
	key := tsigTestKey()
	signedAt := time.Unix(1_700_000_000, 0)
	signed, _, err := TSIGSign(tsigTestMessage(t), key, signedAt, 300, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}

	cases := []struct {
		name   string
		now    time.Time
		wantOK bool
	}{
		{"exact", signedAt, true},
		{"within window, past", signedAt.Add(299 * time.Second), true},
		{"within window, future", signedAt.Add(-299 * time.Second), true},
		{"at the boundary", signedAt.Add(300 * time.Second), true},
		{"beyond window, past", signedAt.Add(301 * time.Second), false},
		{"beyond window, future", signedAt.Add(-301 * time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := TSIGVerify(signed, tsigKeyring(key), nil, tc.now)
			if tc.wantOK && err != nil {
				t.Fatalf("verify failed inside the fudge window: %v", err)
			}
			if !tc.wantOK && !errors.Is(err, ErrTSIGBadTime) {
				t.Fatalf("error = %v, want ErrTSIGBadTime", err)
			}
		})
	}
}

// TestRFC8945_BadTimeOnlyAfterMACVerifies pins the check ordering of §5.2.
// BADTIME must not be reachable without holding the key, or it becomes an
// oracle that tells an attacker which key names exist.
func TestRFC8945_BadTimeOnlyAfterMACVerifies(t *testing.T) {
	key := tsigTestKey()
	signedAt := time.Unix(1_700_000_000, 0)
	signed, _, err := TSIGSign(tsigTestMessage(t), key, signedAt, 300, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}

	wrong := key
	wrong.Secret = []byte("wrong")
	// Far outside the fudge window AND signed with the wrong key: the
	// reported failure must be the signature, not the time.
	_, _, err = TSIGVerify(signed, tsigKeyring(wrong), nil, signedAt.Add(time.Hour))
	if !errors.Is(err, ErrTSIGBadSig) {
		t.Fatalf("error = %v, want ErrTSIGBadSig — a caller without the key must "+
			"not learn anything about the timestamp", err)
	}
}

// TestRFC8945_ResponseBindsToRequestMAC pins §5.3. A response's digest folds
// in the request's MAC, which is what stops a signed response being captured
// and replayed as the answer to a different question.
func TestRFC8945_ResponseBindsToRequestMAC(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)

	_, requestMAC, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}

	response := tsigTestMessage(t)
	signedResp, _, err := TSIGSign(response, key, now, DefaultTSIGFudge, requestMAC)
	if err != nil {
		t.Fatalf("sign response: %v", err)
	}

	// Verifying with the right request MAC succeeds.
	if _, _, err := TSIGVerify(signedResp, tsigKeyring(key), requestMAC, now); err != nil {
		t.Fatalf("verify with the correct request MAC: %v", err)
	}

	// Verifying as though it answered a different request must fail — this
	// is the replay defence.
	otherMAC := make([]byte, len(requestMAC))
	copy(otherMAC, requestMAC)
	otherMAC[0] ^= 0xFF
	if _, _, err := TSIGVerify(signedResp, tsigKeyring(key), otherMAC, now); !errors.Is(err, ErrTSIGBadSig) {
		t.Fatalf("error = %v, want ErrTSIGBadSig — a response must not verify "+
			"against a request it did not answer", err)
	}

	// And verifying with no request MAC at all must fail too, or the
	// binding is trivially bypassed by simply omitting it.
	if _, _, err := TSIGVerify(signedResp, tsigKeyring(key), nil, now); !errors.Is(err, ErrTSIGBadSig) {
		t.Fatalf("error = %v, want ErrTSIGBadSig when the request MAC is omitted", err)
	}
}

// TestRFC8945_TSIGMustBeLastRecord pins §5.1. If a TSIG could sit anywhere but
// last, an attacker could append records after a validly signed one: the MAC
// covers everything before the TSIG and nothing after it, so those records
// would be accepted as authenticated.
func TestRFC8945_TSIGMustBeLastRecord(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	signed, _, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}

	// Append an extra record after the TSIG and bump ARCOUNT to match.
	extra := append([]byte{}, signed...)
	extra = append(extra, BuildPlainName("appended.example")...)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], TypeTXT)
	binary.BigEndian.PutUint16(hdr[2:4], ClassIN)
	binary.BigEndian.PutUint32(hdr[4:8], 300)
	binary.BigEndian.PutUint16(hdr[8:10], 1)
	extra = append(extra, hdr[:]...)
	extra = append(extra, 0x00)
	binary.BigEndian.PutUint16(extra[10:12], binary.BigEndian.Uint16(extra[10:12])+1)

	if _, _, err := TSIGVerify(extra, tsigKeyring(key), nil, now); !errors.Is(err, ErrTSIGNotLast) {
		t.Fatalf("error = %v, want ErrTSIGNotLast — records appended after the "+
			"TSIG are outside the MAC and must not be accepted", err)
	}
}

// TestRFC8945_UnsignedMessageRejected pins that an absent TSIG is a distinct,
// nameable condition rather than a generic parse failure — a server enforcing
// TSIG needs to tell "you didn't sign" from "your signature is wrong".
func TestRFC8945_UnsignedMessageRejected(t *testing.T) {
	if _, _, err := TSIGVerify(tsigTestMessage(t), tsigKeyring(tsigTestKey()), nil, time.Now()); !errors.Is(err, ErrTSIGNotSigned) {
		t.Fatalf("error = %v, want ErrTSIGNotSigned", err)
	}
}

// TestRFC8945_OriginalIDRestored pins §4.2's Original ID handling. A forwarder
// rewrites the transaction ID; the MAC still has to verify afterwards, which
// only works if verification restores the pre-rewrite value before hashing.
func TestRFC8945_OriginalIDRestored(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	signed, _, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}

	// Simulate a forwarder rewriting the header ID while leaving the TSIG's
	// Original ID field intact.
	rewritten := make([]byte, len(signed))
	copy(rewritten, signed)
	binary.BigEndian.PutUint16(rewritten[0:2], 0xBEEF)

	if _, _, err := TSIGVerify(rewritten, tsigKeyring(key), nil, now); err != nil {
		t.Fatalf("verification failed after a transaction-ID rewrite: %v — "+
			"Original ID (RFC 8945 §4.2) exists precisely so this works", err)
	}
}

// TestRFC8945_AlgorithmsSupported pins the algorithm table of §6, and that
// each produces a MAC of its digest length.
func TestRFC8945_AlgorithmsSupported(t *testing.T) {
	cases := map[string]int{
		TSIGHMACSHA1:   20,
		TSIGHMACSHA224: 28,
		TSIGHMACSHA256: 32,
		TSIGHMACSHA384: 48,
		TSIGHMACSHA512: 64,
	}
	now := time.Unix(1_700_000_000, 0)
	for alg, wantLen := range cases {
		t.Run(alg, func(t *testing.T) {
			key := TSIGKey{Name: "k.example", Algorithm: alg, Secret: []byte("secret")}
			signed, mac, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if len(mac) != wantLen {
				t.Errorf("MAC length = %d, want %d", len(mac), wantLen)
			}
			if _, _, err := TSIGVerify(signed, tsigKeyring(key), nil, now); err != nil {
				t.Errorf("verify: %v", err)
			}
		})
	}
}

// TestRFC8945_HMACMD5NotOffered pins the deliberate omission. HMAC-MD5 is the
// RFC 2845 default and a MAY in RFC 8945 §6; leaving it out means an operator
// cannot select it from a config file without understanding why it is gone.
func TestRFC8945_HMACMD5NotOffered(t *testing.T) {
	key := TSIGKey{Name: "k.example", Algorithm: "hmac-md5.sig-alg.reg.int", Secret: []byte("s")}
	if _, _, err := TSIGSign(tsigTestMessage(t), key, time.Now(), DefaultTSIGFudge, nil); !errors.Is(err, ErrTSIGBadAlgorithm) {
		t.Fatalf("error = %v, want ErrTSIGBadAlgorithm for HMAC-MD5", err)
	}
}

// TestRFC8945_KeyNameCaseInsensitive pins that the canonical (lowercased) form
// is what gets hashed. Without it, two operators who wrote the same key name
// with different capitalisation would fail to interoperate for a reason
// neither could see in their config.
func TestRFC8945_KeyNameCaseInsensitive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := TSIGKey{Name: "Key.Example", Algorithm: TSIGHMACSHA256, Secret: []byte("s")}
	verifier := TSIGKey{Name: "key.EXAMPLE", Algorithm: TSIGHMACSHA256, Secret: []byte("s")}

	signed, _, err := TSIGSign(tsigTestMessage(t), signer, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The keyring lookup is on the name as it appears on the wire; the
	// canonicalisation being tested is inside the MAC computation.
	keyring := func(name string) (TSIGKey, bool) { return verifier, true }
	if _, _, err := TSIGVerify(signed, keyring, nil, now); err != nil {
		t.Fatalf("case-differing key names failed to verify: %v", err)
	}
}

// TestRFC8945_TruncatedMACFloor pins §5.2.2.1. A MAC shorter than half the
// digest — or shorter than 10 octets — must be refused, since a short enough
// MAC is brute-forceable offline.
func TestRFC8945_TruncatedMACFloor(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	signed, _, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}

	rec, _, err := extractTSIG(signed)
	if err != nil {
		t.Fatalf("extractTSIG: %v", err)
	}

	// Re-sign with an 8-octet MAC — under both the half-digest (16) and the
	// absolute (10) floors.
	truncated := rec.MAC[:8]
	rdata := buildTSIGRData(TSIGRecord{
		Algorithm: rec.Algorithm, TimeSigned: rec.TimeSigned, Fudge: rec.Fudge,
		MAC: truncated, OriginalID: rec.OriginalID,
	})
	shortMsg := appendTSIGRR(tsigTestMessage(t), key.Name, rdata)

	if _, _, err := TSIGVerify(shortMsg, tsigKeyring(key), nil, now); !errors.Is(err, ErrTSIGBadTrunc) {
		t.Fatalf("error = %v, want ErrTSIGBadTrunc for an 8-octet MAC", err)
	}
}

// TestRFC8945_StreamChaining pins §5.3.1, the multi-message form used by
// AXFR. Each message's digest folds in the previous message's MAC, so the
// stream cannot be reordered or have messages removed from the middle.
func TestRFC8945_StreamChaining(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)

	_, mac1, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("sign first: %v", err)
	}

	second := tsigTestMessage(t)
	signed2, mac2, err := TSIGSignStream(second, key, now, DefaultTSIGFudge, mac1)
	if err != nil {
		t.Fatalf("sign second: %v", err)
	}

	if _, _, err := TSIGVerifyStream(signed2, key, mac1, now); err != nil {
		t.Fatalf("verify second with the correct prior MAC: %v", err)
	}

	// Presenting it as though it followed a different message must fail.
	if _, _, err := TSIGVerifyStream(signed2, key, mac2, now); !errors.Is(err, ErrTSIGBadSig) {
		t.Fatalf("error = %v, want ErrTSIGBadSig — a stream message must not "+
			"verify out of sequence", err)
	}
}

// TestRFC8945_TSIGClassAndTTL pins the §4.2 record-header constants. A TSIG
// with class IN or a non-zero TTL is malformed, and accepting one would mean
// hashing header values that differ from what the sender hashed.
func TestRFC8945_TSIGClassAndTTL(t *testing.T) {
	key := tsigTestKey()
	now := time.Unix(1_700_000_000, 0)
	signed, _, err := TSIGSign(tsigTestMessage(t), key, now, DefaultTSIGFudge, nil)
	if err != nil {
		t.Fatalf("TSIGSign: %v", err)
	}

	_, rrStart, err := extractTSIG(signed)
	if err != nil {
		t.Fatalf("extractTSIG: %v", err)
	}
	// Walk past the owner name to the class field.
	_, next, err := DecodeName(signed, rrStart)
	if err != nil {
		t.Fatalf("DecodeName: %v", err)
	}

	t.Run("class must be ANY", func(t *testing.T) {
		bad := make([]byte, len(signed))
		copy(bad, signed)
		binary.BigEndian.PutUint16(bad[next+2:next+4], ClassIN)
		if _, _, err := TSIGVerify(bad, tsigKeyring(key), nil, now); !errors.Is(err, ErrTSIGWrongClassOrTTL) {
			t.Fatalf("error = %v, want ErrTSIGWrongClassOrTTL", err)
		}
	})

	t.Run("TTL must be zero", func(t *testing.T) {
		bad := make([]byte, len(signed))
		copy(bad, signed)
		binary.BigEndian.PutUint32(bad[next+4:next+8], 300)
		if _, _, err := TSIGVerify(bad, tsigKeyring(key), nil, now); !errors.Is(err, ErrTSIGWrongClassOrTTL) {
			t.Fatalf("error = %v, want ErrTSIGWrongClassOrTTL", err)
		}
	})
}
