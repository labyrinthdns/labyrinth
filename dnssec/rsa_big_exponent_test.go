package dnssec

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// rsaWireKeyBigE encodes (e, n) in DNSKEY wire format (RFC 3110).
func rsaWireKeyBigE(e, n *big.Int) []byte {
	expBytes := e.Bytes()
	wire := []byte{byte(len(expBytes))}
	wire = append(wire, expBytes...)
	return append(wire, n.Bytes()...)
}

// genRSAKeyWithExponent builds a 1024-bit RSA key with an arbitrary public
// exponent; crypto/rsa.GenerateKey only ever uses 65537.
func genRSAKeyWithExponent(t *testing.T, e *big.Int) (n, d *big.Int) {
	t.Helper()
	one := big.NewInt(1)
	for {
		p, err := rand.Prime(rand.Reader, 512)
		if err != nil {
			t.Fatal(err)
		}
		q, err := rand.Prime(rand.Reader, 512)
		if err != nil {
			t.Fatal(err)
		}
		if p.Cmp(q) == 0 {
			continue
		}
		pm1 := new(big.Int).Sub(p, one)
		qm1 := new(big.Int).Sub(q, one)
		phi := new(big.Int).Mul(pm1, qm1)
		d = new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}
		return new(big.Int).Mul(p, q), d
	}
}

// signPKCS1v15Raw produces an RSASSA-PKCS1-v1_5 signature with math/big.
func signPKCS1v15Raw(n, d *big.Int, hashAlg crypto.Hash, data []byte) []byte {
	h := hashAlg.New()
	h.Write(data)
	hashed := h.Sum(nil)
	prefix := rsaDigestInfoPrefix[hashAlg]
	k := (n.BitLen() + 7) / 8
	tLen := len(prefix) + len(hashed)
	em := make([]byte, k)
	em[1] = 0x01
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:], prefix)
	copy(em[k-len(hashed):], hashed)
	m := new(big.Int).SetBytes(em)
	return new(big.Int).Exp(m, d, n).FillBytes(make([]byte, k))
}

// TestVerifyRSA_ExponentAbove2To31 pins the nic.istanbul / cdns.net false
// Bogus: their ZSKs publish E = 0x0100000001 (2^32+1). crypto/rsa rejects
// E > 2^31-1, so every RRSIG by those keys failed, the zones went Bogus and
// public-resolver fallback answered instead.
func TestVerifyRSA_ExponentAbove2To31(t *testing.T) {
	e := new(big.Int).SetBytes([]byte{0x01, 0x00, 0x00, 0x00, 0x01})
	n, d := genRSAKeyWithExponent(t, e)
	wire := rsaWireKeyBigE(e, n)
	data := []byte("signed rrset data")

	for _, tc := range []struct {
		alg  uint8
		hash crypto.Hash
	}{
		{dns.AlgRSASHA1, crypto.SHA1},
		{dns.AlgRSASHA256, crypto.SHA256},
		{dns.AlgRSASHA512, crypto.SHA512},
	} {
		sig := signPKCS1v15Raw(n, d, tc.hash, data)
		if err := verifyRSA(data, sig, wire, tc.alg); err != nil {
			t.Errorf("alg %d: valid signature rejected: %v", tc.alg, err)
		}
		if err := verifyRSA([]byte("tampered"), sig, wire, tc.alg); err != errVerifyFailed {
			t.Errorf("alg %d: tampered data: got %v, want errVerifyFailed", tc.alg, err)
		}
		bad := append([]byte(nil), sig...)
		bad[len(bad)-1] ^= 1
		if err := verifyRSA(data, bad, wire, tc.alg); err != errVerifyFailed {
			t.Errorf("alg %d: tampered sig: got %v, want errVerifyFailed", tc.alg, err)
		}
		if err := verifyRSA(data, sig[1:], wire, tc.alg); err != errVerifyFailed {
			t.Errorf("alg %d: short sig: got %v, want errVerifyFailed", tc.alg, err)
		}
	}
}

// TestVerifyRSABigExponent_MatchesCryptoRSA anchors the math/big path to
// crypto/rsa: a signature made by rsa.SignPKCS1v15 must verify.
func TestVerifyRSABigExponent_MatchesCryptoRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, hashAlg := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA512} {
		h := hashAlg.New()
		h.Write([]byte("data"))
		hashed := h.Sum(nil)
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, hashAlg, hashed)
		if err != nil {
			t.Fatal(err)
		}
		e := big.NewInt(int64(priv.E))
		if err := verifyRSABigExponent(priv.N, e, hashAlg, hashed, sig); err != nil {
			t.Errorf("%v: crypto/rsa signature rejected: %v", hashAlg, err)
		}
	}
}
