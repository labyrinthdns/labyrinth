package dnssec

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// ---------------------------------------------------------------------------
// ComputeNSEC3Hash: cover the name-without-trailing-dot branch (line 40-42).
// ---------------------------------------------------------------------------

func TestComputeNSEC3Hash_NoTrailingDot(t *testing.T) {
	// Without trailing dot, the code adds one before encoding.
	hash1, err := ComputeNSEC3Hash("example.com", 1, 0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hash2, err := ComputeNSEC3Hash("example.com.", 1, 0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if compareHashes(hash1, hash2) != 0 {
		t.Error("hashes should be identical regardless of trailing dot")
	}
}

// ---------------------------------------------------------------------------
// VerifyNSEC3Denial: cover the successful denial path (lines 107-119).
// ---------------------------------------------------------------------------

func TestVerifyNSEC3Denial_SuccessfulDenial(t *testing.T) {
	salt := []byte{0xAA}

	// Compute the hash for a name we want to prove doesn't exist
	targetHash, err := ComputeNSEC3Hash("nonexistent.example.com.", 1, 0, salt)
	if err != nil {
		t.Fatal(err)
	}

	// Build an NSEC3 record whose NextHash differs from the target hash
	// so coversHash returns true (hash != NextHash AND hashInRange returns true).
	// The coversHash/hashInRange logic checks hash != NextHash — so we
	// need a NextHash that is different from targetHash.
	differentHash := make([]byte, len(targetHash))
	copy(differentHash, targetHash)
	differentHash[0] ^= 0xFF // flip bits so it's different

	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 1,
			Flags:         0,
			Iterations:    0,
			Salt:          salt,
			NextHash:      differentHash,
			TypeBitMaps:   []uint16{dns.TypeA},
		},
	}

	denied, err := VerifyNSEC3Denial("nonexistent.example.com.", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Error("expected denial proof to succeed")
	}
}

func TestVerifyNSEC3Denial_NotDenied(t *testing.T) {
	salt := []byte{0xBB}

	// Compute hash and set NextHash to the same value so coversHash returns false.
	targetHash, err := ComputeNSEC3Hash("exists.example.com.", 1, 0, salt)
	if err != nil {
		t.Fatal(err)
	}

	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 1,
			Flags:         0,
			Iterations:    0,
			Salt:          salt,
			NextHash:      targetHash, // same as query hash -> coversHash returns false
			TypeBitMaps:   []uint16{dns.TypeA},
		},
	}

	denied, err := VerifyNSEC3Denial("exists.example.com.", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Error("expected denial proof to fail when hash matches NextHash")
	}
}

func TestVerifyNSEC3Denial_UnsupportedAlgorithm(t *testing.T) {
	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 2, // unsupported
			Flags:         0,
			Iterations:    5,
			Salt:          nil,
			NextHash:      []byte{0x01},
		},
	}
	_, err := VerifyNSEC3Denial("example.com.", records)
	if err == nil {
		t.Error("expected error for unsupported hash algorithm")
	}
}

// ---------------------------------------------------------------------------
// VerifyClosestEncloser: cover error paths and additional branches.
// ---------------------------------------------------------------------------

func TestVerifyClosestEncloser_TooManyIterations(t *testing.T) {
	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 1,
			Iterations:    200, // > MaxNSEC3Iterations
			Salt:          nil,
			NextHash:      []byte{0x01},
		},
	}
	_, err := VerifyClosestEncloser("test.example.com.", records)
	if err != errTooManyIterations {
		t.Errorf("expected errTooManyIterations, got %v", err)
	}
}

func TestVerifyClosestEncloser_NoRecords(t *testing.T) {
	_, err := VerifyClosestEncloser("test.example.com.", nil)
	if err != errNoNSEC3Records {
		t.Errorf("expected errNoNSEC3Records, got %v", err)
	}
}

func TestVerifyClosestEncloser_UnsupportedHashAlg(t *testing.T) {
	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 2, // unsupported
			Iterations:    0,
			Salt:          nil,
			NextHash:      []byte{0x01},
		},
	}
	_, err := VerifyClosestEncloser("test.example.com.", records)
	if err == nil {
		t.Error("expected error for unsupported hash algorithm")
	}
}

func TestVerifyClosestEncloser_NoTrailingDot(t *testing.T) {
	salt := []byte{0x01}
	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 1,
			Iterations:    0,
			Salt:          salt,
			NextHash:      []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	// Name without trailing dot
	encloser, err := VerifyClosestEncloser("does.not.exist.example.com", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if encloser == "" {
		t.Error("expected non-empty closest encloser")
	}
}

func TestVerifyClosestEncloser_ReturnsRootWhenAllCovered(t *testing.T) {
	salt := []byte{0x02}

	// Use a NextHash that matches the hash of everything, so coversHash returns true
	// for all parents. This forces the function to walk all the way to root.
	// Since coversHash checks hash != NextHash, we need a NextHash that is
	// never equal to any hash we compute. A single 0xFF byte (20 bytes expected)
	// would always differ. But we need all parents to be "covered" (coversHash true),
	// which means all parents' hashes differ from NextHash. Since hash != NextHash
	// is the main condition, and we know SHA-1 produces 20 byte hashes, using a
	// 1-byte NextHash means compareHashes will never return 0.
	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 1,
			Iterations:    0,
			Salt:          salt,
			NextHash:      []byte{0xFF}, // 1 byte - never matches 20-byte SHA-1 hash
		},
	}

	encloser, err := VerifyClosestEncloser("a.b.c.", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// When all parents are covered, the function returns "."
	if encloser != "." {
		t.Errorf("expected root '.', got %q", encloser)
	}
}

// ---------------------------------------------------------------------------
// VerifyNSEC3DenialFull: cover too-many-iterations and not-denied paths.
// ---------------------------------------------------------------------------

func TestVerifyNSEC3DenialFull_TooManyIterations(t *testing.T) {
	records := []NSEC3RecordWithOwner{
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1,
				Iterations:    200,
				Salt:          nil,
				NextHash:      []byte{0x01},
			},
			OwnerHash: []byte{0x00},
		},
	}
	_, err := VerifyNSEC3DenialFull("example.com.", records)
	if err != errTooManyIterations {
		t.Errorf("expected errTooManyIterations, got %v", err)
	}
}

func TestVerifyNSEC3DenialFull_UnsupportedAlg(t *testing.T) {
	records := []NSEC3RecordWithOwner{
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 2,
				Iterations:    0,
				Salt:          nil,
				NextHash:      []byte{0x01},
			},
			OwnerHash: []byte{0x00},
		},
	}
	_, err := VerifyNSEC3DenialFull("example.com.", records)
	if err == nil {
		t.Error("expected error for unsupported hash algorithm")
	}
}

func TestVerifyNSEC3DenialFull_NotDenied(t *testing.T) {
	salt := []byte{0xCC}
	targetHash, err := ComputeNSEC3Hash("exists.example.com.", 1, 0, salt)
	if err != nil {
		t.Fatal(err)
	}

	// Place the target hash outside the range [owner, next]
	ownerHash := make([]byte, len(targetHash))
	copy(ownerHash, targetHash)
	ownerHash[len(ownerHash)-1] = targetHash[len(targetHash)-1] + 10
	nextHash := make([]byte, len(targetHash))
	copy(nextHash, targetHash)
	nextHash[len(nextHash)-1] = targetHash[len(targetHash)-1] + 20

	records := []NSEC3RecordWithOwner{
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1,
				Iterations:    0,
				Salt:          salt,
				NextHash:      nextHash,
			},
			OwnerHash: ownerHash,
		},
	}

	denied, err := VerifyNSEC3DenialFull("exists.example.com.", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Error("expected denial to be false when hash is outside range")
	}
}

// ---------------------------------------------------------------------------
// validateDenialResponse: comprehensive tests for all branches.
// ---------------------------------------------------------------------------

// buildNSEC3RData constructs NSEC3 RDATA for testing.
func buildNSEC3RData(hashAlg uint8, flags uint8, iterations uint16, salt, nextHash []byte, typeBitmaps []uint16) []byte {
	var rdata []byte
	rdata = append(rdata, hashAlg, flags)
	iterBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(iterBytes, iterations)
	rdata = append(rdata, iterBytes...)

	rdata = append(rdata, byte(len(salt)))
	rdata = append(rdata, salt...)

	rdata = append(rdata, byte(len(nextHash)))
	rdata = append(rdata, nextHash...)

	// Encode type bitmaps
	if len(typeBitmaps) > 0 {
		// Simple encoding for window 0 (types < 256)
		maxType := uint16(0)
		for _, t := range typeBitmaps {
			if t > maxType {
				maxType = t
			}
		}
		bitmapLen := int(maxType/8) + 1
		bitmap := make([]byte, bitmapLen)
		for _, t := range typeBitmaps {
			bitmap[t/8] |= 0x80 >> (t % 8)
		}
		rdata = append(rdata, 0)                // window block 0
		rdata = append(rdata, byte(bitmapLen))   // bitmap length
		rdata = append(rdata, bitmap...)
	}
	return rdata
}

func TestValidateDenialResponse_InsecureNoRRSIG(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	// NXDOMAIN response with authority but no RRSIG -> Insecure
	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			{
				Name:  "example.com.",
				Type:  dns.TypeSOA,
				Class: dns.ClassIN,
				TTL:   600,
				RData: []byte{0x00}, // minimal SOA
			},
		},
	}

	result := v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("got %v, want Insecure", result)
	}
}

func TestValidateDenialResponse_BogusTimeInvalid(t *testing.T) {
	s := newFullTestSetup(t)

	// Build an RRSIG for SOA that covers the authority section, but with invalid time
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeSOA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  1, // expired
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}

	signedData := buildSignedData([]dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
	}, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	result := s.v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Bogus {
		t.Errorf("got %v, want Bogus (expired RRSIG)", result)
	}
}

func TestValidateDenialResponse_IndeterminateFetchDNSKEYError(t *testing.T) {
	// No DNSKEY responses configured, so fetch will fail
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeSOA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      12345,
		SignerName:  "example.com.",
	}

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	result := v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Indeterminate {
		t.Errorf("got %v, want Indeterminate (DNSKEY fetch error)", result)
	}
}

func TestValidateDenialResponse_IndeterminateNoMatchingDNSKEY(t *testing.T) {
	// DNSKEY response exists but with wrong key tag
	zskRData := encodeDNSKEYRData(256, 3, dns.AlgED25519, make([]byte, 32))
	mq := &mockQuerier{
		responses: map[string]*dns.Message{
			"example.com.|48": {
				Answers: []dns.ResourceRecord{
					{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: zskRData},
				},
			},
		},
	}
	v := NewValidator(mq, nil)

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeSOA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      65535, // won't match any DNSKEY
		SignerName:  "example.com.",
	}

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	result := v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Indeterminate {
		t.Errorf("got %v, want Indeterminate (no matching DNSKEY)", result)
	}
}

func TestValidateDenialResponse_BogusSignatureFailure(t *testing.T) {
	s := newFullTestSetup(t)

	// Add ZSK to the example.com DNSKEY response
	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeSOA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}
	// Wrong signature (random bytes)
	rrsig.Signature = make([]byte, 64)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	result := s.v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Bogus {
		t.Errorf("got %v, want Bogus (wrong signature)", result)
	}
}

func TestValidateDenialResponse_SecureWithSOAOnly(t *testing.T) {
	s := newFullTestSetup(t)

	// Set up DNSKEY for example.com
	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	soaRR := dns.ResourceRecord{
		Name: ".", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeSOA,
		Algorithm:   dns.AlgED25519,
		Labels:      0,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  ".",
	}
	signedData := buildSignedData([]dns.ResourceRecord{soaRR}, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			soaRR,
			{Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	result := s.v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Secure {
		t.Errorf("got %v, want Secure (valid SOA+RRSIG)", result)
	}
}

func TestValidateDenialResponse_SecureWithNSEC3DenialProof(t *testing.T) {
	s := newFullTestSetup(t)

	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	salt := []byte{0xAA}
	// Compute hash of the query name
	targetHash, err := ComputeNSEC3Hash("nonexist.example.com.", 1, 0, salt)
	if err != nil {
		t.Fatal(err)
	}
	// Build NSEC3 with NextHash different from targetHash
	differentHash := make([]byte, len(targetHash))
	copy(differentHash, targetHash)
	differentHash[0] ^= 0xFF

	nsec3RData := buildNSEC3RData(1, 0, 0, salt, differentHash, []uint16{dns.TypeA})
	nsec3RR := dns.ResourceRecord{
		Name: ".", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: nsec3RData,
	}

	// Sign the NSEC3 records
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC3,
		Algorithm:   dns.AlgED25519,
		Labels:      0,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  ".",
	}
	signedData := buildSignedData([]dns.ResourceRecord{nsec3RR}, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			nsec3RR,
			{Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	result := s.v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Secure {
		t.Errorf("got %v, want Secure (NSEC3 denial proof)", result)
	}
}

func TestValidateDenialResponse_NSEC3DenialError(t *testing.T) {
	s := newFullTestSetup(t)

	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	// Build NSEC3 with unsupported hash algorithm to trigger error in VerifyNSEC3Denial
	nsec3RData := buildNSEC3RData(2, 0, 0, nil, []byte{0x01}, nil) // alg=2 unsupported
	nsec3RR := dns.ResourceRecord{
		Name: ".", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: nsec3RData,
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC3,
		Algorithm:   dns.AlgED25519,
		Labels:      0,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  ".",
	}
	signedData := buildSignedData([]dns.ResourceRecord{nsec3RR}, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			nsec3RR,
			{Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	result := s.v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Indeterminate {
		t.Errorf("got %v, want Indeterminate (NSEC3 denial error)", result)
	}
}

func TestValidateDenialResponse_NSEC3DenialInconclusive(t *testing.T) {
	s := newFullTestSetup(t)

	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	// Build NSEC3 where the hash matches NextHash (so coversHash returns false)
	salt := []byte{0xDD}
	targetHash, err := ComputeNSEC3Hash("nonexist.example.com.", 1, 0, salt)
	if err != nil {
		t.Fatal(err)
	}

	nsec3RData := buildNSEC3RData(1, 0, 0, salt, targetHash, nil) // NextHash == target -> not denied
	nsec3RR := dns.ResourceRecord{
		Name: ".", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: nsec3RData,
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC3,
		Algorithm:   dns.AlgED25519,
		Labels:      0,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  ".",
	}
	signedData := buildSignedData([]dns.ResourceRecord{nsec3RR}, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			nsec3RR,
			{Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	// Even though NSEC3 is inconclusive, RRSIG validated. Since there's no
	// SOA RRSIG, it should return Insecure.
	result := s.v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("got %v, want Insecure (NSEC3 inconclusive, no SOA RRSIG)", result)
	}
}

func TestValidateDenialResponse_MalformedRRSIG(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: []byte{0x01, 0x02}}, // too short
		},
	}

	// Malformed RRSIG is skipped, no valid RRSIGs found -> Insecure
	result := v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("got %v, want Insecure (malformed RRSIG skipped)", result)
	}
}

func TestValidateDenialResponse_MalformedNSEC3(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
			{Name: "example.com.", Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 300, RData: []byte{0x01}}, // too short
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: []byte{0x01, 0x02}}, // also malformed
		},
	}

	// All records malformed -> skipped -> Insecure
	result := v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("got %v, want Insecure (all records malformed)", result)
	}
}

func TestValidateDenialResponse_RRSIGSkipsNonNSEC3NonSOA(t *testing.T) {
	s := newFullTestSetup(t)

	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	soaRR := dns.ResourceRecord{
		Name: ".", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00},
	}

	// Create RRSIG for SOA (valid)
	soaRRSIG := &dns.RRSIGRecord{
		TypeCovered: dns.TypeSOA,
		Algorithm:   dns.AlgED25519,
		Labels:      0,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  ".",
	}
	signedData := buildSignedData([]dns.ResourceRecord{soaRR}, soaRRSIG)
	soaRRSIG.Signature = ed25519.Sign(s.privKey, signedData)

	// Also create an RRSIG for NS (should be skipped in the loop)
	nsRRSIG := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNS,
		Algorithm:   dns.AlgED25519,
		Labels:      0,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  ".",
	}
	nsRRSIG.Signature = make([]byte, 64) // dummy

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			soaRR,
			{Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(nsRRSIG)},
			{Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(soaRRSIG)},
		},
	}

	result := s.v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Secure {
		t.Errorf("got %v, want Secure (NS RRSIG skipped, SOA RRSIG validated)", result)
	}
}

func TestValidateDenialResponse_NODATAEmptyAnswers(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	// NODATA: RCODE=0, empty answers, with authority
	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNoError).Build(),
		},
		Answers: []dns.ResourceRecord{}, // empty -> triggers denial path
		Authority: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
		},
	}

	result := v.ValidateResponse(resp, "example.com.", dns.TypeAAAA)
	if result != Insecure {
		t.Errorf("got %v, want Insecure (no RRSIG in authority)", result)
	}
}

// ---------------------------------------------------------------------------
// ValidateResponse: cover NXDOMAIN/NODATA entry from line 92-94 via rcode.
// Also covers the "authorityRRs" branch in validateDenialResponse
// (line 430-431: other RR types are collected into authorityRRs).
// ---------------------------------------------------------------------------

func TestValidateDenialResponse_OtherAuthorityRRsCollected(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 600, RData: []byte{0x00}},
			{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
		},
	}

	result := v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("got %v, want Insecure", result)
	}
}

// ---------------------------------------------------------------------------
// ValidateResponse RRSIG with no RRset for TypeCovered but entry from denial.
// Line 97: The NOERROR with non-empty answers but rcode != NXDOMAIN should
// not enter denial. This is separate from empty answers.
// ---------------------------------------------------------------------------

func TestValidateResponse_NXDomainTriggersValidateDenial(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	// Non-empty answers but RCODE is NXDOMAIN — should still go into denial path
	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Answers:   nil,
		Authority: nil,
	}

	result := v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("got %v, want Insecure (NXDOMAIN with no authority)", result)
	}
}

// Test the inception > now branch (RRSIG not yet valid)
func TestValidateDenialResponse_BogusNotYetValidInception(t *testing.T) {
	s := newFullTestSetup(t)

	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeSOA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0xFFFFFFFE, // far in the future
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}
	rrsig.Signature = make([]byte, 64)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: []byte{0x00}},
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	result := s.v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	if result != Bogus {
		t.Errorf("got %v, want Bogus (RRSIG inception in future)", result)
	}
}

// Test the RRSIGTypeCovered != NSEC3 and != SOA continue branch
// ---------------------------------------------------------------------------
// VerifyClosestEncloser: cover the !covered branch returning parent (line 203-205)
// ---------------------------------------------------------------------------

func TestVerifyClosestEncloser_ParentNotCovered(t *testing.T) {
	salt := []byte{0x03}

	// We need NSEC3 records where some parent's hash is NOT covered by any gap.
	// coversHash checks hash != NextHash AND hashInRange (which also checks
	// hash != NextHash). If we set NextHash to a value that equals the parent's
	// hash, coversHash returns false. But computing the exact parent hash is
	// complex. Instead, we can use an empty NextHash (length 0) which means
	// compareHashes with a 20-byte SHA1 hash will always return != 0, but
	// hashInRange also requires hash != NextHash, which is true. So coversHash
	// returns true. That means the parent IS covered.
	//
	// To make the parent NOT covered, we need coversHash to return false.
	// coversHash returns false when hash == NextHash (first condition fails).
	// So we'd need NextHash to equal the parent hash exactly. Let's compute it.

	// For qname = "sub.example.com.", parent = "example.com."
	parentHash, err := ComputeNSEC3Hash("example.com.", 1, 0, salt)
	if err != nil {
		t.Fatal(err)
	}

	// Set NextHash = parentHash so coversHash returns false for the parent
	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 1,
			Iterations:    0,
			Salt:          salt,
			NextHash:      parentHash,
		},
	}

	encloser, err := VerifyClosestEncloser("sub.example.com.", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The parent "example.com." has hash == NextHash, so !covered -> return "example.com."
	if encloser != "example.com." {
		t.Errorf("expected closest encloser 'example.com.', got %q", encloser)
	}
}

// ---------------------------------------------------------------------------
// ValidateResponse: cover the non-denial empty-answers path (line 97-99)
// This is when RCODE is not NXDOMAIN and not NOERROR, but answers is empty.
// E.g., SERVFAIL (rcode=2) with empty answers.
// ---------------------------------------------------------------------------

func TestValidateResponse_NonDenialEmptyAnswers(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	// SERVFAIL response: rcode=2 (not NXDOMAIN, not NOERROR), empty answers
	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(2).Build(), // SERVFAIL
		},
		Answers: nil,
	}

	result := v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Insecure {
		t.Errorf("got %v, want Insecure (SERVFAIL with empty answers)", result)
	}
}

func TestValidateDenialResponse_RRSIGForEmptyRRSet(t *testing.T) {
	s := newFullTestSetup(t)

	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	// RRSIG covering NSEC3, but no matching NSEC3 in authority -> rrset empty, continue
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC3,
		Algorithm:   dns.AlgED25519,
		Labels:      0,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  ".",
	}
	rrsig.Signature = make([]byte, 64)

	resp := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
		Authority: []dns.ResourceRecord{
			// No NSEC3 here, just the RRSIG covering NSEC3
			{Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
		},
	}

	result := s.v.ValidateResponse(resp, "nonexist.example.com.", dns.TypeA)
	// No NSEC3 in authority, rrset empty -> loop continues, no SOA RRSIG found -> Insecure
	if result != Insecure {
		t.Errorf("got %v, want Insecure (RRSIG with empty rrset)", result)
	}
}
