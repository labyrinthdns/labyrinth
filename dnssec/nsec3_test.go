package dnssec

import (
	"encoding/hex"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestComputeNSEC3Hash_SHA1(t *testing.T) {
	// Test vector from RFC 5155 Appendix A:
	// owner = "example" with algorithm=1, iterations=12, salt=aabbccdd
	salt, _ := hex.DecodeString("aabbccdd")

	hash, err := ComputeNSEC3Hash("example.", 1, 12, salt)
	if err != nil {
		t.Fatalf("ComputeNSEC3Hash error: %v", err)
	}
	if len(hash) == 0 {
		t.Fatal("expected non-empty hash")
	}
	// The hash should be 20 bytes (SHA-1 output)
	if len(hash) != 20 {
		t.Fatalf("expected 20-byte hash, got %d", len(hash))
	}
}

func TestComputeNSEC3Hash_UnsupportedAlgorithm(t *testing.T) {
	_, err := ComputeNSEC3Hash("example.com.", 2, 0, nil)
	if err != errUnsupportedHashAlg {
		t.Errorf("expected errUnsupportedHashAlg, got %v", err)
	}
}

func TestComputeNSEC3Hash_TooManyIterations(t *testing.T) {
	_, err := ComputeNSEC3Hash("example.com.", 1, 200, nil)
	if err != errTooManyIterations {
		t.Errorf("expected errTooManyIterations, got %v", err)
	}
}

func TestComputeNSEC3Hash_MaxIterations(t *testing.T) {
	// Exactly at the limit should work
	_, err := ComputeNSEC3Hash("example.com.", 1, MaxNSEC3Iterations, nil)
	if err != nil {
		t.Errorf("expected no error at max iterations, got %v", err)
	}
}

func TestComputeNSEC3Hash_EmptySalt(t *testing.T) {
	hash, err := ComputeNSEC3Hash("example.com.", 1, 0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hash) != 20 {
		t.Fatalf("expected 20-byte hash, got %d", len(hash))
	}
}

func TestComputeNSEC3Hash_DifferentNames(t *testing.T) {
	hash1, err := ComputeNSEC3Hash("example.com.", 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := ComputeNSEC3Hash("other.com.", 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	if compareHashes(hash1, hash2) == 0 {
		t.Error("different names should produce different hashes")
	}
}

func TestComputeNSEC3Hash_CaseInsensitive(t *testing.T) {
	hash1, err := ComputeNSEC3Hash("Example.COM.", 1, 5, []byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := ComputeNSEC3Hash("example.com.", 1, 5, []byte{0x01})
	if err != nil {
		t.Fatal(err)
	}

	if compareHashes(hash1, hash2) != 0 {
		t.Error("hash should be case-insensitive")
	}
}

func TestNSEC3HashToString(t *testing.T) {
	hash := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	s := NSEC3HashToString(hash)
	if s == "" {
		t.Fatal("expected non-empty string")
	}

	// Round-trip
	decoded, err := nsec3StringToHash(s)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if compareHashes(hash, decoded) != 0 {
		t.Error("round-trip failed")
	}
}

func TestCompareHashes(t *testing.T) {
	tests := []struct {
		a, b []byte
		want int
	}{
		{[]byte{1, 2, 3}, []byte{1, 2, 3}, 0},
		{[]byte{1, 2, 3}, []byte{1, 2, 4}, -1},
		{[]byte{1, 2, 4}, []byte{1, 2, 3}, 1},
		{[]byte{1, 2}, []byte{1, 2, 3}, -1},
		{[]byte{1, 2, 3}, []byte{1, 2}, 1},
		{nil, nil, 0},
	}

	for _, tt := range tests {
		got := compareHashes(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareHashes(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCoversHashFull(t *testing.T) {
	tests := []struct {
		name      string
		owner     []byte
		next      []byte
		hash      []byte
		want      bool
	}{
		{
			name:  "hash in normal range",
			owner: []byte{0x10},
			next:  []byte{0x30},
			hash:  []byte{0x20},
			want:  true,
		},
		{
			name:  "hash below range",
			owner: []byte{0x10},
			next:  []byte{0x30},
			hash:  []byte{0x05},
			want:  false,
		},
		{
			name:  "hash above range",
			owner: []byte{0x10},
			next:  []byte{0x30},
			hash:  []byte{0x40},
			want:  false,
		},
		{
			name:  "hash equals owner (not covered)",
			owner: []byte{0x10},
			next:  []byte{0x30},
			hash:  []byte{0x10},
			want:  false,
		},
		{
			name:  "hash equals next (not covered)",
			owner: []byte{0x10},
			next:  []byte{0x30},
			hash:  []byte{0x30},
			want:  false,
		},
		{
			name:  "wrap-around: hash above owner",
			owner: []byte{0xF0},
			next:  []byte{0x10},
			hash:  []byte{0xF5},
			want:  true,
		},
		{
			name:  "wrap-around: hash below next",
			owner: []byte{0xF0},
			next:  []byte{0x10},
			hash:  []byte{0x05},
			want:  true,
		},
		{
			name:  "wrap-around: hash in middle (not covered)",
			owner: []byte{0xF0},
			next:  []byte{0x10},
			hash:  []byte{0x80},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coversHashFull(tt.owner, tt.next, tt.hash)
			if got != tt.want {
				t.Errorf("coversHashFull(%x, %x, %x) = %v, want %v",
					tt.owner, tt.next, tt.hash, got, tt.want)
			}
		})
	}
}

func TestVerifyNSEC3DenialFull(t *testing.T) {
	// Create NSEC3 records that cover a gap containing our test name's hash
	salt := []byte{0xAA, 0xBB}

	// Compute hash for a name we want to prove doesn't exist
	targetHash, err := ComputeNSEC3Hash("nonexistent.example.com.", 1, 0, salt)
	if err != nil {
		t.Fatal(err)
	}

	// Create an NSEC3 record whose range covers the target hash
	ownerHash := make([]byte, len(targetHash))
	copy(ownerHash, targetHash)
	ownerHash[len(ownerHash)-1] = targetHash[len(targetHash)-1] - 5

	nextHash := make([]byte, len(targetHash))
	copy(nextHash, targetHash)
	nextHash[len(nextHash)-1] = targetHash[len(targetHash)-1] + 5

	records := []NSEC3RecordWithOwner{
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1,
				Flags:         0,
				Iterations:    0,
				Salt:          salt,
				NextHash:      nextHash,
				TypeBitMaps:   []uint16{dns.TypeA, dns.TypeAAAA},
			},
			OwnerHash: ownerHash,
		},
	}

	denied, err := VerifyNSEC3DenialFull("nonexistent.example.com.", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Error("expected denial proof to succeed")
	}
}

func TestVerifyNSEC3DenialFull_NoRecords(t *testing.T) {
	_, err := VerifyNSEC3DenialFull("example.com.", nil)
	if err != errNoNSEC3Records {
		t.Errorf("expected errNoNSEC3Records, got %v", err)
	}
}

func TestVerifyNSEC3Denial_NoRecords(t *testing.T) {
	_, err := VerifyNSEC3Denial("example.com.", nil)
	if err != errNoNSEC3Records {
		t.Errorf("expected errNoNSEC3Records, got %v", err)
	}
}

func TestVerifyNSEC3Denial_TooManyIterations(t *testing.T) {
	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 1,
			Iterations:    200,
			Salt:          nil,
			NextHash:      []byte{0x01},
		},
	}
	_, err := VerifyNSEC3Denial("example.com.", records)
	if err != errTooManyIterations {
		t.Errorf("expected errTooManyIterations, got %v", err)
	}
}

func TestHasType(t *testing.T) {
	nsec3 := &dns.NSEC3Record{
		TypeBitMaps: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX},
	}

	if !HasType(nsec3, dns.TypeA) {
		t.Error("expected TypeA to be present")
	}
	if !HasType(nsec3, dns.TypeAAAA) {
		t.Error("expected TypeAAAA to be present")
	}
	if HasType(nsec3, dns.TypeNS) {
		t.Error("expected TypeNS to be absent")
	}
}

func TestNameToWire(t *testing.T) {
	tests := []struct {
		name string
		want []byte
	}{
		{".", []byte{0}},
		{"com.", []byte{3, 'c', 'o', 'm', 0}},
		{"example.com.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
	}

	for _, tt := range tests {
		got := nameToWire(tt.name)
		if len(got) != len(tt.want) {
			t.Errorf("nameToWire(%q) length = %d, want %d", tt.name, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("nameToWire(%q)[%d] = %d, want %d", tt.name, i, got[i], tt.want[i])
				break
			}
		}
	}
}

func TestVerifyClosestEncloser(t *testing.T) {
	salt := []byte{0x01}

	// Create NSEC3 records with gaps that cover child hashes but not parent
	records := []*dns.NSEC3Record{
		{
			HashAlgorithm: 1,
			Iterations:    0,
			Salt:          salt,
			NextHash:      []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	encloser, err := VerifyClosestEncloser("does.not.exist.example.com.", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should find some ancestor as closest encloser
	if encloser == "" {
		t.Error("expected non-empty closest encloser")
	}
}
