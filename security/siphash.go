package security

import "encoding/binary"

// SipHash24 computes a SipHash-2-4 MAC for the given message using a 128-bit key.
// Used by RFC 9018 for DNS server cookie generation.
func SipHash24(key [16]byte, msg []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])

	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	// Process full 8-byte blocks.
	blocks := len(msg) / 8
	for i := 0; i < blocks; i++ {
		m := binary.LittleEndian.Uint64(msg[i*8:])
		v3 ^= m
		sipRound(&v0, &v1, &v2, &v3)
		sipRound(&v0, &v1, &v2, &v3)
		v0 ^= m
	}

	// Last block: remaining bytes + length in top byte.
	var last uint64
	remaining := msg[blocks*8:]
	for i, b := range remaining {
		last |= uint64(b) << (uint(i) * 8)
	}
	last |= uint64(len(msg)%256) << 56

	v3 ^= last
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	v0 ^= last

	// Finalization: 4 rounds.
	v2 ^= 0xff
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)

	return v0 ^ v1 ^ v2 ^ v3
}

func sipRound(v0, v1, v2, v3 *uint64) {
	*v0 += *v1
	*v1 = rotl64(*v1, 13)
	*v1 ^= *v0
	*v0 = rotl64(*v0, 32)
	*v2 += *v3
	*v3 = rotl64(*v3, 16)
	*v3 ^= *v2
	*v2 += *v1
	*v1 = rotl64(*v1, 17)
	*v1 ^= *v2
	*v2 = rotl64(*v2, 32)
	*v0 += *v3
	*v3 = rotl64(*v3, 21)
	*v3 ^= *v0
}

func rotl64(x uint64, b uint) uint64 {
	return (x << b) | (x >> (64 - b))
}
