package dns

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ECSOption represents an EDNS Client Subnet option (RFC 7871, option code 8).
type ECSOption struct {
	Family          uint16 // 1=IPv4, 2=IPv6
	SourcePrefixLen uint8
	ScopePrefixLen  uint8
	Address         net.IP
}

// ParseECS parses an EDNS Client Subnet option from EDNS0 option data.
func ParseECS(data []byte) (*ECSOption, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("dns: ECS option data too short: %d bytes", len(data))
	}

	ecs := &ECSOption{
		Family:          binary.BigEndian.Uint16(data[0:2]),
		SourcePrefixLen: data[2],
		ScopePrefixLen:  data[3],
	}

	addrBytes := data[4:]

	switch ecs.Family {
	case 1: // IPv4
		if ecs.SourcePrefixLen > 32 {
			return nil, fmt.Errorf("dns: ECS IPv4 source prefix length %d > 32", ecs.SourcePrefixLen)
		}
		ip := make(net.IP, 4)
		copy(ip, addrBytes)
		ecs.Address = ip
	case 2: // IPv6
		if ecs.SourcePrefixLen > 128 {
			return nil, fmt.Errorf("dns: ECS IPv6 source prefix length %d > 128", ecs.SourcePrefixLen)
		}
		ip := make(net.IP, 16)
		copy(ip, addrBytes)
		ecs.Address = ip
	default:
		return nil, fmt.Errorf("dns: ECS unsupported address family %d", ecs.Family)
	}

	return ecs, nil
}

// BuildECS constructs an EDNS Client Subnet option (RFC 7871, option code 8).
func BuildECS(ecs *ECSOption) EDNSOption {
	// Calculate the number of address bytes needed:
	// ceil(SourcePrefixLen / 8)
	addrLen := (int(ecs.SourcePrefixLen) + 7) / 8

	data := make([]byte, 4+addrLen)
	binary.BigEndian.PutUint16(data[0:2], ecs.Family)
	data[2] = ecs.SourcePrefixLen
	data[3] = ecs.ScopePrefixLen

	if ecs.Address != nil && addrLen > 0 {
		var addr []byte
		switch ecs.Family {
		case 1:
			addr = ecs.Address.To4()
		case 2:
			addr = ecs.Address.To16()
		}
		if addr != nil {
			copy(data[4:], addr[:addrLen])
		}
	}

	// Zero out trailing bits in the last byte per RFC 7871
	if addrLen > 0 {
		trailingBits := uint(addrLen*8) - uint(ecs.SourcePrefixLen)
		if trailingBits > 0 {
			mask := byte(0xFF << trailingBits)
			data[4+addrLen-1] &= mask
		}
	}

	return EDNSOption{
		Code: EDNSOptionCodeECS,
		Data: data,
	}
}

// ExtractECSFromOPT walks the OPT record options and returns the first
// EDNS Client Subnet option found, or nil if none is present. Parse errors
// are reported so callers can FORMERR-fail a malformed option per RFC 7871
// §6 (unrecognized FAMILY → SERVFAIL). Missing-ECS is the common case and
// returns (nil, nil).
func ExtractECSFromOPT(opt *EDNS0) (*ECSOption, error) {
	if opt == nil {
		return nil, nil
	}
	for _, o := range opt.Options {
		if o.Code != EDNSOptionCodeECS {
			continue
		}
		return ParseECS(o.Data)
	}
	return nil, nil
}

// CacheKey returns the canonical string used to key ECS-scoped cache
// entries: "<address>/<prefix>" where address is truncated to prefix.
// Returns "" when ecs is nil or SourcePrefixLen is 0 (global scope), so
// callers can distinguish global from ECS-scoped entries by emptiness.
func (ecs *ECSOption) CacheKey() string {
	if ecs == nil || ecs.SourcePrefixLen == 0 {
		return ""
	}
	truncated := TruncateIP(ecs.Address, ecs.SourcePrefixLen)
	return truncated.String() + "/" + itoaECS(int(ecs.SourcePrefixLen))
}

func itoaECS(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// TruncateIP truncates an IP address to the given prefix length,
// zeroing out any bits beyond the prefix.
func TruncateIP(ip net.IP, prefixLen uint8) net.IP {
	var addr []byte
	if v4 := ip.To4(); v4 != nil {
		addr = make(net.IP, 4)
		copy(addr, v4)
	} else {
		addr = make(net.IP, 16)
		copy(addr, ip.To16())
	}

	// Zero bits beyond prefixLen
	byteIndex := int(prefixLen) / 8
	bitIndex := uint(prefixLen) % 8

	if byteIndex < len(addr) {
		if bitIndex > 0 {
			mask := byte(0xFF << (8 - bitIndex))
			addr[byteIndex] &= mask
			byteIndex++
		}
		for i := byteIndex; i < len(addr); i++ {
			addr[i] = 0
		}
	}

	return addr
}
