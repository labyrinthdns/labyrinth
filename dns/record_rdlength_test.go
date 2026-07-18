package dns

import (
	"bytes"
	"testing"
)

func TestUnpackRRNameRDataDoesNotReadPastRDLength(t *testing.T) {
	tests := []struct {
		name   string
		rrType uint16
		rdata  []byte
	}{
		{name: "NS", rrType: TypeNS, rdata: []byte{0xc0}},
		{name: "CNAME", rrType: TypeCNAME, rdata: []byte{0xc0}},
		{name: "PTR", rrType: TypePTR, rdata: []byte{0xc0}},
		{name: "DNAME", rrType: TypeDNAME, rdata: []byte{0xc0}},
		{name: "MX", rrType: TypeMX, rdata: []byte{0, 10, 0xc0}},
		{name: "SOA MNAME", rrType: TypeSOA, rdata: []byte{0xc0}},
		{name: "SOA RNAME", rrType: TypeSOA, rdata: []byte{0, 0xc0}},
		{name: "SRV", rrType: TypeSRV, rdata: []byte{0, 1, 0, 2, 0, 53, 0xc0}},
		{name: "RRSIG", rrType: TypeRRSIG, rdata: append(make([]byte, 18), 0xc0)},
		{name: "NSEC", rrType: TypeNSEC, rdata: []byte{0xc0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, offset := buildMsgWithAnswer(tt.rrType, tt.rdata)
			rdataEnd := len(msg)

			// This byte completes a compression pointer to the question name,
			// but it belongs to the following wire data, not this RR's RDATA.
			msg = append(msg, 0x0c)

			rr, next, err := UnpackRR(msg, offset)
			if err != nil {
				t.Fatalf("UnpackRR() error = %v", err)
			}
			if next != rdataEnd {
				t.Fatalf("next offset = %d, want RDATA end %d", next, rdataEnd)
			}
			if !bytes.Equal(rr.RData, tt.rdata) {
				t.Fatalf("RDATA = %v, want declared-window bytes %v", rr.RData, tt.rdata)
			}
		})
	}
}
