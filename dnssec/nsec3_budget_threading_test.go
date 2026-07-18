package dnssec

import (
	"strings"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func nsec3SingleOwnerProof(t *testing.T, owner string) []NSEC3RecordWithOwner {
	t.Helper()

	ownerHash, err := ComputeNSEC3Hash(owner, 1, 0, nil)
	if err != nil {
		t.Fatalf("ComputeNSEC3Hash(%q) error = %v", owner, err)
	}
	return []NSEC3RecordWithOwner{{
		OwnerHash: ownerHash,
		NSEC3Record: dns.NSEC3Record{
			HashAlgorithm: 1,
			NextHash:      append([]byte(nil), ownerHash...),
			TypeBitMaps:   []uint16{dns.TypeNS, dns.TypeSOA},
		},
	}}
}

func TestVerifyNSEC3Denial5155ThreadsHashBudgetThroughProof(t *testing.T) {
	records := nsec3SingleOwnerProof(t, "example.com.")

	tests := []struct {
		name        string
		qname       string
		max         int
		wantErrStep string
		wantDenied  bool
		wantUsed    int
	}{
		{
			name:        "ancestor walk",
			qname:       "deep.missing.example.com",
			max:         1,
			wantErrStep: "ancestor",
			wantUsed:    1,
		},
		{
			name:        "next closer",
			qname:       "missing.example.com",
			max:         1,
			wantErrStep: "next-closer",
			wantUsed:    1,
		},
		{
			name:        "wildcard",
			qname:       "missing.example.com",
			max:         2,
			wantErrStep: "wildcard",
			wantUsed:    2,
		},
		{
			name:       "complete proof within budget",
			qname:      "missing.example.com",
			max:        3,
			wantDenied: true,
			wantUsed:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			budget := &nsec3HashBudget{max: tt.max}
			denied, err := VerifyNSEC3Denial5155(
				tt.qname, dns.TypeA, dns.RCodeNXDomain, records, budget,
			)

			if tt.wantErrStep == "" {
				if err != nil {
					t.Fatalf("VerifyNSEC3Denial5155() error = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErrStep) || !strings.Contains(err.Error(), "budget exhausted") {
				t.Fatalf("VerifyNSEC3Denial5155() error = %v, want budget exhaustion during %s hashing", err, tt.wantErrStep)
			}
			if denied != tt.wantDenied {
				t.Errorf("VerifyNSEC3Denial5155() denied = %v, want %v", denied, tt.wantDenied)
			}
			if budget.used != tt.wantUsed {
				t.Errorf("budget used = %d, want %d", budget.used, tt.wantUsed)
			}
		})
	}
}
