package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNTAInstall_OversizedReasonRejected pins the v0.8.4 gate: the
// NTA install handler must refuse a `reason` field longer than
// MaxNTAReasonBytes. Without the cap, a single authenticated POST
// could store ~1 MiB of reason text (the body cap); with
// MaxNTAEntries=10000 (v0.7.61) and the NTA store consulted on every
// validation decision, an attacker who could re-install distinct
// zones 10k times would have planted ~10 GiB of validator-resident
// reason payload — a memory-amplification surface even though it
// passes the per-request body cap.
//
// The pin sends a reason exactly one byte over the cap and asserts
// the handler responds 400 with a clear error.
func TestNTAInstall_OversizedReasonRejected(t *testing.T) {
	srv := testAdminServer(t)

	body := map[string]interface{}{
		"zone":           "example.test",
		"duration_hours": 1,
		"reason":         strings.Repeat("X", MaxNTAReasonBytes+1),
	}
	raw, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/dnssec/nta", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleNTAAdd(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized reason, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "reason exceeds") {
		t.Errorf("expected 'reason exceeds' in error body, got: %s", w.Body.String())
	}
}

// TestNTAReasonCap_ConstantStable pins the constant itself. A refactor
// that bumps MaxNTAReasonBytes to MiB-scale would silently reopen the
// memory-amplification gap; the tripwire catches it.
func TestNTAReasonCap_ConstantStable(t *testing.T) {
	if MaxNTAReasonBytes <= 0 {
		t.Fatalf("MaxNTAReasonBytes must be positive, got %d", MaxNTAReasonBytes)
	}
	if MaxNTAReasonBytes > 16<<10 {
		t.Fatalf("MaxNTAReasonBytes = %d is over 16 KiB — accidental relaxation?", MaxNTAReasonBytes)
	}
}
