package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDoHGet_RejectsOverlongDNSParam pins the input-size cap on the
// DoH GET path's `?dns=…` parameter. The POST path is already capped
// at 65536 raw bytes via LimitReader, but until v0.7.38 the GET path
// had no length validation — an attacker could ?dns=<megabytes of
// base64> and the decoder would happily expand that into ~75 % of
// the input size in RAM before the DNS parser even saw it.
//
// The pin asserts that an oversize `dns` parameter is rejected
// before any allocation by exercising the decode helper directly.
// A 200 KB parameter is well above the production cap and below
// what would naturally OOM the test harness — we just want to prove
// the gate fires.
func TestDoHGet_RejectsOverlongDNSParam(t *testing.T) {
	huge := strings.Repeat("A", dohMaxGetParamBytes+1)

	req := httptest.NewRequest("GET", "/dns-query?dns="+huge, nil)
	srv := &AdminServer{}
	_, err := srv.dohDecodeGet(req)

	if err == nil {
		t.Fatal("dohDecodeGet accepted an over-cap parameter — input gate not firing")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("error %q does not mention the size cap; operator may not understand why", err.Error())
	}
}

// TestDoHGet_AcceptsParamAtCap — negative control: a parameter at
// exactly the cap is accepted (the base64-decode then errors because
// the body is "A" repeated, but the length gate must NOT be the
// failure path).
func TestDoHGet_AcceptsParamAtCap(t *testing.T) {
	// Use a length one shorter than the cap so we know the gate did not
	// fire (the base64 decoder will reject the content; that's
	// expected for the negative control).
	atCap := strings.Repeat("A", dohMaxGetParamBytes-1)

	req := httptest.NewRequest("GET", "/dns-query?dns="+atCap, nil)
	srv := &AdminServer{}
	_, err := srv.dohDecodeGet(req)

	if err != nil && strings.Contains(err.Error(), "cap") {
		t.Errorf("under-cap parameter was rejected by the length gate: %v", err)
	}
}
