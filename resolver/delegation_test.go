package resolver

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestValidateReferralNS_Related(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	delegations := []DelegationNS{
		{Hostname: "ns1.example.com."},
		{Hostname: "ns2.example.com."},
	}

	validateReferralNS(delegations, "example.com.", logger)

	if buf.Len() > 0 {
		t.Errorf("expected no warnings for related NS, got: %s", buf.String())
	}
}

func TestValidateReferralNS_ParentHierarchy(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// NS in parent TLD hierarchy should be allowed
	delegations := []DelegationNS{
		{Hostname: "ns1.nic.tr."},
		{Hostname: "ns2.nic.tr."},
	}

	validateReferralNS(delegations, "com.tr.", logger)

	if buf.Len() > 0 {
		t.Errorf("expected no warnings for parent hierarchy NS, got: %s", buf.String())
	}
}

func TestValidateReferralNS_Unrelated(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	delegations := []DelegationNS{
		{Hostname: "ns1.example.com."},
		{Hostname: "evil.totally-different.org."},
	}

	validateReferralNS(delegations, "example.com.", logger)

	output := buf.String()
	if output == "" {
		t.Error("expected warning for unrelated NS hostname")
	}
	if !bytes.Contains(buf.Bytes(), []byte("evil.totally-different.org.")) {
		t.Errorf("warning should mention the suspicious NS, got: %s", output)
	}
}

func TestValidateReferralNS_NilLogger(t *testing.T) {
	delegations := []DelegationNS{
		{Hostname: "evil.example.org."},
	}

	// Should not panic with nil logger
	validateReferralNS(delegations, "example.com.", nil)
}

// TestValidateReferralNS_ArpaSkipped pins the false-positive fix: reverse
// DNS zones (in-addr.arpa subtree) are delegated to RIR domains by IANA
// design — *.lacnic.net for 89.in-addr.arpa, *.ripe.net for 185.in-addr.arpa,
// etc. Those are structurally out of bailiwick of *.arpa and would otherwise
// trigger ~5 WARN events per PTR lookup, drowning real signal.
func TestValidateReferralNS_ArpaSkipped(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cases := []struct {
		zone string
		ns   []string
	}{
		{"89.in-addr.arpa", []string{
			"ns3.lacnic.net.", "ns3.afrinic.net.", "ns4.apnic.net.",
			"pri.authdns.ripe.net.", "rirns.arin.net.",
		}},
		{"185.in-addr.arpa", []string{"ns3.lacnic.net.", "rirns.arin.net."}},
		{"in-addr.arpa", []string{"a.in-addr-servers.arpa.", "b.in-addr-servers.arpa."}},
		{"arpa", []string{"a.root-servers.net."}},
		{"237.254.185.in-addr.arpa", []string{"ns1.dgntek.com.", "ns2.dgntek.com."}},
	}

	for _, c := range cases {
		buf.Reset()
		dels := make([]DelegationNS, len(c.ns))
		for i, h := range c.ns {
			dels[i] = DelegationNS{Hostname: h}
		}
		validateReferralNS(dels, c.zone, logger)
		if buf.Len() > 0 {
			t.Errorf("zone %q: expected no WARN under arpa, got:\n%s", c.zone, buf.String())
		}
	}
}

// TestValidateReferralNS_TLDSkipped pins the second skip class: TLD
// referrals (1-label zones) are served by registry infrastructure that is
// always out of bailiwick of the TLD label itself (e.g. *.gtld-servers.net
// for .com, *.nic.tr for .tr, .ax for .fi).
func TestValidateReferralNS_TLDSkipped(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cases := []struct {
		zone string
		ns   []string
	}{
		{"com", []string{"a.gtld-servers.net.", "l.gtld-servers.net."}},
		{"net", []string{"a.gtld-servers.net.", "j.gtld-servers.net."}},
		{"tr", []string{"ns1.nic.tr.", "ns2.metu.edu.tr."}},
		{"de", []string{"a.nic.de.", "f.nic.de.", "l.de.net."}},
	}

	for _, c := range cases {
		buf.Reset()
		dels := make([]DelegationNS, len(c.ns))
		for i, h := range c.ns {
			dels[i] = DelegationNS{Hostname: h}
		}
		validateReferralNS(dels, c.zone, logger)
		if buf.Len() > 0 {
			t.Errorf("TLD %q: expected no WARN, got:\n%s", c.zone, buf.String())
		}
	}
}

// TestValidateReferralNS_StillFiresOnRealAnomaly makes sure the skip
// rules above did not silence legitimate suspicious-NS detection inside
// regular hierarchical zones (the original threat model).
func TestValidateReferralNS_StillFiresOnRealAnomaly(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	delegations := []DelegationNS{
		{Hostname: "ns1.bank.example."}, // legit
		{Hostname: "ns1.attacker-controlled.evil."},
	}
	validateReferralNS(delegations, "bank.example", logger)

	if !bytes.Contains(buf.Bytes(), []byte("attacker-controlled.evil")) {
		t.Errorf("expected WARN to still fire for a real out-of-bailiwick NS, got: %s", buf.String())
	}
}

func TestValidateReferralNS_EmptyZone(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	delegations := []DelegationNS{
		{Hostname: "ns1.example.com."},
	}

	validateReferralNS(delegations, "", logger)

	if buf.Len() > 0 {
		t.Errorf("expected no warnings for empty zone, got: %s", buf.String())
	}
}

func TestValidateReferralNS_RootNS(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Inside a regular hierarchical zone (not a TLD, not under arpa), an
	// NS hostname pointing at root infrastructure is a real anomaly that
	// should fire the WARN.
	delegations := []DelegationNS{
		{Hostname: "a.root-servers.net."},
	}

	validateReferralNS(delegations, "internal.example.com.", logger)

	output := buf.String()
	if output == "" {
		t.Error("expected warning for root-servers.net NS under internal.example.com. zone")
	}
}

func TestValidateReferralNS_SameAsZone(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	delegations := []DelegationNS{
		{Hostname: "example.com."},
	}

	validateReferralNS(delegations, "example.com.", logger)

	if buf.Len() > 0 {
		t.Errorf("expected no warnings when NS equals zone, got: %s", buf.String())
	}
}
