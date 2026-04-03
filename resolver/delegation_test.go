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

	// Root zone NS are always in a TLD
	delegations := []DelegationNS{
		{Hostname: "a.root-servers.net."},
	}

	validateReferralNS(delegations, "com.", logger)

	// "a.root-servers.net." is not in "com." hierarchy — should warn
	output := buf.String()
	if output == "" {
		t.Error("expected warning for root-servers.net NS under com. zone")
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
