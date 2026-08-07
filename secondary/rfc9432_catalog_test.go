package secondary

import (
	"errors"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// Catalog zones (RFC 9432).
//
// A catalog zone is a normal DNS zone that carries no useful DNS data — its
// records are a list of *other* zones. That makes the parser unusual: every
// record in a catalog is structurally valid DNS regardless of whether it means
// what we think it means, so nothing here fails loudly on its own. The
// version gate is the only thing standing between "this catalog says X" and
// "this catalog is a format we do not understand and X is a guess".

func catalogPTR(t *testing.T, owner, target string) dns.ResourceRecord {
	t.Helper()
	return dns.ResourceRecord{
		Name: owner, Type: dns.TypePTR, Class: dns.ClassIN, TTL: 3600,
		RData: dns.BuildPlainName(target),
	}
}

func catalogTXT(t *testing.T, owner, value string) dns.ResourceRecord {
	t.Helper()
	rdata := append([]byte{byte(len(value))}, value...)
	return dns.ResourceRecord{
		Name: owner, Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 3600,
		RData: rdata,
	}
}

// wellFormedCatalog builds the shape RFC 9432 §4 describes.
func wellFormedCatalog(t *testing.T) []dns.ResourceRecord {
	t.Helper()
	return []dns.ResourceRecord{
		testSOA(t, "catalog.example", 1),
		catalogTXT(t, "version.catalog.example", "2"),
		catalogPTR(t, "abc123.zones.catalog.example", "one.example"),
		catalogPTR(t, "def456.zones.catalog.example", "two.example"),
		catalogTXT(t, "group.def456.zones.catalog.example", "internal"),
	}
}

// TestRFC9432_ParseMembers pins the basic extraction.
func TestRFC9432_ParseMembers(t *testing.T) {
	members, err := ParseCatalog("catalog.example", wellFormedCatalog(t))
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2: %+v", len(members), members)
	}
	// Sorted by name for determinism.
	if members[0].Name != "one.example" || members[1].Name != "two.example" {
		t.Fatalf("members = %+v, want one.example then two.example", members)
	}
	if members[0].UniqueID != "abc123" {
		t.Errorf("unique id = %q, want abc123", members[0].UniqueID)
	}
	if members[1].Group != "internal" {
		t.Errorf("group = %q, want internal", members[1].Group)
	}
	if members[0].Group != "" {
		t.Errorf("member with no group property got group %q", members[0].Group)
	}
}

// TestRFC9432_VersionGate is the test that matters most. RFC 9432 §4.2.2 says
// a catalog whose version is absent or unrecognised MUST NOT be processed.
//
// The reason the RFC is that strict: a future catalog format could reuse these
// exact record shapes with different meanings. A consumer that processed it
// anyway would provision the wrong zones and every record would still parse
// cleanly, so nothing would look broken until someone noticed the fleet was
// serving zones nobody asked for.
func TestRFC9432_VersionGate(t *testing.T) {
	t.Run("missing version is refused", func(t *testing.T) {
		records := []dns.ResourceRecord{
			testSOA(t, "catalog.example", 1),
			catalogPTR(t, "abc123.zones.catalog.example", "one.example"),
		}
		_, err := ParseCatalog("catalog.example", records)
		if !errors.Is(err, ErrCatalogNoVersion) {
			t.Fatalf("error = %v, want ErrCatalogNoVersion", err)
		}
	})

	t.Run("unknown version is refused", func(t *testing.T) {
		records := []dns.ResourceRecord{
			testSOA(t, "catalog.example", 1),
			catalogTXT(t, "version.catalog.example", "3"),
			catalogPTR(t, "abc123.zones.catalog.example", "one.example"),
		}
		_, err := ParseCatalog("catalog.example", records)
		if !errors.Is(err, ErrCatalogBadVersion) {
			t.Fatalf("error = %v, want ErrCatalogBadVersion", err)
		}
	})

	t.Run("refusal is distinct from an empty catalog", func(t *testing.T) {
		// An empty-but-versioned catalog is a real instruction: withdraw
		// everything. An unversioned one is not, and the manager relies on
		// the error to tell them apart — treating a schema mismatch as
		// "withdraw everything" would take the whole fleet's zones offline
		// at once.
		empty := []dns.ResourceRecord{
			testSOA(t, "catalog.example", 1),
			catalogTXT(t, "version.catalog.example", "2"),
		}
		members, err := ParseCatalog("catalog.example", empty)
		if err != nil {
			t.Fatalf("a versioned empty catalog must parse cleanly, got %v", err)
		}
		if len(members) != 0 {
			t.Errorf("got %d members from an empty catalog", len(members))
		}
	})
}

// TestRFC9432_UniqueIDIsOpaque pins §4.3.1: the unique-id label carries no
// meaning. Two entries pointing at different zones must both survive
// regardless of what their ids look like, and an id that resembles a property
// name must not be mistaken for one.
func TestRFC9432_UniqueIDIsOpaque(t *testing.T) {
	records := []dns.ResourceRecord{
		testSOA(t, "catalog.example", 1),
		catalogTXT(t, "version.catalog.example", "2"),
		catalogPTR(t, "group.zones.catalog.example", "confusing.example"),
		catalogPTR(t, "0.zones.catalog.example", "numeric.example"),
		catalogPTR(t, "version.zones.catalog.example", "alsoconfusing.example"),
	}
	members, err := ParseCatalog("catalog.example", records)
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3 — the unique-id label is opaque and "+
			"must not be interpreted: %+v", len(members), members)
	}
}

// TestRFC9432_DuplicateMembersIgnored pins §4.3.1's one-entry-per-zone
// expectation. A duplicate is advisory rather than fatal — the rest of the
// catalog is still usable — but provisioning it twice would leave two transfer
// loops fighting over one zone's data.
func TestRFC9432_DuplicateMembersIgnored(t *testing.T) {
	records := []dns.ResourceRecord{
		testSOA(t, "catalog.example", 1),
		catalogTXT(t, "version.catalog.example", "2"),
		catalogPTR(t, "aaa.zones.catalog.example", "dup.example"),
		catalogPTR(t, "bbb.zones.catalog.example", "dup.example"),
		catalogPTR(t, "ccc.zones.catalog.example", "fine.example"),
	}
	members, err := ParseCatalog("catalog.example", records)
	if err == nil {
		t.Error("a duplicate member should be reported, even though it is not fatal")
	}
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2 (one deduplicated): %+v", len(members), members)
	}
	names := map[string]bool{}
	for _, mz := range members {
		if names[mz.Name] {
			t.Errorf("zone %q provisioned twice", mz.Name)
		}
		names[mz.Name] = true
	}
}

// TestRFC9432_UnrelatedRecordsIgnored pins that a catalog carrying ordinary
// DNS records — an apex NS, records outside the zones subtree — does not
// produce phantom members.
func TestRFC9432_UnrelatedRecordsIgnored(t *testing.T) {
	records := []dns.ResourceRecord{
		testSOA(t, "catalog.example", 1),
		catalogTXT(t, "version.catalog.example", "2"),
		{Name: "catalog.example", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600,
			RData: dns.BuildPlainName("invalid")},
		catalogPTR(t, "somewhere.else.catalog.example", "notamember.example"),
		catalogTXT(t, "abc.zones.catalog.example", "not a PTR"),
		catalogPTR(t, "real.zones.catalog.example", "member.example"),
	}
	members, err := ParseCatalog("catalog.example", records)
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	if len(members) != 1 || members[0].Name != "member.example" {
		t.Fatalf("members = %+v, want only member.example", members)
	}
}

// TestRFC9432_CaseInsensitive pins RFC 4343. A primary that publishes the
// catalog with different capitalisation than the config uses must still have
// its members recognised.
func TestRFC9432_CaseInsensitive(t *testing.T) {
	records := []dns.ResourceRecord{
		testSOA(t, "catalog.example", 1),
		catalogTXT(t, "VERSION.Catalog.Example.", "2"),
		catalogPTR(t, "AbC.ZONES.Catalog.Example.", "Member.Example."),
	}
	members, err := ParseCatalog("Catalog.Example", records)
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	if len(members) != 1 || members[0].Name != "member.example" {
		t.Fatalf("members = %+v, want the lowercased member.example", members)
	}
}

// TestRFC9432_MembersInheritCatalogTransport pins the provisioning mapping.
// RFC 9432 §5.1 leaves it implementation-defined; inheritance is what makes
// the feature useful, since the whole point is not having to configure each
// member.
func TestRFC9432_MembersInheritCatalogTransport(t *testing.T) {
	cat := CatalogConfig{
		Name:          "catalog.example",
		PrimaryAddr:   "10.0.0.53",
		UseTLS:        true,
		TLSServerName: "xfr.example",
		TSIGKey:       dns.TSIGKey{Name: "k", Algorithm: dns.TSIGHMACSHA256, Secret: []byte("s")},
	}
	got := cat.memberZoneConfig("member.example")

	if got.Name != "member.example" {
		t.Errorf("name = %q", got.Name)
	}
	if got.PrimaryAddr != cat.PrimaryAddr {
		t.Errorf("primary = %q, want the catalog's %q", got.PrimaryAddr, cat.PrimaryAddr)
	}
	if !got.UseTLS || got.TLSServerName != cat.TLSServerName {
		t.Error("member did not inherit the catalog's TLS settings")
	}
	if got.TSIGKey.Name != cat.TSIGKey.Name || string(got.TSIGKey.Secret) != string(cat.TSIGKey.Secret) {
		t.Error("member did not inherit the catalog's TSIG key — it would transfer " +
			"unauthenticated while the catalog itself was authenticated")
	}
}

// TestRFC9432_StaticZoneWinsOverCatalog pins the collision rule. A statically
// configured zone is the operator's explicit instruction; letting a catalog
// silently retarget it would move a zone's primary without anyone editing a
// file.
func TestRFC9432_StaticZoneWinsOverCatalog(t *testing.T) {
	m := NewManager(testResolver(t), nil,
		[]ZoneConfig{{Name: "pinned.example", PrimaryAddr: "192.0.2.1"}},
		nil, discardLogger())

	cat := CatalogConfig{Name: "catalog.example", PrimaryAddr: "10.0.0.53"}
	// reconcile with a member that collides with the static zone. Passing a
	// cancelled context keeps any started loop from doing real work; the
	// assertion is about the bookkeeping, not the transfer.
	m.reconcile(cancelledContext(), cat, []MemberZone{{Name: "pinned.example", UniqueID: "x"}})

	m.mu.Lock()
	z := m.zones["pinned.example"]
	m.mu.Unlock()

	if z == nil {
		t.Fatal("static zone disappeared")
	}
	if z.source != "" {
		t.Errorf("static zone was taken over by catalog %q", z.source)
	}
	if z.cfg.PrimaryAddr != "192.0.2.1" {
		t.Errorf("static zone's primary was retargeted to %q", z.cfg.PrimaryAddr)
	}
}

// TestRFC9432_ReconcileWithdrawsRemovedMembers pins that a zone dropped from
// the catalog stops being served. Leaving it in place would mean a zone an
// operator deliberately removed keeps being answered from a stale copy.
func TestRFC9432_ReconcileWithdrawsRemovedMembers(t *testing.T) {
	m := NewManager(testResolver(t), nil, nil, nil, discardLogger())
	cat := CatalogConfig{Name: "catalog.example", PrimaryAddr: "10.0.0.53"}
	ctx := cancelledContext()

	m.reconcile(ctx, cat, []MemberZone{
		{Name: "a.example", UniqueID: "1"},
		{Name: "b.example", UniqueID: "2"},
	})
	m.mu.Lock()
	n := len(m.zones)
	m.mu.Unlock()
	if n != 2 {
		t.Fatalf("provisioned %d zones, want 2", n)
	}

	// The catalog now lists only one.
	m.reconcile(ctx, cat, []MemberZone{{Name: "a.example", UniqueID: "1"}})

	m.mu.Lock()
	_, stillA := m.zones["a.example"]
	_, stillB := m.zones["b.example"]
	m.mu.Unlock()

	if !stillA {
		t.Error("a.example was withdrawn but the catalog still lists it")
	}
	if stillB {
		t.Error("b.example is still provisioned after the catalog dropped it")
	}
}
