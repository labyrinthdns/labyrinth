package blocklist

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
)

func capTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestBlockDomain_CapEnforced pins the v0.7.62 gate: BlockDomain
// must refuse adds past MaxCustomBlocklistEntries. Before v0.7.62
// the map grew without bound; a buggy admin automation script
// importing a 10M-row CSV could pin gigabytes of resolver RAM
// because every distinct domain became an entry in customBlocks
// AND a node in the matcher's exact-match trie. The cap caps that
// at ~100k entries — well above any realistic operator workload
// and small enough to keep the worst-case footprint bounded.
//
// The pin fills the map to the cap, then asserts the (cap+1)th
// Add returns ErrCustomBlocklistFull and that the map size did
// NOT increase past the cap. A regression that dropped the cap
// (or moved the check below the assignment) would fail one or
// both assertions.
func TestBlockDomain_CapEnforced(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, capTestLogger())

	for i := 0; i < MaxCustomBlocklistEntries; i++ {
		if err := mgr.BlockDomain(fmt.Sprintf("cap-test-%d.example", i)); err != nil {
			t.Fatalf("BlockDomain %d returned unexpected error before cap: %v", i, err)
		}
	}

	if len(mgr.customBlocks) != MaxCustomBlocklistEntries {
		t.Fatalf("customBlocks size = %d, want %d after filling to cap", len(mgr.customBlocks), MaxCustomBlocklistEntries)
	}

	// The next distinct add must be rejected.
	err := mgr.BlockDomain("overflow.example")
	if !errors.Is(err, ErrCustomBlocklistFull) {
		t.Errorf("BlockDomain past cap returned %v, want ErrCustomBlocklistFull", err)
	}
	if len(mgr.customBlocks) != MaxCustomBlocklistEntries {
		t.Errorf("customBlocks size after rejected add = %d, want %d (map must not grow past cap)", len(mgr.customBlocks), MaxCustomBlocklistEntries)
	}

	// Re-adding an existing entry must still succeed (idempotent),
	// even at the cap, because it doesn't grow the map.
	if err := mgr.BlockDomain("cap-test-0.example"); err != nil {
		t.Errorf("idempotent re-add of existing entry returned %v, want nil", err)
	}
}

// TestUnblockDomain_CapEnforced is the equivalent pin for the
// customAllows map. /api/blocklist/unblock is symmetric to
// /api/blocklist/block and the same unbounded-growth concern
// applies to operators who flip many domains from blocked → allowed.
func TestUnblockDomain_CapEnforced(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, capTestLogger())

	for i := 0; i < MaxCustomBlocklistEntries; i++ {
		if err := mgr.UnblockDomain(fmt.Sprintf("allow-cap-%d.example", i)); err != nil {
			t.Fatalf("UnblockDomain %d returned unexpected error before cap: %v", i, err)
		}
	}
	if len(mgr.customAllows) != MaxCustomBlocklistEntries {
		t.Fatalf("customAllows size = %d, want %d", len(mgr.customAllows), MaxCustomBlocklistEntries)
	}
	err := mgr.UnblockDomain("overflow.example")
	if !errors.Is(err, ErrCustomBlocklistFull) {
		t.Errorf("UnblockDomain past cap returned %v, want ErrCustomBlocklistFull", err)
	}
	if len(mgr.customAllows) != MaxCustomBlocklistEntries {
		t.Errorf("customAllows size after rejected add = %d, want %d", len(mgr.customAllows), MaxCustomBlocklistEntries)
	}
}
