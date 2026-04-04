package web

import (
	"strings"
	"testing"
)

func TestNormalizeDashboardPanelIDs(t *testing.T) {
	got := normalizeDashboardPanelIDs([]string{
		" query_types ",
		"top_lists",
		"network_security",
		"unknown",
		"top_lists",
	})

	want := []string{"query_types", "top_lists", "network_security"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got=%q want=%q", i, got[i], want[i])
		}
	}
}

func TestUpsertDashboardLayoutBlock(t *testing.T) {
	original := "server:\n  listen_addr: \":53\"\n"
	updated := upsertDashboardLayoutBlock(original, []string{"query_types", "top_lists"}, []string{"network_security"})

	if !strings.Contains(updated, dashboardLayoutBeginMarker) || !strings.Contains(updated, dashboardLayoutEndMarker) {
		t.Fatalf("markers not found in updated content: %q", updated)
	}
	if !strings.Contains(updated, "panel_order:") || !strings.Contains(updated, "hidden_panels:") {
		t.Fatalf("dashboard block missing expected keys: %q", updated)
	}

	updatedAgain := upsertDashboardLayoutBlock(updated, []string{"network_security"}, nil)
	if strings.Count(updatedAgain, dashboardLayoutBeginMarker) != 1 {
		t.Fatalf("expected a single begin marker after upsert replacement")
	}
}

