package web

import (
	"fmt"
	"testing"
)

func TestTopTracker_TiedPagesStable(t *testing.T) {
	tracker := NewTopTracker(20)
	for i := 0; i < 40; i++ {
		tracker.Inc(fmt.Sprintf("client-%02d", i))
	}
	for repeat := 0; repeat < 32; repeat++ {
		for offset := 0; offset < 40; offset += 5 {
			page, total := tracker.TopPage(5, offset)
			if total != 40 || len(page) != 5 {
				t.Fatalf("page length=%d total=%d", len(page), total)
			}
			for i, entry := range page {
				if want := fmt.Sprintf("client-%02d", offset+i); entry.Key != want {
					t.Fatalf("page offset=%d index=%d key=%q, want %q", offset, i, entry.Key, want)
				}
			}
		}
	}
}

func TestTopTracker_PruneTiesStable(t *testing.T) {
	tracker := NewTopTracker(2)
	for i := 0; i < 21; i++ {
		tracker.Inc(fmt.Sprintf("client-%02d", i))
	}
	page, total := tracker.TopPage(10, 0)
	if total != 4 {
		t.Fatalf("pruned total=%d, want 4", total)
	}
	for i, entry := range page {
		if want := fmt.Sprintf("client-%02d", i); entry.Key != want {
			t.Fatalf("pruned key=%q, want %q", entry.Key, want)
		}
	}
}
