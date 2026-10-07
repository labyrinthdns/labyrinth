package dnssec

import (
	"reflect"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestTrustAnchorStore_RefreshOwnerIsolation(t *testing.T) {
	for _, state := range []TrustAnchorState{TAStateAddPending, TAStateValid, TAStateMissing} {
		t.Run(state.String(), func(t *testing.T) {
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			store := NewTrustAnchorStore()
			store.SetClock(func() time.Time { return now })
			if state != TAStateAddPending {
				store.SetHoldDowns(0, time.Hour)
			}
			key := makeKSK(t, []byte("ordinary-alpha-key"), false)
			store.TrackRefresh("alpha.example", []*dns.DNSKEYRecord{key})
			if state == TAStateMissing {
				store.TrackRefresh("alpha.example", nil)
			}
			before := store.All()
			now = now.Add(2 * time.Hour)
			store.TrackRefresh("beta.example", nil)
			if got := store.All(); !reflect.DeepEqual(got, before) {
				t.Fatalf("unrelated owner changed candidates: before=%+v after=%+v", before, got)
			}
		})
	}
}
