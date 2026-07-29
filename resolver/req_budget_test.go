package resolver

import (
	"testing"
	"time"
)

// TestReqBudget_QueryCap pins the per-request outbound-query backstop: once
// maxQueries charges have been made, the next charge errors so the resolution
// loop collapses to SERVFAIL instead of fanning out indefinitely (NXNS /
// runaway-referral defense).
func TestReqBudget_QueryCap(t *testing.T) {
	b := &reqBudget{maxQueries: 3}
	for i := 0; i < 3; i++ {
		if err := b.charge(); err != nil {
			t.Fatalf("charge %d should succeed under cap 3, got %v", i+1, err)
		}
	}
	if err := b.charge(); err != errQueryBudgetExceeded {
		t.Fatalf("4th charge should exceed cap, got %v", err)
	}
}

// TestReqBudget_Unlimited pins that a zero/negative cap and a nil budget never
// block — the path used by tests and internal helpers.
func TestReqBudget_Unlimited(t *testing.T) {
	var nilB *reqBudget
	if err := nilB.charge(); err != nil {
		t.Errorf("nil budget must be unlimited, got %v", err)
	}
	b := &reqBudget{maxQueries: 0}
	for i := 0; i < 10_000; i++ {
		if err := b.charge(); err != nil {
			t.Fatalf("maxQueries=0 must be unlimited, failed at %d: %v", i, err)
		}
	}
}

// TestReqBudget_Deadline pins the wall-clock backstop: a deadline already in
// the past trips on the next charge regardless of query count.
func TestReqBudget_Deadline(t *testing.T) {
	b := &reqBudget{maxQueries: 1000, deadline: time.Now().Add(-time.Second)}
	if err := b.charge(); err != errRequestDeadline {
		t.Fatalf("past deadline must trip, got %v", err)
	}
}

// TestReqBudget_SharedAcrossSubResolution pins that newVisitedSetWithBudget
// shares the SAME budget pointer (so NS-address sub-resolutions count against
// the originating request) while keeping independent loop-detection state.
func TestReqBudget_SharedAcrossSubResolution(t *testing.T) {
	parent := newVisitedSet()
	parent.budget.maxQueries = 5
	parent.Add("ns1|a.com|com") // loop-detection state on the parent

	child := newVisitedSetWithBudget(parent.budget)
	if child.budget != parent.budget {
		t.Fatal("sub-resolution must share the parent budget pointer")
	}
	if child.Has("ns1|a.com|com") {
		t.Error("sub-resolution must have independent loop-detection state")
	}

	// Charges on the child count against the shared budget.
	for i := 0; i < 5; i++ {
		if err := child.budget.charge(); err != nil {
			t.Fatalf("charge %d should succeed, got %v", i+1, err)
		}
	}
	if err := parent.budget.charge(); err != errQueryBudgetExceeded {
		t.Fatal("parent budget should be exhausted by the child's charges")
	}
}
