package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newDecisionStatsStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestDecisionStatsCountsTheWholeWindowNotAPage is the defect this file exists
// for: the console counted a 200-row buffer, so every window those rows did not
// span reported exactly 200. The aggregate must see all of them.
func TestDecisionStatsCountsTheWholeWindowNotAPage(t *testing.T) {
	s := newDecisionStatsStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	from := now.Add(-30 * time.Minute)

	// More decisions than any browser page size, all inside the window.
	const n = 250
	for i := 0; i < n; i++ {
		if _, err := s.InsertDecision(&Decision{
			Timestamp: now.Add(-time.Duration(i) * time.Second),
			ExecID:    "e", PID: 1, Action: "throttle",
			FromState: "pristine", ToState: "throttled", Score: 21,
		}); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := s.DecisionStats(from, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != n {
		t.Fatalf("Total = %d, want %d — the whole window, not a page of it", stats.Total, n)
	}
	if stats.Actions["throttle"] != n {
		t.Fatalf("Actions[throttle] = %d, want %d", stats.Actions["throttle"], n)
	}
}

// The parts must add up to the whole, or the tile and its breakdown disagree.
func TestDecisionStatsActionsSumToTotal(t *testing.T) {
	s := newDecisionStatsStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	for _, a := range []string{"throttle", "throttle", "tarpit", "quarantine", "sever"} {
		if _, err := s.InsertDecision(&Decision{
			Timestamp: now.Add(-time.Minute), ExecID: "e", PID: 1, Action: a,
			FromState: "pristine", ToState: a, Score: 50,
		}); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := s.DecisionStats(now.Add(-30*time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	sum := 0
	for _, n := range stats.Actions {
		sum += n
	}
	if sum != stats.Total || stats.Total != 5 {
		t.Fatalf("actions sum %d vs total %d (want both 5)", sum, stats.Total)
	}
	if stats.Actions["throttle"] != 2 || stats.Actions["sever"] != 1 {
		t.Fatalf("per-action breakdown wrong: %+v", stats.Actions)
	}
}

// Every ladder action is present even at zero, so the console never has to
// distinguish "none" from "missing".
func TestDecisionStatsAlwaysPopulatesEveryAction(t *testing.T) {
	s := newDecisionStatsStore(t)
	now := time.Now().UTC()
	stats, err := s.DecisionStats(now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"throttle", "tarpit", "quarantine", "sever"} {
		if _, ok := stats.Actions[a]; !ok {
			t.Errorf("action %q missing from an empty window", a)
		}
	}
	if stats.Total != 0 || stats.Previous != 0 {
		t.Fatalf("empty window should be all zero, got %+v", stats)
	}
}

// The prior window is what makes a delta a comparison rather than a repeat of
// the current count — the exact bug AlertStats was built to fix for alerts.
func TestDecisionStatsCountsThePriorWindow(t *testing.T) {
	s := newDecisionStatsStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	from := now.Add(-10 * time.Minute)

	ins := func(at time.Time) {
		t.Helper()
		if _, err := s.InsertDecision(&Decision{
			Timestamp: at, ExecID: "e", PID: 1, Action: "tarpit",
			FromState: "pristine", ToState: "tarpit", Score: 60,
		}); err != nil {
			t.Fatal(err)
		}
	}
	ins(now.Add(-1 * time.Minute))  // current
	ins(now.Add(-2 * time.Minute))  // current
	ins(now.Add(-15 * time.Minute)) // prior window
	ins(now.Add(-45 * time.Minute)) // older than both — counted in neither

	stats, err := s.DecisionStats(from, now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 2 {
		t.Fatalf("Total = %d, want 2", stats.Total)
	}
	if stats.Previous != 1 {
		t.Fatalf("Previous = %d, want 1 — the preceding window of equal length", stats.Previous)
	}
}

// A dry-run decision records what WOULD have happened. Counting it as a
// response action taken overstates what the platform actually did.
func TestDecisionStatsSeparatesDryRun(t *testing.T) {
	s := newDecisionStatsStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	for i, dry := range []bool{true, true, false} {
		if _, err := s.InsertDecision(&Decision{
			Timestamp: now.Add(-time.Duration(i+1) * time.Minute),
			ExecID:    "e", PID: 1, Action: "sever",
			FromState: "pristine", ToState: "severed", Score: 200, DryRun: dry,
		}); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := s.DecisionStats(now.Add(-30*time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 3 {
		t.Fatalf("Total = %d, want 3 (dry-run decisions are still decisions)", stats.Total)
	}
	if stats.DryRun != 2 {
		t.Fatalf("DryRun = %d, want 2", stats.DryRun)
	}
}
