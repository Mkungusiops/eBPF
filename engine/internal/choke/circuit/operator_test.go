package circuit

import "testing"

func TestSetThresholdsAtomic(t *testing.T) {
	c := New(DefaultConfig())
	prev := c.SetThresholds(Config{ThrottleAt: 100, TarpitAt: 200, QuarantineAt: 300, SeverAt: 400})
	if prev != DefaultConfig() {
		t.Errorf("returned prev does not match default: %+v", prev)
	}
	now := c.Thresholds()
	if now.ThrottleAt != 100 || now.SeverAt != 400 {
		t.Errorf("thresholds not applied: %+v", now)
	}
}

func TestSetThresholdsZeroIsNoop(t *testing.T) {
	c := New(DefaultConfig())
	prev := c.SetThresholds(Config{}) // all zero — must not zero out the live config
	if prev != DefaultConfig() {
		t.Errorf("prev wrong: %+v", prev)
	}
	if c.Thresholds() != DefaultConfig() {
		t.Errorf("live config zeroed out by all-zero input")
	}
}

func TestSetThresholdsPreservesMonotonicity(t *testing.T) {
	c := New(DefaultConfig())
	// Reach Quarantined under the default thresholds (>=25).
	d := c.Evaluate("A", 1, "/bin/x", 30, "")
	if d == nil || d.To != Quarantined {
		t.Fatalf("setup: expected Quarantined, got %+v", d)
	}
	// Move thresholds higher; the existing process must not regress.
	c.SetThresholds(Config{ThrottleAt: 100, TarpitAt: 200, QuarantineAt: 300, SeverAt: 400})
	if c.State("A") != Quarantined {
		t.Errorf("retuning thresholds must not regress an already-progressed process; got %s", c.State("A"))
	}
}

func TestForceAllowsBothDirections(t *testing.T) {
	c := New(DefaultConfig())
	c.Evaluate("A", 1, "/x", 30, "") // Quarantined
	prev, ok := c.Force("A", Throttled) // de-escalate
	if !ok || prev != Quarantined {
		t.Errorf("force down: prev=%s ok=%v", prev, ok)
	}
	if c.State("A") != Throttled {
		t.Errorf("force did not apply: %s", c.State("A"))
	}
	// Force same state -> no change reported.
	_, ok = c.Force("A", Throttled)
	if ok {
		t.Errorf("force to same state should report ok=false")
	}
	// Force up bypasses score threshold.
	_, ok = c.Force("A", Severed)
	if !ok || c.State("A") != Severed {
		t.Errorf("force up failed")
	}
}

func TestSnapshotReturnsCopies(t *testing.T) {
	c := New(DefaultConfig())
	c.Evaluate("A", 1, "/x", 7, "")
	c.Evaluate("B", 2, "/y", 30, "")
	snap := c.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len=%d want 2", len(snap))
	}
	// Mutate snapshot — must not affect internal state.
	snap[0].State = Severed
	if c.State("A") == Severed && c.State("B") == Severed {
		t.Errorf("snapshot mutation leaked into circuit")
	}
}
