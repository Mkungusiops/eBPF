package circuit

import (
	"strings"
	"testing"
)

func TestSetThresholdsAtomic(t *testing.T) {
	c := New(DefaultConfig())
	prev, err := c.SetThresholds(Config{ThrottleAt: 100, TarpitAt: 200, QuarantineAt: 300, SeverAt: 400})
	if err != nil {
		t.Fatalf("a complete ascending set must be accepted: %v", err)
	}
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
	// All-zero is now REFUSED rather than silently ignored. The old behaviour
	// (apply-if-any-field-positive) is what let a partial body zero sever_at.
	prev, err := c.SetThresholds(Config{})
	if err == nil {
		t.Error("an all-zero config must be refused, not quietly dropped")
	}
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
	if _, err := c.SetThresholds(Config{ThrottleAt: 100, TarpitAt: 200, QuarantineAt: 300, SeverAt: 400}); err != nil {
		t.Fatal(err)
	}
	if c.State("A") != Quarantined {
		t.Errorf("retuning thresholds must not regress an already-progressed process; got %s", c.State("A"))
	}
}

func TestForceAllowsBothDirections(t *testing.T) {
	c := New(DefaultConfig())
	c.Evaluate("A", 1, "/x", 30, "")    // Quarantined
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

// A partial threshold body was a fleet-wide SIGKILL.
//
// SetThresholds applied when ANY field was positive, so {throttle_at: 10} with
// the other three absent installed {10, 0, 0, 0}. stateFor tests sever FIRST,
// so every tracked process with score >= 0 evaluated to Severed. The control
// plane discarded its decode error, the signed command carried the values
// verbatim, and neither the command processor nor the agent's applier checked
// — only the engine's own local handler did, which the fleet path bypasses.
func TestAPartialThresholdSetIsRefused(t *testing.T) {
	c := New(Config{ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200})

	prev, err := c.SetThresholds(Config{ThrottleAt: 10}) // the malformed body
	if err == nil {
		t.Fatal("a partial threshold set must be refused — it zeroes sever_at and severs everything")
	}
	if prev.SeverAt != 200 {
		t.Fatalf("prev should report the config still in force, got sever=%d", prev.SeverAt)
	}
	// And the live config must be untouched.
	if got := c.Thresholds(); got.SeverAt != 200 || got.ThrottleAt != 20 {
		t.Fatalf("a refused set mutated the live ladder: %+v", got)
	}
}

func TestAZeroSeverThresholdIsRefused(t *testing.T) {
	// The specific lethal shape, asserted on its own so the reason survives.
	err := Config{ThrottleAt: 1, TarpitAt: 2, QuarantineAt: 3, SeverAt: 0}.Validate()
	if err == nil {
		t.Fatal("sever_at = 0 means every score >= 0 is Severed")
	}
	if !strings.Contains(err.Error(), "severs every tracked process") {
		t.Fatalf("the error should say what happens, got: %v", err)
	}
}

func TestThresholdsMustAscend(t *testing.T) {
	// A non-ascending ladder makes the lower rungs unreachable.
	if err := (Config{ThrottleAt: 200, TarpitAt: 50, QuarantineAt: 120, SeverAt: 20}).Validate(); err == nil {
		t.Fatal("a descending ladder must be refused")
	}
}

func TestACompleteAscendingSetIsAccepted(t *testing.T) {
	c := New(Config{ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200})
	prev, err := c.SetThresholds(Config{ThrottleAt: 5, TarpitAt: 10, QuarantineAt: 15, SeverAt: 20})
	if err != nil {
		t.Fatalf("a complete ascending set must be accepted: %v", err)
	}
	if prev.ThrottleAt != 20 {
		t.Fatalf("prev = %+v", prev)
	}
	if got := c.Thresholds(); got.SeverAt != 20 {
		t.Fatalf("the new ladder did not take: %+v", got)
	}
}
