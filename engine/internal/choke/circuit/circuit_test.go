package circuit

import "testing"

func TestEvaluateMonotonic(t *testing.T) {
	c := New(DefaultConfig())

	if d := c.Evaluate("A", 100, "/bin/bash", 3, "low"); d != nil {
		t.Fatalf("score 3 should be pristine, got transition to %s", d.To)
	}
	if c.State("A") != Pristine {
		t.Fatalf("state should be pristine")
	}

	d := c.Evaluate("A", 100, "/bin/bash", 7, "rising")
	if d == nil || d.To != Throttled || d.From != Pristine {
		t.Fatalf("expected pristine→throttled, got %+v", d)
	}

	if d := c.Evaluate("A", 100, "/bin/bash", 9, "still throttled"); d != nil {
		t.Fatalf("staying in same state must not emit decision: %+v", d)
	}

	d = c.Evaluate("A", 100, "/bin/bash", 50, "spike")
	if d == nil || d.To != Severed || d.From != Throttled {
		t.Fatalf("expected throttled→severed, got %+v", d)
	}

	if d := c.Evaluate("A", 100, "/bin/bash", 9, "score dropped"); d != nil {
		t.Fatalf("circuit must be monotonic; lower score must not transition: %+v", d)
	}
	if c.State("A") != Severed {
		t.Fatalf("severed is terminal, got %s", c.State("A"))
	}
}

func TestActionMapping(t *testing.T) {
	cases := []struct {
		state State
		want  Action
	}{
		{Pristine, ActNone},
		{Throttled, ActThrottle},
		{Tarpit, ActTarpit},
		{Quarantined, ActQuarantine},
		{Severed, ActSever},
	}
	for _, tc := range cases {
		if got := actionFor(tc.state); got != tc.want {
			t.Errorf("actionFor(%s)=%s want %s", tc.state, got, tc.want)
		}
	}
}

func TestEvaluateUnknownExecIDIsNil(t *testing.T) {
	c := New(DefaultConfig())
	if d := c.Evaluate("", 0, "", 100, ""); d != nil {
		t.Fatalf("empty exec_id must be ignored, got %+v", d)
	}
}

func TestForgetAndTracked(t *testing.T) {
	c := New(DefaultConfig())
	c.Evaluate("A", 1, "/x", 10, "")
	c.Evaluate("B", 2, "/y", 30, "")
	if c.Tracked() != 2 {
		t.Fatalf("tracked=%d want 2", c.Tracked())
	}
	c.Forget("A")
	if c.Tracked() != 1 {
		t.Fatalf("tracked=%d want 1 after forget", c.Tracked())
	}
	if c.State("A") != Pristine {
		t.Fatalf("forgotten exec_id should report pristine")
	}
}

func TestCustomConfig(t *testing.T) {
	c := New(Config{ThrottleAt: 100, TarpitAt: 200, QuarantineAt: 300, SeverAt: 400})
	if d := c.Evaluate("A", 1, "/x", 50, ""); d != nil {
		t.Fatalf("score below custom throttle should be pristine, got %+v", d)
	}
	d := c.Evaluate("A", 1, "/x", 250, "")
	if d == nil || d.To != Tarpit {
		t.Fatalf("expected tarpit, got %+v", d)
	}
}
