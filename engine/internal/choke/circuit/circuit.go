// Package circuit implements the per-process choke state machine.
//
// Each tracked exec_id moves through a strictly monotonic ladder of states
// driven by chain score:
//
//	pristine → throttled → tarpit → quarantined → severed
//
// Once a process reaches a state it never moves back — only forward. Each
// transition produces a Decision, which the enforcer acts on and the store
// records (with hash-chain tamper-evidence). The circuit is the brain; the
// enforcer is the muscle.
package circuit

import (
	"sync"
	"time"
)

type State int

const (
	Pristine State = iota
	Throttled
	Tarpit
	Quarantined
	Severed
)

func (s State) String() string {
	switch s {
	case Pristine:
		return "pristine"
	case Throttled:
		return "throttled"
	case Tarpit:
		return "tarpit"
	case Quarantined:
		return "quarantined"
	case Severed:
		return "severed"
	}
	return "unknown"
}

// Action is what the enforcer should do when a transition fires. There is a
// 1:1 mapping with the destination State, exposed separately so callers can
// switch on the action without parsing strings.
type Action int

const (
	ActNone Action = iota
	ActThrottle
	ActTarpit
	ActQuarantine
	ActSever
)

func (a Action) String() string {
	switch a {
	case ActThrottle:
		return "throttle"
	case ActTarpit:
		return "tarpit"
	case ActQuarantine:
		return "quarantine"
	case ActSever:
		return "sever"
	}
	return "none"
}

func actionFor(s State) Action {
	switch s {
	case Throttled:
		return ActThrottle
	case Tarpit:
		return ActTarpit
	case Quarantined:
		return ActQuarantine
	case Severed:
		return ActSever
	}
	return ActNone
}

// Config holds the score thresholds at which each state is reached. The
// defaults align with the existing Severity ladder (low=5, medium=10,
// high=20, critical=40) but with one extra rung between medium and high.
type Config struct {
	ThrottleAt   int
	TarpitAt     int
	QuarantineAt int
	SeverAt      int
}

// DefaultConfig is the production-ish default. Values are deliberately
// chosen so a single high-severity event (e.g. setuid(0) at +15 alone)
// doesn't sever — chains do.
func DefaultConfig() Config {
	return Config{
		ThrottleAt:   5,
		TarpitAt:     15,
		QuarantineAt: 25,
		SeverAt:      40,
	}
}

// Decision is emitted on every state transition.
type Decision struct {
	ExecID    string
	PID       uint32
	Binary    string
	From      State
	To        State
	Action    Action
	Score     int
	Reason    string
	Timestamp time.Time
}

// Circuit holds per-exec_id state. Concurrency-safe.
type Circuit struct {
	cfg Config

	mu     sync.Mutex
	states map[string]State
}

func New(cfg Config) *Circuit {
	if cfg.ThrottleAt == 0 && cfg.TarpitAt == 0 && cfg.QuarantineAt == 0 && cfg.SeverAt == 0 {
		cfg = DefaultConfig()
	}
	return &Circuit{
		cfg:    cfg,
		states: make(map[string]State),
	}
}

// stateFor maps a chain score to the highest state it has reached.
func (c *Circuit) stateFor(score int) State {
	switch {
	case score >= c.cfg.SeverAt:
		return Severed
	case score >= c.cfg.QuarantineAt:
		return Quarantined
	case score >= c.cfg.TarpitAt:
		return Tarpit
	case score >= c.cfg.ThrottleAt:
		return Throttled
	}
	return Pristine
}

// Evaluate updates the circuit for an exec_id. If the score crosses one or
// more thresholds, a Decision is returned describing the transition. The
// returned state is the *highest* new state reached (not intermediate
// rungs). Returns nil when no transition occurs.
//
// The enforcer should be called with this Decision; recording the decision
// is the caller's responsibility (so dry-run mode can record without
// enforcing).
func (c *Circuit) Evaluate(execID string, pid uint32, binary string, score int, reason string) *Decision {
	if execID == "" {
		return nil
	}
	target := c.stateFor(score)

	c.mu.Lock()
	prev := c.states[execID]
	if target <= prev {
		c.mu.Unlock()
		return nil
	}
	c.states[execID] = target
	c.mu.Unlock()

	return &Decision{
		ExecID:    execID,
		PID:       pid,
		Binary:    binary,
		From:      prev,
		To:        target,
		Action:    actionFor(target),
		Score:     score,
		Reason:    reason,
		Timestamp: time.Now().UTC(),
	}
}

// State returns the current state for an exec_id. Pristine if unknown.
func (c *Circuit) State(execID string) State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.states[execID]
}

// Forget drops state for an exec_id (e.g. on process exit). Idempotent.
func (c *Circuit) Forget(execID string) {
	c.mu.Lock()
	delete(c.states, execID)
	c.mu.Unlock()
}

// Tracked returns the number of exec_ids being tracked. Useful for metrics
// and for sizing-based GC decisions in the wiring layer.
func (c *Circuit) Tracked() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.states)
}

// Thresholds returns a copy of the active threshold config. Safe to call
// concurrently with Evaluate.
func (c *Circuit) Thresholds() Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

// SetThresholds replaces the active thresholds atomically. Existing per-
// exec_id state is preserved (monotonic guarantee still holds), so a
// process that has already reached "severed" stays severed even if the
// new sever threshold is higher.
//
// Returns the previous config so callers can audit what changed.
func (c *Circuit) SetThresholds(cfg Config) Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.cfg
	if cfg.ThrottleAt > 0 || cfg.TarpitAt > 0 || cfg.QuarantineAt > 0 || cfg.SeverAt > 0 {
		c.cfg = cfg
	}
	return old
}

// TrackedState is one row of a circuit snapshot.
type TrackedState struct {
	ExecID string
	State  State
}

// Snapshot returns a copy of every tracked exec_id and its current state.
// Order is undefined; sort in the caller if you need deterministic output.
func (c *Circuit) Snapshot() []TrackedState {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]TrackedState, 0, len(c.states))
	for k, v := range c.states {
		out = append(out, TrackedState{ExecID: k, State: v})
	}
	return out
}

// Force overrides the state for an exec_id, returning the prior state and
// true if the change took effect. Force allows monotonic-down (e.g. an
// operator de-escalating a false-positive); the caller is responsible for
// auditing the override.
func (c *Circuit) Force(execID string, state State) (State, bool) {
	if execID == "" {
		return Pristine, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	prev := c.states[execID]
	if prev == state {
		return prev, false
	}
	c.states[execID] = state
	return prev, true
}
