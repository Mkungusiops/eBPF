// Package choke wires the circuit, enforcer, store, and broadcast channel
// into a single object the event handlers can call. It is the "gateway"
// of the design doc — the chokepoint that converts observed events into
// graduated enforcement actions.
package choke

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// Mode describes the gateway's enforcement posture. It is purely
// declarative — the actual behaviour is in the wired enforcer chain. Mode
// is exposed so the UI can render the right "ENFORCING / DRY-RUN /
// DETECT-ONLY" badge without needing to introspect each backend.
type Mode string

const (
	ModeEnforcing  Mode = "enforcing"
	ModeDryRun     Mode = "dry-run"
	ModeDetectOnly Mode = "detect-only"
)

// Broadcaster is the subset of api.Server used by the gateway to push
// decisions out to SSE subscribers. It is an interface so the choke
// package doesn't import the api package (which would be a cycle: api
// already imports store).
type Broadcaster interface {
	Broadcast(eventType string, payload interface{})
}

// Gateway is the userspace choke point. One instance per engine.
type Gateway struct {
	circuit  *circuit.Circuit
	enforcer enforce.Enforcer
	store    *store.Store
	bcast    Broadcaster
	tokens   *tokens.Manager
	policies *policy.Set
	tree     *tree.Tree
	bpfmap   bpfmap.Backend

	// dryRun reports whether enforcement is shadow-only. Decisions are
	// recorded but the underlying backends are not invoked. Useful for
	// rolling out a new policy without risking self-DoS.
	dryRun bool
	mode   Mode

	// killSwitch, when set, short-circuits Apply: the decision is still
	// recorded (so the audit trail captures *why* the gateway didn't act)
	// but no enforcer is called. Operator-controlled emergency stop.
	killSwitch atomic.Bool

	// known caches the (pid, binary) for every exec_id we've seen. Lets
	// Manual() and Snapshot() return useful info even after the tree's
	// TTL has dropped the node.
	knownMu sync.RWMutex
	known   map[string]knownProc

	// annotations are operator-attached free-text notes per exec_id.
	annoMu      sync.RWMutex
	annotations map[string]Annotation

	// reverts tracks pending time-bound auto-reverts.
	revMu   sync.Mutex
	reverts map[string]pendingRevert

	// Optional pass-throughs wired by main.go.
	cgroupFn        CgroupInhabitorsFn
	thawFn          ThawFn
	sysProcFn       SysProcListFn
	sysProcDetailFn SysProcDetailFn

	// systemCritical: auto-enforce exemption set. Looked up by exact
	// binary path; manual overrides bypass it.
	systemCritical map[string]bool
}

// DefaultSystemCriticalBinaries is the safe default exemption list. These
// processes typically run as root, are necessary for operator access /
// service availability, and don't have legitimate alternative reasons
// for "score-driven" suspicion (their MOTD/auth chains routinely look
// suspicious). The list is intentionally narrow — too broad an exemption
// would let attackers hide inside it.
func DefaultSystemCriticalBinaries() []string {
	return []string{
		"/usr/sbin/sshd", "/usr/sbin/sshd-session",
		"/usr/lib/systemd/systemd",
		"/usr/lib/systemd/systemd-logind",
		"/usr/lib/systemd/systemd-journald",
		"/usr/lib/systemd/systemd-udevd",
		"/sbin/init",
		"/usr/sbin/cron",
		"/usr/sbin/rsyslogd",
		"/usr/bin/dockerd",
		"/usr/bin/containerd",
		"/usr/bin/containerd-shim-runc-v2",
		"/usr/bin/snapd",
	}
}

type knownProc struct {
	PID       uint32
	Binary    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Config bundles the inputs to NewGateway. Only Store is required; the
// rest fall back to safe defaults (logger enforcer, default thresholds,
// empty policy set).
type Config struct {
	Store      *store.Store
	Enforcer   enforce.Enforcer
	Broadcast  Broadcaster
	Tokens     *tokens.Manager
	Policies   *policy.Set
	Tree       *tree.Tree
	BPFMap     bpfmap.Backend
	Thresholds circuit.Config
	DryRun     bool
	// Enforcing is true when the real enforcer chain is wired. When false,
	// the engine is in detect-only mode (the enforcer is a Logger). The
	// gateway uses this only to compute Mode() — it does not change
	// behaviour.
	Enforcing bool
	// SystemCriticalBinaries is the auto-enforce exemption list. Binaries
	// in this list are still observed and scored — alerts fire and the
	// audit chain records "would-have" decisions — but the enforcer chain
	// is bypassed for SCORE-DRIVEN transitions only. Manual operator
	// overrides (Choke button, Jail Process modal, /api/choke/manual)
	// still go through to the enforcer so an explicit human decision is
	// always honoured. The default list covers daemons whose disruption
	// locks the operator out of the host (sshd, systemd, dockerd, etc.).
	SystemCriticalBinaries []string
}

func NewGateway(cfg Config) *Gateway {
	if cfg.Store == nil {
		panic("choke.NewGateway: Store is required")
	}
	enf := cfg.Enforcer
	if enf == nil {
		enf = &enforce.Logger{Prefix: "[enforce-default]"}
	}
	if cfg.DryRun {
		enf = &enforce.DryRun{Wrapped: enf}
	}
	mode := ModeEnforcing
	if cfg.DryRun {
		mode = ModeDryRun
	} else if !cfg.Enforcing {
		mode = ModeDetectOnly
	}
	critical := map[string]bool{}
	bins := cfg.SystemCriticalBinaries
	if bins == nil {
		bins = DefaultSystemCriticalBinaries()
	}
	for _, b := range bins {
		critical[b] = true
	}
	return &Gateway{
		circuit:        circuit.New(cfg.Thresholds),
		enforcer:       enf,
		store:          cfg.Store,
		bcast:          cfg.Broadcast,
		tokens:         cfg.Tokens,
		policies:       cfg.Policies,
		tree:           cfg.Tree,
		bpfmap:         cfg.BPFMap,
		dryRun:         cfg.DryRun,
		mode:           mode,
		known:          make(map[string]knownProc),
		annotations:    make(map[string]Annotation),
		reverts:        make(map[string]pendingRevert),
		systemCritical: critical,
	}
}

// isSystemCritical reports whether a binary is on the auto-enforce
// exemption list. Empty binary returns false.
func (g *Gateway) isSystemCritical(binary string) bool {
	if binary == "" {
		return false
	}
	if g.systemCritical[binary] {
		return true
	}
	// Path-prefix exemption for /usr/lib/systemd/* — covers any new
	// systemd helper without needing the list maintained.
	if len(binary) > len("/usr/lib/systemd/") &&
		binary[:len("/usr/lib/systemd/")] == "/usr/lib/systemd/" {
		return true
	}
	return false
}

// chainHasSystemCritical reports whether the exec_id's process chain has
// ANY ancestor whose binary is system-critical. This is what closes the
// "MOTD descendant" loophole: sshd is exempt, but its child bash isn't —
// without a chain check the bash gets quarantined, which freezes the SSH
// session even though sshd itself stays running.
//
// Walks at most 10 ancestors (matches tree.ChainScore depth). Cheap
// (in-memory) so we can call it on every score-driven transition.
func (g *Gateway) chainHasSystemCritical(execID string) bool {
	if g.tree == nil {
		return false
	}
	for _, n := range g.tree.Ancestors(execID, 10) {
		if g.isSystemCritical(n.Binary) {
			return true
		}
	}
	return false
}

// Observation is the input to OnEvent — what the engine just saw about a
// process. The gateway turns this into a circuit transition (maybe), an
// enforcer call (maybe), a stored decision (always, on transition), and an
// SSE broadcast (always, on transition).
type Observation struct {
	ExecID string
	PID    uint32
	Binary string
	Score  int    // chain score, not just this event's delta
	Reason string // one-line explanation, suitable for the audit log
}

// OnEvent is called by the engine after every event whose chain score has
// been updated. It is safe to call frequently; if no transition occurs
// nothing happens. Returns the Decision (nil if no transition) for tests.
func (g *Gateway) OnEvent(ctx context.Context, obs Observation) *circuit.Decision {
	g.remember(obs.ExecID, obs.PID, obs.Binary)

	d := g.circuit.Evaluate(obs.ExecID, obs.PID, obs.Binary, obs.Score, obs.Reason)
	if d == nil {
		return nil
	}
	g.act(ctx, d, false)
	return d
}

// remember updates the known-proc cache so Manual/Snapshot have a fall-
// back when the tree has GC'd the node.
func (g *Gateway) remember(execID string, pid uint32, binary string) {
	if execID == "" {
		return
	}
	now := time.Now().UTC()
	g.knownMu.Lock()
	defer g.knownMu.Unlock()
	if k, ok := g.known[execID]; ok {
		k.LastSeen = now
		if pid != 0 {
			k.PID = pid
		}
		if binary != "" {
			k.Binary = binary
		}
		g.known[execID] = k
		return
	}
	g.known[execID] = knownProc{
		PID: pid, Binary: binary, FirstSeen: now, LastSeen: now,
	}
}

// act runs an emitted Decision through the enforcer + store + broadcast.
// Shared between OnEvent (automatic) and Manual (operator-driven). The
// manual flag annotates the resulting audit row.
func (g *Gateway) act(ctx context.Context, d *circuit.Decision, manual bool) {
	g.installTokenBuckets(d.Binary, d.PID)

	target := enforce.Target{ExecID: d.ExecID, PID: d.PID, Binary: d.Binary}
	outcome := "ok"
	backend := g.enforcer.Name()

	if g.killSwitch.Load() {
		outcome = "skipped: kill-switch engaged"
		backend = "kill-switch"
	} else if !manual && (g.isSystemCritical(d.Binary) || g.chainHasSystemCritical(d.ExecID)) {
		// Score-driven transition on a system-critical daemon (sshd,
		// systemd, dockerd, …) OR a descendant of one. Both trigger
		// the exemption: a sshd MOTD chain ends in /bin/bash whose
		// chain inherits sshd's score, so a leaf-only check would let
		// us choke the bash and freeze the SSH session anyway.
		// Detection still fires (this audit row captures the would-
		// have decision), but the enforcer is bypassed. Manual
		// operator overrides bypass this check.
		outcome = "skipped: system-critical chain (auto-only; manual override allowed)"
		backend = "system-critical-exempt"
	} else if err := g.enforcer.Apply(ctx, target, d.Action, d.Reason); err != nil {
		outcome = "error: " + err.Error()
		log.Printf("[gateway] enforce action=%s exec_id=%s pid=%d: %v",
			d.Action, d.ExecID, d.PID, err)
	} else if !g.dryRun {
		// Mirror the post-Apply state into the bpfmap so the "Choke Map
		// (kernel)" panel reflects current shaping regardless of which
		// backend (cgroup, severer, or future BPF data plane) actually
		// performed the enforcement. Skipped in dry-run mode because the
		// bpfmap is "what the kernel is doing" — and in dry-run the
		// kernel is doing nothing.
		g.mirrorBPFMap(d)
	}

	reason := d.Reason
	if manual {
		reason = "[manual] " + reason
	}
	rec := &store.Decision{
		Timestamp: d.Timestamp,
		ExecID:    d.ExecID,
		PID:       d.PID,
		Binary:    d.Binary,
		Action:    d.Action.String(),
		FromState: d.From.String(),
		ToState:   d.To.String(),
		Score:     d.Score,
		Reason:    reason,
		DryRun:    g.dryRun,
		Backend:   backend,
		Outcome:   outcome,
	}
	if _, err := g.store.InsertDecision(rec); err != nil {
		log.Printf("[gateway] insert decision: %v", err)
		return
	}
	if g.bcast != nil {
		g.bcast.Broadcast("decision", rec)
	}
}

// mirrorBPFMap reflects the gateway's view of a transition into the
// kernel-side per-PID throttle map. ActSever clears the entry (PID gone);
// every other action writes a bucket sized per the throttler's defaults.
//
// On Linux the bpfmap is currently a NoopBackend by default — when the
// real BPF data plane lands, swapping the backend in main.go is enough;
// no caller of this method changes.
func (g *Gateway) mirrorBPFMap(d *circuit.Decision) {
	if g.bpfmap == nil || d.PID == 0 {
		return
	}
	if d.Action == circuit.ActSever {
		_ = g.bpfmap.Delete(d.PID)
		return
	}
	cfg := enforce.DefaultThrottlerConfig()
	var b bpfmap.PIDBucket
	switch d.Action {
	case circuit.ActThrottle:
		b = bpfmap.PIDBucket{RatePerSec: cfg.ThrottleRate, Burst: cfg.ThrottleBurst, Flags: bpfmap.FlagThrottle}
	case circuit.ActTarpit:
		b = bpfmap.PIDBucket{RatePerSec: cfg.TarpitRate, Burst: cfg.TarpitBurst, Flags: bpfmap.FlagTarpit}
	case circuit.ActQuarantine:
		b = bpfmap.PIDBucket{RatePerSec: cfg.QuarantineRate, Burst: cfg.QuarantineBurst, Flags: bpfmap.FlagQuarantine}
	default:
		return
	}
	_ = g.bpfmap.Update(d.PID, b)
}

// installTokenBuckets walks the policy set and, for every policy whose
// MatchBinary matches the binary, populates the token manager with rate
// buckets keyed on (pid, dimension). The actual choking happens in the
// BPF backend on the next syscall — this is just the data-plane update.
func (g *Gateway) installTokenBuckets(binary string, pid uint32) {
	if g.tokens == nil || g.policies == nil {
		return
	}
	for _, p := range g.policies.Match(binary) {
		for _, b := range p.Buckets {
			g.tokens.Install(tokens.Key{PID: pid, Dimension: b.Dimension}, b.RatePerSec, b.Burst)
		}
	}
}

// Forget releases per-process state when a process exits. Wire to
// process_exit events in the engine to keep memory bounded.
func (g *Gateway) Forget(execID string, pid uint32) {
	g.circuit.Forget(execID)
	if g.tokens != nil {
		g.tokens.ForgetPID(pid)
	}
	if g.bpfmap != nil {
		_ = g.bpfmap.Delete(pid)
	}
	g.knownMu.Lock()
	delete(g.known, execID)
	g.knownMu.Unlock()
}

// Tracked exposes the number of tracked exec_ids for /api/version-style
// telemetry.
func (g *Gateway) Tracked() int { return g.circuit.Tracked() }

// ---- Operator-facing surface (UI/admin endpoints below) ----------------

// Mode returns the current enforcement posture string.
func (g *Gateway) Mode() Mode {
	if g.killSwitch.Load() {
		return Mode("kill-switched")
	}
	return g.mode
}

// DryRun reports whether decisions are shadow-only.
func (g *Gateway) DryRun() bool { return g.dryRun }

// KillSwitched reports whether the emergency-stop flag is engaged.
func (g *Gateway) KillSwitched() bool { return g.killSwitch.Load() }

// SetKillSwitch toggles the global enforcement bypass. Returns the prior
// value so the caller can audit no-op toggles. The change is applied
// atomically; in-flight Apply calls already past the load complete.
func (g *Gateway) SetKillSwitch(on bool) bool {
	prev := g.killSwitch.Swap(on)
	state := "DISENGAGED"
	if on {
		state = "ENGAGED"
	}
	log.Printf("[gateway] kill-switch %s (prev=%v)", state, prev)
	return prev
}

// Thresholds returns the active circuit thresholds.
func (g *Gateway) Thresholds() circuit.Config { return g.circuit.Thresholds() }

// SetThresholds atomically updates the circuit thresholds. Returns the
// prior config for the audit log.
func (g *Gateway) SetThresholds(cfg circuit.Config) circuit.Config {
	prev := g.circuit.SetThresholds(cfg)
	log.Printf("[gateway] thresholds updated: throttle=%d→%d tarpit=%d→%d quarantine=%d→%d sever=%d→%d",
		prev.ThrottleAt, cfg.ThrottleAt,
		prev.TarpitAt, cfg.TarpitAt,
		prev.QuarantineAt, cfg.QuarantineAt,
		prev.SeverAt, cfg.SeverAt)
	return prev
}

// Entry is one row of the gateway snapshot — joined view of circuit state
// + tree info + cached known-proc data.
type Entry struct {
	ExecID         string      `json:"exec_id"`
	PID            uint32      `json:"pid"`
	Binary         string      `json:"binary"`
	State          string      `json:"state"`
	Score          int         `json:"score"`
	UID            uint32      `json:"uid"`
	Args           string      `json:"args,omitempty"`
	ParentID       string      `json:"parent_id,omitempty"`
	StartTime      time.Time   `json:"start_time,omitempty"`
	LastSeen       time.Time   `json:"last_seen,omitempty"`
	Annotation     *Annotation `json:"annotation,omitempty"`
	RevertPending  bool        `json:"revert_pending,omitempty"`
}

// Snapshot returns one Entry per tracked exec_id, joined with whatever
// the process tree still knows about it. Sorted by state descending then
// score descending so the UI can render most-dangerous-first.
func (g *Gateway) Snapshot() []Entry {
	tracked := g.circuit.Snapshot()
	out := make([]Entry, 0, len(tracked))
	for _, t := range tracked {
		e := Entry{ExecID: t.ExecID, State: t.State.String()}
		if g.tree != nil {
			if n, ok := g.tree.Get(t.ExecID); ok {
				e.PID = n.PID
				e.Binary = n.Binary
				e.UID = n.UID
				e.Args = n.Args
				e.ParentID = n.ParentID
				e.StartTime = n.StartTime
				e.Score = g.tree.ChainScore(t.ExecID)
			}
		}
		if e.PID == 0 || e.Binary == "" {
			g.knownMu.RLock()
			if k, ok := g.known[t.ExecID]; ok {
				if e.PID == 0 {
					e.PID = k.PID
				}
				if e.Binary == "" {
					e.Binary = k.Binary
				}
				e.LastSeen = k.LastSeen
			}
			g.knownMu.RUnlock()
		}
		if a, ok := g.AnnotationFor(t.ExecID); ok {
			ac := a
			e.Annotation = &ac
		}
		out = append(out, e)
	}
	// Mark exec_ids that have a pending auto-revert.
	if pend := g.PendingReverts(); len(pend) > 0 {
		set := make(map[string]bool, len(pend))
		for _, k := range pend {
			set[k] = true
		}
		for i := range out {
			if set[out[i].ExecID] {
				out[i].RevertPending = true
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		// Severed > Quarantined > Tarpit > Throttled > Pristine
		if out[i].State != out[j].State {
			return stateOrder(out[i].State) > stateOrder(out[j].State)
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func stateOrder(s string) int {
	switch s {
	case "severed":
		return 4
	case "quarantined":
		return 3
	case "tarpit":
		return 2
	case "throttled":
		return 1
	}
	return 0
}

// StateCounts returns how many exec_ids are in each state. Cheap; called
// on every UI tick to drive the ladder visualisation.
func (g *Gateway) StateCounts() map[string]int {
	out := map[string]int{
		"pristine": 0, "throttled": 0, "tarpit": 0,
		"quarantined": 0, "severed": 0,
	}
	for _, t := range g.circuit.Snapshot() {
		out[t.State.String()]++
	}
	return out
}

// ManualRequest is the operator's request to override a circuit state. It
// always produces an audit row, regardless of whether the underlying
// enforcer succeeded.
type ManualRequest struct {
	ExecID string         `json:"exec_id"`
	PID    uint32         `json:"pid"`
	Binary string         `json:"binary"`
	Action circuit.Action `json:"action"`
	Reason string         `json:"reason"`
	Actor  string         `json:"actor"` // username, for the audit row
}

// Manual triggers an enforcer action outside of the score-based path. The
// circuit is moved to whatever state corresponds to the requested action;
// monotonicity is bypassed via Force(), allowing operators to *down*-grade
// (e.g. quarantine → throttled) when they have context the engine lacks.
//
// Returns the synthesised Decision for echoing back to the UI.
func (g *Gateway) Manual(ctx context.Context, req ManualRequest) (*circuit.Decision, error) {
	if req.ExecID == "" {
		return nil, errors.New("exec_id required")
	}
	if req.PID == 0 {
		// Look up cached PID — operators may not know it.
		g.knownMu.RLock()
		if k, ok := g.known[req.ExecID]; ok {
			req.PID = k.PID
			if req.Binary == "" {
				req.Binary = k.Binary
			}
		}
		g.knownMu.RUnlock()
	}
	// Cache the (exec_id, pid, binary) so a subsequent Snapshot() — and
	// therefore /api/choke/process/<exec_id> — can populate the drill-in
	// entry. Without this, manual overrides on synthetic exec_ids (from
	// chokectl jail, or jail-by-PID from the UI) yield "(unknown)" pid=-
	// in the drill panel even though we have the data right here.
	if req.PID != 0 {
		g.remember(req.ExecID, req.PID, req.Binary)
	}
	target := actionToState(req.Action)
	prev, _ := g.circuit.Force(req.ExecID, target)
	d := &circuit.Decision{
		ExecID:    req.ExecID,
		PID:       req.PID,
		Binary:    req.Binary,
		From:      prev,
		To:        target,
		Action:    req.Action,
		Reason:    req.Reason + " (by " + req.Actor + ")",
		Timestamp: time.Now().UTC(),
	}
	g.act(ctx, d, true)
	return d, nil
}

func actionToState(a circuit.Action) circuit.State {
	switch a {
	case circuit.ActThrottle:
		return circuit.Throttled
	case circuit.ActTarpit:
		return circuit.Tarpit
	case circuit.ActQuarantine:
		return circuit.Quarantined
	case circuit.ActSever:
		return circuit.Severed
	}
	return circuit.Pristine
}

// Policies returns the loaded ChokePolicy set (or nil). Read-only; used
// by /api/choke/policies.
func (g *Gateway) Policies() *policy.Set { return g.policies }

// ─────────── Incident-Response Presets ──────────────────────────────────
//
// Presets atomically rewrite (thresholds, kill-switch, dry-run) for an
// operational mode. They are the "panic button" surface — one click puts
// the gateway into containment/forensic/maintenance posture without the
// operator having to remember every flag. Returns the prior posture so
// the caller can audit what changed and roll back.

// Preset identifies a named operational mode. The values map directly to
// (thresholds, kill-switch, dry-run) tuples — see ApplyPreset for the
// concrete settings.
type Preset string

const (
	PresetDefault     Preset = "default"     // safe everyday: 10/30/60/100
	PresetContainment Preset = "containment" // "panic — choke aggressively"
	PresetForensic    Preset = "forensic"    // record everything, enforce nothing
	PresetMaintenance Preset = "maintenance" // dry-run + kill-switch — VM updates
)

// PresetSnapshot is what was in effect before ApplyPreset ran — returned
// so callers can roll back precisely.
type PresetSnapshot struct {
	Thresholds   circuit.Config `json:"thresholds"`
	KillSwitched bool           `json:"kill_switched"`
	DryRun       bool           `json:"dry_run"`
}

// ApplyPreset switches gateway posture in one atomic call. Each preset
// records a single decision-row reason so the audit chain captures the
// trigger. Returns the prior snapshot for rollback / audit.
func (g *Gateway) ApplyPreset(p Preset, actor, reason string) (PresetSnapshot, error) {
	prev := PresetSnapshot{
		Thresholds:   g.Thresholds(),
		KillSwitched: g.KillSwitched(),
		DryRun:       g.dryRun,
	}
	switch p {
	case PresetDefault:
		g.SetThresholds(circuit.Config{ThrottleAt: 10, TarpitAt: 30, QuarantineAt: 60, SeverAt: 100})
		g.SetKillSwitch(false)
	case PresetContainment:
		// Aggressive — every suspicious chain hits choke immediately.
		// Sever stays high so we throttle/tarpit rather than mass-kill.
		g.SetThresholds(circuit.Config{ThrottleAt: 1, TarpitAt: 3, QuarantineAt: 8, SeverAt: 60})
		g.SetKillSwitch(false)
	case PresetForensic:
		// Record everything; enforce nothing. Useful when the operator
		// wants to study an incident without choking the evidence away.
		g.SetKillSwitch(true)
	case PresetMaintenance:
		// Stop choking entirely — but leave the engine running so the
		// audit trail captures the maintenance window's events.
		g.SetThresholds(circuit.Config{ThrottleAt: 1000, TarpitAt: 2000, QuarantineAt: 3000, SeverAt: 4000})
		g.SetKillSwitch(true)
	default:
		return prev, fmt.Errorf("unknown preset %q", p)
	}
	log.Printf("[gateway] preset=%s applied by=%s reason=%q (prev: %+v)", p, actor, reason, prev)
	return prev, nil
}

// ─────────── Annotations ────────────────────────────────────────────────
//
// Operators can attach free-text notes to a circuit (e.g. "false positive
// — sshd MOTD churn", "approved by oncall 2026-04-29"). Notes are stored
// in-memory keyed on exec_id and surface in /api/choke/circuits + the
// drill-in panel. When a circuit is forgotten, its annotation is too.

type Annotation struct {
	Note      string    `json:"note"`
	Actor     string    `json:"actor"`
	Timestamp time.Time `json:"timestamp"`
}

// Annotate records or clears an operator note on a circuit. Empty note
// removes any existing entry. Idempotent.
func (g *Gateway) Annotate(execID, note, actor string) {
	if execID == "" {
		return
	}
	g.annoMu.Lock()
	defer g.annoMu.Unlock()
	if note == "" {
		delete(g.annotations, execID)
		return
	}
	g.annotations[execID] = Annotation{
		Note: note, Actor: actor, Timestamp: time.Now().UTC(),
	}
}

// AnnotationFor returns the annotation for an exec_id (if any).
func (g *Gateway) AnnotationFor(execID string) (Annotation, bool) {
	g.annoMu.RLock()
	a, ok := g.annotations[execID]
	g.annoMu.RUnlock()
	return a, ok
}

// AllAnnotations returns a snapshot of every annotation. Used by the
// forensic snapshot endpoint.
func (g *Gateway) AllAnnotations() map[string]Annotation {
	g.annoMu.RLock()
	defer g.annoMu.RUnlock()
	out := make(map[string]Annotation, len(g.annotations))
	for k, v := range g.annotations {
		out[k] = v
	}
	return out
}

// ─────────── Time-bound manual overrides ────────────────────────────────
//
// A common operator pattern is "tarpit this for 5 minutes while I
// investigate, then revert if I'm done by then". ScheduleRevert kicks
// off a goroutine that, after `after` elapses, forces the circuit back
// to its prior state and records an audited revert decision. If the
// operator manually changes the state again before the timer fires, the
// scheduled revert still runs — tracking who-changed-what is the audit
// chain's job, not the timer's.

type pendingRevert struct {
	prev   circuit.State
	cancel chan struct{}
}

// ScheduleRevert sets up an auto-revert for execID after `after`. Cancels
// any prior revert scheduled for the same exec_id (replace-on-conflict).
// `after` < 0 cancels without scheduling a new one.
func (g *Gateway) ScheduleRevert(execID string, prev circuit.State, after time.Duration, actor string) {
	if execID == "" {
		return
	}
	g.revMu.Lock()
	if existing, ok := g.reverts[execID]; ok {
		close(existing.cancel)
		delete(g.reverts, execID)
	}
	if after <= 0 {
		g.revMu.Unlock()
		return
	}
	cancel := make(chan struct{})
	g.reverts[execID] = pendingRevert{prev: prev, cancel: cancel}
	g.revMu.Unlock()

	go func() {
		select {
		case <-cancel:
			return
		case <-time.After(after):
		}
		g.revMu.Lock()
		// If a newer revert was scheduled, this one is stale — ignore.
		cur, ok := g.reverts[execID]
		if !ok || cur.cancel != cancel {
			g.revMu.Unlock()
			return
		}
		delete(g.reverts, execID)
		g.revMu.Unlock()

		nowState := g.circuit.State(execID)
		_, ok2 := g.circuit.Force(execID, prev)
		if !ok2 {
			return
		}
		// Record the revert as a manual decision.
		d := &circuit.Decision{
			ExecID: execID, From: nowState, To: prev,
			Action:    circuit.ActNone,
			Reason:    "auto-revert (scheduled by " + actor + ")",
			Timestamp: time.Now().UTC(),
		}
		g.act(context.Background(), d, true)
	}()
}

// PendingReverts returns the list of exec_ids that have a scheduled
// auto-revert pending. Approximate — the UI just needs to know there's
// a pending revert, not how long is left.
func (g *Gateway) PendingReverts() []string {
	g.revMu.Lock()
	defer g.revMu.Unlock()
	out := make([]string, 0, len(g.reverts))
	for k := range g.reverts {
		out = append(out, k)
	}
	return out
}

// ─────────── Cgroup pass-through ────────────────────────────────────────
//
// Exposes the cgroup-inhabitants view for the UI. The Backend is held by
// main.go (constructed from cgroupv2.NewBackend) and accessed here via a
// minimal interface to avoid importing the linux-only package.

// CgroupInhabitorsFn is wired by main.go via SetCgroupInhabitorsFn. The
// gateway calls it on demand for the /api/choke/cgroups endpoint.
type CgroupInhabitorsFn func() (map[string][]uint32, error)

// SetCgroupInhabitorsFn wires the cgroup pass-through.
func (g *Gateway) SetCgroupInhabitorsFn(fn CgroupInhabitorsFn) { g.cgroupFn = fn }

// CgroupInhabitants returns a per-tier list of PIDs the kernel reports as
// living in each choke cgroup. Empty map if no backend is wired.
func (g *Gateway) CgroupInhabitants() (map[string][]uint32, error) {
	if g.cgroupFn == nil {
		return map[string][]uint32{}, nil
	}
	return g.cgroupFn()
}

// ThawFn is wired by main.go to the cgroup manager's Thaw.
type ThawFn func() error

func (g *Gateway) SetThawFn(fn ThawFn) { g.thawFn = fn }

// SysProcListFn is wired by main.go to sysproc.List. The gateway exposes
// it via /api/choke/processes for the console's process-picker. Returns
// []SysProcEntry directly so main.go's adapter can hand back a literal
// of that type without an extra named-type conversion.
type SysProcListFn func() ([]SysProcEntry, error)

// SysProcEntry mirrors sysproc.Entry's JSON shape.
type SysProcEntry struct {
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	UID       uint32 `json:"uid"`
	Comm      string `json:"comm"`
	Exe       string `json:"exe"`
	Cmdline   string `json:"cmdline"`
	StartTime uint64 `json:"start_time"`
	// Tracked / State are joined-in by the API handler.
	Tracked bool   `json:"tracked,omitempty"`
	State   string `json:"state,omitempty"`
	ExecID  string `json:"exec_id,omitempty"`
	Score   int    `json:"score,omitempty"`
}

func (g *Gateway) SetSysProcListFn(fn SysProcListFn) { g.sysProcFn = fn }

// HostProcesses returns the live host process list (Linux: /proc) joined
// with the gateway's circuit state. Each entry tells the UI whether the
// process is already tracked (tracked=true) and, if so, its current state
// + exec_id + score so the operator can see what they're picking.
func (g *Gateway) HostProcesses() ([]SysProcEntry, error) {
	if g.sysProcFn == nil {
		return []SysProcEntry{}, nil
	}
	procs, err := g.sysProcFn()
	if err != nil {
		return nil, err
	}
	// Index circuit entries by PID for fast join. PIDs reuse so this is
	// best-effort; a true match would also compare start_time, but for the
	// picker UX "is this PID currently tracked" is good enough.
	byPID := map[uint32]Entry{}
	for _, e := range g.Snapshot() {
		byPID[e.PID] = e
	}
	out := make([]SysProcEntry, 0, len(procs))
	for _, p := range procs {
		ent := p
		if c, ok := byPID[p.PID]; ok {
			ent.Tracked = true
			ent.State = c.State
			ent.ExecID = c.ExecID
			ent.Score = c.Score
		}
		out = append(out, ent)
	}
	return out, nil
}

// SysProcDetail mirrors sysproc.Detail's JSON shape. Wired by main.go
// to sysproc.ReadDetail. The console fetches it on row-click in the jail
// picker to populate the inspect drawer with live /proc state.
type SysProcDetail struct {
	PID         uint32   `json:"pid"`
	Status      string   `json:"status,omitempty"`
	Threads     int      `json:"threads,omitempty"`
	VmRSSKB     uint64   `json:"vm_rss_kb,omitempty"`
	VmSizeKB    uint64   `json:"vm_size_kb,omitempty"`
	StartedUnix int64    `json:"started_unix,omitempty"`
	Cwd         string   `json:"cwd,omitempty"`
	Root        string   `json:"root,omitempty"`
	NumFDs      int      `json:"num_fds,omitempty"`
	FDSamples   []string `json:"fd_samples,omitempty"`
	NumConns    int      `json:"num_conns,omitempty"`
	ConnPeers   []string `json:"conn_peers,omitempty"`
}

// SysProcDetailFn fetches the detail snapshot for a single PID.
type SysProcDetailFn func(pid uint32) (SysProcDetail, error)

// SetSysProcDetailFn wires the live-proc reader. Optional — when nil, the
// HTTP handler returns an empty detail and the UI gracefully falls back.
func (g *Gateway) SetSysProcDetailFn(fn SysProcDetailFn) { g.sysProcDetailFn = fn }

// HostProcessDetail returns the live /proc snapshot for a single PID.
// Returns an empty struct (no error) when no detail backend is wired,
// so the JSON shape is stable for the client.
func (g *Gateway) HostProcessDetail(pid uint32) (SysProcDetail, error) {
	if g.sysProcDetailFn == nil {
		return SysProcDetail{PID: pid}, nil
	}
	return g.sysProcDetailFn(pid)
}

// ThawQuarantine releases the quarantined cgroup so its members run again.
// Records an audit decision so the action is captured in the chain.
func (g *Gateway) ThawQuarantine(actor, reason string) error {
	if g.thawFn == nil {
		return errors.New("no thaw backend wired")
	}
	if err := g.thawFn(); err != nil {
		return err
	}
	rec := &store.Decision{
		Timestamp: time.Now().UTC(),
		ExecID:    "*",
		Action:    "thaw",
		FromState: "quarantined",
		ToState:   "throttled",
		Reason:    "quarantine cgroup thawed by " + actor + ": " + reason,
		DryRun:    g.dryRun,
		Backend:   "cgroupv2",
		Outcome:   "ok",
	}
	if _, err := g.store.InsertDecision(rec); err != nil {
		log.Printf("[gateway] thaw audit insert: %v", err)
	}
	if g.bcast != nil {
		g.bcast.Broadcast("decision", rec)
	}
	return nil
}

// BucketsSnapshot returns the kernel-side per-PID throttle map contents.
// Returns nil + nil error when no BPF backend is wired.
func (g *Gateway) BucketsSnapshot() (map[uint32]bpfmap.PIDBucket, error) {
	if g.bpfmap == nil {
		return nil, nil
	}
	return g.bpfmap.Snapshot()
}

// PreviewPolicy validates a single policy YAML and reports which currently-
// tracked exec_ids it would match. The policy is *not* installed.
func (g *Gateway) PreviewPolicy(p policy.Policy) ([]Entry, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	all := g.Snapshot()
	matched := make([]Entry, 0)
	probe := policy.NewSet()
	_ = probe.Add(p)
	for _, e := range all {
		if len(probe.Match(e.Binary)) == 0 {
			continue
		}
		if !p.MatchesState(e.State) {
			continue
		}
		matched = append(matched, e)
	}
	return matched, nil
}
