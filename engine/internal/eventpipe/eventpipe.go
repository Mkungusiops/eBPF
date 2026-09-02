// Package eventpipe carries a Tetragon event from the wire to the four places
// that have to see it: the process tree that scores the chain, the event store
// the console reads, the SSE broadcast the live view follows, and the choke
// gateway that may act on it.
//
// It exists because cmd/engine and cmd/agent each carried their own copy of
// this path, differing only in three lines that tee records to the
// control-plane uplink. That is the most dangerous kind of duplication in this
// tree: the alert-escalation guard here was fixed once (per-event alerting made
// 91 of 100 alerts critical on a measured run) and the second copy had to be
// found and fixed by hand afterwards. A scoring or gateway-dispatch change that
// lands on one binary and not the other means two hosts running the same
// version disagree about whether a chain is worth containing.
//
// Ordering inside the handlers is behaviour, not style. The store insert
// happens before the broadcast so the console never receives an event id it
// cannot fetch, and the gateway dispatch happens on EVERY event regardless of
// the alert threshold so a process can be throttled before it has ever produced
// an alert.
package eventpipe

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
	"github.com/jeffmk/ebpf-poc-engine/internal/baseline"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/findings"
	"github.com/jeffmk/ebpf-poc-engine/internal/intel"
	"github.com/jeffmk/ebpf-poc-engine/internal/metrics"
	"github.com/jeffmk/ebpf-poc-engine/internal/score"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/sysproc"
	"github.com/jeffmk/ebpf-poc-engine/internal/tetrabridge"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// Pipeline holds everything one host's sensing path writes to. Construct it
// once at the end of startup and call Handle for each event off the stream.
type Pipeline struct {
	// Store is the local event/alert record. Insert failures abort the rest of
	// the path for that event: an event with no id cannot be correlated, and
	// broadcasting one would put a row on the console that no drill-down can
	// resolve.
	Store *store.Store
	// Tree is the in-memory process tree that accumulates chain scores.
	Tree *tree.Tree
	// Broadcast feeds the console's SSE stream. Sends are best-effort; see
	// tetrabridge.Send for why the loop must never block on a slow subscriber.
	Broadcast chan<- api.Broadcast
	// Gateway is the process choke gateway. nil disables dispatch entirely,
	// which is what a test or a not-yet-wired startup gets.
	Gateway *choke.Gateway

	// EventSink and AlertSink tee records to the control-plane uplink. Both
	// are nil on a standalone host, and that is the autonomy contract in code:
	// the uplink is additive, never a step the enforcement path waits on.
	EventSink func(*store.Event)
	AlertSink func(*store.Alert)

	// Baseline is the host's learned behavioural profile. nil disables
	// behavioural scoring entirely, which is what a test or an older wiring
	// gets — every enrichment field here is independently optional, so a
	// deployment that configures neither behaves exactly as it did before.
	Baseline *baseline.Profile
	// Intel is the loaded indicator set. nil disables indicator matching.
	Intel *intel.Set
	// Hasher computes binary digests for hash-feed matching. Consulted ONLY
	// for binaries the baseline flags as novel — see hashIfNovel for why that
	// gating is what makes the feature affordable on the event path.
	Hasher *intel.Hasher
	// Findings is the bounded ring of recent enrichment results the console
	// and the assistant read. nil discards them; scoring is unaffected.
	Findings *findings.Ring

	// suppress holds the operator's own scoring suppressions. Nil is a valid
	// state — a pipeline built without one simply applies no operator rules,
	// which is the same fail-open posture the loader takes.
	suppress *suppressor
}

// chainAnomalyBudget caps how much BEHAVIOURAL score one process chain may
// accumulate, across every event on it.
//
// 25 sits above the high band (20) and below critical (40). A chain that is
// behaviourally novel from top to bottom can therefore reach high on novelty
// alone — which is right, that is a genuinely unusual session — but reaching
// CRITICAL, the band that drives the harshest containment, always requires
// corroboration from a rule hit or an indicator match. Novelty is evidence, not
// a verdict, and a host in the middle of a package upgrade must not be able to
// contain its own package manager.
const chainAnomalyBudget = 25

// Consume drains the Tetragon stream until it closes, then returns.
//
// A Recv error ends the run rather than retrying, which is what both build
// targets already did: the caller's deferred cleanup includes flipping the
// metrics gauge and /api/system-health to disconnected, and an operator has to
// see that this host has stopped sensing. Reconnecting quietly in here would
// leave the console showing a healthy agent that is receiving nothing.
func (p *Pipeline) Consume(stream tetragon.FineGuidanceSensors_GetEventsClient) {
	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Printf("stream closed: %v", err)
			return
		}
		p.Handle(resp)
	}
}

// Handle routes one event off the Tetragon stream. Event kinds this build does
// not score are ignored rather than logged — the stream carries everything the
// daemon sees, and logging the remainder would drown the ones that matter.
func (p *Pipeline) Handle(resp *tetragon.GetEventsResponse) {
	switch ev := resp.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		p.HandleExec(ev.ProcessExec)
	case *tetragon.GetEventsResponse_ProcessKprobe:
		p.HandleKprobe(ev.ProcessKprobe)
	case *tetragon.GetEventsResponse_ProcessExit:
		tetrabridge.HandleExit(ev.ProcessExit, p.Broadcast)
		p.HandleExit(ev.ProcessExit)
	}
}

// HandleExit releases the per-process enforcement state of a process that has
// died.
//
// # Why this is a correctness fix and not housekeeping
//
// Gateway.Forget has always deleted the process's row from the kernel choke
// map, and its own doc said "wire to process_exit events in the engine". It
// was never wired: the only caller was the operator's manual Forget button.
// So every choked process left its bucket in the map for the life of the
// engine — measured on the live estate as rows still rate-limiting two PIDs
// that no longer existed.
//
// Linux recycles PIDs. An unrelated process that lands on a recycled PID
// inherits a bucket it never earned, complete with exhausted tokens, and is
// throttled by a decision taken about something else entirely. Nothing in the
// console attributes that to a cause, because as far as the audit chain is
// concerned no decision was ever taken about the new process. That is the
// worst shape of enforcement bug this product can have: real, silent, and
// unattributable.
//
// It also makes the console honest. The state ladder counted dead processes as
// throttled, so "7 throttled" could mean seven processes that no longer exist.
func (p *Pipeline) HandleExit(ev *tetragon.ProcessExit) {
	if p.Gateway == nil || ev == nil || ev.Process == nil {
		return
	}
	p.Gateway.Forget(ev.Process.ExecId, ev.Process.Pid.GetValue())
}

// HandleExec records a process exec: it joins the chain in the process tree,
// scores it, persists it, and lets the gateway decide whether the chain has
// earned a choke.
func (p *Pipeline) HandleExec(ev *tetragon.ProcessExec) {
	if ev == nil || ev.Process == nil {
		return
	}
	pr := ev.Process
	parentID := ""
	if ev.Parent != nil {
		parentID = ev.Parent.ExecId
	}
	// Resolved once, here, and used for the tree node, the score, the baseline
	// and the stored event alike — so every layer reasons about, and the
	// console displays, the same executable. See effectiveBinary.
	binary := effectiveBinary(pr.Binary, pr.Pid.GetValue())
	node := &tree.Node{
		ExecID:    pr.ExecId,
		PID:       pr.Pid.GetValue(),
		ParentID:  parentID,
		Binary:    binary,
		Args:      pr.Arguments,
		UID:       pr.Uid.GetValue(),
		StartTime: time.Now(),
	}
	p.Tree.Add(node)

	delta, reason, finding := score.Score("process_exec", binary, pr.Arguments, "", pr.Uid.GetValue())

	// Operator suppressions apply to exec scoring as well: "our deploy tool
	// runs as root and that is expected here" is the same class of statement.
	if delta > 0 && p.suppress != nil {
		if rule, ok := p.suppress.Suppressed(binary, "", p.parentBinary(pr.ExecId, ev.Parent)); ok {
			delta, finding = 0, ""
			reason = suppressionReason(rule)
			metrics.IncEvent("operator_suppressed")
		}
	}
	if delta > 0 {
		p.Tree.AddScore(pr.ExecId, delta, "process_exec")
	}

	parentPID := uint32(0)
	parentBinary := ""
	if ev.Parent != nil {
		parentPID = ev.Parent.Pid.GetValue()
		// Resolved too: the baseline's highest-value facet is the parent→child
		// edge, and an unresolved parent makes every edge below a re-exec
		// unique per run. That is how "/proc/self/fd" ended up as a parent in
		// the console's lineage reasons.
		parentBinary = effectiveBinary(ev.Parent.Binary, parentPID)
	}

	// Behavioural baseline and indicator matching, layered on the rule score.
	// Runs before checkAlert so an event the rules alone would leave below the
	// threshold can still alert when it is novel AND talking to a known-bad
	// address — the case a static rule table cannot express.
	enr := p.enrichExec(pr.ExecId, binary, parentBinary, pr.Arguments,
		pr.Uid.GetValue(), pr.Pid.GetValue(), node.StartTime)

	e := &store.Event{
		Timestamp: time.Now(),
		EventType: "process_exec",
		PID:       pr.Pid.GetValue(),
		ParentPID: parentPID,
		ExecID:    pr.ExecId,
		Binary:    binary,
		Args:      pr.Arguments,
		UID:       pr.Uid.GetValue(),
	}
	id, err := p.Store.InsertEvent(e)
	if err != nil {
		log.Printf("insert event: %v", err)
		return
	}
	e.ID = id

	p.enqueueEvent(e)
	metrics.IncEvent("process_exec")
	tetrabridge.Send(p.Broadcast, api.Broadcast{Type: "event", Payload: e})
	p.checkAlert(pr.ExecId, reason, finding, enr)
}

// HandleKprobe records a policy-triggered kernel probe — the file reads,
// privilege changes, and outbound connections the TracingPolicies watch for.
func (p *Pipeline) HandleKprobe(ev *tetragon.ProcessKprobe) {
	if ev == nil || ev.Process == nil {
		return
	}
	pr := ev.Process
	policyName := ev.PolicyName

	argStr := tetrabridge.ExtractKprobeArgs(ev.Args)
	// The peer as its own value, not a substring of argStr. Args keeps it too,
	// so nothing that reads the flattened form regresses.
	peerAddr, peerPort := tetrabridge.ExtractKprobePeer(ev.Args)
	binary := effectiveBinary(pr.Binary, pr.Pid.GetValue())

	// A kprobe can be the FIRST event this pipeline ever sees for an exec_id,
	// and until that id has a tree node its score has nowhere to land.
	//
	// The case that matters is a privilege transition inside a fork. sudo does
	// not call setuid(0) in the process the shell exec'd: it fork()s, and the
	// CHILD calls setuid(0) in the window between clone() and execve().
	// Tetragon gives that child its own exec_id (exec_id is nodename:ktime:pid
	// and the ktime is new) and never emits a ProcessExec for it — the v1.6.1
	// gRPC API has no clone event at all. So AddScore below looked the id up,
	// missed, returned a (nil, false) that nobody checked, and the 15 points
	// for T1548 were dropped on the floor.
	//
	// Measured on the live engine 2026-08-22: 22 of 22 privilege-escalation
	// kprobes on /usr/bin/sudo had no matching exec, and ChainScore returned 0
	// for every one. The only setuid alerts the box produced came from
	// sshd-auth, which survives purely because sshd-session execve()s it, so
	// its exec_id IS in the tree (9 of 9 matched).
	//
	// ev.Parent is the exec'd parent, so the synthesised node joins the real
	// chain and ChainScore inherits everything above it. AddIfAbsent, not Add:
	// a genuine exec for this id must win if one ever arrives.
	if p.Tree != nil {
		kparentID := ""
		if ev.Parent != nil {
			kparentID = ev.Parent.ExecId
		}
		if p.Tree.AddIfAbsent(&tree.Node{
			ExecID:    pr.ExecId,
			PID:       pr.Pid.GetValue(),
			ParentID:  kparentID,
			Binary:    binary,
			Args:      pr.Arguments,
			UID:       pr.Uid.GetValue(),
			StartTime: time.Now(),
		}) {
			metrics.IncEvent("kprobe_synthesised_node")
		}
	}

	delta, reason, finding := score.Score("process_kprobe", binary, argStr, policyName, pr.Uid.GetValue())

	// The host's own login stack reading the shadow file is not a finding.
	// Resolved from the tree first and the event second: Tetragon populates
	// ev.Parent, but the tree is the authority on the chain everywhere else in
	// this file, and a kprobe whose exec we missed still has an ancestor there.
	// See score.IsAuthStackCredentialRead for the measurement behind this.
	parent := p.parentBinary(pr.ExecId, ev.Parent)
	if delta > 0 && (score.IsAuthStackCredentialRead(binary, parent, policyName) ||
		score.IsRoutinePrivilegeTransition(binary, policyName)) {
		delta, reason, finding = 0, "", ""
		metrics.IncEvent("auth_stack_suppressed")
	}

	// The OPERATOR'S own suppressions, applied after the built-in ones.
	//
	// The two above are universal — every Linux host's login stack reads
	// /etc/shadow. These are the patterns true of ONE estate: a backup agent
	// that reads credential paths, a config tool that calls setuid on a
	// schedule. Without a way to say so a customer either lives with the noise
	// or disarms the platform, and they disarm it.
	//
	// Only the SCORE is withheld. The event is still recorded, the chain is
	// still in the tree, and the binary can still be contained by hand — the
	// score is what drives AUTOMATIC action, and that is the only thing being
	// asked to stop.
	if delta > 0 && p.suppress != nil {
		if rule, ok := p.suppress.Suppressed(binary, policyName, parent); ok {
			delta, finding = 0, ""
			reason = suppressionReason(rule)
			metrics.IncEvent("operator_suppressed")
		}
	}

	if delta > 0 {
		if _, ok := p.Tree.AddScore(pr.ExecId, delta, "process_kprobe:"+policyName); !ok {
			// Unreachable after the synthesis above. Counted rather than
			// ignored because this exact silent drop cost the platform its
			// T1548 detection once already, and a discarded (nil, false) is
			// invisible in every log and every dashboard.
			metrics.IncEvent("score_dropped_no_node")
		}
	}

	// An outbound-connections event carries the destination of a connection
	// that actually happened, which is the strongest observable this platform
	// produces. Matched at full weight; the same address merely named on a
	// command line is halved.
	enr := p.enrichKprobe(pr.ExecId, policyName, binary, argStr, pr.Pid.GetValue(), time.Now())

	e := &store.Event{
		Timestamp:  time.Now(),
		EventType:  "process_kprobe",
		PID:        pr.Pid.GetValue(),
		ExecID:     pr.ExecId,
		Binary:     binary,
		Args:       argStr,
		PeerIP:     peerAddr,
		PeerPort:   peerPort,
		UID:        pr.Uid.GetValue(),
		PolicyName: policyName,
	}
	id, err := p.Store.InsertEvent(e)
	if err != nil {
		log.Printf("insert event: %v", err)
		return
	}
	e.ID = id

	p.enqueueEvent(e)
	metrics.IncEvent("process_kprobe")
	tetrabridge.Send(p.Broadcast, api.Broadcast{Type: "event", Payload: e})
	p.checkAlert(pr.ExecId, reason, finding, enr)
}

// effectiveBinary returns the executable path to REASON about for a process.
//
// Tetragon reports the executable as the kernel sees it, and a process that
// re-exec'd through a file descriptor is reported as "/proc/self/fd/<n>". That
// is not an identity: it names a descriptor number, it differs run to run, and
// no path-based rule can match it.
//
// Measured on the live engine 2026-08-21, this cost real accuracy in three
// separate places at once:
//
//   - systemd's own re-exec ("--deserialize 43", parent PID 1) read /etc/passwd
//     and /etc/shadow eleven times, scored 109 and alerted CRITICAL — the auth
//     suppression could not recognise it because the path was not systemd's;
//   - the behavioural baseline keyed it as the "executable" `9`, which reached
//     6,116 observations and collided with every other numeric basename;
//   - the console attributed the alert to "/proc/self/fd/9", which is not a
//     process an analyst can look up or act on.
//
// So the fd path is resolved back to the real one through /proc/<pid>/exe. The
// lookup is gated on the "/proc/" prefix, so the common path costs one string
// comparison and nothing else; a process that has already exited resolves to ""
// and the caller keeps the kernel-reported path rather than inventing one.
func effectiveBinary(binary string, pid uint32) string {
	if !strings.HasPrefix(binary, "/proc/") {
		return binary
	}
	if resolved := sysproc.ResolveExe(pid); resolved != "" {
		return resolved
	}
	return binary
}

// parentBinary resolves the immediate parent's executable path for an event.
//
// The tree is consulted first because it is the authority on the chain
// everywhere else in this file, and it holds the parent even when the daemon
// sends a kprobe whose parent block is absent. evParent is the fallback for the
// window before an exec has been folded in.
func (p *Pipeline) parentBinary(execID string, evParent *tetragon.Process) string {
	if p.Tree != nil {
		if n, ok := p.Tree.Get(execID); ok && n.ParentID != "" {
			if parent, ok := p.Tree.Get(n.ParentID); ok && parent.Binary != "" {
				return parent.Binary
			}
		}
	}
	if evParent != nil {
		return effectiveBinary(evParent.Binary, evParent.Pid.GetValue())
	}
	return ""
}

func (p *Pipeline) enqueueEvent(e *store.Event) {
	if p.EventSink != nil {
		p.EventSink(e)
	}
}

func (p *Pipeline) enqueueAlert(a *store.Alert) {
	if p.AlertSink != nil {
		p.AlertSink(a)
	}
}

func (p *Pipeline) checkAlert(execID, reason, finding string, enr enrichment) {
	chainScore := p.Tree.ChainScore(execID)

	// Gateway runs on every event regardless of alert threshold so a process
	// can transition to "throttled" before it ever produces an alert. The
	// gateway is monotonic — repeated calls below threshold are no-ops.
	p.dispatchGateway(execID, chainScore, reason)

	if chainScore < 10 {
		return
	}

	// Enrichment supplies a finding of its own when the rules produced none.
	//
	// Without this, an event whose ONLY signal is enrichment — a never-seen
	// binary reaching a known C2 address, matching no rule — carries an empty
	// finding, and EscalateAlert's per-chain reason set cannot tell it from any
	// other unscored event on the same chain. The alert would be suppressed as
	// a duplicate of something it has nothing in common with. The finding is
	// the enrichment KIND, not the full reason text, for the reason the scorer
	// already learned: a finding that embeds a path or an address is unique per
	// event and deduplicates nothing.
	if finding == "" {
		switch {
		case len(enr.matches) > 0:
			finding = "threat-intel-match"
		case len(enr.reasons) > 0:
			finding = "behavioural-anomaly"
		}
	}
	if reason == "" {
		reason = enr.describe()
	} else if extra := enr.describe(); extra != "" {
		reason = reason + " — " + extra
	}
	// Alert on an escalation in severity, or on a finding this chain has not
	// reported before — not on every event. Chain scores are cumulative and
	// never fall, so alerting on each event above the threshold made 91 of 100
	// alerts critical on a measured run, and an operator could not tell an
	// escalation from noise. Enforcement is untouched: dispatchGateway above
	// runs on every event regardless.
	if !p.Tree.EscalateAlert(execID, score.Band(chainScore), finding) {
		return
	}
	severity := score.Severity(chainScore)
	chain := p.Tree.Ancestors(execID, 8)
	binaries := make([]string, 0, len(chain))
	for _, n := range chain {
		binaries = append(binaries, n.Binary)
	}
	title := fmt.Sprintf("Suspicious chain: %s (score %d)", strings.Join(binaries, " → "), chainScore)
	a := &store.Alert{
		Timestamp:   time.Now(),
		Severity:    severity,
		Title:       title,
		Description: reason,
		ExecID:      execID,
		Score:       chainScore,
	}
	id, err := p.Store.InsertAlert(a)
	if err != nil {
		log.Printf("insert alert: %v", err)
		return
	}
	a.ID = id
	p.enqueueAlert(a)
	metrics.IncAlert(severity)
	tetrabridge.Send(p.Broadcast, api.Broadcast{Type: "alert", Payload: a})
	log.Printf("[ALERT %s] %s", severity, title)
}

// dispatchGateway calls the choke gateway with the latest chain score for an
// exec_id. Looks up the node in the process tree to get the canonical
// PID/binary so the enforcer has a real target. nil-safe: if the gateway isn't
// initialised (early init or tests) this is a no-op.
func (p *Pipeline) dispatchGateway(execID string, chainScore int, reason string) {
	if p.Gateway == nil {
		return
	}
	n, ok := p.Tree.Get(execID)
	if !ok {
		return
	}
	p.Gateway.OnEvent(context.Background(), choke.Observation{
		ExecID: execID,
		PID:    n.PID,
		Binary: n.Binary,
		Score:  chainScore,
		Reason: reason,
	})
}

// SetSuppressions installs the operator's suppression set, replacing any
// previous one. Called at startup and whenever the settings surface changes a
// rule, so a new suppression takes effect without a restart — the whole point
// of it being a setting rather than a config file.
func (p *Pipeline) SetSuppressions(rules []store.Suppression) {
	if p.suppress == nil {
		p.suppress = newSuppressor()
	}
	p.suppress.Reload(rules)
}

// SuppressionHits reports how often each rule has fired since start, so the
// settings page can show which rules are doing work and which are dead.
func (p *Pipeline) SuppressionHits() map[int64]int64 {
	if p.suppress == nil {
		return nil
	}
	return p.suppress.Hits()
}
