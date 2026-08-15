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
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/metrics"
	"github.com/jeffmk/ebpf-poc-engine/internal/score"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
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
}

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
	}
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
	node := &tree.Node{
		ExecID:    pr.ExecId,
		PID:       pr.Pid.GetValue(),
		ParentID:  parentID,
		Binary:    pr.Binary,
		Args:      pr.Arguments,
		UID:       pr.Uid.GetValue(),
		StartTime: time.Now(),
	}
	p.Tree.Add(node)

	delta, reason, finding := score.Score("process_exec", pr.Binary, pr.Arguments, "", pr.Uid.GetValue())
	if delta > 0 {
		p.Tree.AddScore(pr.ExecId, delta, "process_exec")
	}

	parentPID := uint32(0)
	if ev.Parent != nil {
		parentPID = ev.Parent.Pid.GetValue()
	}

	e := &store.Event{
		Timestamp: time.Now(),
		EventType: "process_exec",
		PID:       pr.Pid.GetValue(),
		ParentPID: parentPID,
		ExecID:    pr.ExecId,
		Binary:    pr.Binary,
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
	p.checkAlert(pr.ExecId, reason, finding)
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

	delta, reason, finding := score.Score("process_kprobe", pr.Binary, argStr, policyName, pr.Uid.GetValue())
	if delta > 0 {
		p.Tree.AddScore(pr.ExecId, delta, "process_kprobe:"+policyName)
	}

	e := &store.Event{
		Timestamp:  time.Now(),
		EventType:  "process_kprobe",
		PID:        pr.Pid.GetValue(),
		ExecID:     pr.ExecId,
		Binary:     pr.Binary,
		Args:       argStr,
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
	p.checkAlert(pr.ExecId, reason, finding)
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

func (p *Pipeline) checkAlert(execID, reason, finding string) {
	chainScore := p.Tree.ChainScore(execID)

	// Gateway runs on every event regardless of alert threshold so a process
	// can transition to "throttled" before it ever produces an alert. The
	// gateway is monotonic — repeated calls below threshold are no-ops.
	p.dispatchGateway(execID, chainScore, reason)

	if chainScore < 10 {
		return
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
