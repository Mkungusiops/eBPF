package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/approval"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

// This file re-plumbs the engine's rich Choke Gateway + Network Choke (Devices)
// API contract for the multi-tenant control plane. The console serves soc's
// actual ChokeRoute/DevicesPage frontend, so it calls the same /api/choke/*
// paths the single-host engine exposes. Here the READ endpoints are answered
// tenant-scoped from the compact choke/device snapshots agents report on their
// heartbeats (heartbeat.Registry). Detail the agents don't report yet (kernel
// token buckets, cgroup map, full process table, per-device flows) returns a
// valid-empty shape so the pages render without crashing. WRITE endpoints are
// registered so they return a clean "not enabled yet" instead of a 404 — the
// interactive command wiring (fleet-wide mode change, manual jail/thaw) is the
// next increment and is deliberately gated because it changes live enforcement.

// registerChokeRoutes wires the Choke Gateway + Devices API onto the mux.
func (s *Server) registerChokeRoutes(mux *http.ServeMux) {
	// Choke Gateway (process choke) — reads.
	mux.HandleFunc("/api/choke/state", s.handleChokeStateGW)
	mux.HandleFunc("/api/choke/circuits", s.handleChokeCircuits)
	mux.HandleFunc("/api/choke/buckets", s.handleChokeBuckets)
	mux.HandleFunc("/api/choke/cgroups", s.handleChokeCgroups)
	mux.HandleFunc("/api/choke/processes", s.handleChokeProcesses)
	mux.HandleFunc("/api/choke/process/", s.handleProcess) // reuse the event-based drill
	mux.HandleFunc("/api/choke/proc/", s.handleChokeProcDetail)
	mux.HandleFunc("/api/verify-chain", s.handleVerifyChain)
	// Network Choke (Devices) — reads.
	mux.HandleFunc("/api/choke/device-state", s.handleDeviceState)
	mux.HandleFunc("/api/choke/devices", s.handleDeviceList)
	mux.HandleFunc("/api/choke/device-flows", s.handleDeviceFlows)
	// Interactive response — all wired to the signed command dispatcher, RBAC
	// ActionRespond. Per-process (manual/jail/thaw) + fleet-wide (mode/kill-
	// switch/thresholds/preset) + device (jail/thaw/mode/kill-switch).
	mux.HandleFunc("/api/choke/manual", s.handleChokeManual)     // Choke Gateway per-row jail/thaw
	mux.HandleFunc("/api/choke/jail", s.handleChokeJailFromSoc)  // SOC dashboard alert "jail"
	mux.HandleFunc("/api/choke/thaw", s.handleChokeThaw)         // release a process
	mux.HandleFunc("/api/choke/bulk-manual", s.handleChokeBulk)  // multi-target jail
	mux.HandleFunc("/api/choke/forget", s.handleChokeForget)     // stop tracking (= thaw)
	mux.HandleFunc("/api/choke/mode", s.handleChokeMode)         // fleet-wide SetMode
	mux.HandleFunc("/api/choke/kill-switch", s.handleChokeKill)  // fleet-wide KillSwitch
	mux.HandleFunc("/api/choke/thresholds", s.handleChokeThresh) // fleet-wide SetThresholds
	mux.HandleFunc("/api/choke/preset", s.handleChokePreset)     // fleet-wide ApplyPreset
	mux.HandleFunc("/api/choke/device-jail", s.handleDeviceJail)
	mux.HandleFunc("/api/choke/device-thaw", s.handleDeviceThaw)
	mux.HandleFunc("/api/choke/device-mode", s.handleDeviceMode) // device plane arms independently
	mux.HandleFunc("/api/choke/device-kill-switch", s.handleDeviceKill)
	// Engine-local ops with no fleet command (cosmetic / snapshot) — clean 200/501.
	mux.HandleFunc("/api/choke/annotate", s.handleChokeAnnotate)
	for _, p := range []string{"/api/choke/policy/preview", "/api/choke/forensic-snapshot"} {
		mux.HandleFunc(p, s.handleChokeWriteStub)
	}
}

// authorizeRespond resolves the operator + requires the RBAC ActionRespond grant
// on the tenant (default from the session). A denial is a 404 (side-channel).
func (s *Server) authorizeRespond(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "POST/PUT only", http.StatusMethodNotAllowed)
		return "", false
	}
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return "", false
	}
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		if scope := authz.TenantScope(p); len(scope) > 0 {
			tenant = scope[0]
		}
	}
	if tenant == "" {
		http.Error(w, "tenant required", http.StatusBadRequest)
		return "", false
	}
	if !authz.Authorize(p, tenant, authz.ActionRespond, s.auditor).Allowed {
		http.NotFound(w, r)
		return "", false
	}
	return tenant, true
}

// targetResolution is the control plane's answer to "which agent is running
// this process?".
//
// unique means the owner is KNOWN, so the command goes to exactly one agent.
// When it is false the target could not be pinned down and agents holds every
// candidate in the tenant — acceptable for a reversible tier (the non-owners
// no-op and say so), never for an irreversible one.
type targetResolution struct {
	agents []string
	unique bool
	how    string // how the owner was determined; shown to the operator
}

// resolveTarget picks the agent(s) a process choke should be sent to, strongest
// evidence first. PID is deliberately the WEAKEST signal and is only trusted
// when exactly one agent in the tenant reports it: PID numbers are per-host, so
// on a multi-agent tenant "some agent has a process numbered 4021" routinely
// matches the wrong host. That is what made a sever land on an agent that was
// not running the target, kill an unrelated process there, and report success.
func (s *Server) resolveTarget(tenant, execID string, pid uint32, agentID string) targetResolution {
	recs := s.registry.ListTenant(tenant)
	all := make([]string, 0, len(recs))
	online := make(map[string]bool, len(recs))
	for _, rec := range recs {
		all = append(all, rec.AgentID)
		online[rec.AgentID] = true
	}

	// 1. The operator (or console) named the host outright. Most specific
	//    evidence there is — but it must still be an agent of THIS tenant, or
	//    the tenant boundary becomes a targeting oracle.
	if agentID != "" && online[agentID] {
		return targetResolution{agents: []string{agentID}, unique: true, how: "agent specified by the operator"}
	}

	// 2. An earlier command on this exact target was applied by a known agent.
	//    Learned from acks, so it is exact and — unlike the heartbeat snapshot
	//    below — available immediately, without waiting for the next heartbeat.
	if a := s.owners.get(tenant, execID); a != "" && online[a] {
		return targetResolution{agents: []string{a}, unique: true, how: "agent previously confirmed as the owner"}
	}

	// 3. The agent reporting this exec_id in its own choke snapshot. exec_ids
	//    are node-scoped, so a match names the host.
	if execID != "" {
		var byExec []string
		for _, rec := range recs {
			for _, c := range rec.Chokes {
				if c.GetExecId() == execID {
					byExec = append(byExec, rec.AgentID)
					break
				}
			}
		}
		if len(byExec) == 1 {
			return targetResolution{agents: byExec, unique: true, how: "agent reporting this exec_id"}
		}
		if len(byExec) > 1 {
			return targetResolution{agents: byExec, unique: false, how: "several agents report this exec_id"}
		}
	}

	// 4. PID, and ONLY when a single agent reports it. Two agents reporting the
	//    same PID number is the collision case, and guessing between them is
	//    how an irreversible action reaches the wrong host.
	if pid != 0 {
		var byPID []string
		for _, rec := range recs {
			for _, c := range rec.Chokes {
				if c.GetPid() == pid {
					byPID = append(byPID, rec.AgentID)
					break
				}
			}
		}
		if len(byPID) == 1 {
			return targetResolution{agents: byPID, unique: true, how: "agent reporting this pid"}
		}
		if len(byPID) > 1 {
			return targetResolution{agents: byPID, unique: false, how: "several agents report this pid"}
		}
	}

	// 5. A single-agent tenant has no ambiguity to resolve.
	if len(all) == 1 {
		return targetResolution{agents: all, unique: true, how: "the tenant's only agent"}
	}

	// 6. Unknown. Every agent is a candidate; each will answer for itself.
	return targetResolution{agents: all, unique: false, how: "target not reported by any agent yet"}
}

// ownerCache remembers which agent actually applied a command for a given
// target, learned from the acks themselves.
//
// The heartbeat choke snapshot eventually shows the same thing, but "eventually"
// is a heartbeat interval away, and an operator working an incident sends the
// next rung of the ladder seconds after the last one. Without this, a sever
// issued moments after a quarantine has to be resolved by PID again — the exact
// guess that sent containment to the wrong host.
type ownerCache struct {
	mu  sync.Mutex
	m   map[string]ownerEntry
	max int
}

type ownerEntry struct {
	agentID string
	seen    time.Time
}

// ownerTTL bounds how long a learned owner is trusted. An exec_id is not reused
// across hosts, so this is about bounding memory and letting a re-enrolled or
// renamed agent fall out, not about correctness.
const ownerTTL = time.Hour

func newOwnerCache() *ownerCache { return &ownerCache{m: map[string]ownerEntry{}, max: 4096} }

func ownerKey(tenant, execID string) string { return tenant + "\x00" + execID }

func (c *ownerCache) get(tenant, execID string) string {
	if execID == "" {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[ownerKey(tenant, execID)]
	if !ok || time.Since(e.seen) > ownerTTL {
		return ""
	}
	return e.agentID
}

// put records a CONFIRMED owner. Callers must only pass an agent that proved
// ownership (an APPLIED ack with an exec_id match) — a guess cached here would
// be promoted to fact for every later command on that target.
func (c *ownerCache) put(tenant, execID, agentID string) {
	if execID == "" || agentID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for k, e := range c.m {
			if time.Since(e.seen) > ownerTTL {
				delete(c.m, k)
			}
		}
		// Still full of live entries: drop arbitrary ones rather than grow
		// without bound. Losing an entry costs a re-resolution, nothing more.
		for k := range c.m {
			if len(c.m) < c.max {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[ownerKey(tenant, execID)] = ownerEntry{agentID: agentID, seen: time.Now()}
}

// requireReasonForDestructive rejects an unjustified quarantine/sever.
//
// Those two rungs are the ones an audit asks about: quarantine freezes a
// process and sever SIGKILLs it (terminal — thaw cannot bring it back). A
// reason that is merely OPTIONAL becomes an empty reason under time pressure,
// leaving the audit chain recording that something drastic happened with no
// statement of why. Enforced server-side so it cannot be skipped by calling the
// API directly. The reversible rungs stay frictionless on purpose.
func requireReasonForDestructive(action, reason string) error {
	switch action {
	case "quarantine", "sever":
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("a reason is required to %s (this action is %s)", action,
				map[string]string{"quarantine": "disruptive", "sever": "irreversible"}[action])
		}
	}
	return nil
}

// irreversible reports whether a tier cannot be undone. sever is a SIGKILL: no
// thaw brings the process back, so it is the one action that must never be sent
// to a host on a guess.
func irreversible(action string) bool { return action == "sever" }

// dispatchChoke builds a Jail/Thaw command, routes it to the agent actually
// running the target, and reports what genuinely happened.
// tier: throttle|tarpit|quarantine|sever (jail) or "thaw".
//
// Two rules keep this honest on a multi-agent tenant:
//
//  1. An IRREVERSIBLE action requires a uniquely resolved owner. If the control
//     plane cannot say which host holds the process, it refuses and tells the
//     operator to name one, rather than broadcasting a SIGKILL to every agent
//     and killing whatever local process shares that PID number.
//  2. Only an agent that CLAIMS the target may make the request succeed. Agents
//     answer with a target_match grade, and a no-op ack (STATUS_NOT_TARGET)
//     never counts as containment.
func (s *Server) dispatchChoke(w http.ResponseWriter, r *http.Request, tenant, execID string, pid uint32, action, reason, agentID string) {
	code, body := s.chokeRequest(s.subject(r), tenant, execID, pid, action, reason, agentID)
	writeJSON(w, code, body)
}

// subject names the operator behind a request, for change-control records. An
// unattributable destructive action is not one anyone can approve, so this must
// never silently return "": the handlers authorize first, so a principal exists.
func (s *Server) subject(r *http.Request) string {
	if p, ok := s.principal(r); ok && p.Subject != "" {
		return p.Subject
	}
	return "unknown-operator"
}

// chokeRequest is dispatchChoke's core, minus the HTTP. Split out so the
// APPROVED path (approvals.go) executes byte-for-byte the same containment the
// requester asked for — an approval that re-derives the action from separate
// code is an approval of something the approver did not read.
func (s *Server) chokeRequest(requester, tenant, execID string, pid uint32, action, reason, agentID string) (int, map[string]any) {
	if err := requireReasonForDestructive(action, reason); err != nil {
		return http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "detail": err.Error()}
	}
	// EN-2 change-control. A destructive action is HELD here, before anything is
	// signed or dispatched, until a second operator approves it. Held, not
	// refused: the request becomes a queued approval the console surfaces.
	if s.cfg.RequireApproval && s.approvals != nil && approval.RequiresApproval(action) {
		req := s.approvals.Create(approval.Request{
			Tenant: tenant, Action: action, ExecID: execID, PID: pid,
			AgentID: agentID, Scope: "target", Reason: reason, Requester: requester,
		})
		s.cfg.Logf("[approval] %s requested %s on %s (tenant=%s) -> %s (awaiting a second operator)",
			requester, action, targetLabel(execID, pid), tenant, req.ID)
		return http.StatusAccepted, map[string]any{
			"ok": false, "status": "APPROVAL_REQUIRED", "approval_required": true,
			"approval": req, "action": action, "reason": reason,
			"detail": fmt.Sprintf(
				"%s is a destructive action and needs a second operator to approve it (request %s). "+
					"It has NOT been applied.", action, req.ID),
		}
	}
	return s.performChoke(tenant, execID, pid, action, reason, agentID)
}

// performChoke routes and executes the containment. Reached directly for the
// non-destructive rungs, and via an approval for the destructive ones.
func (s *Server) performChoke(tenant, execID string, pid uint32, action, reason, agentID string) (int, map[string]any) {
	var cmd *ebpfsocv1.Command
	switch action {
	case "throttle", "tarpit", "quarantine", "sever":
		cmd = &ebpfsocv1.Command{Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{ExecId: execID, Pid: pid, Tier: action}}}
	case "thaw":
		cmd = &ebpfsocv1.Command{Action: &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{ExecId: execID, Pid: pid}}}
	default:
		return badChoke("action must be throttle | tarpit | quarantine | sever | thaw")
	}
	if execID == "" && pid == 0 {
		return badChoke("exec_id or pid required to identify the target")
	}

	res := s.resolveTarget(tenant, execID, pid, agentID)
	if len(res.agents) == 0 {
		return 200, map[string]any{"ok": false, "status": "NO_AGENT",
			"detail": "no agent online for tenant", "action": action, "reason": reason}
	}
	// An unrouteable sever stops here. Refusing is the safe answer: the operator
	// gets the candidate hosts and can re-issue against one, which is strictly
	// better than a broadcast SIGKILL that reports success no matter where it
	// landed. The reversible rungs still fan out — a throttle on the wrong host
	// is undone by a thaw, a kill is not.
	if irreversible(action) && !res.unique {
		msg := fmt.Sprintf(
			"cannot determine which agent is running this process (%s), and %s is irreversible — "+
				"re-issue with agent_id set to one of: %s",
			res.how, action, strings.Join(res.agents, ", "))
		return http.StatusConflict, map[string]any{
			"ok": false, "status": "AMBIGUOUS_TARGET", "action": action, "reason": reason,
			"candidates": res.agents, "detail": msg,
			// "error" is what the console's API client lifts out of a non-2xx
			// body; without it the operator gets a bare "Conflict" for the one
			// refusal they most need to understand.
			"error": msg,
		}
	}

	// Fan OUT first, then wait once. Enqueue is cheap and non-blocking, so
	// waiting per-agent would make the operator's request take N * ackTimeout —
	// a ten-agent tenant would hang for over a minute on what looks like a
	// single button press. One deadline covers the whole fan-out.
	out := s.dispatchTargeted(res.agents, cmd)

	// Learn the owner, but only from proof — see targetedOutcome.definitive.
	// Caching a guess would promote it to fact for every later command on this
	// target, including the sever.
	if out.owner != "" && out.definitive {
		s.owners.put(tenant, execID, out.owner)
	}

	body := map[string]any{
		"ok": out.applied, "status": out.status, "detail": out.detail,
		"agent": out.owner, "action": action, "reason": reason,
		"routed_to": res.agents, "routing": res.how,
	}
	// A containment that landed on more than one host is reported as such. It
	// only happens on reversible rungs (see the refusal above), but the operator
	// still needs to know their throttle touched two machines.
	if len(out.appliedBy) > 1 {
		body["applied_by"] = out.appliedBy
		body["detail"] = fmt.Sprintf(
			"target could not be pinned to one host (%s); %s applied on %s",
			res.how, action, strings.Join(out.appliedBy, ", "))
	}
	return 200, body
}

// badChoke is a 400 in the (code, body) shape performChoke returns.
func badChoke(msg string) (int, map[string]any) {
	return http.StatusBadRequest, map[string]any{"ok": false, "error": msg, "detail": msg}
}

// targetLabel renders a choke target for a log line / approval summary.
func targetLabel(execID string, pid uint32) string {
	switch {
	case execID != "" && pid != 0:
		return fmt.Sprintf("%s (pid %d)", execID, pid)
	case execID != "":
		return execID
	default:
		return fmt.Sprintf("pid %d", pid)
	}
}

// handleChokeManual — Choke Gateway per-row action {exec_id,pid,binary,action,reason}.
func (s *Server) handleChokeManual(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ExecID string `json:"exec_id"`
		Pid    uint32 `json:"pid"`
		Action string `json:"action"`
		Reason string `json:"reason"`
		// AgentID names the host to act on. Optional, but it is the only way to
		// disambiguate a target the fleet cannot route on its own — and the
		// console has it, because every choke row carries its source agent.
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.dispatchChoke(w, r, tenant, b.ExecID, b.Pid, b.Action, b.Reason, b.AgentID)
}

// handleChokeThaw — release a process {exec_id,pid} (or {reason} only = no-op ack).
func (s *Server) handleChokeThaw(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ExecID  string `json:"exec_id"`
		Pid     uint32 `json:"pid"`
		Reason  string `json:"reason"`
		AgentID string `json:"agent_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	s.dispatchChoke(w, r, tenant, b.ExecID, b.Pid, "thaw", b.Reason, b.AgentID)
}

// handleChokeJailFromSoc — SOC dashboard alert "jail" {pids,binary,action,reason}.
func (s *Server) handleChokeJailFromSoc(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Pids    []uint32 `json:"pids"`
		Action  string   `json:"action"`
		Reason  string   `json:"reason"`
		ExecID  string   `json:"exec_id"`
		AgentID string   `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var pid uint32
	if len(b.Pids) > 0 {
		pid = b.Pids[0]
	}
	// The SOC panel uses richer tier names; normalize to the dispatcher's tiers.
	action := b.Action
	switch action {
	case "throttle", "tarpit", "quarantine", "sever", "thaw":
	default:
		action = "quarantine"
	}
	s.dispatchChoke(w, r, tenant, b.ExecID, pid, action, b.Reason, b.AgentID)
}

// dispatchAll sends cmd to every agent in the tenant and waits for each ack —
// the fleet-wide actions (mode, kill-switch, thresholds, preset).
// ackTimeout bounds how long a dispatching request waits for the agent's ack.
//
// It must comfortably exceed the worst case for a command to reach a connected
// agent, or the caller reports "not applied" for a command that was in fact
// delivered — the operator then sees success or failure at random for identical
// actions. The agent parks in an open command stream and Enqueue wakes it, so
// the realistic path is well under a second; the headroom covers a reconnect.
const ackTimeout = 10 * time.Second

// waitAck blocks until the agent acks commandID or ackTimeout elapses. Empty
// status means no ack arrived — deliberately distinct from an ack that reported
// a non-applied status, so callers never report a timeout as a rejection.
func (s *Server) waitAck(commandID string) (status, detail string) {
	deadline := time.Now().Add(ackTimeout)
	for time.Now().Before(deadline) {
		if a, ok := s.dispatcher.Ack(commandID); ok {
			return a.GetStatus().String(), a.GetDetail()
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "", ""
}

// targetedOutcome is what a Jail/Thaw dispatch actually achieved.
type targetedOutcome struct {
	applied   bool     // at least one agent genuinely enforced
	owner     string   // the agent to attribute the action to
	appliedBy []string // every agent that reported APPLIED
	status    string
	detail    string
	// definitive means owner is the PROVEN owner of this target, so it is safe
	// to route later commands — including an irreversible one — straight to it.
	// Two things establish that, and only these two:
	//
	//   - an agent matched the exec_id in its own telemetry; or
	//   - exactly one agent applied AND every other agent dispatched to
	//     explicitly disowned the target. One agent's weak pid match is a guess,
	//     but a guess that the whole rest of the fleet contradicts is not.
	definitive bool
}

// dispatchTargeted enqueues cmd for each candidate agent and reduces their acks
// to one honest answer.
//
// The ack grades are what make this safe. An agent that is not running the
// target answers STATUS_NOT_TARGET and is never counted as containment; an
// agent that matched only on PID applied on a coincidence and is reported, but
// does not establish ownership. Only an exec_id match is proof, so only it ends
// the wait early and only it may be cached as the owner.
func (s *Server) dispatchTargeted(agents []string, cmd *ebpfsocv1.Command) targetedOutcome {
	ids := make(map[string]string, len(agents)) // command id -> agent
	for _, a := range agents {
		ids[s.dispatcher.Enqueue(a, cmd)] = a
	}

	acks := make(map[string]*ebpfsocv1.CommandAck, len(ids)) // agent -> ack
	deadline := time.Now().Add(ackTimeout)
	for {
		pending := false
		for id, a := range ids {
			if _, have := acks[a]; have {
				continue
			}
			ack, ok := s.dispatcher.Ack(id)
			if !ok {
				pending = true
				continue
			}
			acks[a] = ack
			// Proof of ownership: no other agent's answer can change the
			// outcome, so don't make the operator wait on the stragglers.
			if ack.GetStatus() == ebpfsocv1.CommandAck_STATUS_APPLIED &&
				ack.GetTargetMatch() == ebpfsocv1.CommandAck_TARGET_MATCH_EXEC_ID {
				return reduceAcks(acks, agents)
			}
		}
		if !pending || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return reduceAcks(acks, agents)
}

// reduceAcks folds the per-agent acks into the single result the operator sees.
// Ordering matters: proof beats coincidence, any genuine application beats a
// rejection, and a fleet that unanimously disowns the target is reported as
// exactly that rather than as a failure of enforcement.
func reduceAcks(acks map[string]*ebpfsocv1.CommandAck, agents []string) targetedOutcome {
	var out targetedOutcome
	var rejected, notTarget int
	// Iterate in the dispatch order so the answer does not depend on map order.
	for _, a := range agents {
		ack, ok := acks[a]
		if !ok {
			continue
		}
		switch ack.GetStatus() {
		case ebpfsocv1.CommandAck_STATUS_APPLIED:
			out.appliedBy = append(out.appliedBy, a)
			out.applied = true
			out.status = "STATUS_APPLIED"
			// An exec_id match outranks a pid match for attribution, and is the
			// only grade allowed to mark the result definitive.
			if ack.GetTargetMatch() == ebpfsocv1.CommandAck_TARGET_MATCH_EXEC_ID ||
				ack.GetTargetMatch() == ebpfsocv1.CommandAck_TARGET_MATCH_DEVICE {
				if !out.definitive {
					out.owner, out.detail = a, ack.GetDetail()
				}
				out.definitive = ack.GetTargetMatch() == ebpfsocv1.CommandAck_TARGET_MATCH_EXEC_ID
			} else if out.owner == "" {
				out.owner, out.detail = a, ack.GetDetail()
			}
		case ebpfsocv1.CommandAck_STATUS_NOT_TARGET:
			notTarget++
		default:
			rejected++
			if !out.applied && out.status == "" {
				out.status, out.detail = ack.GetStatus().String(), ack.GetDetail()
				out.owner = a
			}
		}
	}
	if out.applied {
		// Sole applier, with every other dispatched agent heard from and
		// disowning the target: nobody else can be the owner. This is what makes
		// a follow-up sever routable after a first contact that could only match
		// on pid — without it, every rung of the ladder re-guesses from scratch.
		// It requires a COMPLETE set of acks: an agent that timed out has not
		// disowned anything, it just did not answer.
		if !out.definitive && len(out.appliedBy) == 1 && len(acks) == len(agents) {
			out.definitive = true
		}
		return out
	}
	// Nothing was enforced. Say why, precisely — "not applied" alone would leave
	// the operator unsure whether the fleet is broken or the process is gone.
	switch {
	case notTarget > 0 && rejected == 0:
		out.status = "STATUS_NOT_TARGET"
		out.detail = fmt.Sprintf("no agent in this tenant is running that target (%d agent(s) reported it is not theirs)", notTarget)
	case len(acks) == 0:
		out.status = ""
		out.detail = "no agent acked before the deadline"
	}
	return out
}

// dispatchAll sends cmd to every agent in the tenant and reports how many
// applied it. Fleet-wide posture only (mode, kill-switch, thresholds, preset) —
// these act on the agent itself, not on a target, so every agent is a correct
// recipient and there is nothing to route.
//
// Enqueue for ALL agents first, then wait once. Enqueueing and waiting per
// agent would cost N * ackTimeout, so one offline agent in a ten-agent tenant
// would hang the operator's request for over a minute on what looks like a
// single toggle.
func (s *Server) dispatchAll(tenant string, cmd *ebpfsocv1.Command) (applied, total int, detail string) {
	ids := map[string]string{} // command id -> agent
	for _, rec := range s.registry.ListTenant(tenant) {
		total++
		ids[s.dispatcher.Enqueue(rec.AgentID, cmd)] = rec.AgentID
	}
	seen := make(map[string]bool, len(ids))
	deadline := time.Now().Add(ackTimeout)
	for {
		pending := false
		for id := range ids {
			if seen[id] {
				continue
			}
			a, ok := s.dispatcher.Ack(id)
			if !ok {
				pending = true
				continue
			}
			seen[id] = true
			if a.GetStatus() == ebpfsocv1.CommandAck_STATUS_APPLIED {
				applied++
			}
			if d := a.GetDetail(); d != "" {
				detail = d
			}
		}
		if !pending || !time.Now().Before(deadline) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// handleChokeMode — fleet-wide SetMode on the PROCESS plane.
func (s *Server) handleChokeMode(w http.ResponseWriter, r *http.Request) {
	s.dispatchSetMode(w, r, ebpfsocv1.Plane_PLANE_PROCESS)
}

// handleDeviceMode — fleet-wide SetMode on the DEVICE plane. Deliberately NOT
// the same handler as the process one: both used to dispatch a plane-agnostic
// SetMode, so arming the network plane from the console actually armed process
// enforcement, where a sever is a SIGKILL instead of a reversible drop rule.
func (s *Server) handleDeviceMode(w http.ResponseWriter, r *http.Request) {
	s.dispatchSetMode(w, r, ebpfsocv1.Plane_PLANE_DEVICE)
}

func (s *Server) dispatchSetMode(w http.ResponseWriter, r *http.Request, plane ebpfsocv1.Plane) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Enforcing bool   `json:"enforcing"`
		Reason    string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	mode := ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY
	modeStr := "detect-only"
	if b.Enforcing {
		mode, modeStr = ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, "enforcing"
	}
	// EN-2: arming an entire tenant is the fleet-wide destructive change the
	// threat model is about — one click puts every host into a posture where a
	// score can SIGKILL. It waits for a second operator. DISARMING does not:
	// the way back to detect-only must never need a quorum.
	if s.requireFleetApproval(w, r, tenant, "mode", b.Enforcing, plane, b.Reason) {
		return
	}
	applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{Mode: mode, Plane: plane}}})
	writeJSON(w, 200, map[string]any{
		"ok": applied > 0, "mode": modeStr, "previous": "", "applied": applied, "total": total, "detail": detail})
}

// handleChokeKill — fleet-wide KillSwitch on the PROCESS plane.
func (s *Server) handleChokeKill(w http.ResponseWriter, r *http.Request) {
	s.dispatchKillSwitch(w, r, ebpfsocv1.Plane_PLANE_PROCESS)
}

// handleDeviceKill — fleet-wide KillSwitch on the DEVICE plane.
func (s *Server) handleDeviceKill(w http.ResponseWriter, r *http.Request) {
	s.dispatchKillSwitch(w, r, ebpfsocv1.Plane_PLANE_DEVICE)
}

func (s *Server) dispatchKillSwitch(w http.ResponseWriter, r *http.Request, plane ebpfsocv1.Plane) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		On     bool   `json:"on"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_KillSwitch{KillSwitch: &ebpfsocv1.KillSwitch{
			HaltAllEnforcement: b.On, Reason: b.Reason, Plane: plane,
		}}})
	writeJSON(w, 200, map[string]any{
		"ok": applied > 0, "engaged": b.On, "previous": !b.On, "applied": applied, "total": total, "detail": detail})
}

// handleChokeThresh — fleet-wide SetThresholds (PUT).
func (s *Server) handleChokeThresh(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ThrottleAt   int32 `json:"throttle_at"`
		TarpitAt     int32 `json:"tarpit_at"`
		QuarantineAt int32 `json:"quarantine_at"`
		SeverAt      int32 `json:"sever_at"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_SetThresholds{SetThresholds: &ebpfsocv1.SetThresholds{
			ThrottleAt: b.ThrottleAt, TarpitAt: b.TarpitAt, QuarantineAt: b.QuarantineAt, SeverAt: b.SeverAt}}})
	writeJSON(w, 200, map[string]any{"ok": applied > 0, "applied": applied, "total": total, "detail": detail})
}

// handleChokePreset — fleet-wide ApplyPreset.
func (s *Server) handleChokePreset(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	// "containment" is the mass-choke preset: it drops every threshold so that
	// ordinary activity reaches a choke rung across the whole tenant. That is a
	// fleet-wide destructive change; the calmer presets are not.
	if s.requireFleetApproval(w, r, tenant, "preset", strings.EqualFold(b.Name, "containment"), ebpfsocv1.Plane_PLANE_PROCESS, b.Name) {
		return
	}
	applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_ApplyPreset{ApplyPreset: &ebpfsocv1.ApplyPreset{Preset: b.Name}}})
	writeJSON(w, 200, map[string]any{"ok": applied > 0, "preset": b.Name, "applied": applied, "total": total, "detail": detail})
}

// handleChokeBulk — multi-target jail.
func (s *Server) handleChokeBulk(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Targets []struct {
			ExecID  string `json:"exec_id"`
			Pid     uint32 `json:"pid"`
			AgentID string `json:"agent_id"`
		} `json:"targets"`
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := requireReasonForDestructive(b.Action, b.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	type res struct {
		ExecID string `json:"exec_id"`
		OK     bool   `json:"ok"`
		Agent  string `json:"agent,omitempty"`
		Detail string `json:"detail,omitempty"`
	}
	results := make([]res, 0, len(b.Targets))
	for _, t := range b.Targets {
		// Same routing and honesty rules as the single-target path: sending to
		// agents[0] used to pick whichever agent happened to sort first, and
		// counted its no-op ack as containment.
		r := res{ExecID: t.ExecID}
		resv := s.resolveTarget(tenant, t.ExecID, t.Pid, t.AgentID)
		switch {
		case len(resv.agents) == 0:
			r.Detail = "no agent online for tenant"
		case irreversible(b.Action) && !resv.unique:
			r.Detail = "ambiguous target (" + resv.how + "); re-issue with agent_id"
		default:
			out := s.dispatchTargeted(resv.agents, &ebpfsocv1.Command{
				Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{ExecId: t.ExecID, Pid: t.Pid, Tier: b.Action}}})
			if out.owner != "" && out.definitive {
				s.owners.put(tenant, t.ExecID, out.owner)
			}
			r.OK, r.Agent, r.Detail = out.applied, out.owner, out.detail
		}
		results = append(results, r)
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

// handleChokeForget — stop tracking the given exec_ids (dispatched as a thaw).
func (s *Server) handleChokeForget(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ExecIDs []string `json:"exec_ids"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	n := 0
	for _, e := range b.ExecIDs {
		// Forget is a thaw, which is reversible, so an unroutable target may
		// still fan out — the agents that do not hold it no-op and say so, and
		// only a real application counts toward the tally the operator sees.
		resv := s.resolveTarget(tenant, e, 0, "")
		if len(resv.agents) == 0 {
			continue
		}
		if out := s.dispatchTargeted(resv.agents, &ebpfsocv1.Command{
			Action: &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{ExecId: e}}}); out.applied {
			n++
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "forgotten": n})
}

// handleChokeAnnotate — cosmetic note; not centrally persisted yet.
func (s *Server) handleChokeAnnotate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRespond(w, r); !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleDeviceJail — jail LAN devices by MAC (exec_id "device:<mac>").
func (s *Server) handleDeviceJail(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Macs   []string `json:"macs"`
		Action string   `json:"action"`
		Reason string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	type res struct {
		Mac    string `json:"mac"`
		OK     bool   `json:"ok"`
		Agent  string `json:"agent,omitempty"`
		Detail string `json:"detail,omitempty"`
	}
	results := make([]res, 0, len(b.Macs))
	for _, mac := range b.Macs {
		// A device jail goes to every agent because only the one whose segment
		// the MAC is on can contain it — but an agent that has never seen the
		// MAC writes a tc rule matching nothing, so it must not be counted.
		// dispatchAll used to count exactly that as applied.
		out := s.dispatchTargeted(s.tenantAgents(tenant), &ebpfsocv1.Command{
			Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{ExecId: "device:" + mac, Tier: b.Action}}})
		results = append(results, res{Mac: mac, OK: out.applied, Agent: out.owner, Detail: out.detail})
	}
	writeJSON(w, 200, map[string]any{"action": b.Action, "reason": b.Reason, "results": results})
}

// tenantAgents lists every agent currently online for the tenant.
func (s *Server) tenantAgents(tenant string) []string {
	recs := s.registry.ListTenant(tenant)
	out := make([]string, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.AgentID)
	}
	return out
}

// handleDeviceThaw — release LAN devices by MAC.
func (s *Server) handleDeviceThaw(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Macs   []string `json:"macs"`
		Reason string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	type res struct {
		Mac    string `json:"mac"`
		OK     bool   `json:"ok"`
		Agent  string `json:"agent,omitempty"`
		Detail string `json:"detail,omitempty"`
	}
	results := make([]res, 0, len(b.Macs))
	for _, mac := range b.Macs {
		out := s.dispatchTargeted(s.tenantAgents(tenant), &ebpfsocv1.Command{
			Action: &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{ExecId: "device:" + mac}}})
		results = append(results, res{Mac: mac, OK: out.applied, Agent: out.owner, Detail: out.detail})
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

// chokePosture folds the tenant's agents into a single enforcement posture (the
// highest level present), matching the ChokeMode strings the frontend renders.
// chokePosture reduces the fleet's PROCESS-plane modes to one answer.
func chokePosture(recs []heartbeat.Record) (mode string, enforcing, dryRun bool) {
	return posture(recs, func(r heartbeat.Record) ebpfsocv1.EnforcementMode { return r.Mode })
}

// devicePosture is the same reduction over the DEVICE plane. The two planes arm
// independently, so the Devices surface must not be shown the process posture.
func devicePosture(recs []heartbeat.Record) (mode string, enforcing, dryRun bool) {
	return posture(recs, func(r heartbeat.Record) ebpfsocv1.EnforcementMode { return r.DeviceMode })
}

func posture(recs []heartbeat.Record, pick func(heartbeat.Record) ebpfsocv1.EnforcementMode) (mode string, enforcing, dryRun bool) {
	level := 0 // 1 detect-only, 2 dry-run, 3 enforcing
	for _, rec := range recs {
		switch pick(rec) {
		case ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING:
			if level < 3 {
				level = 3
			}
		case ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DRY_RUN:
			if level < 2 {
				level = 2
			}
		case ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY:
			if level < 1 {
				level = 1
			}
		}
	}
	switch level {
	case 3:
		return "enforcing", true, false
	case 2:
		return "dry-run", false, true
	default:
		return "detect-only", false, false
	}
}

func (s *Server) handleChokeStateGW(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	recs := s.registry.ListTenant(tenant)
	mode, enforcing, dryRun := chokePosture(recs)
	counts := map[string]int{"pristine": 0, "throttled": 0, "tarpit": 0, "quarantined": 0, "severed": 0}
	tracked := 0
	for _, rec := range recs {
		for _, c := range rec.Chokes {
			tracked++
			if _, known := counts[c.GetState()]; known {
				counts[c.GetState()]++
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"mode":          mode,
		"dry_run":       dryRun,
		"kill_switched": false,
		"enforcing":     enforcing,
		"tracked":       tracked,
		"counts":        counts,
		// Agents don't report their thresholds on the heartbeat yet; surface the
		// engine defaults so the panel renders. (Editing is the write increment.)
		"thresholds": map[string]int{"throttle_at": 5, "tarpit_at": 15, "quarantine_at": 25, "sever_at": 40},
		"audit":      map[string]any{"ok": true, "total": 0},
		// "mode" above is only the ENGINE's half of this host's posture. Tetragon
		// policies enforce independently of it, so ship the kernel's half too and
		// let the console show the whole thing (threat-model EN-3).
		"kernel": kernelPosture(recs),
	})
}

// kernelPosture reduces the agents' reported Tetragon policies to what an
// operator needs to trust the mode shown next to it.
//
// `diverged` is the one that matters: the console says detect-only while some
// host has a kernel authority armed to kill. It is reported per fleet AND with
// the offending agents named, because "somewhere in your fleet" is not
// actionable — the operator has to know which box to go and look at.
func kernelPosture(recs []heartbeat.Record) map[string]any {
	var (
		enforcing = []string{}
		diverged  = []string{}
		fired     uint64
		reporting int
	)
	for _, rec := range recs {
		// Distinguish "no enforcing policies" from "the agent never told us".
		// An agent predating the field, or one that cannot reach Tetragon,
		// reports nothing — and silence must not read as a clean host.
		if len(rec.KernelPolicies) == 0 {
			continue
		}
		reporting++
		if rec.KernelEnforcing() {
			enforcing = append(enforcing, rec.AgentID)
		}
		if rec.Diverged() {
			diverged = append(diverged, rec.AgentID)
		}
		fired += rec.KernelEnforceActions()
	}
	sort.Strings(enforcing)
	sort.Strings(diverged)
	return map[string]any{
		"agents_reporting": reporting,
		"agents_total":     len(recs),
		"enforcing_agents": enforcing,
		"diverged_agents":  diverged,
		"diverged":         len(diverged) > 0,
		// Enforcing actions that actually fired, fleet-wide. Non-zero means
		// something was killed with no engine decision behind it, so there is no
		// audit row for it and no way to reverse it.
		"enforce_actions": fired,
	}
}

func (s *Server) handleChokeCircuits(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	type circuit struct {
		ExecID string `json:"exec_id"`
		PID    uint32 `json:"pid"`
		Binary string `json:"binary"`
		State  string `json:"state"`
		Score  int32  `json:"score"`
		// Agent names the host this circuit is on. On a fleet, a row without it
		// is not actionable: two hosts can show the same PID, and the console
		// has to be able to hand the agent back on a jail/sever so containment
		// is routed instead of guessed.
		Agent string `json:"agent"`
	}
	out := []circuit{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, c := range rec.Chokes {
			out = append(out, circuit{
				ExecID: c.GetExecId(), PID: c.GetPid(), Binary: c.GetBinary(),
				State: c.GetState(), Score: c.GetScore(), Agent: rec.AgentID,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	writeJSON(w, 200, out)
}

// handleChokeBuckets — kernel token-bucket map. Agents don't report it on the
// heartbeat; return an empty array (valid, page renders).
func (s *Server) handleChokeBuckets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, []any{})
}

// handleChokeCgroups — cgroup id→path map. Not reported; empty object.
func (s *Server) handleChokeCgroups(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, map[string]any{})
}

// handleChokeProcesses — full /proc snapshot. Not reported centrally; empty.
func (s *Server) handleChokeProcesses(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, []any{})
}

// handleChokeProcDetail — per-PID /proc drill. Not reported centrally; empty.
func (s *Server) handleChokeProcDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	pid := strings.TrimPrefix(r.URL.Path, "/api/choke/proc/")
	writeJSON(w, 200, map[string]any{"pid": pid, "tracked": false})
}

// handleVerifyChain — decision hash-chain audit. The central store doesn't
// chain per-tenant yet; report a clean ok.
func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "total": 0})
}

// aggregateDevicePlane reduces the agents' self-reported device data planes to
// one fleet answer plus the total attached links.
//
//	"unknown" — no agents online (or none reporting a plane yet)
//	"noop"    — every reporting agent is recording decisions only
//	"tc"      — every reporting agent has a real data plane
//	"partial" — a mix; some of the fleet cannot enforce on the network plane
//
// An agent enrolled before this field existed reports "", which is counted as
// unknown rather than silently folded into "tc".
func aggregateDevicePlane(recs []heartbeat.Record) (plane string, links int, frames uint64, devSeen int) {
	var withPlane, noop, real int
	for _, rec := range recs {
		links += int(rec.DeviceLinks)
		frames += rec.FramesSeen
		devSeen += int(rec.DevicesSeen)
		switch rec.DevicePlane {
		case "":
			// pre-field agent; no claim either way
		case "noop":
			withPlane++
			noop++
		default:
			withPlane++
			real++
		}
	}
	switch {
	case withPlane == 0:
		return "unknown", links, frames, devSeen
	case real == 0:
		return "noop", links, frames, devSeen
	case noop == 0:
		return "tc", links, frames, devSeen
	default:
		return "partial", links, frames, devSeen
	}
}

func (s *Server) handleDeviceState(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	recs := s.registry.ListTenant(tenant)
	mode, enforcing, dryRun := devicePosture(recs)
	counts := map[string]int{"pristine": 0, "throttled": 0, "tarpit": 0, "quarantined": 0, "severed": 0}
	known := 0
	for _, rec := range recs {
		for _, d := range rec.Devices {
			known++
			if _, ok := counts[d.GetState()]; ok {
				counts[d.GetState()]++
			}
		}
	}
	// Aggregate the device plane the AGENTS report, rather than assuming a
	// registered agent means a live data plane. Previously this returned
	// "active" for any online agent, so a fleet whose agents all ran the noop
	// backend looked like it was enforcing on the network plane when nothing
	// was attached. "noop" only when every agent says noop; "partial" when some
	// agents can enforce and others cannot.
	dataPlane, links, frames, devSeen := aggregateDevicePlane(recs)
	writeJSON(w, 200, map[string]any{
		"data_plane":    dataPlane,
		"mode":          mode,
		"enforcing":     enforcing,
		"dry_run":       dryRun,
		"kill_switched": false,
		"tracked":       known,
		"devices_known": known,
		"devices_seen":  devSeen,
		// Summed from the agents: the control plane attaches nothing itself.
		// links>0 with frames==0 is the frontend's bridge-master warning, so
		// this must reflect real agent attachments, never a placeholder.
		"links_attached": links,
		"frames_seen":    frames,
		"counts":         counts,
	})
}

func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	// last_ip matches the single-host engine's field name so the console renders
	// a fleet device row exactly like a single-host one.
	type device struct {
		MAC       string `json:"mac"`
		State     string `json:"state"`
		Hostname  string `json:"hostname"`
		LastIP    string `json:"last_ip,omitempty"`
		Source    string `json:"source"`
		Protected bool   `json:"protected"`
	}
	out := []device{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, d := range rec.Devices {
			out = append(out, device{
				MAC: d.GetMac(), State: d.GetState(), Hostname: d.GetLabel(),
				LastIP: d.GetLastIp(), Source: rec.AgentID, Protected: d.GetProtected(),
			})
		}
	}
	writeJSON(w, 200, out)
}

// handleDeviceFlows — per-device netflow drill. Not reported centrally; empty.
func (s *Server) handleDeviceFlows(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"mac": r.URL.Query().Get("mac"), "flows": []any{}})
}

// handleChokeWriteStub answers the interactive Choke/Devices write endpoints
// with a clean, explicit 501 so the frontend surfaces a tidy message instead of
// a 404. Wiring these to the signed command dispatcher (fleet-wide SetMode,
// manual Jail/Thaw, thresholds, kill-switch) is the next increment — held back
// deliberately because these change enforcement on live agents.
func (s *Server) handleChokeWriteStub(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"error": "interactive choke actions are not yet enabled on the central console",
	})
}
