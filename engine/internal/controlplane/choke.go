package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"io"
	"net/http"
	"sort"
	"strconv"
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
// heartbeats (heartbeat.Registry), INCLUDING the drill detail — kernel token
// buckets, the cgroup map and the host process table — which agents now report
// alongside chokes/devices. Those three used to return hardcoded empty shapes
// because the data lives only on the agent, which left the multi-tenant Choke
// Gateway page permanently blank where the single-host console showed hundreds
// of rows: the same product, visibly less working. Per-device flows remain
// empty (agents do not report netflow centrally yet) and say so.
//
// Response shapes deliberately mirror the engine's byte-for-byte — the console
// is the SAME bundle on both deployments, so a divergence here (a friendly
// string where the engine sends a bitmask, say) renders one of them wrong.

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
	mux.HandleFunc("/api/verify-chain/repair", s.handleChainRepair)
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
	mux.HandleFunc("/api/choke/preset", s.handleChokePreset)
	mux.HandleFunc("/api/policies/push", s.handlePolicyPush) // detection policy over the signed command channel
	mux.HandleFunc("/api/choke/device-jail", s.handleDeviceJail)
	mux.HandleFunc("/api/choke/device-thaw", s.handleDeviceThaw)
	mux.HandleFunc("/api/choke/device-mode", s.handleDeviceMode) // device plane arms independently
	mux.HandleFunc("/api/choke/device-kill-switch", s.handleDeviceKill)
	// Engine-local ops with no fleet command (cosmetic / snapshot) — clean 200/501.
	mux.HandleFunc("/api/choke/annotate", s.handleChokeAnnotate)
	// policy/preview is gone with its console surface — see the note in
	// internal/api/http.go. forensic-snapshot keeps its honest 501 stub.
	mux.HandleFunc("/api/choke/forensic-snapshot", s.handleChokeWriteStub)
}

// authorizeRespond resolves the operator + requires the RBAC ActionRespond grant
// on the tenant (default from the session). A denial is a 404 (side-channel).
func (s *Server) authorizeRespond(w http.ResponseWriter, r *http.Request) (string, bool) {
	return s.authorizeRespondMethods(w, r, http.MethodPost, http.MethodPut)
}

// authorizeRespondMethods is authorizeRespond with the permitted verbs named.
//
// Every write on this plane was POST or PUT, so the method guard was inlined.
// Settings needs DELETE — removing a suppression is a removal, and expressing
// it as a POST would be a worse lie than the extra parameter. Parameterised
// rather than widened: relaxing the shared guard would have quietly permitted
// DELETE on every containment endpoint too.
func (s *Server) authorizeRespondMethods(w http.ResponseWriter, r *http.Request, allowed ...string) (string, bool) {
	ok := false
	for _, m := range allowed {
		if r.Method == m {
			ok = true
			break
		}
	}
	if !ok {
		http.Error(w, strings.Join(allowed, "/")+" only", http.StatusMethodNotAllowed)
		return "", false
	}
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return "", false
	}
	return s.authorizeRespondAs(w, r, p)
}

// authorizeRespondAs is authorizeRespondMethods once the method is accepted and
// the operator is known: resolve the tenant, then check the RBAC grant.
//
// Split out for the same reason authorizeReadAs is: the identity path that
// actually runs on the estate is an OIDC session, which no test can construct,
// and the only principal a test could otherwise reach this code with is the
// break-glass bearer token — which carries no tenant and so never exercises the
// resolution below. That is exactly why the regression this comment describes
// shipped with a full green suite.
//
// THE RESOLUTION. A tenant-less request was resolved through authz.TenantScope,
// which answers a DIFFERENT question: "which tenants may this principal reach
// without naming one". For a cross-tenant role the honest answer to that is
// none — a cross-tenant operator reaches a tenant by naming it, one audited
// access at a time — so scope is empty and every write by an MSOC admin or
// cross-tenant responder fell through to the 400 below. The console names a
// tenant on no request it makes, so that was the entire write plane: every
// containment, revert, mode change, policy push, attack and settings write.
//
// authz.DefaultTenant answers the question actually being asked — "which tenant
// is this tenant-less request about" — with the tenant stamped on the account,
// which is the same value whoami publishes as viewing_tenant and the same
// default authorizeRead uses. One fact, one source, so the read and write planes
// cannot disagree about which customer is on screen.
//
// It confers nothing. The resolved tenant still goes through Authorize below,
// and for a cross-tenant principal that respond is recorded as a cross-tenant
// access exactly as a named one is — operator_audit's contract is written from
// Authorize's outcome, so a write resolved this way is audited wherever a read
// would be. A principal carrying no tenant at all (the break-glass bearer token)
// still gets the 400: there is nothing to resolve and nothing may be invented.
func (s *Server) authorizeRespondAs(w http.ResponseWriter, r *http.Request, p authz.Principal) (string, bool) {
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		tenant = authz.DefaultTenant(p)
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

// chokeThresholds reports the score ladder the AGENTS are actually running.
//
// It used to return the engine's compiled-in defaults as a constant —
// 5/15/25/40 — because nothing on the wire carried the real values. Every agent
// on this estate runs 20/50/120/200 (scripts/deploy/provision-agent-ssh.sh
// writes them), so the multi-tenant console told operators that a chain severs
// at 40 when the true figure was 200. Verified live on 2026-08-21: the CP
// served 5/15/25/40 while every agent.yaml on the fleet said otherwise.
//
// DataPlaneState.thresholds now carries them per agent, so this reads what the
// fleet reported. Three cases, all distinguishable by the caller:
//
//   - every reporting agent agrees        -> those values
//   - agents disagree                     -> the SAFEST reading, i.e. the
//     lowest of each rung across the fleet, because a threshold shown higher
//     than some host's real one under-warns about that host
//   - nothing reported it yet             -> nil, and the caller must omit the
//     field rather than substitute defaults. An absent ladder renders as
//     "unknown"; a wrong one renders as fact.
//
// Fleet disagreement is legitimate — thresholds are agent-local and settable at
// runtime over the command channel — so it is reported, not averaged away.
func chokeThresholds(recs []heartbeat.Record) map[string]int {
	out := map[string]int{}
	for _, rec := range recs {
		t := rec.Thresholds
		if t == nil {
			continue // agent predates the field; it cannot vote
		}
		for k, v := range map[string]int{
			"throttle_at":   int(t.GetThrottleAt()),
			"tarpit_at":     int(t.GetTarpitAt()),
			"quarantine_at": int(t.GetQuarantineAt()),
			"sever_at":      int(t.GetSeverAt()),
		} {
			// A zero rung is an unset rung, not "contain immediately".
			if v <= 0 {
				continue
			}
			if cur, seen := out[k]; !seen || v < cur {
				out[k] = v
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// processPlaneTier reduces the fleet's process-plane backends to one word, on
// the same rule aggregateDevicePlane uses for the device plane: "noop" only
// when every agent says noop, "partial" when some can enforce in the kernel and
// others cannot. An agent that has not reported the field yet abstains rather
// than being counted as noop, because "we do not know" and "it is not attached"
// are different facts and only one of them is a defect.
func processPlaneTier(recs []heartbeat.Record) string {
	live, noop := 0, 0
	for _, rec := range recs {
		switch rec.ProcessPlane {
		case "":
			continue
		case "noop":
			noop++
		default:
			live++
		}
	}
	switch {
	case live == 0 && noop == 0:
		return "unknown"
	case live == 0:
		return "noop"
	case noop == 0:
		return "cilium-ebpf"
	default:
		return "partial"
	}
}

// processPlaneLinks sums attached cgroup links across the fleet. Zero with a
// non-noop tier is the process-plane equivalent of the device plane's
// bridge-master trap: the program loaded and is attached nowhere.
func processPlaneLinks(recs []heartbeat.Record) int {
	total := 0
	for _, rec := range recs {
		total += int(rec.ProcessLinks)
	}
	return total
}

// thresholdsDiverge reports whether the reporting agents disagree about any
// rung, so the console can say so instead of presenting one host's ladder as
// the fleet's.
func thresholdsDiverge(recs []heartbeat.Record) bool {
	var first *ebpfsocv1.ChokeThresholds
	for _, rec := range recs {
		if rec.Thresholds == nil {
			continue
		}
		if first == nil {
			first = rec.Thresholds
			continue
		}
		t := rec.Thresholds
		if t.GetThrottleAt() != first.GetThrottleAt() || t.GetTarpitAt() != first.GetTarpitAt() ||
			t.GetQuarantineAt() != first.GetQuarantineAt() || t.GetSeverAt() != first.GetSeverAt() {
			return true
		}
	}
	return false
}

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
func (s *Server) dispatchChoke(w http.ResponseWriter, r *http.Request, tenant, execID string, pid uint32, action, reason, agentID string, revertAfter uint32) {
	code, body := s.chokeRequest(s.subject(r), tenant, execID, pid, action, reason, agentID, revertAfter)
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
func (s *Server) chokeRequest(requester, tenant, execID string, pid uint32, action, reason, agentID string, revertAfter uint32) (int, map[string]any) {
	if err := requireReasonForDestructive(action, reason); err != nil {
		return http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "detail": err.Error()}
	}
	// EN-2 change-control. A destructive action is HELD here, before anything is
	// signed or dispatched, until a second operator approves it. Held, not
	// refused: the request becomes a queued approval the console surfaces.
	if s.approvalRequired(tenant) && s.approvals != nil && approval.RequiresApproval(action) {
		req := s.approvals.Create(approval.Request{
			Tenant: tenant, Action: action, ExecID: execID, PID: pid,
			AgentID: agentID, Scope: "target", Reason: reason, Requester: requester,
			// Carried into the queue so the approver judges the actual ask, and
			// so an approved temporary containment does not come back permanent.
			RevertAfterSeconds: revertAfter,
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
	return s.performChoke(tenant, execID, pid, action, reason, agentID, revertAfter)
}

// performChoke routes and executes the containment. Reached directly for the
// non-destructive rungs, and via an approval for the destructive ones.
func (s *Server) performChoke(tenant, execID string, pid uint32, action, reason, agentID string, revertAfter uint32) (int, map[string]any) {
	var cmd *ebpfsocv1.Command
	switch action {
	case "throttle", "tarpit", "quarantine", "sever":
		cmd = &ebpfsocv1.Command{Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{
			ExecId: execID, Pid: pid, Tier: action, RevertAfterSeconds: revertAfter}}}
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

// maxWriteBodyBytes caps what one control-plane choke write may send.
// decodeWriteBody reads the body twice — once as an object, once into the
// handler's struct — so it buffers it, and an unbounded buffer on an
// authenticated write is a cost nobody asked for. Orders of magnitude above the
// largest real body here (a bulk jail naming thousands of targets).
const maxWriteBodyBytes = 4 << 20

// decodeWriteBody decodes a write's body into dst, refusing every body that
// states no intent: absent, empty, whitespace-only, a literal `null`, or any
// JSON that is not an object.
//
// This is the layer under the engine's own decodeWrite (internal/api/choke.go),
// and it exists because THIS file was worse. Several handlers wrote
// `_ = json.NewDecoder(r.Body).Decode(&b)`, discarding the error outright, so a
// malformed body, an absent body and a valid one were indistinguishable — and
// every field then held its zero value, which on this surface is the disarming
// direction: HaltAllEnforcement true from `on`, detect-only from `enforcing`,
// "release everything this tenant is holding" from an empty thaw. A body that
// names no intent is not an instruction, least of all a fleet-wide one.
//
// WHY the map hop rather than decoding straight into dst: encoding/json decodes
// `null` into a struct with a NIL ERROR and all zero values, so the struct
// cannot tell "the operator said false" from "the body said nothing". A
// map[string]json.RawMessage separates not-an-object, key-omitted and
// key-stated. writeChangeControl in changecontrol.go carries the same rule with
// a *bool; a pointer covers the one field somebody remembered to make a
// pointer, and this rule has to hold for every write on the surface.
func decodeWriteBody(r *http.Request, dst any) (map[string]json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxWriteBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("unreadable request body: %w", err)
	}
	if len(raw) > maxWriteBodyBytes {
		return nil, fmt.Errorf("request body is larger than the %d byte limit for a choke write", maxWriteBodyBytes)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("empty request body: this write must be a JSON object saying what to do")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("malformed request: %w", err)
	}
	if fields == nil {
		// The literal `null`: valid JSON that unmarshals into a NIL map with a
		// nil error, so every key reads as absent and every struct field as its
		// zero value. This is the shape that turned an empty request into a
		// fleet-wide "halt enforcement".
		return nil, fmt.Errorf(`this write must be a JSON object; a literal "null" states no intent`)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return nil, fmt.Errorf("malformed request: %w", err)
	}
	return fields, nil
}

// bodyStates reports whether the body actually named this field. A key whose
// value is `null` is NOT stated: `{"on":null}` carries no more intent than
// omitting it, and decodes to the same false.
func bodyStates(fields map[string]json.RawMessage, key string) bool {
	raw, ok := fields[key]
	return ok && string(bytes.TrimSpace(raw)) != "null"
}

// requireBodyStates guards a field whose ZERO VALUE IS AN ACT across a whole
// fleet — `on` false releases the kill-switch, `enforcing` false disarms every
// targeted host, an absent `action` used to default to quarantine. Explicit
// false keeps working; silence does not become a decision.
func requireBodyStates(w http.ResponseWriter, fields map[string]json.RawMessage, key, meaning string) bool {
	if bodyStates(fields, key) {
		return true
	}
	refuseWriteBody(w, fmt.Errorf(
		"%q is required: %s. State it explicitly — an absent field is not an instruction", key, meaning))
	return false
}

// refuseWriteBody answers a body that could not be read as an instruction, in
// the same {ok,error,detail} shape as writeFleetTargetError so the console
// renders a refused body exactly like a refused target set.
func refuseWriteBody(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"ok": false, "error": err.Error(), "detail": err.Error()})
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
		// RevertAfterSeconds arms an auto-revert, as the engine-local API has
		// always allowed. Its absence here meant a fleet operator could only
		// contain permanently, which pushes people toward not containing at all.
		RevertAfterSeconds uint32 `json:"revert_after_seconds"`
	}
	_, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	s.dispatchChoke(w, r, tenant, b.ExecID, b.Pid, b.Action, b.Reason, b.AgentID, b.RevertAfterSeconds)
}

// handleChokeThaw — release containment. Two shapes, both real:
//
//   - {exec_id|pid}: release THAT process. A host list narrows where it is
//     released instead of letting the router guess which agents may own it.
//   - {reason} only: release EVERY contained process on the targeted hosts —
//     the console's "Thaw quarantine" button, which sends {reason, targets}
//     and nothing else. targets and agent_id both narrow WHERE; agent_id means
//     the same single host it means on the branch above, never "and also
//     everybody else".
//
// The second shape used to 400 with "exec_id or pid required", so the fleet
// Thaw control was dead on the control plane while the identical button worked
// on the single-host engine (whose reason-only thaw releases the quarantine
// tier). The protobuf Thaw message carries an exec_id, so there is no
// fleet-wide release COMMAND — but the control plane already knows what each
// agent has contained, because every agent reports its choke snapshot on each
// heartbeat and this file renders it. So a fleet thaw is N per-process Thaws
// against the targeted agents, and needs no protocol change.
func (s *Server) handleChokeThaw(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ExecID  string    `json:"exec_id"`
		Pid     uint32    `json:"pid"`
		Reason  string    `json:"reason"`
		AgentID string    `json:"agent_id"`
		Targets *[]string `json:"targets"`
	}
	// The decode error was discarded here, which mattered more than anywhere
	// else in the file: with no exec_id and no pid this handler releases
	// EVERY contained process on every targeted host, so a body of `null`
	// swept the whole tenant's containment off with an empty reason. No
	// field is required — the reason-only shape is the console's "Thaw
	// quarantine" button and releasing must never be blocked — but the body
	// has to be an object that asks for something.
	_, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	agents, unknown, err := s.resolveFleetTargets(tenant, b.Targets)
	if err != nil {
		writeFleetTargetError(w, unknown, err)
		return
	}
	// No process named: release everything the targeted hosts are holding.
	// Resolved the same way the other fleet writes resolve theirs, so absent
	// targets means the whole tenant and a named list means exactly those hosts.
	if b.ExecID == "" && b.Pid == 0 {
		// A REASON IS REQUIRED ON THIS BRANCH, and only on this branch.
		//
		// `decodeWriteBody` refuses a body that is not an object, but `{}` IS an
		// object: it passed that gate and then swept every contained process off
		// every agent in the tenant, with an empty reason in the audit row. That
		// is a wider blast radius than a quarantine, which this file has always
		// required a reason for — and unlike a quarantine it is the action that
		// puts containment BACK OFF, so the row explaining why is the only
		// record of an intruder having been deliberately released.
		//
		// Before the fleet-release branch existed this shape was a 400, so
		// nothing that works today is broken by refusing it: the console's
		// "Thaw quarantine" button sends {reason}, and the per-process path
		// below is unaffected. An operator releasing one process still needs no
		// reason — releasing an estate does.
		if strings.TrimSpace(b.Reason) == "" {
			http.Error(w, "a reason is required to release containment across hosts "+
				"(this releases every contained process on the targeted hosts)", http.StatusBadRequest)
			return
		}
		// agent_id means "this host" on the exec_id branch below, and it has to
		// mean the same thing here. It was decoded and then dropped, so a
		// release naming one host swept the WHOLE tenant — and the asymmetry
		// was the tell: an UNKNOWN host name was a 400 from resolveFleetTargets
		// while a KNOWN one was silently widened to everybody. That is the same
		// class of defect this endpoint's routing exists to prevent, running in
		// the release direction: thawing hosts the operator never named puts
		// containment back off an intruder they meant to leave held.
		//
		// Narrowing, never widening: the host must survive the target list the
		// operator already gave, so agent_id can only ever select from what
		// resolveFleetTargets authorized, and a name outside it is refused with
		// the same message an unknown target gets rather than quietly ignored.
		if b.AgentID != "" {
			named := false
			for _, a := range agents {
				if a == b.AgentID {
					named = true
					break
				}
			}
			if !named {
				writeFleetTargetError(w, []string{b.AgentID},
					fmt.Errorf("no agent in this release's target set is named %s", b.AgentID))
				return
			}
			agents = []string{b.AgentID}
		}
		s.writeFleetRelease(w, r, tenant, agents, b.Targets != nil || b.AgentID != "", b.Reason)
		return
	}
	if b.Targets != nil {
		out := s.dispatchFleet(r, agents, &ebpfsocv1.Command{
			Action: &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{ExecId: b.ExecID, Pid: b.Pid}}})
		writeJSON(w, 200, map[string]any{
			"ok": out.applied > 0, "status": fleetStatus(out.hosts), "detail": out.detail,
			"agent": firstApplied(out.hosts), "action": "thaw", "reason": b.Reason,
			"routed_to": agents, "routing": "hosts named by the operator",
			"applied": out.applied, "total": out.total, "hosts": out.hosts})
		return
	}
	// A thaw has nothing to revert to: it IS the release.
	s.dispatchChoke(w, r, tenant, b.ExecID, b.Pid, "thaw", b.Reason, b.AgentID, 0)
}

// containedProcess is one process an agent reports as currently held, and so
// one Thaw a fleet release has to send. Both identifiers travel: exec_id is
// what an agent matches on, and pid is the fallback for a snapshot row that
// predates it.
type containedProcess struct {
	execID string
	pid    uint32
}

// releasableState reports whether a choke state is one a thaw can undo.
//
// pristine and watch are not containment. severed is: the process took a
// SIGKILL and is gone, so "released" would be a false claim about a dead
// process — a fleet release reports those separately instead of thawing them.
// Anything else counts, INCLUDING a state this build does not recognise: the
// codebase's standing rule is that the way out of a bad state is never blocked,
// and an unknown rung is far more likely to be a new containment tier than a
// new form of idleness.
func releasableState(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "", "pristine", "watch", "watched", "none", "sever", "severed":
		return false
	default:
		return true
	}
}

// containedProcesses lists what each of the named agents currently holds,
// read from the choke snapshot on its latest heartbeat — the same source the
// Choke Gateway's circuits view renders, so an operator releases exactly what
// that screen showed them.
//
// Two properties of that source, both of which bound this and are why the
// response says where the list came from: the snapshot is a heartbeat old, so a
// process contained since then is not in this sweep; and the agent caps it at
// its 100 highest-scoring entries, so a host holding more than that needs a
// second pass. Both are visible-and-stated limits rather than silent ones — an
// operator who is told "released 100 of 100" can look again.
func (s *Server) containedProcesses(tenant string, agents []string) map[string][]containedProcess {
	want := make(map[string]bool, len(agents))
	for _, a := range agents {
		want[a] = true
	}
	out := make(map[string][]containedProcess, len(agents))
	for _, rec := range s.registry.ListTenant(tenant) {
		if !want[rec.AgentID] {
			continue
		}
		for _, c := range rec.Chokes {
			if !releasableState(c.GetState()) {
				continue
			}
			if c.GetExecId() == "" && c.GetPid() == 0 {
				continue // nothing a Thaw could name
			}
			out[rec.AgentID] = append(out[rec.AgentID], containedProcess{execID: c.GetExecId(), pid: c.GetPid()})
		}
	}
	return out
}

// fleetRelease is what a fleet-wide thaw achieved, per host and in total.
type fleetRelease struct {
	fleetDispatch
	contained int // processes the fleet reported as held
	released  int // agents confirmed these released
	gone      int // the agent disowned the target: the process had already exited
}

// sentRelease is one Thaw the fleet release put on an agent's queue. id is
// empty when the control plane refused to sign it, which is a control-plane
// failure and not the host's.
type sentRelease struct {
	agent string
	id    string
}

// releaseFleet sends one Thaw per contained process on the named agents and
// folds the acks into a per-host report.
//
// Enqueue everything first, then wait once — the same rule dispatchFleet
// follows. Waiting per command would cost N * ackTimeout, and a release is the
// action an operator is most likely to be running under time pressure.
func (s *Server) releaseFleet(r *http.Request, tenant string, agents []string) fleetRelease {
	held := s.containedProcesses(tenant, agents)
	actor := s.subject(r)

	cmds := []sentRelease{}
	for _, agent := range agents {
		for _, p := range held[agent] {
			cmd := &ebpfsocv1.Command{Action: &ebpfsocv1.Command_Thaw{
				Thaw: &ebpfsocv1.Thaw{ExecId: p.execID, Pid: p.pid}}}
			// Stamped before Enqueue signs it, as dispatchFleet does: the agent
			// writes this name into its audit row, and an unattributed release
			// is a hole in the same timeline the containment is recorded in.
			cmd.Actor = actor
			cmds = append(cmds, sentRelease{agent: agent, id: s.dispatcher.Enqueue(agent, cmd)})
		}
	}

	acks := make(map[int]*ebpfsocv1.CommandAck, len(cmds))
	deadline := time.Now().Add(ackTimeout)
	for len(acks) < len(cmds) {
		pending := false
		for i, c := range cmds {
			if _, have := acks[i]; have || c.id == "" {
				continue
			}
			if ack, ok := s.dispatcher.Ack(c.id); ok {
				acks[i] = ack
				continue
			}
			pending = true
		}
		if !pending || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return releaseOutcome(agents, held, cmds, acks)
}

// releaseOutcome folds a fleet release's acks into the report the operator
// reads. Split from the dispatch, as fleetOutcome is, so the rules that decide
// what counts as released can be tested without a live agent acking.
func releaseOutcome(agents []string, held map[string][]containedProcess, cmds []sentRelease, acks map[int]*ebpfsocv1.CommandAck) fleetRelease {
	out := fleetRelease{fleetDispatch: fleetDispatch{
		hosts: make([]fleetHostResult, 0, len(agents)), total: len(agents)}}
	for _, agent := range agents {
		n := len(held[agent])
		out.contained += n
		host := fleetHostResult{Name: agent}
		if n == 0 {
			// Nothing held, so this host is already in the state the operator
			// asked for. Counting it as a failure would turn "one host was
			// contained and is now released" into a red 1/5 report.
			host.OK, host.Status = true, "STATUS_NOTHING_TO_RELEASE"
			out.applied++
			out.hosts = append(out.hosts, host)
			continue
		}
		released, gone, unsigned, timedOut, refused, firstErr := 0, 0, 0, 0, 0, ""
		for i, c := range cmds {
			if c.agent != agent {
				continue
			}
			switch ack, acked := acks[i]; {
			case c.id == "":
				unsigned++
			case !acked:
				timedOut++
			case ack.GetStatus() == ebpfsocv1.CommandAck_STATUS_APPLIED:
				released++
			case ack.GetStatus() == ebpfsocv1.CommandAck_STATUS_NOT_TARGET:
				// The agent no longer has this process: it exited between the
				// heartbeat and now. Nothing is still contained, which is what
				// the operator wanted, so it is not a failure — but it is not a
				// release either, and the two are counted apart.
				gone++
			default:
				refused++
				if firstErr == "" {
					firstErr = ack.GetDetail()
				}
			}
		}
		out.released += released
		out.gone += gone
		host.OK = released+gone == n
		switch {
		case host.OK:
			host.Status = "STATUS_APPLIED"
			out.applied++
		case timedOut > 0 && refused == 0 && unsigned == 0:
			// Silence is not a refusal — the release may well have landed on a
			// host whose ack was still in flight — but it is not confirmation
			// either, and a process still frozen is what the operator is
			// hunting. Unconfirmed, which is what we actually know.
			host.Status = "timeout"
			host.Error = fmt.Sprintf("released %d of %d; %d had no acknowledgement before the deadline",
				released, n, timedOut)
		case unsigned > 0:
			host.Status = "not_dispatched"
			host.Error = fmt.Sprintf("released %d of %d; the control plane could not sign %d release(s)",
				released, n, unsigned)
		default:
			host.Status = "STATUS_REJECTED"
			host.Error = fmt.Sprintf("released %d of %d; %d refused (%s)", released, n, refused, firstErr)
		}
		out.hosts = append(out.hosts, host)
	}
	return out
}

// writeFleetRelease runs a fleet-wide thaw and answers in the fan-out envelope
// the console summarises — hosts/applied/total, not a bare ok. Without those
// keys summarizeFanout renders even a complete release as "coverage unknown".
func (s *Server) writeFleetRelease(w http.ResponseWriter, r *http.Request, tenant string, agents []string, targeted bool, reason string) {
	if len(agents) == 0 {
		msg := "no agent in this tenant is reporting, so there was nothing to release"
		writeJSON(w, 200, map[string]any{
			"ok": false, "status": "NO_AGENT", "detail": msg, "error": msg,
			"action": "thaw", "scope": "fleet", "reason": reason,
			"applied": 0, "total": 0, "hosts": []fleetHostResult{}, "released": 0})
		return
	}
	out := s.releaseFleet(r, tenant, agents)
	routing := "every agent in the tenant"
	if targeted {
		routing = "hosts named by the operator"
	}
	// Says what was released and where the list came from. "0 released" with a
	// green tick would otherwise be indistinguishable from a release that
	// worked, and the heartbeat snapshot is a moment old — a process contained
	// since the last heartbeat is not in this sweep, and the operator has to
	// know that rather than read the report as "this fleet holds nothing".
	detail := fmt.Sprintf("released %d of %d contained process(es) across %d host(s), from each agent's latest heartbeat",
		out.released, out.contained, out.total)
	if out.gone > 0 {
		detail += fmt.Sprintf("; %d had already exited", out.gone)
	}
	if out.contained == 0 {
		detail = fmt.Sprintf("no contained process on %d host(s) as of their latest heartbeat; nothing to release", out.total)
	}
	writeJSON(w, 200, map[string]any{
		// Every targeted host had to end up holding nothing. A release that
		// left one host frozen is not a release, and the whole point of the
		// per-host envelope is that the operator sees which one.
		"ok": out.applied == out.total, "status": fleetStatus(out.hosts), "detail": detail,
		"action": "thaw", "scope": "fleet", "reason": reason,
		"routed_to": agents, "routing": routing,
		"applied": out.applied, "total": out.total, "hosts": out.hosts,
		// Beyond the fan-out envelope: how many processes actually came back,
		// which is the number an operator is really asking for.
		"released": out.released, "contained": out.contained, "already_exited": out.gone,
	})
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
		// Optional auto-revert, in seconds. See handleChokeManual.
		RevertAfterSeconds uint32 `json:"revert_after_seconds"`
	}
	fields, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	// An absent action used to fall through the switch below to the
	// "quarantine" default, so a body that named a pid and nothing else
	// froze that process. The normalisation of an unrecognised NAME stays —
	// the SOC panel has richer tier words — but no name at all is silence,
	// and silence must not pick the destructive rung.
	if !requireBodyStates(w, fields, "action", "the containment rung to apply") {
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
	s.dispatchChoke(w, r, tenant, b.ExecID, pid, action, b.Reason, b.AgentID, b.RevertAfterSeconds)
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
// A var rather than a const only so tests can shorten the wait: a handler
// test dispatching to an agent nobody is acking for would otherwise spend the
// full ten seconds in every case.
var ackTimeout = 10 * time.Second

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

// fleetHostResult is one host's outcome inside a fleet-wide write's response.
// It is the multi-tenant half of the frontend's fan-out envelope: the console
// reads `result.hosts ?? []` and summarises THAT, so a control-plane response
// carrying only applied/total reported a write that reached every agent as
// "0/0 hosts succeeded" — in a success-toned toast. Name is the agent id,
// because on the control plane the tenant's agents ARE the fleet's hosts.
type fleetHostResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// fleetDispatch is what a fleet-wide write actually achieved: the per-host
// outcomes plus the applied/total/detail summary the existing keys carry.
type fleetDispatch struct {
	hosts   []fleetHostResult
	applied int
	total   int
	detail  string
}

// resolveFleetTargets turns a write's "targets" field into the exact set of
// agents it may touch, reading the tenant's registry ONCE so the validation and
// the dispatch cannot disagree about who is in scope.
//
//   - absent or null  -> every agent in the tenant, unchanged from before.
//   - a named list    -> exactly those agents, in the order given, and no others.
//   - an empty list   -> refused. "Selected hosts only, nothing selected" must
//     never degrade into "every host": that is the difference between a no-op
//     and containing the whole estate.
//   - an unknown name -> refused, naming it, with NOTHING dispatched. A write
//     whose target set the server only half understood must not half apply; the
//     operator has to learn that the host they picked is not one we know.
func (s *Server) resolveFleetTargets(tenant string, targets *[]string) (agents, unknown []string, err error) {
	known := s.tenantAgents(tenant)
	if targets == nil {
		return known, nil, nil
	}
	if len(*targets) == 0 {
		return nil, nil, fmt.Errorf(
			"targets was an empty list: name the hosts to write to, or omit targets to write to the whole tenant")
	}
	inTenant := make(map[string]bool, len(known))
	for _, a := range known {
		inTenant[a] = true
	}
	seen := make(map[string]bool, len(*targets))
	for _, name := range *targets {
		switch {
		case !inTenant[name]:
			unknown = append(unknown, name)
		case !seen[name]:
			// A name repeated in the request is one host, not two — counting it
			// twice would inflate the "applied N of M" the operator reads.
			seen[name] = true
			agents = append(agents, name)
		}
	}
	if len(unknown) > 0 {
		return nil, unknown, fmt.Errorf("no agent in this tenant is named %s", strings.Join(unknown, ", "))
	}
	return agents, nil, nil
}

// writeFleetTargetError answers a target set we could not honour. The unknown
// names are echoed because "one of the hosts you named is not here" is useless
// to an operator holding a list of twelve.
func writeFleetTargetError(w http.ResponseWriter, unknown []string, err error) {
	body := map[string]any{"ok": false, "error": err.Error(), "detail": err.Error()}
	if len(unknown) > 0 {
		body["unknown"] = unknown
	}
	writeJSON(w, http.StatusBadRequest, body)
}

// dispatchFleet sends cmd to exactly the named agents and reports what each one
// did. Fleet-wide posture only (mode, kill-switch, thresholds, preset) — these
// act on the agent itself, not on a process, so every agent in the set is a
// correct recipient and there is nothing to route.
//
// Enqueue for ALL agents first, then wait once. Enqueueing and waiting per
// agent would cost N * ackTimeout, so one offline agent in a ten-agent tenant
// would hang the operator's request for over a minute on what looks like a
// single toggle.
func (s *Server) dispatchFleet(r *http.Request, agents []string, cmd *ebpfsocv1.Command) fleetDispatch {
	// Stamp the operator HERE, not at the nine call sites. The agent writes
	// this name into a tamper-evident audit row, and a call site that forgot
	// would produce a row saying the platform acted on its own — the one
	// reading an incident review must be able to trust.
	//
	// Before the signature is computed: Canonical covers the actor, so
	// stamping after Enqueue would sign bytes that do not match what is sent.
	if a := s.subject(r); a != "" {
		cmd.Actor = a
	}
	ids := make(map[string]string, len(agents)) // agent -> command id
	for _, agent := range agents {
		ids[agent] = s.dispatcher.Enqueue(agent, cmd)
	}
	acks := make(map[string]*ebpfsocv1.CommandAck, len(ids))
	deadline := time.Now().Add(ackTimeout)
	for {
		pending := false
		for agent, id := range ids {
			if _, have := acks[agent]; have || id == "" {
				continue
			}
			ack, ok := s.dispatcher.Ack(id)
			if !ok {
				pending = true
				continue
			}
			acks[agent] = ack
		}
		if !pending || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	return fleetOutcome(agents, ids, acks)
}

// fleetOutcome folds the per-agent acks into the response the operator reads.
// Split from the dispatch so the reporting rules — what counts as applied, what
// an absent ack is allowed to be called — are testable without a live agent.
func fleetOutcome(agents []string, ids map[string]string, acks map[string]*ebpfsocv1.CommandAck) fleetDispatch {
	out := fleetDispatch{hosts: make([]fleetHostResult, 0, len(agents)), total: len(agents)}
	// Reported in dispatch order, so the same write does not come back with its
	// hosts shuffled by Go's map iteration.
	for _, agent := range agents {
		host := fleetHostResult{Name: agent}
		ack, acked := acks[agent]
		switch {
		case ids[agent] == "":
			// Enqueue refuses to sign a command it cannot canonicalise and
			// returns no id, so nothing was sent to this agent at all. Calling
			// that a timeout would blame the host for a control-plane refusal.
			host.Status = "not_dispatched"
			host.Error = "the control plane could not sign this command for dispatch"
		case !acked:
			// Silence is not a rejection: the command may well have applied on a
			// host whose ack was still in flight. So the word is "timeout" and
			// ok stays false — unconfirmed, which is what we actually know.
			host.Status = "timeout"
			host.Error = "no acknowledgement before the deadline"
		default:
			host.Status = ack.GetStatus().String()
			host.OK = ack.GetStatus() == ebpfsocv1.CommandAck_STATUS_APPLIED
			if host.OK {
				out.applied++
			} else {
				host.Error = ack.GetDetail()
			}
			if d := ack.GetDetail(); d != "" {
				out.detail = d
			}
		}
		out.hosts = append(out.hosts, host)
	}
	return out
}

// fleetStatus reduces per-host outcomes to the single status word the
// per-process envelope has always carried. Empty when nothing answered, which
// is waitAck's convention for "no ack arrived" — deliberately not the same as
// an ack that reported a non-applied status.
func fleetStatus(hosts []fleetHostResult) string {
	first := ""
	for _, h := range hosts {
		if h.OK {
			return "STATUS_APPLIED"
		}
		if first == "" && h.Status != "" && h.Status != "timeout" {
			first = h.Status
		}
	}
	return first
}

// firstApplied names a host to attribute the action to — the first that
// genuinely applied it, empty when none did. The full picture is in hosts.
func firstApplied(hosts []fleetHostResult) string {
	for _, h := range hosts {
		if h.OK {
			return h.Name
		}
	}
	return ""
}

// dispatchAll sends cmd to every agent in the tenant and reports how many
// applied it. The fleet-wide HTTP handlers call dispatchFleet directly, so they
// can honour an explicit target set and report per host; this stays for the
// callers that genuinely mean the whole tenant (an approved fleet change,
// tenant settings, policy push).
func (s *Server) dispatchAll(r *http.Request, tenant string, cmd *ebpfsocv1.Command) (applied, total int, detail string) {
	out := s.dispatchFleet(r, s.tenantAgents(tenant), cmd)
	return out.applied, out.total, out.detail
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
		// Targets is the console's selected-host set. Absent or null still means
		// every agent in the tenant; see resolveFleetTargets.
		Targets *[]string `json:"targets"`
	}
	fields, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	if !requireBodyStates(w, fields, "enforcing",
		"true arms the targeted hosts, false drops them to detect-only") {
		return
	}
	// Resolved BEFORE the approval gate: a target set we do not understand is a
	// bad request, not something to park for a second operator to judge.
	agents, unknown, err := s.resolveFleetTargets(tenant, b.Targets)
	if err != nil {
		writeFleetTargetError(w, unknown, err)
		return
	}
	mode := ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY
	modeStr := "detect-only"
	if b.Enforcing {
		mode, modeStr = ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, "enforcing"
	}
	// EN-2: arming an entire tenant is the fleet-wide destructive change the
	// threat model is about — one click puts every host into a posture where a
	// score can SIGKILL. It waits for a second operator. DISARMING does not:
	// the way back to detect-only must never need a quorum.
	// Targeted or not, the gate is the same one: what changes is the blast
	// radius carried into the queue, which is what the approver judges and what
	// the approved dispatch is held to. Refusing a targeted arming outright —
	// as this did — withheld host-scoped containment from precisely the tenants
	// that run four-eyes, and accepted the WIDER untargeted form of the same ask.
	if s.requireFleetApproval(w, r, tenant, "mode", b.Enforcing, plane, b.Reason, agents, b.Targets != nil) {
		return
	}
	out := s.dispatchFleet(r, agents, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{Mode: mode, Plane: plane}}})
	writeJSON(w, 200, map[string]any{
		"ok": out.applied > 0, "mode": modeStr, "previous": "",
		"applied": out.applied, "total": out.total, "detail": out.detail, "hosts": out.hosts})
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
		// Targets scopes the halt. A kill-switch on two named hosts and one on
		// the whole tenant are different acts, and the console distinguishes
		// them on screen, so the server has to distinguish them on the wire.
		Targets *[]string `json:"targets"`
	}
	// The worst instance of the class: this discarded its decode error AND
	// read the zero value as "off", so `null` — or a truncated body, or no
	// body — dispatched HaltAllEnforcement=false to every agent in the
	// tenant with an empty reason, indistinguishable from an operator
	// releasing the kill-switch on purpose. Which is a legitimate act, and
	// still works: it just has to be said.
	fields, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	if !requireBodyStates(w, fields, "on",
		"true halts all enforcement on the targeted hosts, false releases the halt") {
		return
	}
	agents, unknown, err := s.resolveFleetTargets(tenant, b.Targets)
	if err != nil {
		writeFleetTargetError(w, unknown, err)
		return
	}
	out := s.dispatchFleet(r, agents, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_KillSwitch{KillSwitch: &ebpfsocv1.KillSwitch{
			HaltAllEnforcement: b.On, Reason: b.Reason, Plane: plane,
		}}})
	writeJSON(w, 200, map[string]any{
		"ok": out.applied > 0, "engaged": b.On, "previous": !b.On,
		"applied": out.applied, "total": out.total, "detail": out.detail, "hosts": out.hosts})
}

// handleChokeThresh — fleet-wide SetThresholds (PUT).
func (s *Server) handleChokeThresh(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ThrottleAt   int32  `json:"throttle_at"`
		TarpitAt     int32  `json:"tarpit_at"`
		QuarantineAt int32  `json:"quarantine_at"`
		SeverAt      int32  `json:"sever_at"`
		Reason       string `json:"reason"`
		// Targets scopes the ladder to named hosts; absent means the tenant.
		Targets *[]string `json:"targets"`
	}
	_, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	// VALIDATE BEFORE DISPATCH.
	//
	// This handler discarded its decode error and sent whatever arrived down
	// the signed command channel, where no hop downstream checked either. A
	// body of {"throttle_at":10} therefore left sever_at = 0 on every agent in
	// the tenant — and the ladder tests sever FIRST, so every tracked process
	// evaluated to Severed. On an armed host that is a fleet-wide SIGKILL from
	// one malformed request by an authenticated operator.
	//
	// circuit.Config.Validate is the same rule the engine's own handler and
	// the agent's applier now use. Three hops, one rule.
	if err := (circuit.Config{
		ThrottleAt: int(b.ThrottleAt), TarpitAt: int(b.TarpitAt),
		QuarantineAt: int(b.QuarantineAt), SeverAt: int(b.SeverAt),
	}).Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	agents, unknown, err := s.resolveFleetTargets(tenant, b.Targets)
	if err != nil {
		writeFleetTargetError(w, unknown, err)
		return
	}
	// Stored as a TENANT policy before dispatch, so an agent that enrols
	// tomorrow inherits this ladder instead of the deploy default. Dispatch
	// alone only reaches the agents that happen to exist right now — which is
	// how a tenant ends up with one host quietly running different thresholds
	// from the rest of its fleet.
	//
	// Best-effort: the operator's change is already valid and about to reach
	// every live agent, and failing the request because the note could not be
	// written would be the wrong trade. Logged, because the consequence is
	// quiet — it works today and the next agent does not inherit it.
	//
	// A TARGETED ladder is not stored at all: the operator changed two hosts,
	// not the tenant's policy, and writing it here would silently hand the same
	// ladder to every agent that enrols afterwards — the opposite of the scope
	// they asked for. stored_for_tenant then reports false, which is true.
	cfg := circuit.Config{
		ThrottleAt: int(b.ThrottleAt), TarpitAt: int(b.TarpitAt),
		QuarantineAt: int(b.QuarantineAt), SeverAt: int(b.SeverAt),
	}
	stored := false
	if b.Targets == nil {
		ok, err := storeTenantThresholds(s, tenant, cfg, b.Reason, s.subject(r))
		if err != nil {
			s.cfg.Logf("[thresholds] applied to the fleet but NOT stored for tenant=%s (%v) — "+
				"a newly enrolled agent will start on the deployed ladder", tenant, err)
		}
		stored = ok
	}
	out := s.dispatchFleet(r, agents, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_SetThresholds{SetThresholds: &ebpfsocv1.SetThresholds{
			ThrottleAt: b.ThrottleAt, TarpitAt: b.TarpitAt, QuarantineAt: b.QuarantineAt, SeverAt: b.SeverAt}}})
	writeJSON(w, 200, map[string]any{
		"ok": out.applied > 0, "applied": out.applied, "total": out.total, "detail": out.detail,
		"hosts": out.hosts,
		// Stated rather than assumed: "applied to 3 agents" and "this is now
		// the tenant's ladder" are different claims and only one of them
		// survives a new enrolment.
		"stored_for_tenant": stored,
	})
}

// storeTenantThresholds records a ladder as the TENANT's policy, so an agent
// that enrols tomorrow inherits it. Reports whether it was actually stored:
// a deployment with no Postgres store has nowhere to put it, which is not an
// error and must not be reported as one.
//
// A var, like ackTimeout above, and for the same kind of reason: it is the seam
// the caller's targeting guard is TESTED through. That guard — only an
// untargeted write is stored — has a silent failure mode. Drop it and a ladder
// meant for two hosts becomes the tenant's policy, and the damage only appears
// when the next agent enrols with thresholds nobody chose for it. Nothing in a
// response reveals that, so the test has to watch the store itself.
var storeTenantThresholds = func(s *Server, tenant string, cfg circuit.Config, reason, actor string) (bool, error) {
	pg, ok := s.pgStore()
	if !ok {
		return false, nil
	}
	if err := pg.SetThresholds(tenant, cfg, reason, actor); err != nil {
		return false, err
	}
	return true, nil
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
		// Targets is the whole point of this handler's fix. The console shows
		// "Writes target 1 selected host." and sent that host list; this decoded
		// {name, reason} only and dispatched to every agent in the tenant, so
		// containing one host contained the fleet.
		Targets *[]string `json:"targets"`
	}
	fields, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	// A preset with no name is not an instruction. It used to reach every
	// targeted agent as ApplyPreset("") for the agent to make sense of.
	if !requireBodyStates(w, fields, "name", "the preset to apply") {
		return
	}
	agents, unknown, err := s.resolveFleetTargets(tenant, b.Targets)
	if err != nil {
		writeFleetTargetError(w, unknown, err)
		return
	}
	// "containment" is the mass-choke preset: it drops every threshold so that
	// ordinary activity reaches a choke rung across every host it lands on. That
	// is a destructive change; the calmer presets are not. Targeting narrows who
	// it reaches, it does not make it something else, so the gate still fires on
	// a containment aimed at a single host.
	containment := strings.EqualFold(b.Name, "containment")
	if s.requireFleetApproval(w, r, tenant, "preset", containment, ebpfsocv1.Plane_PLANE_PROCESS, b.Name,
		agents, b.Targets != nil) {
		return
	}
	out := s.dispatchFleet(r, agents, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_ApplyPreset{ApplyPreset: &ebpfsocv1.ApplyPreset{Preset: b.Name}}})
	// A preset lasts exactly as long as a threshold write of the same scope, and
	// only the threshold write said so. A preset moves the agents' ladder, and
	// reconcileLadders pushes the tenant's stored ladder back over any agent
	// whose ladder differs from it every two minutes — so an operator saw
	// "Containment applied", then saw containment come off, with nothing
	// anywhere connecting the two. Both writes now answer the durability
	// question with the same key, so the console can treat them identically
	// instead of carrying a warning for one and silence for the other.
	//
	// The answer is a constant, and honestly so: nothing in this handler writes
	// a preset's ladder to the tenant's policy, and it could not — the ladder a
	// preset installs is a compile-time tuple inside the AGENT
	// (choke.Gateway.ApplyPreset), so this hop has no numbers to store, and
	// forensic/maintenance also move the kill-switch, which a tenant ladder
	// cannot hold.
	writeJSON(w, 200, map[string]any{"ok": out.applied > 0, "preset": b.Name,
		"applied": out.applied, "total": out.total, "detail": out.detail, "hosts": out.hosts,
		// Never stored as the tenant's policy: applied to the agents named here
		// and liable to be reconciled back to the tenant's ladder.
		"stored_for_tenant": false})
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
		// One revert window for the whole batch: a bulk jail is one operator
		// decision, and per-target windows would be a different feature.
		RevertAfterSeconds uint32 `json:"revert_after_seconds"`
	}
	_, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	if err := requireReasonForDestructive(b.Action, b.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	type res struct {
		ExecID           string `json:"exec_id"`
		OK               bool   `json:"ok"`
		Agent            string `json:"agent,omitempty"`
		Detail           string `json:"detail,omitempty"`
		Status           string `json:"status,omitempty"`
		ApprovalRequired bool   `json:"approval_required,omitempty"`
		ApprovalID       string `json:"approval_id,omitempty"`
	}
	requester := s.subject(r)
	results := make([]res, 0, len(b.Targets))
	held := 0
	for _, t := range b.Targets {
		// Every target goes through chokeRequest, the SAME gate the single-target
		// path uses. Bulk previously called dispatchTargeted directly, which meant
		// the one endpoint built to act on many hosts at once was also the one
		// endpoint that skipped EN-2 dual control — precisely the "ONE command
		// severs many hosts" risk the approval package exists to stop. Routing
		// through chokeRequest also inherits performChoke's target resolution and
		// its refusal to broadcast an irreversible action, rather than restating
		// both here where they drifted.
		out := res{ExecID: t.ExecID}
		_, body := s.chokeRequest(requester, tenant, t.ExecID, t.Pid, b.Action, b.Reason, t.AgentID, b.RevertAfterSeconds)
		out.OK, _ = body["ok"].(bool)
		out.Agent, _ = body["agent"].(string)
		out.Detail, _ = body["detail"].(string)
		out.Status, _ = body["status"].(string)
		if req, ok := body["approval"].(approval.Request); ok {
			out.ApprovalRequired, out.ApprovalID = true, req.ID
			held++
		}
		results = append(results, out)
	}
	resp := map[string]any{"results": results}
	// Say plainly that nothing was applied, rather than leaving the console to
	// infer it from a list of ok:false rows.
	if held > 0 {
		resp["approval_required"] = true
		resp["held"] = held
		resp["detail"] = fmt.Sprintf(
			"%d of %d targets need a second operator to approve %s; those have NOT been applied.",
			held, len(b.Targets), b.Action)
	}
	writeJSON(w, 200, resp)
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
	_, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
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

// handleChokeAnnotate refuses, because it cannot do what it was claiming to do.
//
// It authorized the caller and returned {"ok": true} WITHOUT EVER READING THE
// BODY. The console took that as success and toasted "note saved"; the operator
// wrote a justification onto a containment — the kind of thing that exists to
// be read back during an incident review — and it went nowhere. On refresh the
// field was empty again, because no control-plane endpoint emits an annotation
// at all. This is the same defect family as the tool contract that advertised
// eleven filter parameters no server read.
//
// 501 with the reason is the honest interim: the console can disable the
// control instead of offering one that discards what is typed into it.
//
// The full fix is a hash-chained store.Decision with Action "annotate" and the
// note as Reason, mirroring the audit write in internal/api/policypush.go —
// Reason and Actor are both chained, so an annotation becomes tamper-evident
// evidence rather than decoration. It needs a length cap (the handler accepts
// an unbounded string) and a look at /api/choke/forensic-snapshot, which reads
// a fixed RecentDecisions(2000) budget that annotations would start consuming.
//
// NOTE: this keeps authorizeRespond. Routing it to handleChokeWriteStub, which
// is the obvious tidy-up, would silently downgrade this to authorizeRead.
func (s *Server) handleChokeAnnotate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRespond(w, r); !ok {
		return
	}
	// No decode, deliberately: this endpoint stores nothing, so there is no
	// body to read and nothing a body could change. Stated because every other
	// write in this file now goes through decodeWriteBody, and a silent
	// omission here would read as one more handler that forgot.
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"error": "this control plane cannot store an annotation yet, so it will not pretend to. " +
			"The note was NOT saved. Record it in your ticketing system until annotations are persisted.",
	})
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
	fields, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	// Same rule as the process plane: an absent action dispatched a Jail
	// with an empty tier to every agent for them to interpret.
	if !requireBodyStates(w, fields, "action", "the containment rung to apply to these devices") {
		return
	}
	// Same reason rule as the process plane. Severing a device cuts a host off
	// the network; the audit chain may not record that with no statement of why.
	if err := requireReasonForDestructive(b.Action, b.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	type res struct {
		Mac              string `json:"mac"`
		OK               bool   `json:"ok"`
		Agent            string `json:"agent,omitempty"`
		Detail           string `json:"detail,omitempty"`
		Status           string `json:"status,omitempty"`
		ApprovalRequired bool   `json:"approval_required,omitempty"`
		ApprovalID       string `json:"approval_id,omitempty"`
	}
	requester := s.subject(r)
	results := make([]res, 0, len(b.Macs))
	held := 0
	for _, mac := range b.Macs {
		out := res{Mac: mac}
		// EN-2 applies to the device plane too: quarantining or severing a set of
		// MACs from one console session is the same blast radius as doing it to a
		// set of processes, and this handler takes a LIST. Held before dispatch.
		if s.approvalRequired(tenant) && s.approvals != nil && approval.RequiresApproval(b.Action) {
			req := s.approvals.Create(approval.Request{
				Tenant: tenant, Action: b.Action, MAC: mac, Scope: "device",
				Reason: b.Reason, Requester: requester,
			})
			s.cfg.Logf("[approval] %s requested device %s on %s (tenant=%s) -> %s (awaiting a second operator)",
				requester, b.Action, mac, tenant, req.ID)
			out.Status, out.ApprovalRequired, out.ApprovalID = "APPROVAL_REQUIRED", true, req.ID
			out.Detail = fmt.Sprintf(
				"%s is a destructive action and needs a second operator to approve it (request %s). "+
					"It has NOT been applied.", b.Action, req.ID)
			held++
			results = append(results, out)
			continue
		}
		jailed := s.performDeviceJail(tenant, mac, b.Action)
		out.OK, out.Agent, out.Detail, out.Status = jailed.applied, jailed.owner, jailed.detail, jailed.status
		results = append(results, out)
	}
	resp := map[string]any{"action": b.Action, "reason": b.Reason, "results": results}
	if held > 0 {
		resp["approval_required"] = true
		resp["held"] = held
		resp["detail"] = fmt.Sprintf(
			"%d of %d devices need a second operator to approve %s; those have NOT been applied.",
			held, len(b.Macs), b.Action)
	}
	writeJSON(w, 200, resp)
}

// performDeviceJail executes a device-plane containment. Split out so the
// APPROVED path replays byte-for-byte the containment the approver read, the
// same reason chokeRequest and performChoke are split on the process plane.
//
// A device jail goes to every agent because only the one whose segment the MAC
// is on can contain it — but an agent that has never seen the MAC writes a tc
// rule matching nothing, so it must not be counted. dispatchAll used to count
// exactly that as applied.
func (s *Server) performDeviceJail(tenant, mac, action string) targetedOutcome {
	return s.dispatchTargeted(s.tenantAgents(tenant), &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{ExecId: "device:" + mac, Tier: action}}})
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
//
// The release is attributed: the operator is stamped on each command as its
// actor, and the agent copies that into the tamper-evident audit row it writes
// when it tears the tc rule down.
//
// `reason` is optional and, when given, is recorded on the CONTROL PLANE's
// operator trail rather than travelling to the agent — ebpfsoc.v1.Thaw has no
// field to carry it. An absent reason is recorded as absent; nothing is
// substituted for one the operator did not type.
func (s *Server) handleDeviceThaw(w http.ResponseWriter, r *http.Request) {
	// THIS RELEASE USED TO RECORD NEITHER WHO NOR WHY.
	//
	// WHO: cmd.Actor was never set, while releaseFleet — the process plane's
	// release, twenty lines up in this file — has always stamped it. So on the
	// plane where a release is what restores a possibly-compromised host's
	// network access, the agent's audit row said the PLATFORM had done it.
	// Stamped before Enqueue signs the command, because the actor is inside the
	// signature (command.Canonical): attribution anyone on the path could
	// rewrite is worse than none, since it names a specific person.
	//
	// WHY: the reason was decoded into the body struct below and then never
	// touched again — the one outcome with no record anywhere. It cannot reach
	// the agent's row (ebpfsoc.v1.Thaw carries exec_id and pid and nothing
	// else), so recordWriteReason puts it where this control plane can hold it.
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Macs   []string `json:"macs"`
		Reason string   `json:"reason"`
	}
	_, err := decodeWriteBody(r, &b)
	if err != nil {
		refuseWriteBody(w, err)
		return
	}
	type res struct {
		Mac    string `json:"mac"`
		OK     bool   `json:"ok"`
		Agent  string `json:"agent,omitempty"`
		Detail string `json:"detail,omitempty"`
	}
	actor := s.subject(r)
	results := make([]res, 0, len(b.Macs))
	for _, mac := range b.Macs {
		out := s.dispatchTargeted(s.tenantAgents(tenant), &ebpfsocv1.Command{
			Actor:  actor,
			Action: &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{ExecId: "device:" + mac}}})
		results = append(results, res{Mac: mac, OK: out.applied, Agent: out.owner, Detail: out.detail})
	}
	s.recordWriteReason(r, tenant, "device-thaw", actor, b.Reason,
		fmt.Sprintf("released %d device(s): %s", len(b.Macs), strings.Join(b.Macs, ", ")))
	writeJSON(w, 200, map[string]any{"results": results})
}

// recordWriteReason writes an operator's justification for one write to the
// operator trail, for the actions whose reason cannot travel to the agent.
//
// WHY IT RE-ASKS AUTHORIZE. The row has to say whether this operator reached
// the tenant through a cross-tenant role, and that is Authorize's answer, not a
// property of the principal — a provider operator who also holds a tenant-bound
// grant on this customer is NOT crossing a boundary here. Re-deriving the flag
// locally is how the trail would come to disagree with the gate that let the
// write through, so the decision is asked for again, with a nil auditor so
// asking does not itself write a second row.
//
// WHAT IT CANNOT PROMISE. Both auditors deliberately drop own-tenant ALLOWED
// rows (centralstore.PGStore.RecordAccess, authz.MemAuditor.RecordAccess): an
// operator working inside their own tenant is the system working, and recording
// every such access would bury the cross-tenant and denied entries an auditor
// is looking for. So this durably records a PROVIDER's release — the
// cross-tenant case an MSSP runs on, and the one where "who let this device
// back on" is asked from outside — while a tenant-bound analyst releasing their
// own devices leaves the reason in the journal line this also writes, and
// nowhere else.
// That is a smaller gap than the one it replaces, which was no record anywhere,
// and it is stated here rather than implied so nobody reads this call as a
// guarantee the trail does not make.
func (s *Server) recordWriteReason(r *http.Request, tenant, action, actor, reason, what string) {
	stated := reason
	if strings.TrimSpace(stated) == "" {
		// Said, not invented. An absent reason is a fact about the release and
		// the trail has to carry it as one.
		stated = "(no reason given)"
	}
	detail := what + "; reason: " + stated
	s.cfg.Logf("[%s] %s on tenant %s: %s", action, actor, tenant, detail)

	aud, ok := s.auditor.(authz.AccessAuditor)
	if !ok {
		return
	}
	p, ok := s.principal(r)
	if !ok {
		return
	}
	d := authz.Authorize(p, tenant, authz.ActionRespond, nil)
	aud.RecordAccess(actor, tenant, action, d.Allowed, d.CrossTenant, detail)
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
		"mode":    mode,
		"dry_run": dryRun,
		// OMITTED, not false. No heartbeat field carries the agent's
		// kill-switch state (grep kill_switch in the proto: only the outbound
		// Command has one), so the control plane cannot know it. Emitting
		// `false` told an operator who had just engaged the emergency stop that
		// enforcement was still armed — the same three-state lesson as
		// audit.supported one line below. nil renders as "unknown".
		"kill_switched": nil,
		"enforcing":     enforcing,
		"tracked":       tracked,
		"counts":        counts,
		// The ladder the AGENTS are running, read off the heartbeat. Omitted
		// entirely (nil) when no agent has reported one, so the console shows
		// "unknown" rather than the engine's defaults dressed up as fact.
		"thresholds":         chokeThresholds(recs),
		"thresholds_diverge": thresholdsDiverge(recs),
		// Every host whose ladder the reconciler put back to tenant policy.
		// Without this an operator who set a ladder on one host watches it
		// revert two minutes later with no explanation reachable from the
		// console — the change applied, then undid itself.
		"ladder_corrections": s.ladderCorrections.forTenant(tenant, 20),
		// The PROCESS data plane the agents report, aggregated exactly the way
		// the device plane already is on /api/choke/device-state. Both wire
		// fields existed from the start and neither was populated, so the
		// control plane could not tell an agent with a live cgroup/BPF plane
		// from one on the userspace noop fallback — and it renders as
		// "enforcing" either way. Live on this estate every agent reports
		// "noop": the per-PID token buckets are modelled, not in the kernel.
		"data_plane":     processPlaneTier(recs),
		"links_attached": processPlaneLinks(recs),
		// NOT {"ok":true}. The control plane does not hash-chain decisions
		// centrally, so claiming the chain is intact renders a green "intact ·
		// 0 rows" in the header for a check that never ran. supported=false is
		// the third state: unverifiable here, as opposed to verified or broken.
		"audit": map[string]any{"ok": false, "supported": false, "total": 0},
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
		// RevertPending: this containment thaws on its own. The agent-local
		// console has shown it since the revert timer existed and the fleet
		// console rendered a self-releasing quarantine identically to a
		// permanent one — so an operator either manually thawed something
		// already about to release, or walked away from one that never would.
		RevertPending bool `json:"revert_pending,omitempty"`
		// LastSeen: when the agent last observed the process. A contained
		// exec_id whose process has exited stays in the snapshot, and without
		// this the row reads as a live containment.
		LastSeen string `json:"last_seen,omitempty"`
	}
	out := []circuit{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, c := range rec.Chokes {
			e := circuit{
				ExecID: c.GetExecId(), PID: c.GetPid(), Binary: c.GetBinary(),
				State: c.GetState(), Score: c.GetScore(), Agent: rec.AgentID,
				RevertPending: c.GetRevertPending(),
			}
			// Omitted rather than zero-stamped: an agent that predates the
			// field sends nothing, and 1970 on a containment row would read as
			// a process last seen fifty years ago.
			if ts := c.GetLastSeen(); ts != nil && ts.IsValid() && !ts.AsTime().IsZero() {
				e.LastSeen = ts.AsTime().UTC().Format(time.RFC3339)
			}
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	writeJSON(w, 200, out)
}

// handleChokeBuckets — the kernel token buckets the tenant's agents installed.
//
// Served from the heartbeat snapshots. This used to return a hardcoded empty
// array because agents did not report the map, so the console's "Choke Map
// (kernel)" panel was blank on every tenant while the single-host engine showed
// hundreds of live buckets — the panel that proves a throttle reached the
// kernel rather than only being recorded as a decision.
func (s *Server) handleChokeBuckets(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	type bucket struct {
		PID        uint32 `json:"pid"`
		RatePerSec uint64 `json:"rate_per_sec"`
		Burst      uint64 `json:"burst"`
		Tokens     uint64 `json:"tokens"`
		Flags      uint32 `json:"flags"`
		Agent      string `json:"agent"`
	}
	out := []bucket{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, b := range rec.Buckets {
			out = append(out, bucket{
				PID: b.GetPid(), RatePerSec: b.GetRatePerSec(), Burst: b.GetBurst(),
				Tokens: b.GetTokens(), Flags: b.GetFlags(), Agent: rec.AgentID,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Agent != out[j].Agent {
			return out[i].Agent < out[j].Agent
		}
		return out[i].PID < out[j].PID
	})
	writeJSON(w, 200, out)
}

// handleChokeCgroups — which PIDs the kernel reports inside each choke cgroup,
// merged across the tenant's agents.
//
// Previously a hardcoded empty object. This is what is ACTUALLY confined right
// now, as distinct from what a decision row says should be; with it empty the
// console could not show an operator that a quarantine had taken hold.
func (s *Server) handleChokeCgroups(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	// Shape matches the engine's: tier -> []pid, so the same panel renders on
	// both deployments without a branch.
	out := map[string][]uint32{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, cg := range rec.Cgroups {
			tier := cg.GetTier()
			// Seed with a non-nil empty slice. A nil slice marshals to JSON
			// `null`, and the console types this map as number[] | {pids,count}
			// — null is in neither, so an empty tier would render as a broken
			// cell instead of an empty one. The engine sends [] here.
			if _, seen := out[tier]; !seen {
				out[tier] = []uint32{}
			}
			out[tier] = append(out[tier], cg.GetPids()...)
		}
	}
	writeJSON(w, 200, out)
}

// handleChokeProcesses — the live host process table across the tenant's
// agents, joined with choke state.
//
// Previously a hardcoded empty array, which left the console's process picker
// with nothing to pick: an operator could not choose a process to contain
// unless it had already alerted. Agents cap what they report (tracked first,
// then by score), so this is a scan surface — the agent-local API stays
// authoritative for a full table.
func (s *Server) handleChokeProcesses(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	type proc struct {
		PID     uint32 `json:"pid"`
		PPID    uint32 `json:"ppid"`
		UID     uint32 `json:"uid"`
		Comm    string `json:"comm,omitempty"`
		Exe     string `json:"exe"`
		Cmdline string `json:"cmdline,omitempty"`
		Tracked bool   `json:"tracked,omitempty"`
		State   string `json:"state,omitempty"`
		Score   int32  `json:"score,omitempty"`
		ExecID  string `json:"exec_id,omitempty"`
		Agent   string `json:"agent"`
	}
	out := []proc{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, p := range rec.Processes {
			out = append(out, proc{
				PID: p.GetPid(), PPID: p.GetPpid(), UID: p.GetUid(),
				Comm: p.GetComm(), Exe: p.GetExe(),
				Cmdline: p.GetCmdline(), Tracked: p.GetTracked(), State: p.GetState(),
				Score: p.GetScore(), ExecID: p.GetExecId(), Agent: rec.AgentID,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tracked != out[j].Tracked {
			return out[i].Tracked
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].PID < out[j].PID
	})
	writeJSON(w, 200, out)
}

// handleChokeProcDetail — per-PID /proc drill. Not reported centrally; empty.
func (s *Server) handleChokeProcDetail(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	pidStr := strings.TrimPrefix(r.URL.Path, "/api/choke/proc/")
	pid64, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		http.Error(w, "bad pid", http.StatusBadRequest)
		return
	}
	// Answer from what the agents actually report. Previously a stub that always
	// said {"pid":"<string>","tracked":false} — so the console's per-PID drill was
	// blank on the fleet console AND typed pid as a string where the engine sends
	// a number.
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, p := range rec.Processes {
			if p.GetPid() != uint32(pid64) {
				continue
			}
			writeJSON(w, 200, map[string]any{
				"pid": p.GetPid(), "ppid": p.GetPpid(), "uid": p.GetUid(),
				"comm": p.GetComm(), "exe": p.GetExe(), "cmdline": p.GetCmdline(),
				"tracked": p.GetTracked(), "state": p.GetState(),
				"score": p.GetScore(), "exec_id": p.GetExecId(),
				"agent": rec.AgentID,
				// Named so the panel can say why it is thinner than the engine's:
				// the agent reports a summary, not a full /proc scrape.
				"source": "agent heartbeat summary",
			})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"pid": uint32(pid64), "tracked": false,
		"detail": "no agent in this tenant reported that pid"})
}

// handleVerifyChain — decision hash-chain audit.
//
// The central store does NOT hash-chain decisions per tenant yet, so there is
// nothing here to verify. This used to answer {"ok":true,"total":0}, and the
// console renders anything that is not ok=false as "audit chain verified" — so
// pressing Verify on the fleet console told the operator their tamper-evidence
// was intact after checking exactly zero records. A security product may report
// that a control is unavailable; it may not report an unrun check as passed.
//
// supported=false is what the console keys on to say "not available here"
// rather than either "verified" or the equally wrong "chain broken".

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
		"data_plane": dataPlane,
		"mode":       mode,
		"enforcing":  enforcing,
		"dry_run":    dryRun,
		// OMITTED, not false. No heartbeat field carries the agent's
		// kill-switch state (grep kill_switch in the proto: only the outbound
		// Command has one), so the control plane cannot know it. Emitting
		// `false` told an operator who had just engaged the emergency stop that
		// enforcement was still armed — the same three-state lesson as
		// audit.supported one line below. nil renders as "unknown".
		"kill_switched": nil,
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
	// Reads no body on purpose: it refuses every caller, so there is nothing a
	// body could ask for. See handleChokeAnnotate.
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"error": "interactive choke actions are not yet enabled on the central console",
	})
}
