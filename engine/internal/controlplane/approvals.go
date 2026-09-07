package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/approval"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// Change-control endpoints for destructive fleet actions (threat-model EN-2).
//
// A destructive request never reaches an agent on the strength of one session.
// It is parked here as a pending approval, a SECOND operator approves it, and
// only then is the command signed and dispatched. The request record is the
// audit trail: who asked, who approved, when, and what actually happened.

func (s *Server) registerApprovalRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/approvals", s.handleApprovals)             // GET: the queue
	mux.HandleFunc("/api/approvals/decide", s.handleApprovalDecide) // POST: approve/deny
	mux.HandleFunc("/api/approvals/policy", s.handleApprovalPolicy) // GET: what is gated
}

// handleApprovals lists the tenant's change-control queue (pending first).
func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	list := s.approvals.List(tenant)
	// The viewer's own requests are marked so the console can grey out the
	// approve button rather than letting an operator discover the four-eyes rule
	// by being rejected after they have committed to the action.
	me := s.subject(r)
	type row struct {
		approval.Request
		Mine bool `json:"mine"`
		// Targets and Radius are the BLAST RADIUS of a parked fleet change.
		// Without them the queue showed "fleet · preset containment" for both a
		// two-host containment and one that arms every agent in the tenant, and
		// an approver cannot judge an action whose reach is not on the row.
		// Targets is absent for an untargeted request; Radius says so in words.
		Targets []string `json:"targets,omitempty"`
		Radius  string   `json:"radius,omitempty"`
	}
	out := make([]row, 0, len(list))
	for _, req := range list {
		entry := row{Request: req, Mine: strings.EqualFold(req.Requester, me)}
		if req.Scope == "fleet" {
			// Only when the radius is actually known. An unrecorded request
			// renders neither field: "the whole tenant" for a change whose scope
			// we lost would be a claim the server cannot support, and it is the
			// wrong claim in the dangerous direction.
			if rec, known := fleetApprovalTargets.get(req.ID); known {
				entry.Targets = targetsOrNil(rec.agents, rec.targeted)
				entry.Radius = radiusLabel(rec.agents, rec.targeted)
			}
		}
		out = append(out, entry)
	}
	writeJSON(w, 200, map[string]any{
		"approvals": out,
		"pending":   s.approvals.PendingCount(tenant),
		"you":       me,
	})
}

// handleApprovalPolicy tells the console which actions are gated, so it can warn
// before an operator commits rather than after. Read-only.
func (s *Server) handleApprovalPolicy(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	// Per tenant, not per deployment. This endpoint tells the console what to
	// warn about BEFORE an operator commits; reading the deploy flag here
	// while the gate reads the tenant setting would warn the wrong operators
	// in both directions.
	enabled := s.approvalRequired(tenant)
	gated := []string{}
	if enabled {
		gated = []string{"quarantine", "sever"}
	}
	writeJSON(w, 200, map[string]any{
		// Empty when change-control is off for this deployment, so the console
		// states the posture rather than implying a control that is not running.
		"enabled":           enabled,
		"requires_approval": gated,
		"fleet_arming":      enabled,
		// Stated explicitly because it is a safety property, not an omission:
		// nothing that STOPS enforcement may ever wait on a quorum.
		"never_gated": []string{"thaw", "throttle", "tarpit", "kill-switch", "detect-only"},
		"ttl_seconds": int(approval.DefaultTTL.Seconds()),
	})
}

// authorizeApproveAs resolves which tenant a decision is about, then checks the
// RBAC APPROVE grant on it. Split out of handleApprovalDecide so the resolution
// can be driven with a real Keycloak-shaped principal: the identity path that
// runs on the estate is an OIDC session no test can construct, and the only
// principal a test could otherwise reach this code with is the break-glass
// bearer token — which carries no tenant and so never exercises the branch
// below. That gap is why the regression this comment describes shipped green.
//
// bodyTenant is the `tenant` field of the decision itself; the query parameter
// is the fallback the console never sends.
//
// THE RESOLUTION. A tenant-less decision was resolved through authz.TenantScope,
// which answers a different question — "which tenants may this principal reach
// without naming one" — and is correctly EMPTY for a cross-tenant role, because
// such an operator reaches a tenant by naming it, one audited access at a time.
// So every decision made by an MSOC admin or cross-tenant responder fell through
// to the 400 below, and the approval queue is precisely the release valve for
// the destructive actions change-control gates: the operators who staff it
// across customers are the cross-tenant ones, and it was dead for all of them.
//
// authz.DefaultTenant answers the question actually asked — which tenant this
// request is about — with the tenant stamped on the account, the same value
// whoami publishes as viewing_tenant and the same default the read and respond
// gates use. One fact, one source, so the planes cannot disagree about which
// customer is on screen.
//
// It confers nothing. The resolved tenant still goes through Authorize below,
// and for a cross-tenant principal that decision is recorded as a cross-tenant
// access exactly as a named one is.
func (s *Server) authorizeApproveAs(w http.ResponseWriter, r *http.Request, p authz.Principal, bodyTenant string) (string, bool) {
	tenant := bodyTenant
	if tenant == "" {
		tenant = r.URL.Query().Get("tenant")
	}
	if tenant == "" {
		tenant = authz.DefaultTenant(p)
	}
	if tenant == "" {
		// Nothing to resolve — the break-glass bearer token carries no tenant,
		// and a tenant may not be invented for it.
		http.Error(w, "tenant required", http.StatusBadRequest)
		return "", false
	}
	// Approving someone else's destructive action is its own capability.
	if !authz.Authorize(p, tenant, authz.ActionApprove, s.auditor).Allowed {
		http.NotFound(w, r)
		return "", false
	}
	return tenant, true
}

// handleApprovalDecide approves or denies a pending request. On approval it
// EXECUTES the action and records the outcome on the same record, so "approved"
// and "applied" can never drift apart in the audit trail.
func (s *Server) handleApprovalDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var b struct {
		ID      string `json:"id"`
		Approve bool   `json:"approve"`
		Note    string `json:"note"`
		Tenant  string `json:"tenant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tenant, ok := s.authorizeApproveAs(w, r, p, b.Tenant)
	if !ok {
		return
	}
	req, err := s.approvals.Decide(tenant, b.ID, s.subject(r), b.Note, b.Approve)
	switch {
	case errors.Is(err, approval.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, approval.ErrSelfApproval):
		// 403, and say why plainly — this is the control working, not a bug.
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "status": "SELF_APPROVAL_DENIED",
			"error":  err.Error(),
			"detail": err.Error(),
		})
		s.cfg.Logf("[approval] DENIED self-approval of %s by %s (tenant=%s)", b.ID, s.subject(r), tenant)
		return
	case err != nil:
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "status": "NOT_PENDING", "error": err.Error(), "detail": err.Error(), "approval": req,
		})
		return
	}

	if !b.Approve {
		s.cfg.Logf("[approval] %s DENIED %s (%s on %s, requested by %s)",
			req.Approver, req.ID, req.Action, targetLabel(req.ExecID, req.PID), req.Requester)
		writeJSON(w, 200, map[string]any{"ok": true, "status": "DENIED", "approval": req,
			"detail": "request denied; nothing was dispatched"})
		return
	}

	s.cfg.Logf("[approval] %s APPROVED %s (%s on %s, requested by %s) — executing",
		req.Approver, req.ID, req.Action, targetLabel(req.ExecID, req.PID), req.Requester)

	code, body := s.executeApproved(r, tenant, req)
	outcome, _ := body["status"].(string)
	if applied, _ := body["ok"].(bool); applied {
		outcome = "APPLIED:" + outcome
	}
	s.approvals.MarkExecuted(tenant, req.ID, outcome)
	updated, _ := s.approvals.Get(tenant, req.ID)
	body["approval"] = updated
	body["approved_by"] = req.Approver
	body["requested_by"] = req.Requester
	writeJSON(w, code, body)
}

// executeApproved runs the action the approver actually read. Fleet-scope
// requests re-enter the fleet path; target-scope ones re-enter performChoke —
// deliberately the SAME code the un-gated rungs use, so approval changes who may
// act, never what the action does.
//
// "The action the approver read" includes its BLAST RADIUS. A request parked
// with a host list executes against exactly that list; only a request parked
// without one reaches the whole tenant. Running an approved "contain host-3"
// through dispatchAll would broadcast it — the false-containment class this
// codebase has already been bitten by, and worse here because an approval
// record would swear the narrow thing was authorised.
func (s *Server) executeApproved(r *http.Request, tenant string, req approval.Request) (int, map[string]any) {
	if req.Scope == "fleet" {
		agents, scoped, known, gone := s.approvalTargets(tenant, req.ID)
		if !known {
			// The radius this was requested with is not on file, so what the
			// approver read cannot be reproduced. Dispatching to the tenant
			// would be a guess in the widening direction — exactly the
			// substitution this whole path exists to prevent.
			msg := "the host set this request was raised with is no longer on file, so it cannot be " +
				"executed as approved — nothing was dispatched. Re-issue the change."
			return http.StatusConflict, map[string]any{
				"ok": false, "status": "STATUS_SCOPE_UNKNOWN", "error": msg, "detail": msg,
				"applied": 0, "total": 0, "hosts": []fleetHostResult{},
			}
		}
		if scoped && len(agents) == 0 {
			// Every host this was approved for has left the tenant. Widening to
			// "all agents" here is the exact substitution that must never
			// happen, so nothing is dispatched and the record says why.
			msg := fmt.Sprintf(
				"this request was approved for %s, and no longer names any agent in this tenant — "+
					"nothing was dispatched. Re-issue it against the hosts you mean.",
				strings.Join(gone, ", "))
			return http.StatusConflict, map[string]any{
				"ok": false, "status": "STATUS_TARGETS_GONE", "error": msg, "detail": msg,
				"applied": 0, "total": 0, "hosts": []fleetHostResult{}, "targets": gone,
			}
		}
		var cmd *ebpfsocv1.Command
		extra := map[string]any{}
		switch req.Action {
		case "mode":
			cmd = &ebpfsocv1.Command{Action: &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{
				Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, Plane: planeFor(req.MAC)}}}
			extra["mode"] = "enforcing"
		case "preset":
			cmd = &ebpfsocv1.Command{Action: &ebpfsocv1.Command_ApplyPreset{
				ApplyPreset: &ebpfsocv1.ApplyPreset{Preset: req.Reason}}}
		default:
			return badChoke("unknown fleet change: " + req.Action)
		}
		out := s.dispatchFleet(r, agents, cmd)
		// The status the agents reported, not a constant. This read
		// "STATUS_APPLIED" unconditionally, so an approved change that no agent
		// took was recorded on the approval as APPLIED — the audit trail
		// asserting an enforcement state the fleet was never in.
		status := fleetStatus(out.hosts)
		if status == "" {
			// fleetStatus returns empty when nothing answered. Blank on an
			// approval record reads as "never executed", so the silence is
			// named instead.
			status = "STATUS_NO_ACK"
		}
		body := map[string]any{"ok": out.applied > 0, "status": status,
			"applied": out.applied, "total": out.total, "detail": out.detail,
			// The per-host envelope the console summarises. Without it an
			// approved fleet change rendered as "coverage unknown" — the one
			// dispatch an operator has most reason to want confirmed.
			"hosts": out.hosts,
		}
		if scoped {
			// Echoed so the applied record states the radius, not just the act.
			body["targets"] = agents
			if len(gone) > 0 {
				body["targets_gone"] = gone
			}
		}
		for k, v := range extra {
			body[k] = v
		}
		return 200, body
	}
	// Device-scope requests target a MAC, not a process, so they re-enter the
	// device path rather than performChoke — which resolves a process owner and
	// would find nothing for a MAC.
	if req.Scope == "device" {
		out := s.performDeviceJail(tenant, req.MAC, req.Action)
		return 200, map[string]any{
			"ok": out.applied, "status": out.status, "detail": out.detail,
			"agent": out.owner, "action": req.Action, "reason": req.Reason, "mac": req.MAC,
		}
	}
	return s.performChoke(tenant, req.ExecID, req.PID, req.Action, req.Reason, req.AgentID, req.RevertAfterSeconds)
}

// planeFor picks the plane a stored fleet request targets. The device plane is
// recorded by putting "device" in MAC, since a fleet-wide arming has no single
// MAC of its own.
func planeFor(mac string) ebpfsocv1.Plane {
	if mac == "device" {
		return ebpfsocv1.Plane_PLANE_DEVICE
	}
	return ebpfsocv1.Plane_PLANE_PROCESS
}

// requireFleetApproval parks a fleet-wide ARMING change for a second operator.
// Returns true when the request was parked and the caller must not dispatch.
//
// agents is the resolved host set the change would touch and targeted says
// whether the operator named it. Both travel with the parked request: an
// approval that does not state its blast radius is worth little, and an
// approved narrow change that then broadcasts is worse than no approval at all.
//
// Disarming and the kill-switch never reach here: see the approval package doc
// for why the exit from a bad state must never need a quorum.
func (s *Server) requireFleetApproval(w http.ResponseWriter, r *http.Request, tenant, change string, arming bool, plane ebpfsocv1.Plane, detail string, agents []string, targeted bool) bool {
	if !s.approvalRequired(tenant) || s.approvals == nil || !approval.FleetChangeRequiresApproval(change, arming) {
		return false
	}
	mac := ""
	if plane == ebpfsocv1.Plane_PLANE_DEVICE {
		mac = "device"
	}
	req := s.approvals.Create(approval.Request{
		Tenant: tenant, Action: change, Scope: "fleet", MAC: mac,
		Reason: detail, Requester: s.subject(r),
	})
	// Recorded whether or not the operator named hosts: the ledger is what
	// executeApproved reads, and an unrecorded fleet request is refused there
	// rather than guessed at as tenant-wide.
	fleetApprovalTargets.put(req.ID, agents, targeted)
	s.cfg.Logf("[approval] %s requested fleet %s on %s (tenant=%s) -> %s (awaiting a second operator)",
		req.Requester, change, radiusLabel(agents, targeted), tenant, req.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": false, "status": "APPROVAL_REQUIRED", "approval_required": true, "approval": req,
		// Echoed on the parking response too, so the requester's own console can
		// show what it just asked for rather than re-deriving it.
		"targets": targetsOrNil(agents, targeted),
		"detail": fmt.Sprintf(
			"arming %s is a fleet-wide destructive change and needs a second operator "+
				"to approve it (request %s). Nothing has been armed.", radiusLabel(agents, targeted), req.ID),
	})
	return true
}

// radiusLabel renders a blast radius for an operator: the named hosts, or the
// whole tenant when none were named. "the whole tenant" and "2 hosts" are the
// difference the approver is being asked to judge, so it is never elided.
func radiusLabel(agents []string, targeted bool) string {
	if !targeted {
		return "the whole tenant"
	}
	if len(agents) == 0 {
		return "no host"
	}
	return strings.Join(agents, ", ")
}

// targetsOrNil returns the host list for a targeted request and nil for an
// untargeted one. nil, not []: an empty array in the response would read as
// "targets: none", which is the opposite of "targets: everything".
func targetsOrNil(agents []string, targeted bool) []string {
	if !targeted {
		return nil
	}
	return agents
}

// fleetApprovalTargets remembers the blast radius each parked fleet change was
// requested with, so the approver reads it and the executor honours it.
//
// It lives beside the approval store rather than on approval.Request because
// that type is owned by the approval package; the field belongs there and this
// is the seam that carries it until it moves. The property is what matters, and
// it holds either way: a fleet change parked with a host list is dispatched to
// exactly that list and can never widen to the tenant (see executeApproved).
//
// EVERY parked fleet request is recorded, targeted or not. "No entry" therefore
// means the scope is unknown rather than "unscoped", and executeApproved
// refuses those instead of treating them as tenant-wide — the one guess that
// could turn an approved two-host change into a fleet-wide one. Losing the
// ledger on restart fails in the same direction the approval store does: the
// pending request is gone with it, so nothing runs.
var fleetApprovalTargets = &approvalTargetLedger{byID: map[string]approvalTargets{}, max: 4096}

// approvalTargets is one parked request's radius. targeted distinguishes "the
// operator named these hosts" from "the operator meant the whole tenant"; the
// two are different asks and an empty agent list means neither.
type approvalTargets struct {
	agents   []string
	targeted bool
	at       time.Time
}

type approvalTargetLedger struct {
	mu   sync.Mutex
	byID map[string]approvalTargets
	max  int
}

func (l *approvalTargetLedger) put(id string, agents []string, targeted bool) {
	if id == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// A request that expires unapproved is never executed and would otherwise
	// sit here forever. Two request TTLs of slack, so an entry is only ever
	// dropped long after the request it describes stopped being approvable.
	cutoff := time.Now().Add(-2 * approval.DefaultTTL)
	for k, v := range l.byID {
		if v.at.Before(cutoff) {
			delete(l.byID, k)
		}
	}
	// Still full of recent entries: drop the oldest rather than grow without
	// bound. Arbitrary eviction would drop live ones, and a live entry lost is
	// a request that can no longer be executed at all (executeApproved fails
	// closed), so age order is what keeps that from hitting a pending request.
	for len(l.byID) >= l.max {
		oldest, at := "", time.Time{}
		for k, v := range l.byID {
			if at.IsZero() || v.at.Before(at) {
				oldest, at = k, v.at
			}
		}
		delete(l.byID, oldest)
	}
	l.byID[id] = approvalTargets{agents: append([]string(nil), agents...), targeted: targeted, at: time.Now()}
}

func (l *approvalTargetLedger) get(id string) (approvalTargets, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.byID[id]
	return v, ok
}

// approvalTargets resolves the host set a parked fleet change was approved for
// against the tenant's CURRENT agents.
//
//   - known false: the request's radius was never recorded or has aged out. The
//     caller must refuse; it must NOT assume "whole tenant".
//   - scoped false: the request named no hosts and legitimately covers the
//     tenant, so the tenant's agents are returned.
//   - scoped true: only the recorded hosts that are still agents of this
//     tenant, with gone naming the rest. A host that left the fleet between
//     request and approval is not silently replaced by the ones that remain,
//     and can never widen the dispatch.
func (s *Server) approvalTargets(tenant, id string) (agents []string, scoped, known bool, gone []string) {
	rec, ok := fleetApprovalTargets.get(id)
	if !ok {
		return nil, false, false, nil
	}
	if !rec.targeted {
		return s.tenantAgents(tenant), false, true, nil
	}
	inTenant := make(map[string]bool)
	for _, a := range s.tenantAgents(tenant) {
		inTenant[a] = true
	}
	for _, a := range rec.agents {
		if inTenant[a] {
			agents = append(agents, a)
		} else {
			gone = append(gone, a)
		}
	}
	if len(agents) == 0 {
		// Nothing left to dispatch to: hand back what was asked for so the
		// refusal can name it.
		return nil, true, true, rec.agents
	}
	return agents, true, true, gone
}
