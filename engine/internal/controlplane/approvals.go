package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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
	}
	out := make([]row, 0, len(list))
	for _, req := range list {
		out = append(out, row{Request: req, Mine: strings.EqualFold(req.Requester, me)})
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
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	gated := []string{}
	if s.cfg.RequireApproval {
		gated = []string{"quarantine", "sever"}
	}
	writeJSON(w, 200, map[string]any{
		// Empty when change-control is off for this deployment, so the console
		// states the posture rather than implying a control that is not running.
		"enabled":           s.cfg.RequireApproval,
		"requires_approval": gated,
		"fleet_arming":      s.cfg.RequireApproval,
		// Stated explicitly because it is a safety property, not an omission:
		// nothing that STOPS enforcement may ever wait on a quorum.
		"never_gated": []string{"thaw", "throttle", "tarpit", "kill-switch", "detect-only"},
		"ttl_seconds": int(approval.DefaultTTL.Seconds()),
	})
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
	tenant := b.Tenant
	if tenant == "" {
		tenant = r.URL.Query().Get("tenant")
	}
	if tenant == "" {
		if scope := authz.TenantScope(p); len(scope) > 0 {
			tenant = scope[0]
		}
	}
	if tenant == "" {
		http.Error(w, "tenant required", http.StatusBadRequest)
		return
	}
	// Approving someone else's destructive action is its own capability.
	if !authz.Authorize(p, tenant, authz.ActionApprove, s.auditor).Allowed {
		http.NotFound(w, r)
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

	code, body := s.executeApproved(tenant, req)
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
func (s *Server) executeApproved(tenant string, req approval.Request) (int, map[string]any) {
	if req.Scope == "fleet" {
		switch req.Action {
		case "mode":
			applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
				Action: &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{
					Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, Plane: planeFor(req.MAC)}}})
			return 200, map[string]any{"ok": applied > 0, "status": "STATUS_APPLIED", "mode": "enforcing",
				"applied": applied, "total": total, "detail": detail}
		case "preset":
			applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
				Action: &ebpfsocv1.Command_ApplyPreset{ApplyPreset: &ebpfsocv1.ApplyPreset{Preset: req.Reason}}})
			return 200, map[string]any{"ok": applied > 0, "status": "STATUS_APPLIED",
				"applied": applied, "total": total, "detail": detail}
		}
		return badChoke("unknown fleet change: " + req.Action)
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
	return s.performChoke(tenant, req.ExecID, req.PID, req.Action, req.Reason, req.AgentID)
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
// Disarming and the kill-switch never reach here: see the approval package doc
// for why the exit from a bad state must never need a quorum.
func (s *Server) requireFleetApproval(w http.ResponseWriter, r *http.Request, tenant, change string, arming bool, plane ebpfsocv1.Plane, detail string) bool {
	if !s.cfg.RequireApproval || s.approvals == nil || !approval.FleetChangeRequiresApproval(change, arming) {
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
	s.cfg.Logf("[approval] %s requested fleet %s (tenant=%s) -> %s (awaiting a second operator)",
		req.Requester, change, tenant, req.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": false, "status": "APPROVAL_REQUIRED", "approval_required": true, "approval": req,
		"detail": fmt.Sprintf(
			"arming the whole tenant is a fleet-wide destructive change and needs a second operator "+
				"to approve it (request %s). Nothing has been armed.", req.ID),
	})
	return true
}
