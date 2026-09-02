package controlplane

import (
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/approval"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

// A temporary containment that needs a second operator must not come back
// permanent.
//
// The approval queue stores the request and replays it after someone approves.
// If the revert window is not stored with it, the approver is shown "quarantine,
// reverts in 30 minutes", approves that, and the agent receives a quarantine
// that never lifts — the queue silently converting a reversible action into an
// irreversible one, which is the opposite of what a change-control gate is for.
func TestTheRevertWindowSurvivesTheApprovalQueue(t *testing.T) {
	s := &Server{
		registry:      heartbeat.NewRegistry(),
		auditor:       authz.NewMemAuditor(),
		approvals:     approval.NewStore(approval.DefaultTTL),
		changeControl: newChangeControlCache(),
	}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.RequireApproval = true

	// A destructive action with a 30-minute auto-revert, requested by alice.
	code, body := s.chokeRequest("alice", "acme", "exec-1", 4021, "sever", "confirmed C2", "", 1800)
	if code != 202 {
		t.Fatalf("status %d, want 202 (held for approval): %v", code, body)
	}
	req, ok := body["approval"].(approval.Request)
	if !ok {
		t.Fatalf("no approval request in the response: %v", body)
	}
	if req.RevertAfterSeconds != 1800 {
		t.Fatalf("the queued request carries revert=%d, want 1800 — the approved "+
			"containment would be permanent", req.RevertAfterSeconds)
	}
}

// A jail with no window must stay permanent through the queue: the absence of a
// revert is itself a decision the approver is judging.
func TestAPermanentJailStaysPermanentThroughApproval(t *testing.T) {
	s := &Server{
		registry:      heartbeat.NewRegistry(),
		auditor:       authz.NewMemAuditor(),
		approvals:     approval.NewStore(approval.DefaultTTL),
		changeControl: newChangeControlCache(),
	}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.RequireApproval = true

	_, body := s.chokeRequest("alice", "acme", "exec-1", 4021, "sever", "confirmed C2", "", 0)
	req, ok := body["approval"].(approval.Request)
	if !ok {
		t.Fatalf("no approval request: %v", body)
	}
	if req.RevertAfterSeconds != 0 {
		t.Fatalf("an auto-revert appeared from nowhere: %d", req.RevertAfterSeconds)
	}
}
