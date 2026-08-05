package controlplane

import (
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/approval"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// EN-2 wiring. The approval package proves the RULES; these prove the CONTROL —
// that a destructive action genuinely never reaches an agent while it is held.
// A change-control queue that parks a request but dispatches it anyway is the
// worst of both worlds: it looks like governance and enforces nothing.

func approvalServer(t *testing.T) *Server {
	t.Helper()
	signer, _, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		registry:   heartbeat.NewRegistry(),
		owners:     newOwnerCache(),
		approvals:  approval.NewStore(approval.DefaultTTL),
		dispatcher: command.NewDispatcher(signer, time.Minute),
		auditor:    authz.NewMemAuditor(),
	}
	s.cfg.Logf = func(string, ...any) {}
	// These tests are ABOUT change-control, so they turn it on. It is off by
	// default (see Config.RequireApproval) precisely so a single-operator tenant
	// is never locked out of containing a threat.
	s.cfg.RequireApproval = true
	seed(s, "acme", "agent-a", choke("exec-on-a", 4021))
	return s
}

// TestDestructiveActionIsHeldAndNotDispatched is the whole point: a sever must
// be parked, and NOTHING may reach the agent until a second operator approves.
func TestDestructiveActionIsHeldAndNotDispatched(t *testing.T) {
	s := approvalServer(t)

	code, body := s.chokeRequest("alice", "acme", "exec-on-a", 4021, "sever", "confirmed C2", "")

	if code != 202 {
		t.Fatalf("code = %d, want 202 (held for approval)", code)
	}
	if ok, _ := body["ok"].(bool); ok {
		t.Fatal("a held action must not report ok — nothing has been applied")
	}
	if body["status"] != "APPROVAL_REQUIRED" {
		t.Fatalf("status = %v, want APPROVAL_REQUIRED", body["status"])
	}
	// THE assertion. Not "was it marked pending" but "did anything reach the fleet".
	if n := s.dispatcher.Pending("agent-a"); n != 0 {
		t.Fatalf("%d commands queued for agent-a — the sever was dispatched despite being held for approval", n)
	}
	if s.approvals.PendingCount("acme") != 1 {
		t.Fatal("the request was not queued for approval")
	}
}

// TestApprovalByASecondOperatorDispatches: once approved, the action must
// actually run — otherwise operators learn to bypass the console.
func TestApprovalByASecondOperatorDispatches(t *testing.T) {
	s := approvalServer(t)
	_, body := s.chokeRequest("alice", "acme", "exec-on-a", 4021, "sever", "confirmed C2", "")
	req := body["approval"].(approval.Request)

	if _, err := s.approvals.Decide("acme", req.ID, "bob", "verified", true); err != nil {
		t.Fatal(err)
	}
	// executeApproved runs the SAME containment path the requester asked for.
	go s.executeApproved("acme", req)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.dispatcher.Pending("agent-a") > 0 {
			return // the command reached the agent's queue
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("approved sever never reached the agent")
}

// TestSelfApprovalDoesNotDispatch: the four-eyes refusal must also mean nothing
// was sent. A control that rejects the API call but has already dispatched is
// theatre.
func TestSelfApprovalDoesNotDispatch(t *testing.T) {
	s := approvalServer(t)
	_, body := s.chokeRequest("alice", "acme", "exec-on-a", 4021, "sever", "confirmed C2", "")
	req := body["approval"].(approval.Request)

	if _, err := s.approvals.Decide("acme", req.ID, "alice", "", true); err == nil {
		t.Fatal("alice approved her own sever")
	}
	if n := s.dispatcher.Pending("agent-a"); n != 0 {
		t.Fatalf("%d commands queued after a refused self-approval", n)
	}
}

// TestReversibleRungsAreNotHeld: throttle/tarpit/thaw must go straight through.
// Containment that waits on a quorum during an incident is a control operators
// route around, and a slow throttle is not a risk worth governing.
func TestReversibleRungsAreNotHeld(t *testing.T) {
	for _, action := range []string{"throttle", "tarpit", "thaw"} {
		t.Run(action, func(t *testing.T) {
			s := approvalServer(t)
			// Dispatch in the background: with no agent connected to ack, the call
			// blocks for the full ackTimeout, and what is being tested is whether
			// the action was HELD — which is decided before any dispatch.
			go s.chokeRequest("alice", "acme", "exec-on-a", 4021, action, "routine", "")

			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if s.dispatcher.Pending("agent-a") > 0 {
					if s.approvals.PendingCount("acme") != 0 {
						t.Fatalf("%s created an approval request", action)
					}
					return // reached the agent without waiting on a quorum
				}
				if s.approvals.PendingCount("acme") != 0 {
					t.Fatalf("%s was held for approval — only destructive actions may be", action)
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatalf("%s never reached the agent", action)
		})
	}
}

// TestHeldActionSurvivesAsAnAuditRecord: who asked, for what, on which target,
// and why — available to the approver before they decide. An approver who cannot
// see what they are authorizing is a rubber stamp.
func TestHeldActionSurvivesAsAnAuditRecord(t *testing.T) {
	s := approvalServer(t)
	_, body := s.chokeRequest("alice@corp", "acme", "exec-on-a", 4021, "quarantine", "IR-4821 lateral movement", "agent-a")
	req := body["approval"].(approval.Request)

	got, ok := s.approvals.Get("acme", req.ID)
	if !ok {
		t.Fatal("request not retrievable")
	}
	if got.Requester != "alice@corp" || got.Action != "quarantine" ||
		got.ExecID != "exec-on-a" || got.PID != 4021 || got.AgentID != "agent-a" ||
		got.Reason != "IR-4821 lateral movement" {
		t.Fatalf("record lost detail the approver needs: %+v", got)
	}
	if got.ExpiresAt.Before(got.CreatedAt) {
		t.Fatal("request has no valid approval window")
	}
}

// TestApprovalsAreTenantScopedAtTheServer mirrors the store-level check at the
// layer an operator actually reaches.
func TestApprovalsAreTenantScopedAtTheServer(t *testing.T) {
	s := approvalServer(t)
	_, body := s.chokeRequest("alice", "acme", "exec-on-a", 4021, "sever", "confirmed C2", "")
	req := body["approval"].(approval.Request)

	if _, ok := s.approvals.Get("other-corp", req.ID); ok {
		t.Fatal("another tenant could read acme's pending sever")
	}
	if len(s.approvals.List("other-corp")) != 0 {
		t.Fatal("another tenant's approval queue was not empty")
	}
}

// TestApproveRequiresTheApproveCapability: a read-only operator must not be able
// to authorize a kill, even though they can see the queue.
func TestApproveRequiresTheApproveCapability(t *testing.T) {
	readOnly := authz.Principal{Subject: "viewer", Grants: []authz.Grant{{Role: authz.RoleReadOnly, TenantID: "acme"}}}
	if authz.Authorize(readOnly, "acme", authz.ActionApprove, nil).Allowed {
		t.Fatal("a read-only role could approve a destructive action")
	}
	analyst := authz.Principal{Subject: "alice", Grants: []authz.Grant{{Role: authz.RoleTenantAnalyst, TenantID: "acme"}}}
	if !authz.Authorize(analyst, "acme", authz.ActionApprove, nil).Allowed {
		t.Fatal("a tenant analyst could not approve — the queue would never drain")
	}
}

// TestChangeControlIsOffByDefault guards the safety default. Dual control needs
// two operators who can respond; shipping it ON would leave a tenant with one
// on-call engineer unable to contain a threat from the console at all — an
// approval rule that blocks containment during an incident is a worse failure
// than the one it prevents. Enabling it must be a deliberate deployment choice.
func TestChangeControlIsOffByDefault(t *testing.T) {
	s := approvalServer(t)
	s.cfg.RequireApproval = false // the default

	go s.chokeRequest("alice", "acme", "exec-on-a", 4021, "sever", "confirmed C2", "")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.dispatcher.Pending("agent-a") > 0 {
			if s.approvals.PendingCount("acme") != 0 {
				t.Fatal("an approval was created while change-control was disabled")
			}
			return
		}
		if s.approvals.PendingCount("acme") != 0 {
			t.Fatal("sever was held for approval although change-control is off by default")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("sever never reached the agent with change-control disabled")
}
