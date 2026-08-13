package approval

import (
	"errors"
	"testing"
	"time"
)

// EN-2 change-control. The threat is one command quarantining or severing many
// hosts — operator error, a stolen console session, or a compromised control
// plane. A reason string records why AFTERWARDS; only dual control stops it.

// TestSelfApprovalIsRefused is the control this package exists for. Without it
// "approvals" is a two-click version of the same single-operator action, and a
// stolen session satisfies it just as easily as one click did.
func TestSelfApprovalIsRefused(t *testing.T) {
	s := NewStore(DefaultTTL)
	r := s.Create(Request{Tenant: "acme", Action: "sever", ExecID: "e1", Requester: "op@example.com"})

	if _, err := s.Decide("acme", r.ID, "op@example.com", "", true); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("err = %v, want ErrSelfApproval — the requester approved their own destructive action", err)
	}
	got, _ := s.Get("acme", r.ID)
	if got.Status != StatusPending {
		t.Fatalf("status = %q, want still pending after a refused self-approval", got.Status)
	}
}

// TestSelfApprovalCheckIgnoresCase: the same human arrives as "Op@example.com"
// and "op@example.com" from different sessions. A control defeated by the shift
// key is not a control.
func TestSelfApprovalCheckIgnoresCase(t *testing.T) {
	s := NewStore(DefaultTTL)
	r := s.Create(Request{Tenant: "acme", Action: "sever", Requester: "Op@Example.com"})
	if _, err := s.Decide("acme", r.ID, "  op@example.com  ", "", true); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("err = %v, want ErrSelfApproval for the same person in different casing", err)
	}
}

// TestSecondOperatorCanApprove: the mechanism must actually let work through,
// or operators route around it.
func TestSecondOperatorCanApprove(t *testing.T) {
	s := NewStore(DefaultTTL)
	r := s.Create(Request{Tenant: "acme", Action: "sever", ExecID: "e1", Requester: "alice"})

	got, err := s.Decide("acme", r.ID, "bob", "confirmed on the host", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || got.Approver != "bob" {
		t.Fatalf("got status=%q approver=%q, want approved by bob", got.Status, got.Approver)
	}
	if got.DecidedAt.IsZero() {
		t.Fatal("approval must be timestamped — it is the audit record")
	}
}

// TestDecideIsOnceOnly: a decided request cannot be re-decided, so an approval
// cannot be replayed into a second execution of a destructive action.
func TestDecideIsOnceOnly(t *testing.T) {
	s := NewStore(DefaultTTL)
	r := s.Create(Request{Tenant: "acme", Action: "sever", Requester: "alice"})
	if _, err := s.Decide("acme", r.ID, "bob", "", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide("acme", r.ID, "carol", "", true); !errors.Is(err, ErrDecided) {
		t.Fatalf("err = %v, want ErrDecided on a second decision", err)
	}
}

// TestExpiredRequestCannotBeApproved: an approval hours later is not an approval
// of the situation anyone reviewed — the process may be gone and its PID reused.
func TestExpiredRequestCannotBeApproved(t *testing.T) {
	s := NewStore(time.Minute)
	base := time.Now()
	s.now = func() time.Time { return base }
	r := s.Create(Request{Tenant: "acme", Action: "sever", Requester: "alice"})

	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := s.Decide("acme", r.ID, "bob", "", true); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	got, _ := s.Get("acme", r.ID)
	if got.Status != StatusExpired {
		t.Fatalf("status = %q, want expired", got.Status)
	}
}

// TestQueueIsTenantScoped: one tenant must not see, or act on, another's
// change-control queue — it would leak what they are responding to and let a
// neighbour authorize their kills.
func TestQueueIsTenantScoped(t *testing.T) {
	s := NewStore(DefaultTTL)
	r := s.Create(Request{Tenant: "acme", Action: "sever", Requester: "alice"})

	if _, ok := s.Get("other-corp", r.ID); ok {
		t.Fatal("another tenant read acme's approval request")
	}
	if _, err := s.Decide("other-corp", r.ID, "mallory", "", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound — another tenant approved acme's sever", err)
	}
	if len(s.List("other-corp")) != 0 {
		t.Fatal("another tenant's queue was not empty")
	}
	if n := s.PendingCount("acme"); n != 1 {
		t.Fatalf("acme pending = %d, want 1", n)
	}
}

// TestOnlyDestructiveActionsAreGated. Gating the reversible rungs would make
// containment slower for no safety gain, and operators route around controls
// that cost them during an incident.
func TestOnlyDestructiveActionsAreGated(t *testing.T) {
	for _, a := range []string{"sever", "quarantine", "SEVER", " sever "} {
		if !RequiresApproval(a) {
			t.Errorf("RequiresApproval(%q) = false, want true", a)
		}
	}
	for _, a := range []string{"throttle", "tarpit", "thaw", ""} {
		if RequiresApproval(a) {
			t.Errorf("RequiresApproval(%q) = true — a reversible rung must not wait on a quorum", a)
		}
	}
}

// TestOnlyArmingIsGated is the safety property, and the one most likely to be
// broken by a well-meaning change: everything that STOPS enforcement — disarming
// to detect-only, the kill-switch — must go through instantly. Requiring a
// second operator to halt a bad rollout is how a mistake becomes an outage.
func TestOnlyArmingIsGated(t *testing.T) {
	if !FleetChangeRequiresApproval("mode", true) {
		t.Error("arming a whole tenant must need approval — that is EN-2")
	}
	if FleetChangeRequiresApproval("mode", false) {
		t.Error("DISARMING to detect-only must never wait on a quorum")
	}
	if FleetChangeRequiresApproval("preset", false) {
		t.Error("a non-containment preset must not be gated")
	}
	if FleetChangeRequiresApproval("kill-switch", true) {
		t.Error("the kill-switch is the emergency stop and must NEVER need approval")
	}
}

// TestMarkExecutedRecordsTheOutcome: the record has to answer "was it applied?",
// not merely "was it allowed?" — otherwise approved and applied silently drift.
func TestMarkExecutedRecordsTheOutcome(t *testing.T) {
	s := NewStore(DefaultTTL)
	r := s.Create(Request{Tenant: "acme", Action: "sever", Requester: "alice"})
	if _, err := s.Decide("acme", r.ID, "bob", "", true); err != nil {
		t.Fatal(err)
	}
	s.MarkExecuted("acme", r.ID, "APPLIED:STATUS_APPLIED")

	got, _ := s.Get("acme", r.ID)
	if !got.Executed || got.Outcome != "APPLIED:STATUS_APPLIED" {
		t.Fatalf("executed=%v outcome=%q, want the execution result recorded", got.Executed, got.Outcome)
	}
}

// TestDenyDoesNotExecute: a denied request must stay denied and unexecuted.
func TestDenyDoesNotExecute(t *testing.T) {
	s := NewStore(DefaultTTL)
	r := s.Create(Request{Tenant: "acme", Action: "sever", Requester: "alice"})
	got, err := s.Decide("acme", r.ID, "bob", "not our host", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusDenied {
		t.Fatalf("status = %q, want denied", got.Status)
	}
	if got.Executed {
		t.Fatal("a denied request must never be marked executed")
	}
}

// TestPendingSurvivesRetentionPressure: decided records are evicted under
// pressure, pending ones never are — dropping an undecided destructive action
// silently would make it un-approvable and un-auditable.
func TestPendingSurvivesRetentionPressure(t *testing.T) {
	s := NewStore(DefaultTTL)
	s.history = 5
	pending := s.Create(Request{Tenant: "acme", Action: "sever", Requester: "alice"})
	for i := 0; i < 50; i++ {
		r := s.Create(Request{Tenant: "acme", Action: "sever", Requester: "alice"})
		if _, err := s.Decide("acme", r.ID, "bob", "", false); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.Get("acme", pending.ID); !ok {
		t.Fatal("a pending destructive request was evicted by retention pressure")
	}
}
