package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/approval"
)

// Blast radius THROUGH change control.
//
// A targeted fleet change used to be refused outright when the tenant required
// approval, because the parked request carried no host list and the executor
// dispatched to the whole tenant. That refusal had two costs: host-scoped
// containment was unavailable to precisely the tenants that run four-eyes, and
// the wider untargeted form of the same ask was accepted while the narrow one
// was not.
//
// These pin the replacement. The property that matters is not "targeting is
// allowed" — it is that an APPROVED narrow change stays narrow. An approved
// "contain agent-a" that reaches agent-b is the false-containment class this
// codebase has already been bitten by, made worse by an audit record swearing
// the narrow action was the one authorised.

// parkedApprovalID pulls the request id out of a 202 parking response.
func parkedApprovalID(t *testing.T, body map[string]any) string {
	t.Helper()
	req, ok := body["approval"].(map[string]any)
	if !ok {
		t.Fatalf("the parking response carries no approval record: %v", body)
	}
	id, _ := req["id"].(string)
	if id == "" {
		t.Fatalf("the parked approval has no id: %v", body)
	}
	return id
}

// approveAndRun decides a parked request as a second operator and executes it,
// returning what the executor answered.
func approveAndRun(t *testing.T, s *Server, tenant, id string) (int, map[string]any) {
	t.Helper()
	req, err := s.approvals.Decide(tenant, id, "bob", "verified", true)
	if err != nil {
		t.Fatal(err)
	}
	return s.executeApproved(httptest.NewRequest(http.MethodPost, "/api/approvals/decide", nil), tenant, req)
}

// TestApprovedTargetedChangeReachesOnlyTheHostsItWasApprovedFor is the finding.
// Parking the request is not the fix on its own: what the approver read has to
// be what runs.
func TestApprovedTargetedChangeReachesOnlyTheHostsItWasApprovedFor(t *testing.T) {
	s := targetingServer(t)
	s.cfg.RequireApproval = true

	code, body := fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
		map[string]any{"name": "containment", "reason": "IR-4821", "targets": []string{"agent-a"}})
	if code != http.StatusAccepted {
		t.Fatalf("a targeted containment returned %d, want 202: %v", code, body)
	}
	id := parkedApprovalID(t, body)

	code, out := approveAndRun(t, s, "acme", id)
	if code != 200 {
		t.Fatalf("the approved containment returned %d: %v", code, out)
	}
	if n := s.dispatcher.Pending("agent-b"); n != 0 {
		t.Fatalf("the approved containment reached agent-b (%d queued) — it was approved for agent-a alone", n)
	}
	if n := s.dispatcher.Pending("agent-a"); n != 1 {
		t.Fatalf("agent-a has %d queued commands, want the 1 that was approved for it", n)
	}
	// And the executor answers in the envelope the console summarises, so an
	// approved change is not reported as "coverage unknown". Read off the Go
	// value here rather than through hostNames, which decodes a JSON body.
	hosts, ok := out["hosts"].([]fleetHostResult)
	if !ok {
		t.Fatalf("the approved change carries no per-host envelope, so the console renders it as coverage unknown: %v", out)
	}
	if len(hosts) != 1 || hosts[0].Name != "agent-a" {
		t.Fatalf("hosts = %v, want just agent-a", hosts)
	}
	if out["total"] != 1 {
		t.Fatalf("total = %v, want 1 — total counts the hosts the approval covered", out["total"])
	}
	if got := targetsOf(out["targets"]); len(got) != 1 || got[0] != "agent-a" {
		t.Fatalf("the applied record reports targets %v, want [agent-a]", got)
	}
}

// TestApprovedUntargetedChangeStillReachesEveryAgent: the fix must not narrow
// what was always fleet-wide. A request parked without a host list means the
// tenant, and approving it has to arm the tenant.
func TestApprovedUntargetedChangeStillReachesEveryAgent(t *testing.T) {
	s := targetingServer(t)
	s.cfg.RequireApproval = true

	code, body := fleetWrite(t, s, s.handleChokeMode, "POST", "/api/fleet/mode?tenant=acme",
		map[string]any{"enforcing": true, "reason": "IR-4821"})
	if code != http.StatusAccepted {
		t.Fatalf("a fleet-wide arming returned %d, want 202: %v", code, body)
	}
	if _, ok := body["targets"]; ok && body["targets"] != nil {
		t.Fatalf("an untargeted request reported a host list, which reads as 'these hosts only': %v", body["targets"])
	}

	if code, out := approveAndRun(t, s, "acme", parkedApprovalID(t, body)); code != 200 {
		t.Fatalf("the approved arming returned %d: %v", code, out)
	}
	for _, agent := range []string{"agent-a", "agent-b"} {
		if n := s.dispatcher.Pending(agent); n != 1 {
			t.Fatalf("%s has %d queued commands, want the tenant-wide arming that was approved", agent, n)
		}
	}
}

// TestTheQueueShowsTheApproverTheBlastRadius. An approver judging "preset
// containment" with no idea whether it reaches one host or the estate is
// rubber-stamping, which manufactures an audit trail that implies review.
func TestTheQueueShowsTheApproverTheBlastRadius(t *testing.T) {
	s := targetingServer(t)
	s.cfg.RequireApproval = true
	s.cfg.AdminToken = "admin-secret"

	_, narrow := fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
		map[string]any{"name": "containment", "reason": "IR-4821", "targets": []string{"agent-b"}})
	_, wide := fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
		map[string]any{"name": "containment", "reason": "IR-4822"})
	narrowID, wideID := parkedApprovalID(t, narrow), parkedApprovalID(t, wide)

	req := httptest.NewRequest(http.MethodGet, "/api/approvals?tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rec := httptest.NewRecorder()
	s.handleApprovals(rec, req)
	if rec.Code != 200 {
		t.Fatalf("the queue returned %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		Approvals []struct {
			ID      string   `json:"id"`
			Targets []string `json:"targets"`
			Radius  string   `json:"radius"`
		} `json:"approvals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	rows := map[string]struct {
		targets []string
		radius  string
	}{}
	for _, row := range got.Approvals {
		rows[row.ID] = struct {
			targets []string
			radius  string
		}{row.Targets, row.Radius}
	}
	if r := rows[narrowID]; len(r.targets) != 1 || r.targets[0] != "agent-b" || r.radius != "agent-b" {
		t.Fatalf("the targeted request renders as %v / %q — the approver cannot see it is one host", r.targets, r.radius)
	}
	if r := rows[wideID]; len(r.targets) != 0 || r.radius != "the whole tenant" {
		t.Fatalf("the fleet-wide request renders as %v / %q — the approver cannot see it is the estate", r.targets, r.radius)
	}
}

// TestAnApprovedChangeWhoseHostsLeftIsNotBroadcast. The dangerous fallback: if
// the recorded hosts are gone by the time someone approves, dispatching to
// whoever remains is exactly the widening substitution the record exists to
// prevent. Nothing is sent, and the refusal names what was approved.
func TestAnApprovedChangeWhoseHostsLeftIsNotBroadcast(t *testing.T) {
	s := targetingServer(t)
	req := approval.Request{ID: "req-ghost", Tenant: "acme", Scope: "fleet", Action: "preset", Reason: "containment"}
	fleetApprovalTargets.put(req.ID, []string{"agent-that-left"}, true)

	code, out := s.executeApproved(httptest.NewRequest(http.MethodPost, "/x", nil), "acme", req)
	if code != http.StatusConflict {
		t.Fatalf("status %d, want 409 — an approval for a host that is gone must not run: %v", code, out)
	}
	for _, agent := range []string{"agent-a", "agent-b"} {
		if n := s.dispatcher.Pending(agent); n != 0 {
			t.Fatalf("%s received %d command(s) from an approval that named a different host", agent, n)
		}
	}
	if got := targetsOf(out["targets"]); len(got) != 1 || got[0] != "agent-that-left" {
		t.Fatalf("the refusal does not name what was approved: %v", out)
	}
}

// TestAnApprovedFleetChangeWithNoRecordedScopeIsRefused. The ledger is the only
// statement of what a parked fleet change covers, so a request without one
// cannot be executed as approved. Falling back to "the whole tenant" would make
// a lost record the widest possible action.
func TestAnApprovedFleetChangeWithNoRecordedScopeIsRefused(t *testing.T) {
	s := targetingServer(t)
	req := approval.Request{ID: "req-never-recorded", Tenant: "acme", Scope: "fleet", Action: "mode"}

	code, out := s.executeApproved(httptest.NewRequest(http.MethodPost, "/x", nil), "acme", req)
	if code != http.StatusConflict || out["status"] != "STATUS_SCOPE_UNKNOWN" {
		t.Fatalf("status %d / %v, want 409 STATUS_SCOPE_UNKNOWN: %v", code, out["status"], out)
	}
	for _, agent := range []string{"agent-a", "agent-b"} {
		if n := s.dispatcher.Pending(agent); n != 0 {
			t.Fatalf("%s received %d command(s) from an approval with no recorded scope", agent, n)
		}
	}
}
