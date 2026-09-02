package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// EN-2 became a per-tenant setting. These pin the two properties that make
// that safe: a tenant can only ever TIGHTEN past the platform's floor, and
// loosening does not retroactively release what the queue is already holding.

func changeControlServer(t *testing.T) *Server {
	t.Helper()
	s := approvalServer(t)
	s.cfg.RequireApproval = false // the shipped default; the tenant decides
	s.changeControl = newChangeControlCache()
	return s
}

func TestTenantSettingHoldsASeverTheDeploymentWouldHaveDispatched(t *testing.T) {
	// The whole reason this stopped being a startup flag: a tenant that turns
	// four-eyes on mid-incident must get it without a control-plane restart.
	s := changeControlServer(t)

	// Off: the sever goes straight through to performChoke.
	code, _ := s.chokeRequest("alice", "acme", "exec-on-a", 4021, "sever", "confirmed C2", "", 0)
	if code == http.StatusAccepted {
		t.Fatalf("change control is off for this tenant, yet the sever was parked (status %d)", code)
	}

	// The tenant turns it on. No restart, no redeploy.
	s.cacheChangeControl("acme", true, "")

	code, body := s.chokeRequest("alice", "acme", "exec-on-a", 4021, "sever", "confirmed C2", "", 0)
	if code != http.StatusAccepted {
		t.Fatalf("the tenant enabled change control and the sever was NOT held: status %d body %v", code, body)
	}
	if body["approval_required"] != true {
		t.Fatalf("held, but the response does not say why: %v", body)
	}
}

func TestOneTenantsChangeControlDoesNotGovernAnother(t *testing.T) {
	// One control plane, many customers. A regulated tenant turning four-eyes
	// on must not start parking another customer's containment — that would
	// make the strict customer set policy for everyone.
	s := changeControlServer(t)
	seed(s, "beta", "agent-b", choke("exec-on-b", 5150))
	s.cacheChangeControl("acme", true, "")

	if code, _ := s.chokeRequest("bob", "beta", "exec-on-b", 5150, "sever", "unrelated", "", 0); code == http.StatusAccepted {
		t.Fatal("tenant beta's sever was parked by tenant acme's setting")
	}
	if code, _ := s.chokeRequest("alice", "acme", "exec-on-a", 4021, "sever", "confirmed C2", "", 0); code != http.StatusAccepted {
		t.Fatal("tenant acme's own setting did not hold its sever")
	}
}

func TestTheDeploymentFloorCannotBeSwitchedOffByATenant(t *testing.T) {
	// A platform deployed with change control mandated has made that decision
	// above the console. A tenant-scoped off switch would let the person the
	// control exists to check remove the check.
	s := changeControlServer(t)
	s.cfg.RequireApproval = true

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/settings/change-control?tenant=acme",
		strings.NewReader(`{"enabled":false,"reason":"we would rather move fast"}`))
	s.writeChangeControl(rec, req, "acme")

	if rec.Code != http.StatusConflict {
		t.Fatalf("a mandated platform let a tenant switch change control off: status %d body %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "deployed with change control mandated") {
		t.Fatalf("the refusal does not say who owns the decision: %s", rec.Body)
	}
	// And the gate is unmoved.
	if !s.approvalRequired("acme") {
		t.Fatal("the refusal was reported and the gate opened anyway")
	}
}

func TestAMalformedBodyCannotDisableChangeControl(t *testing.T) {
	// enabled is a *bool on purpose. A missing field decoding to false would
	// switch off a safety control from a body that never mentioned it — the
	// same shape as the threshold request that zeroed sever_at and severed a
	// fleet.
	s := changeControlServer(t)
	s.cacheChangeControl("acme", true, "")

	for _, body := range []string{`{}`, `{"reason":"tidy up"}`, `not json`} {
		rec := httptest.NewRecorder()
		s.writeChangeControl(rec, httptest.NewRequest(http.MethodPut, "/x", strings.NewReader(body)), "acme")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q was accepted (status %d)", body, rec.Code)
		}
	}
	if !s.approvalRequired("acme") {
		t.Fatal("a malformed request switched change control off")
	}
}

func TestReadReportsTheFloorSoTheConsoleCanLockTheControl(t *testing.T) {
	// The console must be able to render "you cannot change this here"
	// WITHOUT discovering it from a 409 after the operator commits.
	s := changeControlServer(t)
	s.cfg.RequireApproval = true

	rec := httptest.NewRecorder()
	s.readChangeControl(rec, "acme")
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != true || got["mandated"] != true || got["can_disable"] != false {
		t.Fatalf("a mandated deployment reported %v", got)
	}
	// The exit from a bad state must never be gated, and the surface says so.
	never, _ := got["never_gated"].([]any)
	var hasKill bool
	for _, v := range never {
		if v == "kill-switch" {
			hasKill = true
		}
	}
	if !hasKill {
		t.Fatalf("never_gated does not name the kill-switch: %v", got["never_gated"])
	}
}

func TestTurningChangeControlOffDoesNotReleaseWhatIsAlreadyHeld(t *testing.T) {
	// The response says this out loud, so it had better be true. The opposite
	// assumption is the dangerous one: an operator who believed switching off
	// released the queue would walk away from a parked sever.
	s := changeControlServer(t)
	s.cacheChangeControl("acme", true, "")

	if code, _ := s.chokeRequest("alice", "acme", "exec-on-a", 4021, "sever", "confirmed C2", "", 0); code != http.StatusAccepted {
		t.Fatalf("setup: the sever was not held (status %d)", code)
	}
	if n := s.approvals.PendingCount("acme"); n != 1 {
		t.Fatalf("setup: expected one parked request, got %d", n)
	}

	s.cacheChangeControl("acme", false, "")

	if n := s.approvals.PendingCount("acme"); n != 1 {
		t.Fatalf("switching change control off changed the queue: %d pending, want 1 still held", n)
	}
	// And the four-eyes rule on the parked request is unaffected: it lives in
	// the approval store, not in the flag that decided to park it.
	if _, err := s.approvals.Decide("acme", pendingID(t, s, "acme"), "alice", "on reflection", true); err == nil {
		t.Fatal("the requester approved their own parked request after change control was switched off")
	}
}

func pendingID(t *testing.T, s *Server, tenant string) string {
	t.Helper()
	for _, r := range s.approvals.List(tenant) {
		return r.ID
	}
	t.Fatal("no parked request")
	return ""
}
