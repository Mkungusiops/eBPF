package controlplane

import (
	"testing"
)

// THE RELEASE DIRECTION OF THE TARGETING DEFECT.
//
// handleChokeThaw takes two shapes, and agent_id has to mean the same thing in
// both: "this host". On the exec_id shape it does — it goes to the router. On
// the reason-only fleet-release shape it was decoded and then DROPPED, and the
// release swept every agent in the tenant.
//
// The asymmetry was the tell. An UNKNOWN host name is a 400 from
// resolveFleetTargets, while a KNOWN one was silently widened to everybody —
// the operator gets a confident 200 saying "every agent in the tenant" for a
// request that named one. Thawing hosts nobody named takes containment back off
// an intruder the operator meant to leave held, which is the same class of bug
// the routing work exists to prevent, running backwards.

// TestReasonOnlyThawHonoursAgentIDAsASingleHost is the defect: the unnamed
// agent's queue must be untouched.
func TestReasonOnlyThawHonoursAgentIDAsASingleHost(t *testing.T) {
	s := targetingServer(t)
	seed(s, "acme", "agent-a", jailed("exec-a1", 11, "quarantined"))
	seed(s, "acme", "agent-b", jailed("exec-b1", 21, "quarantined"))

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/choke/thaw?tenant=acme",
		map[string]any{"reason": "IR-4821 closed on this host", "agent_id": "agent-a"})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-b"); n != 0 {
		t.Fatalf("%d release(s) reached agent-b, which the operator did not name — "+
			"a release aimed at one host that lands on the fleet un-contains an intruder", n)
	}
	if n := s.dispatcher.Pending("agent-a"); n != 1 {
		t.Fatalf("agent-a was sent %d release(s), want the 1 process it is holding", n)
	}
	// And the report has to say it went to one host. A body that reads "every
	// agent in the tenant" over a single-host release is the same lie in the
	// audit trail even when the dispatch is right.
	if got := hostNames(t, body); len(got) != 1 || got[0] != "agent-a" {
		t.Fatalf("hosts = %v, want just agent-a", got)
	}
	if body["routing"] != "hosts named by the operator" {
		t.Fatalf("routing = %v, want the operator-named phrasing — the response describes the blast radius",
			body["routing"])
	}
	if body["contained"].(float64) != 1 {
		t.Fatalf("contained = %v, want only agent-a's 1 held process counted", body["contained"])
	}
}

// A named host that is not in this tenant (or not in the target list the
// operator already gave) is REFUSED, not ignored. Ignoring it is what turned a
// single-host release into a fleet-wide one.
func TestReasonOnlyThawRefusesAnAgentIDItCannotHonour(t *testing.T) {
	s := targetingServer(t)
	seed(s, "acme", "agent-a", jailed("exec-a1", 11, "quarantined"))
	seed(s, "acme", "agent-b", jailed("exec-b1", 21, "quarantined"))

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/choke/thaw?tenant=acme",
		map[string]any{"reason": "r", "agent_id": "agent-in-another-tenant"})
	if code != 400 {
		t.Fatalf("status %d for a host this tenant does not have, want 400: %v", code, body)
	}
	for _, a := range []string{"agent-a", "agent-b"} {
		if n := s.dispatcher.Pending(a); n != 0 {
			t.Fatalf("%d release(s) reached %s after a refused request", n, a)
		}
	}
}

// agent_id NARROWS the target list, it never widens it. A host outside the
// list the operator already named is refused rather than added, so the two
// fields can never combine into a larger blast radius than either alone.
func TestReasonOnlyThawAgentIDCannotEscapeTheTargetList(t *testing.T) {
	s := targetingServer(t)
	seed(s, "acme", "agent-a", jailed("exec-a1", 11, "quarantined"))
	seed(s, "acme", "agent-b", jailed("exec-b1", 21, "quarantined"))

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/choke/thaw?tenant=acme",
		map[string]any{"reason": "r", "targets": []string{"agent-a"}, "agent_id": "agent-b"})
	if code != 400 {
		t.Fatalf("status %d for an agent_id outside the named targets, want 400: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-b"); n != 0 {
		t.Fatalf("%d release(s) reached agent-b, which the targets list excluded", n)
	}
}

// The unnamed case is unchanged: no agent_id and no targets still releases the
// whole tenant, which is what the console's "Thaw quarantine" button asks for.
func TestReasonOnlyThawWithoutAgentIDStillReleasesTheFleet(t *testing.T) {
	s := targetingServer(t)
	seed(s, "acme", "agent-a", jailed("exec-a1", 11, "quarantined"))
	seed(s, "acme", "agent-b", jailed("exec-b1", 21, "quarantined"))

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/choke/thaw?tenant=acme",
		map[string]any{"reason": "incident closed"})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-a"); n != 1 {
		t.Fatalf("agent-a was sent %d release(s), want 1", n)
	}
	if n := s.dispatcher.Pending("agent-b"); n != 1 {
		t.Fatalf("agent-b was sent %d release(s), want 1", n)
	}
	if body["routing"] != "every agent in the tenant" {
		t.Fatalf("routing = %v, want the fleet-wide phrasing", body["routing"])
	}
}
