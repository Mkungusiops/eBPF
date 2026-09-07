package controlplane

import "testing"

// A FLEET-WIDE RELEASE MUST STATE WHY.
//
// `{}` is a JSON object, so it survives the body gate that refuses `null` and
// the other non-objects — and then it named no process, no host and no reason,
// and swept every contained process off every agent in the tenant with an empty
// audit row. Before the fleet-release branch existed this shape was a 400, so
// the branch that closed one dead control opened a wider hole than the one it
// closed: the release direction of the same rule, and the direction where the
// row explaining why is the ONLY record of an intruder having been let go.
//
// The per-process release is deliberately NOT covered by this: releasing one
// process is an ordinary triage action and requiring paperwork for it is how
// operators learn to type "." into reason boxes.
func TestFleetWideReleaseRefusesAnEmptyReason(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"an empty object asks for nothing", map[string]any{}},
		{"an explicitly empty reason", map[string]any{"reason": ""}},
		{"whitespace is not a reason", map[string]any{"reason": "   "}},
		{"a target list does not excuse it", map[string]any{"targets": []string{"agent-a"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := targetingServer(t)
			seed(s, "acme", "agent-a", jailed("exec-a1", 11, "quarantined"))
			seed(s, "acme", "agent-b", jailed("exec-b1", 21, "quarantined"))

			code, _ := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/choke/thaw?tenant=acme", tc.body)
			if code != 400 {
				t.Fatalf("status %d, want 400 — a reasonless fleet release must be refused", code)
			}
			// The refusal has to be total. A release that reached one agent and
			// then failed validation would leave the estate half-contained,
			// which is the state this whole endpoint's routing exists to avoid.
			for _, agent := range []string{"agent-a", "agent-b"} {
				if n := s.dispatcher.Pending(agent); n != 0 {
					t.Fatalf("%s was sent %d release(s) by a refused request, want 0", agent, n)
				}
			}
		})
	}
}

// The console's "Thaw quarantine" button sends {reason} and its confirm marks
// the reason required, so the shape that actually ships must keep working —
// this is what stops the guard above from being tightened into a dead control.
func TestFleetWideReleaseStillWorksWithAReason(t *testing.T) {
	s := targetingServer(t)
	seed(s, "acme", "agent-a", jailed("exec-a1", 11, "quarantined"))

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/choke/thaw?tenant=acme",
		map[string]any{"reason": "incident 4471 closed"})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-a"); n != 1 {
		t.Fatalf("agent-a was sent %d release(s), want 1", n)
	}
}
