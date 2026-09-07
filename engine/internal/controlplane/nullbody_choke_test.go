package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A body that names no intent is not an instruction — the control-plane half.
//
// This surface had the defect in its worst form. Several handlers wrote
// `_ = json.NewDecoder(r.Body).Decode(&b)`, discarding the error outright, so a
// malformed body, an absent body and a valid one were indistinguishable; every
// field then held its zero value, and on a fleet write the zero value is the
// disarming direction:
//
//   - dispatchKillSwitch sent HaltAllEnforcement=false to every agent in the
//     tenant, with an empty reason, from a body that said nothing.
//   - dispatchSetMode dropped every targeted host to detect-only the same way.
//   - handleChokeThaw with no exec_id and no pid releases EVERY contained
//     process on every targeted host, so `null` swept a tenant's containment
//     off an intruder it was holding.
//   - handleChokeJailFromSoc fell through its switch to the "quarantine"
//     default, so a body naming no action froze the named process.
//   - handleChokePreset dispatched ApplyPreset("") for the agents to interpret.
//
// The distinction that matters: "the operator said false" is a real request and
// must keep working (TestNullBodyControlPlaneStillHonoursAnExplicitFalse);
// "the body said nothing" is not a request at all.

type nullbodyCPRoute struct {
	name   string
	method string
	path   string
	pick   func(*Server) http.HandlerFunc
}

func nullbodyCPRoutes() []nullbodyCPRoute {
	return []nullbodyCPRoute{
		{"kill-switch", "POST", "/api/fleet/kill-switch?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleChokeKill }},
		{"device-kill-switch", "POST", "/api/choke/device-kill-switch?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleDeviceKill }},
		{"mode", "POST", "/api/choke/mode?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleChokeMode }},
		{"device-mode", "POST", "/api/choke/device-mode?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleDeviceMode }},
		{"thaw", "POST", "/api/choke/thaw?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleChokeThaw }},
		{"preset", "POST", "/api/fleet/preset?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleChokePreset }},
		{"thresholds", "PUT", "/api/fleet/thresholds?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleChokeThresh }},
		{"manual", "POST", "/api/choke/manual?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleChokeManual }},
		{"jail", "POST", "/api/choke/jail?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleChokeJailFromSoc }},
		{"bulk", "POST", "/api/choke/bulk-manual?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleChokeBulk }},
		{"forget", "POST", "/api/choke/forget?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleChokeForget }},
		{"device-jail", "POST", "/api/choke/device-jail?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleDeviceJail }},
		{"device-thaw", "POST", "/api/choke/device-thaw?tenant=acme",
			func(s *Server) http.HandlerFunc { return s.handleDeviceThaw }},
	}
}

// nullbodyCPCall posts a RAW body — the point of this file is the shapes
// fleetWrite's map[string]any cannot express: `null`, empty, whitespace, and
// JSON that is not an object at all.
func nullbodyCPCall(t *testing.T, s *Server, rt nullbodyCPRoute, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	rt.pick(s)(w, req)
	return w
}

func nullbodyCPPending(t *testing.T, s *Server) int {
	t.Helper()
	return s.dispatcher.Pending("agent-a") + s.dispatcher.Pending("agent-b")
}

// TestNullBodyIsRefusedOnEveryControlPlaneChokeWrite. The whole class in one
// table, and the assertion that matters is the second one: nothing is signed
// and nothing is enqueued. There is no unwinding a kill-switch that has already
// reached the fleet.
func TestNullBodyIsRefusedOnEveryControlPlaneChokeWrite(t *testing.T) {
	bodies := map[string]string{
		"literal null":     `null`,
		"empty body":       ``,
		"whitespace only":  "  \n\t ",
		"truncated object": `{"on":true,`,
		"json array":       `[{"on":true}]`,
		"bare string":      `"on"`,
		"number":           `7`,
		"bool":             `false`,
	}
	for _, rt := range nullbodyCPRoutes() {
		for label, body := range bodies {
			t.Run(rt.name+"/"+label, func(t *testing.T) {
				s := targetingServer(t)

				w := nullbodyCPCall(t, s, rt, body)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 for a body that states no intent; got %s",
						w.Code, strings.TrimSpace(w.Body.String()))
				}
				var out map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatalf("400 body %q is not JSON the console can render", w.Body.String())
				}
				if msg, _ := out["error"].(string); msg == "" {
					t.Errorf("400 body %v carries no error the operator can read", out)
				}
				if n := nullbodyCPPending(t, s); n != 0 {
					t.Fatalf("%d command(s) were dispatched from a body that asked for nothing", n)
				}
			})
		}
	}
}

// TestNullBodyRefusesAnObjectThatOmitsTheAct. `{}` is an object, so it survives
// the shape check above — and it decodes to on=false / enforcing=false /
// action="" / name="", each of which used to be dispatched as if an operator
// had asked for it. A field whose zero value is an act must be STATED.
func TestNullBodyRefusesAnObjectThatOmitsTheAct(t *testing.T) {
	byName := map[string]nullbodyCPRoute{}
	for _, rt := range nullbodyCPRoutes() {
		byName[rt.name] = rt
	}
	for _, tc := range []struct{ route, body, why string }{
		{"kill-switch", `{}`, "on=false halts nothing and releases a halt that is in place"},
		{"kill-switch", `{"reason":"maintenance"}`, "a reason is not an instruction"},
		{"kill-switch", `{"on":null}`, "a null value is the same silence wearing a key"},
		{"device-kill-switch", `{}`, "the device plane disarms on the same zero value"},
		{"mode", `{}`, "enforcing=false drops every targeted host to detect-only"},
		{"mode", `{"reason":"maintenance"}`, "a reason is not an instruction"},
		{"device-mode", `{}`, "the device plane disarms on the same zero value"},
		{"jail", `{"pids":[4021]}`, "an absent action used to default to quarantine"},
		{"preset", `{"reason":"x"}`, `an unnamed preset reached the agents as ApplyPreset("")`},
		{"device-jail", `{"macs":["aa:bb:cc:dd:ee:ff"]}`, "an absent action jailed with an empty tier"},
	} {
		t.Run(tc.route+"/"+tc.body, func(t *testing.T) {
			s := targetingServer(t)

			w := nullbodyCPCall(t, s, byName[tc.route], tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s); got %s", w.Code, tc.why,
					strings.TrimSpace(w.Body.String()))
			}
			if n := nullbodyCPPending(t, s); n != 0 {
				t.Fatalf("%d command(s) were dispatched from a body that never named the act (%s)", n, tc.why)
			}
		})
	}
}

// TestNullBodyControlPlaneStillHonoursAnExplicitFalse. Releasing the fleet
// kill-switch, disarming the fleet and releasing containment are real operator
// acts. The refusals above must not have been bought by breaking them — that is
// the difference between reading the body and merely requiring one.
func TestNullBodyControlPlaneStillHonoursAnExplicitFalse(t *testing.T) {
	byName := map[string]nullbodyCPRoute{}
	for _, rt := range nullbodyCPRoutes() {
		byName[rt.name] = rt
	}

	t.Run("kill-switch off reaches every agent", func(t *testing.T) {
		s := targetingServer(t)
		w := nullbodyCPCall(t, s, byName["kill-switch"],
			`{"on":false,"reason":"incident closed, restoring enforcement"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for an explicit release: %s", w.Code,
				strings.TrimSpace(w.Body.String()))
		}
		if n := nullbodyCPPending(t, s); n != 2 {
			t.Fatalf("%d command(s) queued, want one per agent — an explicit release must still dispatch", n)
		}
	})

	t.Run("mode off reaches every agent", func(t *testing.T) {
		s := targetingServer(t)
		w := nullbodyCPCall(t, s, byName["mode"], `{"enforcing":false,"reason":"noisy build fleet"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for an explicit disarm: %s", w.Code,
				strings.TrimSpace(w.Body.String()))
		}
		if n := nullbodyCPPending(t, s); n != 2 {
			t.Fatalf("%d command(s) queued, want one per agent", n)
		}
	})

	// Thaw requires no field on purpose: the reason-only shape IS the console's
	// "Thaw quarantine" button, and releasing must never be blocked. What it
	// requires is a body that asks for something.
	t.Run("reason-only thaw is still a fleet release", func(t *testing.T) {
		s := targetingServer(t)
		w := nullbodyCPCall(t, s, byName["thaw"], `{"reason":"incident closed"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for the reason-only release: %s", w.Code,
				strings.TrimSpace(w.Body.String()))
		}
	})
}
