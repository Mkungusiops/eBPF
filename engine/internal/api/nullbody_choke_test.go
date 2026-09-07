package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// A body that names no intent is not an instruction.
//
// The fleet fan-out learned this one layer up (see fleetbody_shapes_test.go):
// every body that is not a JSON object is refused before any peer is called.
// The same defect was still open on the handlers UNDER it, and worse there,
// because these are the ones that actually turn enforcement off:
//
//   - handleChokeKillSwitch decoded into a struct and treated a nil error as a
//     valid request. `null` decodes with err == nil and ZERO VALUES, so POST
//     /api/choke/kill-switch with the body `null` called SetKillSwitch(false) —
//     releasing the widest-blast-radius toggle on the platform — and wrote the
//     audit row with an empty reason.
//   - handleChokeMode is the same shape: `null` meant enforcing=false, which
//     drops the host out of enforcement entirely.
//   - handleChokeThaw discarded its decode error outright, so `null` fell
//     through to the tier-wide unfreeze branch with no reason at all.
//
// The distinction the fix turns on: "the operator said false" is a legitimate,
// meaningful request and must keep working; "the body said nothing" is not a
// request at all. TestNullBodyStillHonoursAnExplicitFalse pins the first half,
// so a later tightening cannot satisfy this file by refusing both.

// nullbodyServer builds an engine server with a real gateway, and records
// whether the tier-wide thaw backend was ever called — the one write on this
// surface whose effect leaves no state on the gateway to read back.
func nullbodyServer(t *testing.T) (*Server, *store.Store, *int) {
	t.Helper()
	st, err := store.New(t.TempDir() + "/nullbody.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	g := choke.NewGateway(choke.Config{
		Store:      st,
		Enforcer:   &enforce.Multi{},
		Tokens:     tokens.NewManager(),
		Tree:       tree.New(time.Hour),
		Policies:   policy.NewSet(),
		Thresholds: circuit.Config{ThrottleAt: 10, TarpitAt: 20, QuarantineAt: 30, SeverAt: 40},
		Enforcing:  true,
	})
	thaws := 0
	g.SetThawFn(func() error { thaws++; return nil })
	return &Server{store: st, auth: &Auth{}, gateway: g, tree: tree.New(time.Hour)}, st, &thaws
}

// nullbodyRoute is one write handler and the method it answers.
type nullbodyRoute struct {
	name   string
	method string
	path   string
	pick   func(*Server) http.HandlerFunc
}

func nullbodyWriteRoutes() []nullbodyRoute {
	return []nullbodyRoute{
		{"kill-switch", http.MethodPost, "/api/choke/kill-switch",
			func(s *Server) http.HandlerFunc { return s.handleChokeKillSwitch }},
		{"mode", http.MethodPost, "/api/choke/mode",
			func(s *Server) http.HandlerFunc { return s.handleChokeMode }},
		{"thaw", http.MethodPost, "/api/choke/thaw",
			func(s *Server) http.HandlerFunc { return s.handleChokeThaw }},
		{"preset", http.MethodPost, "/api/choke/preset",
			func(s *Server) http.HandlerFunc { return s.handleChokePreset }},
		{"thresholds", http.MethodPut, "/api/choke/thresholds",
			func(s *Server) http.HandlerFunc { return s.handleChokeThresholds }},
		{"manual", http.MethodPost, "/api/choke/manual",
			func(s *Server) http.HandlerFunc { return s.handleChokeManual }},
		{"bulk-manual", http.MethodPost, "/api/choke/bulk-manual",
			func(s *Server) http.HandlerFunc { return s.handleChokeBulkManual }},
		{"forget", http.MethodPost, "/api/choke/forget",
			func(s *Server) http.HandlerFunc { return s.handleChokeForget }},
		{"annotate", http.MethodPost, "/api/choke/annotate",
			func(s *Server) http.HandlerFunc { return s.handleChokeAnnotate }},
		{"jail", http.MethodPost, "/api/choke/jail",
			func(s *Server) http.HandlerFunc { return s.handleChokeJail }},
		{"policy-preview", http.MethodPost, "/api/choke/policy/preview",
			func(s *Server) http.HandlerFunc { return s.handleChokePolicyPreview }},
	}
}

func nullbodyCall(t *testing.T, s *Server, rt nullbodyRoute, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	rt.pick(s)(rec, httptest.NewRequest(rt.method, rt.path, strings.NewReader(body)))
	return rec
}

// nullbodyState is everything a refused write must have left untouched.
type nullbodyState struct {
	killSwitched bool
	mode         string
	thresholds   circuit.Config
	decisions    int
	thaws        int
}

func nullbodySnapshot(t *testing.T, s *Server, st *store.Store, thaws *int) nullbodyState {
	t.Helper()
	rows, err := st.RecentDecisions(2000)
	if err != nil {
		t.Fatalf("read decisions: %v", err)
	}
	return nullbodyState{
		killSwitched: s.gateway.KillSwitched(),
		mode:         string(s.gateway.Mode()),
		thresholds:   s.gateway.Thresholds(),
		decisions:    len(rows),
		thaws:        *thaws,
	}
}

// TestNullBodyIsRefusedOnEveryChokeWrite. The table is the whole class, so no
// shape is left to the reader's imagination: a body that is absent, empty,
// whitespace, a literal `null`, or any JSON that is not an object is refused
// 400, and the gateway is in exactly the state it was in beforehand.
func TestNullBodyIsRefusedOnEveryChokeWrite(t *testing.T) {
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
	for _, rt := range nullbodyWriteRoutes() {
		for label, body := range bodies {
			t.Run(rt.name+"/"+label, func(t *testing.T) {
				s, st, thaws := nullbodyServer(t)
				// Start from the state an incident is actually in: enforcement
				// armed and the kill-switch engaged. A refusal that silently
				// released either is the defect, and starting from the zero
				// value would hide it.
				s.gateway.SetKillSwitch(true)
				before := nullbodySnapshot(t, s, st, thaws)

				rec := nullbodyCall(t, s, rt, body)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 for a body that states no intent; got %q",
						rec.Code, strings.TrimSpace(rec.Body.String()))
				}
				if after := nullbodySnapshot(t, s, st, thaws); after != before {
					t.Fatalf("a refused write changed enforcement state: %+v -> %+v", before, after)
				}
			})
		}
	}
}

// TestNullBodyRefusesAnObjectThatOmitsTheToggle. Refusing non-objects is only
// half the rule. `{}` and `{"reason":"..."}` ARE objects, and they still say
// nothing about the toggle — yet they decode to on=false / enforcing=false,
// which are the disarming direction. The field has to be stated.
//
// `{"on":null}` is in the table because it is the same silence wearing a key.
func TestNullBodyRefusesAnObjectThatOmitsTheToggle(t *testing.T) {
	for _, tc := range []struct {
		route nullbodyRoute
		body  string
	}{
		{nullbodyWriteRoutes()[0], `{}`},
		{nullbodyWriteRoutes()[0], `{"reason":"maintenance window"}`},
		{nullbodyWriteRoutes()[0], `{"on":null}`},
		{nullbodyWriteRoutes()[1], `{}`},
		{nullbodyWriteRoutes()[1], `{"reason":"maintenance window"}`},
		{nullbodyWriteRoutes()[1], `{"enforcing":null}`},
	} {
		t.Run(tc.route.name+"/"+tc.body, func(t *testing.T) {
			s, st, thaws := nullbodyServer(t)
			s.gateway.SetKillSwitch(true)
			before := nullbodySnapshot(t, s, st, thaws)

			rec := nullbodyCall(t, s, tc.route, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: an object that never names the toggle is not a "+
					"request to switch it off; got %q", rec.Code, strings.TrimSpace(rec.Body.String()))
			}
			if after := nullbodySnapshot(t, s, st, thaws); after != before {
				t.Fatalf("a refused write changed enforcement state: %+v -> %+v", before, after)
			}
		})
	}
}

// TestNullBodyStillHonoursAnExplicitFalse. Releasing the kill-switch and
// dropping to detect-only are real operator acts, and the fix must not have
// bought its safety by refusing them too. This is the half of the finding that
// a blunt "require a non-empty body" would break.
func TestNullBodyStillHonoursAnExplicitFalse(t *testing.T) {
	t.Run("kill-switch off", func(t *testing.T) {
		s, st, thaws := nullbodyServer(t)
		s.gateway.SetKillSwitch(true)
		before := nullbodySnapshot(t, s, st, thaws)

		rec := nullbodyCall(t, s, nullbodyWriteRoutes()[0],
			`{"on":false,"reason":"incident closed, restoring enforcement"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for an explicit release: %q",
				rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		if s.gateway.KillSwitched() {
			t.Fatal("the kill-switch is still engaged after an explicit {\"on\":false}")
		}
		// The audit row is the other half of the contract: this transition is
		// the one an incident review asks about.
		rows, err := st.RecentDecisions(2000)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != before.decisions+1 {
			t.Fatalf("decision rows %d -> %d, want exactly one audit row for the release",
				before.decisions, len(rows))
		}
		if rows[0].Action != "kill-switch" || strings.TrimSpace(rows[0].Reason) == "" {
			t.Fatalf("audit row %+v does not record the release with the operator's reason", rows[0])
		}
	})

	t.Run("mode off", func(t *testing.T) {
		s, _, _ := nullbodyServer(t)
		rec := nullbodyCall(t, s, nullbodyWriteRoutes()[1],
			`{"enforcing":false,"reason":"noisy build host"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for an explicit disarm: %q",
				rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		if got := string(s.gateway.Mode()); got != "detect-only" {
			t.Fatalf("mode = %q, want detect-only after an explicit {\"enforcing\":false}", got)
		}
	})

	// Thaw takes no required field on purpose — the reason-only shape is the
	// console's "Thaw quarantine" control, and releasing must never be blocked.
	// What it does require is a body that asks for something.
	t.Run("tier-wide thaw with a reason", func(t *testing.T) {
		s, _, thaws := nullbodyServer(t)
		rec := nullbodyCall(t, s, nullbodyWriteRoutes()[2], `{"reason":"incident closed"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %q", rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		if *thaws != 1 {
			t.Fatalf("thaw backend called %d times, want 1", *thaws)
		}
	})
}
