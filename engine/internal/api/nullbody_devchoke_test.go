package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/device"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/devbpf"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// The DEVICE plane half of "a body that names no intent is not an instruction".
//
// nullbody_choke_test.go closed this on the process writes and
// fleetbody_shapes_test.go on the fan-out above them; the network plane was
// still decoding with `json.NewDecoder(r.Body).Decode(&body)` and treating a
// nil error as a valid request. A literal `null` decodes with err == nil and
// ZERO VALUES, so:
//
//   - POST /api/choke/device-kill-switch with the body `null` called
//     SetKillSwitch(false) — the emergency stop an operator had deliberately
//     engaged came back OFF from a request that named nothing, and at the time
//     the device gateway wrote no audit row for that transition at all. It
//     writes a hash-chained one now, which makes a silent release traceable
//     but no less wrong: the fix is still to refuse the request.
//   - POST /api/choke/device-mode with `null` meant enforcing=false, dropping
//     this host's network plane to detect-only with an empty reason: every
//     subsequent device decision audited, none of it reaching the kernel.
//
// The distinction the fix turns on is the same one as on the process plane:
// "the operator said false" is a real instruction and must keep working;
// "the body said nothing" is not a request at all. The explicit-false tests
// below pin that half, so a blunter tightening cannot satisfy this file by
// refusing both.

// nullbodyDevServer builds an engine server with a REAL device gateway over the
// noop kernel backend, so a refused write can be checked against the thing it
// would have changed: the mode, the kill-switch, the circuit, the audit chain,
// and the data plane itself.
func nullbodyDevServer(t *testing.T) (*Server, *store.Store, devbpf.Backend) {
	t.Helper()
	st, err := store.New(t.TempDir() + "/nullbody-dev.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	backend := devbpf.NewNoopDeviceBackend()
	if err := backend.Open(); err != nil {
		t.Fatalf("backend.Open: %v", err)
	}
	g := choke.NewDeviceGateway(choke.DeviceConfig{
		Throttler: enforce.NewDeviceThrottler(backend, map[devbpf.MAC]bool{}),
		Backend:   backend,
		Table:     device.NewTable(time.Hour),
		Store:     st,
		Enforcing: true,
	})
	return &Server{store: st, auth: &Auth{}, deviceGW: g}, st, backend
}

func nullbodyDevRoutes() []nullbodyRoute {
	return []nullbodyRoute{
		{"device-kill-switch", http.MethodPost, "/api/choke/device-kill-switch",
			func(s *Server) http.HandlerFunc { return s.handleChokeDeviceKillSwitch }},
		{"device-mode", http.MethodPost, "/api/choke/device-mode",
			func(s *Server) http.HandlerFunc { return s.handleChokeDeviceMode }},
		{"device-jail", http.MethodPost, "/api/choke/device-jail",
			func(s *Server) http.HandlerFunc { return s.handleChokeDeviceJail }},
		{"device-thaw", http.MethodPost, "/api/choke/device-thaw",
			func(s *Server) http.HandlerFunc { return s.handleChokeDeviceThaw }},
	}
}

// nullbodyDevState is everything a refused device write must have left alone —
// including the kernel buckets, which is where "nothing was dispatched" lives
// on this plane.
type nullbodyDevState struct {
	killSwitched bool
	mode         string
	tracked      int
	buckets      int
	decisions    int
}

func nullbodyDevSnapshot(t *testing.T, s *Server, st *store.Store, backend devbpf.Backend) nullbodyDevState {
	t.Helper()
	rows, err := st.RecentDecisions(2000)
	if err != nil {
		t.Fatalf("read decisions: %v", err)
	}
	snap, err := backend.Snapshot()
	if err != nil {
		t.Fatalf("backend snapshot: %v", err)
	}
	return nullbodyDevState{
		killSwitched: s.deviceGW.KillSwitched(),
		mode:         s.deviceGW.Mode(),
		tracked:      s.deviceGW.Tracked(),
		buckets:      len(snap),
		decisions:    len(rows),
	}
}

// TestNullBodyIsRefusedOnEveryDeviceChokeWrite. The table is the whole class,
// so no shape is left to the reader's imagination.
func TestNullBodyIsRefusedOnEveryDeviceChokeWrite(t *testing.T) {
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
	for _, rt := range nullbodyDevRoutes() {
		for label, body := range bodies {
			t.Run(rt.name+"/"+label, func(t *testing.T) {
				s, st, backend := nullbodyDevServer(t)
				// Start from the state an incident is actually in: the device
				// plane armed and the kill-switch engaged. Starting from the
				// zero value would hide a refusal that silently released one.
				s.deviceGW.SetKillSwitch(true)
				before := nullbodyDevSnapshot(t, s, st, backend)

				rec := nullbodyCall(t, s, rt, body)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 for a body that states no intent; got %q",
						rec.Code, strings.TrimSpace(rec.Body.String()))
				}
				if after := nullbodyDevSnapshot(t, s, st, backend); after != before {
					t.Fatalf("a refused device write changed enforcement state: %+v -> %+v", before, after)
				}
			})
		}
	}
}

// TestNullBodyRefusesADeviceObjectThatOmitsTheToggle. Refusing non-objects is
// only half the rule: `{}` and `{"reason":"..."}` ARE objects, and they still
// say nothing about the toggle — yet they decode to on=false / enforcing=false,
// which is the disarming direction on both endpoints. `{"on":null}` is in the
// table because it is the same silence wearing a key.
func TestNullBodyRefusesADeviceObjectThatOmitsTheToggle(t *testing.T) {
	kill, mode := nullbodyDevRoutes()[0], nullbodyDevRoutes()[1]
	for _, tc := range []struct {
		route nullbodyRoute
		body  string
	}{
		{kill, `{}`},
		{kill, `{"reason":"maintenance window"}`},
		{kill, `{"on":null}`},
		{mode, `{}`},
		{mode, `{"reason":"maintenance window"}`},
		{mode, `{"enforcing":null}`},
		// SetEnforcing writes a hash-chained row through recordDecision for
		// the transition, and the operator's words are the only part of that
		// row a person supplies, so the statement of WHY may not be empty
		// either.
		{mode, `{"enforcing":false}`},
		{mode, `{"enforcing":false,"reason":"   "}`},
	} {
		t.Run(tc.route.name+"/"+tc.body, func(t *testing.T) {
			s, st, backend := nullbodyDevServer(t)
			s.deviceGW.SetKillSwitch(true)
			before := nullbodyDevSnapshot(t, s, st, backend)

			rec := nullbodyCall(t, s, tc.route, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: an object that never names the toggle is not a "+
					"request to switch it off; got %q", rec.Code, strings.TrimSpace(rec.Body.String()))
			}
			if after := nullbodyDevSnapshot(t, s, st, backend); after != before {
				t.Fatalf("a refused device write changed enforcement state: %+v -> %+v", before, after)
			}
		})
	}
}

// TestNullBodyStillHonoursAnExplicitFalseOnTheDevicePlane. Releasing the
// device kill-switch and dropping the plane to detect-only are real operator
// acts. The fix must not have bought its safety by refusing them too.
func TestNullBodyStillHonoursAnExplicitFalseOnTheDevicePlane(t *testing.T) {
	t.Run("device kill-switch off", func(t *testing.T) {
		s, _, _ := nullbodyDevServer(t)
		s.deviceGW.SetKillSwitch(true)

		rec := nullbodyCall(t, s, nullbodyDevRoutes()[0], `{"on":false}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for an explicit release: %q",
				rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		if s.deviceGW.KillSwitched() {
			t.Fatal(`the device kill-switch is still engaged after an explicit {"on":false}`)
		}
	})

	t.Run("device mode off", func(t *testing.T) {
		s, _, _ := nullbodyDevServer(t)
		rec := nullbodyCall(t, s, nullbodyDevRoutes()[1],
			`{"enforcing":false,"reason":"staging device policy"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for an explicit disarm: %q",
				rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		if got := s.deviceGW.Mode(); got != "detect-only" {
			t.Fatalf("mode = %q, want detect-only after an explicit {\"enforcing\":false}", got)
		}
	})
}

// TestNullBodyDeviceReleaseIsNeverBlockedButIsRecordedHonestly.
//
// device-thaw requires the MACs and nothing else: blocking a release is how a
// device stays cut off longer than anyone intended, and the process plane's
// per-target thaw asks for no reason either. What the audit row must not do is
// read as though a reason was given when the body stated none. The console no
// longer substitutes the literal "operator thaw" for a blank box — it omits
// the field — so every reason-less release, from the console or from a script,
// arrives here stating nothing, and the server's own marker is what keeps the
// row from reading like an operator's sentence.
func TestNullBodyDeviceReleaseIsNeverBlockedButIsRecordedHonestly(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:07"

	t.Run("no reason stated", func(t *testing.T) {
		s, st, _ := nullbodyDevServer(t)
		rec := nullbodyCall(t, s, nullbodyDevRoutes()[3], `{"macs":["`+mac+`"]}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: a release must not be blocked for want of a reason: %q",
				rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		rows, err := st.RecentDecisions(10)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("decision rows = %d, want exactly one audit row for the release", len(rows))
		}
		if !strings.Contains(rows[0].Reason, "no reason stated") {
			t.Fatalf("audit reason = %q; a release nobody justified must not read as though "+
				"an operator justified it", rows[0].Reason)
		}
	})

	t.Run("reason stated is kept verbatim", func(t *testing.T) {
		s, st, _ := nullbodyDevServer(t)
		rec := nullbodyCall(t, s, nullbodyDevRoutes()[3],
			`{"macs":["`+mac+`"],"reason":"incident 4412 closed"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %q", rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		rows, err := st.RecentDecisions(10)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || !strings.Contains(rows[0].Reason, "incident 4412 closed") {
			t.Fatalf("audit rows %+v do not carry the operator's own reason", rows)
		}
	})
}

// TestNullBodyDeviceJailStillWorks pins the other direction on the jail route:
// the refusals above must not have cost the endpoint its actual job, and the
// data plane is where that shows.
func TestNullBodyDeviceJailStillWorks(t *testing.T) {
	s, st, backend := nullbodyDevServer(t)
	rec := nullbodyCall(t, s, nullbodyDevRoutes()[2],
		`{"macs":["aa:bb:cc:dd:ee:08"],"action":"tarpit","reason":"beaconing to a known C2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a fully stated jail: %q",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	snap, err := backend.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 1 {
		t.Fatalf("kernel buckets = %d, want 1: the jail never reached the data plane", len(snap))
	}
	rows, err := st.RecentDecisions(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("decision rows = %d, want exactly one audit row for the jail", len(rows))
	}
}
