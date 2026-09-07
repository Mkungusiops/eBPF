package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The fleet console's host selection was inert. Every write handler called
// (*Fleet).fanout, which reaches every peer in the hosts file, and forwarded
// the request body verbatim — so an operator who ticked ONE host, read "Writes
// target 1 selected host" and pressed Containment contained the whole fleet.
// These tests pin the wire contract that fixed it: "targets" names the peers a
// write may touch, an unset target set still means everybody, and a target set
// that cannot be honoured is refused whole rather than applied in part.

// fleetCall is one request a peer engine actually received.
type fleetCall struct {
	Method string
	Path   string
	Body   string
}

// fakePeer stands in for one peer engine: it answers the fleet's login the way
// the real middleware does and records everything else.
type fakePeer struct {
	srv *httptest.Server

	mu    sync.Mutex
	calls []fleetCall
}

func (p *fakePeer) record(c fleetCall) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, c)
}

// writes returns the unsafe-method calls only. Peer logins and read fan-outs
// share the same server, and it is the WRITES whose blast radius is under test.
func (p *fakePeer) writes() []fleetCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []fleetCall
	for _, c := range p.calls {
		if isUnsafeMethod(c.Method) {
			out = append(out, c)
		}
	}
	return out
}

func (p *fakePeer) reads() []fleetCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []fleetCall
	for _, c := range p.calls {
		if !isUnsafeMethod(c.Method) {
			out = append(out, c)
		}
	}
	return out
}

// newFleetServer wires a Server whose fleet points at three fake peers named
// alpha, bravo and charlie, in that hosts-file order.
func newFleetServer(t *testing.T) (*Server, map[string]*fakePeer) {
	t.Helper()

	names := []string{"alpha", "bravo", "charlie"}
	peers := make(map[string]*fakePeer, len(names))
	var lines []string
	for _, name := range names {
		p := &fakePeer{}
		p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/login" {
				http.SetCookie(w, &http.Cookie{Name: "soc_session", Value: "sess"})
				http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "csrf"})
				w.WriteHeader(http.StatusSeeOther)
				return
			}
			body, _ := io.ReadAll(r.Body)
			p.record(fleetCall{Method: r.Method, Path: r.URL.Path, Body: string(body)})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		t.Cleanup(p.srv.Close)
		peers[name] = p
		lines = append(lines, name+" "+p.srv.URL)
	}

	path := filepath.Join(t.TempDir(), "chokectl.hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write hosts file: %v", err)
	}
	return &Server{fleet: NewFleet(path, "admin", "pw")}, peers
}

// fleetWriteRoute is one of the write endpoints the wire contract covers: the
// handler, the method the console uses, and the peer path it proxies to.
type fleetWriteRoute struct {
	name   string
	method string
	handle func(*Server) http.HandlerFunc
	peer   string
	body   func(targets string) string
	// survives names the payload keys the PEER acts on, with the values the
	// body above sends. Stripping "targets" must not disturb them: a fan-out
	// that dropped, say, a threshold would apply a write nobody asked for.
	survives map[string]interface{}
}

func fleetWriteRoutes() []fleetWriteRoute {
	return []fleetWriteRoute{
		{
			name:   "preset",
			method: http.MethodPost,
			handle: func(s *Server) http.HandlerFunc { return s.handleFleetPreset },
			peer:   "/api/choke/preset",
			body: func(targets string) string {
				return `{"name":"containment","reason":"beaconing","targets":` + targets + `}`
			},
			survives: map[string]interface{}{"name": "containment", "reason": "beaconing"},
		},
		{
			name:   "thresholds",
			method: http.MethodPut,
			handle: func(s *Server) http.HandlerFunc { return s.handleFleetThresholds },
			peer:   "/api/choke/thresholds",
			body: func(targets string) string {
				return `{"throttle_at":6,"tarpit_at":12,"quarantine_at":24,"sever_at":48,"targets":` + targets + `}`
			},
			survives: map[string]interface{}{
				"throttle_at": 6.0, "tarpit_at": 12.0, "quarantine_at": 24.0, "sever_at": 48.0,
			},
		},
		{
			name:   "kill-switch",
			method: http.MethodPost,
			handle: func(s *Server) http.HandlerFunc { return s.handleFleetKillSwitch },
			peer:   "/api/choke/kill-switch",
			body: func(targets string) string {
				return `{"on":true,"targets":` + targets + `}`
			},
			survives: map[string]interface{}{"on": true},
		},
		{
			name:   "thaw",
			method: http.MethodPost,
			handle: func(s *Server) http.HandlerFunc { return s.handleFleetThaw },
			peer:   "/api/choke/thaw",
			body: func(targets string) string {
				return `{"reason":"false positive","targets":` + targets + `}`
			},
			survives: map[string]interface{}{"reason": "false positive"},
		},
		// Device containment is the plane where a mis-scoped write is worst:
		// it cuts LAN access for hosts nobody named, and the gateway that
		// enforces it is not the box the operator was looking at. It goes
		// through the same fan-out, so it is held to the same contract.
		{
			name:   "device-jail",
			method: http.MethodPost,
			handle: func(s *Server) http.HandlerFunc { return s.handleFleetDeviceJail },
			peer:   "/api/choke/device-jail",
			body: func(targets string) string {
				return `{"macs":["aa:bb:cc:dd:ee:ff"],"action":"quarantine",` +
					`"reason":"beaconing","targets":` + targets + `}`
			},
			survives: map[string]interface{}{"action": "quarantine", "reason": "beaconing"},
		},
	}
}

func callFleet(t *testing.T, s *Server, route fleetWriteRoute, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(route.method, "/api/fleet/"+route.name, strings.NewReader(body))
	rec := httptest.NewRecorder()
	route.handle(s)(rec, req)
	return rec
}

// The whole point: a write naming one host must reach that host and no other.
func TestFleetWriteReachesOnlyNamedTargets(t *testing.T) {
	for _, route := range fleetWriteRoutes() {
		t.Run(route.name, func(t *testing.T) {
			s, peers := newFleetServer(t)

			rec := callFleet(t, s, route, route.body(`["bravo"]`))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}

			if got := len(peers["bravo"].writes()); got != 1 {
				t.Fatalf("bravo received %d writes, want 1 — the named target was not written to", got)
			}
			for _, name := range []string{"alpha", "charlie"} {
				if got := peers[name].writes(); len(got) != 0 {
					t.Fatalf("%s received %d writes (%+v) — selecting bravo applied to the rest of the fleet", name, len(got), got)
				}
			}

			// The response's per-host list is what the console reconciles
			// against its own table, so it must describe the hosts actually
			// dispatched to — not the whole hosts file.
			var envelope struct {
				Hosts []struct {
					Name string `json:"name"`
					OK   bool   `json:"ok"`
				} `json:"hosts"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode response: %v (body %s)", err, rec.Body.String())
			}
			if len(envelope.Hosts) != 1 || envelope.Hosts[0].Name != "bravo" || !envelope.Hosts[0].OK {
				t.Fatalf("hosts envelope = %+v, want exactly bravo ok", envelope.Hosts)
			}
		})
	}
}

// "targets" addresses the fan-out, not the peer's handler. Forwarding it would
// hand every peer a key it does not understand and, worse, invite a future peer
// to act on a target list that was already resolved a hop earlier.
func TestFleetWriteStripsTargetsFromForwardedBody(t *testing.T) {
	for _, route := range fleetWriteRoutes() {
		t.Run(route.name, func(t *testing.T) {
			s, peers := newFleetServer(t)

			if rec := callFleet(t, s, route, route.body(`["alpha","charlie"]`)); rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}

			for _, name := range []string{"alpha", "charlie"} {
				writes := peers[name].writes()
				if len(writes) != 1 {
					t.Fatalf("%s received %d writes, want 1", name, len(writes))
				}
				var forwarded map[string]interface{}
				if err := json.Unmarshal([]byte(writes[0].Body), &forwarded); err != nil {
					t.Fatalf("%s got an undecodable body %q: %v", name, writes[0].Body, err)
				}
				if _, ok := forwarded["targets"]; ok {
					t.Errorf("%s was forwarded the targets key: %s", name, writes[0].Body)
				}
				// The payload the peer acts on must survive the trip through
				// the target filter intact: a fan-out that stripped too much
				// would quietly apply a write nobody asked for.
				for key, want := range route.survives {
					if got := forwarded[key]; got != want {
						t.Errorf("%s: forwarded %q = %v, want %v (body %s)", name, key, got, want, writes[0].Body)
					}
				}
				if writes[0].Path != route.peer {
					t.Errorf("%s was called on %s, want %s", name, writes[0].Path, route.peer)
				}
			}
			if got := peers["bravo"].writes(); len(got) != 0 {
				t.Errorf("bravo was written to though it was not named: %+v", got)
			}
		})
	}
}

// A name that resolves to no peer means the operator and the engine disagree
// about the target set. Applying to the subset that did resolve would leave a
// fleet the operator believes is uniform and is not, so the whole write fails.
func TestFleetWriteRejectsUnknownTargetWithoutApplyingAnything(t *testing.T) {
	for _, route := range fleetWriteRoutes() {
		t.Run(route.name, func(t *testing.T) {
			testFleetWriteRejectsUnknownTarget(t, route)
		})
	}
}

func testFleetWriteRejectsUnknownTarget(t *testing.T, route fleetWriteRoute) {
	t.Helper()
	s, peers := newFleetServer(t)

	rec := callFleet(t, s, route, route.body(`["bravo","ghost-edge"]`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}

	var out struct {
		Error   string   `json:"error"`
		Unknown []string `json:"unknown"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode error body: %v (%s)", err, rec.Body.String())
	}
	if len(out.Unknown) != 1 || out.Unknown[0] != "ghost-edge" {
		t.Errorf("unknown = %v, want [ghost-edge] — the operator is not told which name failed", out.Unknown)
	}
	if !strings.Contains(out.Error, "ghost-edge") {
		t.Errorf("error message %q does not name the host that failed to resolve", out.Error)
	}

	for name, p := range peers {
		if got := p.writes(); len(got) != 0 {
			t.Errorf("%s took the write despite the request being rejected: %+v", name, got)
		}
	}
}

// An empty list is "I have not picked a host yet". Degrading it to "all" is how
// a mis-click becomes an estate-wide containment.
func TestFleetWriteRejectsEmptyTargets(t *testing.T) {
	for _, route := range fleetWriteRoutes() {
		t.Run(route.name, func(t *testing.T) {
			s, peers := newFleetServer(t)

			rec := callFleet(t, s, route, route.body(`[]`))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; an empty target list must never mean every host (body %s)",
					rec.Code, rec.Body.String())
			}
			for name, p := range peers {
				if got := p.writes(); len(got) != 0 {
					t.Errorf("%s was written to on an empty target list: %+v", name, got)
				}
			}
		})
	}
}

// The estate-wide write is still the estate-wide write: "All hosts" sends null,
// and older clients send no targets key at all.
func TestFleetWriteWithoutTargetsReachesEveryPeer(t *testing.T) {
	route := fleetWriteRoutes()[0]
	cases := map[string]string{
		"explicit null": route.body(`null`),
		"key absent":    `{"name":"containment","reason":"beaconing"}`,
	}
	for label, body := range cases {
		body := body
		t.Run(label, func(t *testing.T) {
			s, peers := newFleetServer(t)

			if rec := callFleet(t, s, route, body); rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			for name, p := range peers {
				writes := p.writes()
				if len(writes) != 1 {
					t.Fatalf("%s received %d writes, want 1 — an unscoped write must still reach every peer", name, len(writes))
				}
				if strings.Contains(writes[0].Body, "targets") {
					t.Errorf("%s was forwarded the targets key: %s", name, writes[0].Body)
				}
			}
		})
	}
}

// Reads are not a blast-radius decision, so they keep reaching every peer even
// though writes no longer do.
func TestFleetReadsStillFanOutToEveryPeer(t *testing.T) {
	s, peers := newFleetServer(t)

	rec := httptest.NewRecorder()
	s.handleFleetState(rec, httptest.NewRequest(http.MethodGet, "/api/fleet/state", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	for name, p := range peers {
		if got := len(p.reads()); got != 1 {
			t.Errorf("%s served %d reads, want 1 — the read fan-out lost a peer", name, got)
		}
	}
}

// A body the fan-out cannot parse as a JSON object cannot be checked for a
// target set either. Before targeting existed, such a body was forwarded to
// every peer and each one's rejection came back inside a 200 envelope; now the
// fan-out refuses it 400 and dispatches nothing. That is a deliberate widening
// of the 400: forwarding an unreadable body estate-wide is precisely the
// unscoped write this contract exists to prevent, and the operator cannot tell
// from an all-failed envelope whether the write was scoped as they intended.
func TestFleetWriteRejectsUnreadableBodyWithoutDispatching(t *testing.T) {
	bodies := map[string]string{
		"truncated object": `{"name":"containment",`,
		"json array":       `["bravo"]`,
		"bare string":      `"containment"`,
	}
	for _, route := range fleetWriteRoutes() {
		for label, body := range bodies {
			t.Run(route.name+"/"+label, func(t *testing.T) {
				s, peers := newFleetServer(t)

				rec := callFleet(t, s, route, body)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 for a body that is not a JSON object; got %s",
						rec.Code, rec.Body.String())
				}
				var out struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Error == "" {
					t.Errorf("400 body %q is not the documented {error} shape", rec.Body.String())
				}
				for name, p := range peers {
					if got := p.writes(); len(got) != 0 {
						t.Errorf("%s took a write whose body could not be checked for targets: %+v", name, got)
					}
				}
			})
		}
	}
}
