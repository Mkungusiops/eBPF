package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// The guardrail surface. Its failure mode is not "does not save" — it is
// looking protected while protecting nothing, which an operator only finds out
// when the uplink goes dark.

func guardrailServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(t.TempDir() + "/g.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	g := choke.NewGateway(choke.Config{
		Store:    st,
		Enforcer: &enforce.Multi{},
		Tokens:   tokens.NewManager(),
		Tree:     tree.New(time.Hour),
		Policies: policy.NewSet(),
	})
	return &Server{store: st, auth: &Auth{}, gateway: g}, st
}

func protectedCall(t *testing.T, s *Server, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleSettingsProtected(rec, httptest.NewRequest(method, "/api/settings/protected", strings.NewReader(body)))
	return rec
}

func decodeProtected(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

func strList(t *testing.T, m map[string]any, key string) []string {
	t.Helper()
	raw, ok := m[key].([]any)
	if !ok {
		t.Fatalf("%s missing or not a list in %v", key, m)
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

func TestProtectedReadSeparatesTheFixedFloorFromTheAdditions(t *testing.T) {
	// The console renders the floor as unremovable chips and the additions as
	// an editable list. If the read returned the union in "binaries", the
	// operator would be offered a Remove on sshd that comes straight back on
	// the next apply — a control that appears not to work.
	s, _ := guardrailServer(t)

	got := decodeProtected(t, protectedCall(t, s, http.MethodGet, ""))
	floor := strList(t, got, "floor")
	if len(floor) == 0 {
		t.Fatal("no compiled-in floor reported; the console would show nothing as always-protected")
	}
	if bins := strList(t, got, "binaries"); len(bins) != 0 {
		t.Fatalf("a fresh gateway reported additions %v; the floor leaked into the editable list", bins)
	}
	if got["desired_only"] != false {
		t.Fatalf("the engine reads the live gateway, so desired_only must be false, got %v", got["desired_only"])
	}
}

func TestProtectedWriteWidensAndCannotStripTheLoginPath(t *testing.T) {
	// Threat-model EN-1. A write that replaced the list wholesale would let an
	// operator — or a compromised console — remove sshd and sudo, and a host
	// nobody can log into cannot be remediated.
	s, _ := guardrailServer(t)

	rec := protectedCall(t, s, http.MethodPut,
		`{"binaries":["/opt/monitoring/agent"],"reason":"our monitoring agent must never be contained"}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	effective := s.gateway.SystemCriticalList()
	var haveAdded, haveFloor bool
	for _, b := range effective {
		if b == "/opt/monitoring/agent" {
			haveAdded = true
		}
		if strings.Contains(b, "sshd") {
			haveFloor = true
		}
	}
	if !haveAdded {
		t.Fatalf("the addition never reached the gateway: %v", effective)
	}
	if !haveFloor {
		t.Fatalf("the login path was stripped by a write that only asked to add: %v", effective)
	}

	// And the read still shows only the addition as editable.
	got := decodeProtected(t, protectedCall(t, s, http.MethodGet, ""))
	if bins := strList(t, got, "binaries"); len(bins) != 1 || bins[0] != "/opt/monitoring/agent" {
		t.Fatalf("read back %v, want just the addition", bins)
	}
}

func TestProtectedWriteEchoesTheSameShapeTheReadReturns(t *testing.T) {
	// One field name, one meaning. The write used to answer with the effective
	// union while the read answered with the additions, so a client that
	// trusted the write response would render the compiled-in floor as a list
	// of removable chips — a Remove that quietly comes back on the next apply.
	s, _ := guardrailServer(t)

	wrote := decodeProtected(t, protectedCall(t, s, http.MethodPut,
		`{"binaries":["/opt/monitoring/agent"],"reason":"must never be contained"}`))
	read := decodeProtected(t, protectedCall(t, s, http.MethodGet, ""))

	w, r := strList(t, wrote, "binaries"), strList(t, read, "binaries")
	if len(w) != len(r) {
		t.Fatalf("write answered %v and read answered %v for the same field", w, r)
	}
	for i := range w {
		if w[i] != r[i] {
			t.Fatalf("write answered %v and read answered %v for the same field", w, r)
		}
	}
	if len(strList(t, wrote, "floor")) == 0 {
		t.Fatal("the write response omits the floor, so a client cannot tell fixed from editable without a second call")
	}
}

func TestProtectedWriteRefusesAPathThatCouldNeverMatch(t *testing.T) {
	// isSystemCritical is an exact string compare against the event's binary
	// field. A bare name protects nothing and looks protected, which is worse
	// than no entry at all.
	s, _ := guardrailServer(t)

	rec := protectedCall(t, s, http.MethodPut, `{"binaries":["monitoring-agent"],"reason":"protect it"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a bare binary name was accepted (status %d): %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "never match") {
		t.Fatalf("the refusal does not say why: %s", rec.Body.String())
	}
}

func TestProtectedWriteRequiresAReasonAndAuditsIt(t *testing.T) {
	// Narrowing what the platform refuses to touch is the edit an attacker
	// with console access makes before acting, and what a review asks about
	// afterwards. It belongs in the hash chain, not a log line.
	s, st := guardrailServer(t)

	if rec := protectedCall(t, s, http.MethodPut, `{"binaries":["/opt/x"],"reason":"  "}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unjustified guardrail change was accepted: %d %s", rec.Code, rec.Body.String())
	}

	if rec := protectedCall(t, s, http.MethodPut,
		`{"binaries":["/opt/x"],"reason":"jump host tooling"}`); rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	decisions, err := st.RecentDecisions(50)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range decisions {
		if d.ExecID == "settings:guardrail" && d.Reason == "jump host tooling" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the guardrail change wrote no audit row; %d decisions recorded", len(decisions))
	}
}

func TestProtectedWriteSaysWhenTheDevicePlaneIsAbsent(t *testing.T) {
	// Silently accepting MACs on a host with no device gateway is how an
	// operator comes away believing the uplink is protected on a host where
	// nothing was applied.
	s, _ := guardrailServer(t)

	rec := protectedCall(t, s, http.MethodPut,
		`{"macs":["0a:1b:2c:3d:4e:5f"],"reason":"the top-of-rack uplink"}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if w, _ := decodeProtected(t, rec)["warning"].(string); !strings.Contains(w, "device plane is not attached") {
		t.Fatalf("no warning that the addresses were not applied: %s", rec.Body.String())
	}
}
