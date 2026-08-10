package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

// The multi-tenant Choke Gateway page must show what the single-host one shows.
//
// Buckets, the cgroup map and the host process table used to be hardcoded empty
// on the control plane because agents never reported them: the same page that
// listed 462 kernel buckets, a populated cgroup map and 122 processes on the
// engine showed 0 / {} / 0 on the console for every tenant, permanently. To an
// enterprise running both, that is not a gap in a roadmap — it is the product
// visibly not working.

func detailServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "t0k"
	s.registry.Record("acme", "agent-a", &ebpfsocv1.HeartbeatRequest{
		Buckets: []*ebpfsocv1.BucketSummary{
			{Pid: 4021, RatePerSec: 50, Burst: 100, Tokens: 7, Flags: 1},
		},
		Cgroups: []*ebpfsocv1.CgroupSummary{
			{Tier: "choke-throttled", Pids: []uint32{4021, 4022}},
		},
		Processes: []*ebpfsocv1.ProcessSummary{
			{Pid: 1, Comm: "systemd", Exe: "/usr/lib/systemd/systemd"},
			{Pid: 4021, Comm: "curl", Exe: "/usr/bin/curl", Tracked: true, State: "throttled", Score: 47},
		},
	})
	return s
}

func getJSON(t *testing.T, s *Server, path string) []byte {
	t.Helper()
	req := httptest.NewRequest("GET", path+"?tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer t0k")
	w := httptest.NewRecorder()
	s.buildHTTP().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("%s -> %d, want 200", path, w.Code)
	}
	return w.Body.Bytes()
}

// TestBucketsAreServedFromAgentReports: the panel that proves a throttle
// reached the KERNEL, rather than only being written as a decision row.
func TestBucketsAreServedFromAgentReports(t *testing.T) {
	s := detailServer(t)
	var got []map[string]any
	if err := json.Unmarshal(getJSON(t, s, "/api/choke/buckets"), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("buckets = %d, want 1 — the panel is empty again", len(got))
	}
	// flags must be a NUMBER: the engine serves `"flags": 1` and the console
	// types it as one. A friendly string here renders the fleet panel
	// differently from the identical single-host panel.
	if _, ok := got[0]["flags"].(float64); !ok {
		t.Fatalf("flags = %#v, want a numeric bitmask like the engine's", got[0]["flags"])
	}
	if got[0]["agent"] != "agent-a" {
		t.Fatalf("bucket not attributed to its host: %v", got[0]["agent"])
	}
}

// TestCgroupMapIsServed: what is ACTUALLY confined, as opposed to what a
// decision row claims should be.
func TestCgroupMapIsServed(t *testing.T) {
	s := detailServer(t)
	var got map[string][]uint32
	if err := json.Unmarshal(getJSON(t, s, "/api/choke/cgroups"), &got); err != nil {
		t.Fatal(err)
	}
	if len(got["choke-throttled"]) != 2 {
		t.Fatalf("cgroup map = %v, want the throttled tier's two pids", got)
	}
}

// TestProcessPickerIsServed: without this an operator could only contain a
// process that had already alerted — there was nothing to pick from.
func TestProcessPickerIsServed(t *testing.T) {
	s := detailServer(t)
	var got []map[string]any
	if err := json.Unmarshal(getJSON(t, s, "/api/choke/processes"), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("processes = %d, want 2", len(got))
	}
	// Tracked first: truncation must never drop the rows the gateway is acting on.
	if got[0]["tracked"] != true {
		t.Fatalf("first row = %v, want the tracked process first", got[0])
	}
	// Both comm and exe survive — kernel threads have no exe at all.
	if got[0]["comm"] != "curl" || got[0]["exe"] != "/usr/bin/curl" {
		t.Fatalf("row lost comm/exe: %v", got[0])
	}
}

// TestDetailIsTenantScoped: drill detail is host state, and must not leak.
func TestDetailIsTenantScoped(t *testing.T) {
	s := detailServer(t)
	for _, p := range []string{"/api/choke/buckets", "/api/choke/processes"} {
		req := httptest.NewRequest("GET", p+"?tenant=other-corp", nil)
		req.Header.Set("Authorization", "Bearer t0k")
		w := httptest.NewRecorder()
		s.buildHTTP().ServeHTTP(w, req)
		var got []map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 0 {
			t.Fatalf("%s leaked %d rows to another tenant", p, len(got))
		}
	}
}

// TestEmptyCgroupTierIsAnArrayNotNull: the console types the cgroup map as
// number[] | {pids,count} — JSON null is in neither union arm, so a tier with
// no PIDs must serialise as [] exactly as the single-host engine does. A nil Go
// slice marshals to null, which is the easy way to reintroduce this.
func TestEmptyCgroupTierIsAnArrayNotNull(t *testing.T) {
	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "t0k"
	s.registry.Record("acme", "agent-a", &ebpfsocv1.HeartbeatRequest{
		Cgroups: []*ebpfsocv1.CgroupSummary{
			{Tier: "choke-quarantined"}, // no pids — the empty case
			{Tier: "choke-throttled", Pids: []uint32{7}},
		},
	})
	raw := getJSON(t, s, "/api/choke/cgroups")
	if string(raw) == "" {
		t.Fatal("empty body")
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if probe["choke-quarantined"] == nil {
		t.Fatalf("empty tier serialised as null: %s", raw)
	}
	if _, ok := probe["choke-quarantined"].([]any); !ok {
		t.Fatalf("empty tier is %T, want an array: %s", probe["choke-quarantined"], raw)
	}
}
