package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// A quarantine that thaws on its own and one that never will must not render
// identically. The agent-local console has distinguished them since the revert
// timer existed; the fleet console had no field to distinguish them WITH, so an
// operator either manually thawed something already about to release, or walked
// away from a containment believing it would.
func TestFleetCircuitsCarryRevertPendingAndLastSeen(t *testing.T) {
	seen := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	reg := heartbeat.NewRegistry()
	reg.Record("acme", "agent-1", &ebpfsocv1.HeartbeatRequest{
		Chokes: []*ebpfsocv1.ChokeSummary{
			{ExecId: "e1", Pid: 100, Binary: "/usr/bin/curl", State: "quarantined", Score: 130,
				RevertPending: true, LastSeen: timestamppb.New(seen)},
			// No revert armed, and an agent that predates the field sends no
			// timestamp at all.
			{ExecId: "e2", Pid: 101, Binary: "/usr/bin/nc", State: "severed", Score: 210},
		},
	})

	s := &Server{registry: reg, auditor: authz.NewMemAuditor()}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"

	req := httptest.NewRequest(http.MethodGet, "/api/choke/circuits?tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.handleChokeCircuits(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	var got []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d circuits, want 2", len(got))
	}
	byExec := map[string]map[string]any{}
	for _, c := range got {
		byExec[c["exec_id"].(string)] = c
	}

	if byExec["e1"]["revert_pending"] != true {
		t.Fatal("the self-releasing quarantine did not report revert_pending")
	}
	if ls, _ := byExec["e1"]["last_seen"].(string); ls != seen.Format(time.RFC3339) {
		t.Fatalf("last_seen=%q, want %q", ls, seen.Format(time.RFC3339))
	}

	// The absent cases must be ABSENT, not zero. A false revert_pending is a
	// fair reading of "no revert armed", but a 1970 last_seen on a containment
	// row states the process was last observed fifty years ago.
	if _, present := byExec["e2"]["last_seen"]; present {
		t.Fatalf("an agent that sent no timestamp got one anyway: %v", byExec["e2"]["last_seen"])
	}
	if rp, present := byExec["e2"]["revert_pending"]; present && rp == true {
		t.Fatal("a permanent containment was reported as self-releasing")
	}
}
