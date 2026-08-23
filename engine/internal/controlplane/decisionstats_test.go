package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// The console's "Response actions" tile asked /api/decision-stats, the control
// plane 404'd, and the tile fell back to counting a 200-row page — a fetch
// limit rendered as a window total. These pin the endpoint that replaces it.
func decisionStatsFixture(t *testing.T) *Server {
	t.Helper()
	cs, err := centralstore.Open(t.TempDir() + "/central.db")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	put := func(tenant, action string, at time.Time, dry bool) {
		t.Helper()
		rec := &ebpfsocv1.TelemetryRecord{
			DedupKey: tenant + action + at.String(),
			Payload: &ebpfsocv1.TelemetryRecord_Decision{Decision: &ebpfsocv1.Decision{
				Action: action, OccurredAt: timestamppb.New(at), DryRun: dry,
			}},
		}
		// Kind and the stored `at` are derived by the store: kind from the
		// payload type, `at` from INGEST time. The handler selects on that and
		// classifies on the decision's own OccurredAt, which is what the
		// timestamps below exercise.
		if err := cs.Put(ingest.StampedRecord{
			TenantID: tenant, AgentID: "a1", Record: rec,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// tenant-a: 4 in-window (one dry-run, one unknown action), 2 in the prior
	// window, 1 far older than both.
	put("tenant-a", "throttle", now.Add(-5*time.Minute), false)
	put("tenant-a", "throttle", now.Add(-6*time.Minute), false)
	put("tenant-a", "sever", now.Add(-7*time.Minute), true)
	put("tenant-a", "thaw", now.Add(-8*time.Minute), false)
	put("tenant-a", "tarpit", now.Add(-40*time.Minute), false)
	put("tenant-a", "tarpit", now.Add(-45*time.Minute), false)
	put("tenant-a", "sever", now.Add(-300*time.Minute), false)
	// tenant-b exists so the scoping assertion is meaningful.
	put("tenant-b", "quarantine", now.Add(-5*time.Minute), false)

	t.Cleanup(func() { _ = cs.Close() })
	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Store = cs
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"
	return s
}

func getDecisionStats(t *testing.T, s *Server, tenant string) map[string]any {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/decision-stats?window_min=30&tenant="+tenant, nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.buildHTTP().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The whole window, not a page of it — and the prior window separately, so the
// console's delta is a comparison rather than a repeat of the current count.
func TestCPDecisionStatsCountsWindowAndPriorWindow(t *testing.T) {
	s := decisionStatsFixture(t)

	out := getDecisionStats(t, s, "tenant-a")
	if got := out["total"].(float64); got != 4 {
		t.Errorf("total = %v, want 4", got)
	}
	if got := out["previous"].(float64); got != 2 {
		t.Errorf("previous = %v, want 2 (the preceding 30m)", got)
	}
	if got := out["dry_run"].(float64); got != 1 {
		t.Errorf("dry_run = %v, want 1", got)
	}
	if out["truncated"].(bool) {
		t.Error("truncated must be false well below the scan bound")
	}
}

// The parts must add up to the whole, including an action this build has never
// heard of — otherwise the tile and its breakdown disagree.
func TestCPDecisionStatsActionsSumToTotal(t *testing.T) {
	s := decisionStatsFixture(t)

	out := getDecisionStats(t, s, "tenant-a")
	actions := out["actions"].(map[string]any)
	sum := 0.0
	for _, v := range actions {
		sum += v.(float64)
	}
	if sum != out["total"].(float64) {
		t.Fatalf("actions sum %v != total %v — breakdown disagrees with the whole", sum, out["total"])
	}
	if actions["throttle"].(float64) != 2 || actions["sever"].(float64) != 1 {
		t.Errorf("per-action counts wrong: %v", actions)
	}
	if _, ok := actions["thaw"]; !ok {
		t.Error("an unrecognised action must still get a key, not vanish from the breakdown")
	}
	for _, rung := range []string{"throttle", "tarpit", "quarantine", "sever"} {
		if _, ok := actions[rung]; !ok {
			t.Errorf("ladder action %q missing — the console must not have to tell zero from absent", rung)
		}
	}
}

// Layer-4: the count is tenant-scoped, and one tenant's decisions never appear
// in another's total.
func TestCPDecisionStatsIsTenantScoped(t *testing.T) {
	s := decisionStatsFixture(t)

	if got := getDecisionStats(t, s, "tenant-b")["total"].(float64); got != 1 {
		t.Fatalf("tenant-b total = %v, want 1 — tenant-a's decisions must not leak in", got)
	}
}

func TestCPDecisionStatsRequiresAuth(t *testing.T) {
	s := decisionStatsFixture(t)

	req := httptest.NewRequest("GET", "/api/decision-stats?window_min=30&tenant=tenant-a", nil)
	w := httptest.NewRecorder()
	s.buildHTTP().ServeHTTP(w, req)
	if w.Code == 200 {
		t.Fatal("unauthenticated read of decision stats must not succeed")
	}
}
