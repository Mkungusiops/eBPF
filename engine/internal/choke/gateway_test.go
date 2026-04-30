package choke

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

type recordingBcast struct {
	got []string
}

func (r *recordingBcast) Broadcast(t string, _ interface{}) { r.got = append(r.got, t) }

func newTestGateway(t *testing.T, dryRun bool) (*Gateway, *store.Store, *tree.Tree, *recordingBcast, *bpfmap.NoopBackend) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pt := tree.New(time.Hour)
	be := bpfmap.NewNoopBackend()
	_ = be.Open()
	bcast := &recordingBcast{}
	enf := &enforce.Multi{Backends: []enforce.Enforcer{
		&enforce.Throttler{Backend: be},
		&enforce.Severer{},
	}}
	g := NewGateway(Config{
		Store: st, Enforcer: enf, Broadcast: bcast,
		Tokens: tokens.NewManager(), Tree: pt, BPFMap: be,
		Policies:  policy.NewSet(),
		DryRun:    dryRun,
		Enforcing: true,
	})
	return g, st, pt, bcast, be
}

func TestGatewayManualEscalateAndAudit(t *testing.T) {
	g, st, pt, _, be := newTestGateway(t, false)
	pt.Add(&tree.Node{ExecID: "X", PID: 1234, Binary: "/bin/yes", StartTime: time.Now()})
	g.OnEvent(context.Background(), Observation{ExecID: "X", PID: 1234, Binary: "/bin/yes", Score: 0})

	d, err := g.Manual(context.Background(), ManualRequest{
		ExecID: "X", PID: 1234, Binary: "/bin/yes",
		Action: circuit.ActQuarantine, Reason: "operator gut check",
		Actor:  "alice",
	})
	if err != nil {
		t.Fatalf("manual: %v", err)
	}
	if d.To != circuit.Quarantined {
		t.Errorf("expected Quarantined, got %s", d.To)
	}

	rows, _ := st.RecentDecisions(10)
	if len(rows) == 0 {
		t.Fatalf("manual must record audit row")
	}
	if rows[0].Action != "quarantine" || rows[0].ToState != "quarantined" {
		t.Errorf("audit row mismatch: %+v", rows[0])
	}
	if !contains(rows[0].Reason, "[manual]") || !contains(rows[0].Reason, "alice") {
		t.Errorf("audit reason should record actor + manual flag: %q", rows[0].Reason)
	}

	// Throttler should have written a quarantine bucket for pid 1234.
	snap, _ := be.Snapshot()
	if _, ok := snap[1234]; !ok {
		t.Errorf("throttler did not write quarantine bucket for manual override")
	}
}

func TestGatewayKillSwitchSkipsEnforcer(t *testing.T) {
	g, st, pt, _, be := newTestGateway(t, false)
	pt.Add(&tree.Node{ExecID: "X", PID: 99, Binary: "/bin/yes", StartTime: time.Now()})
	prev := g.SetKillSwitch(true)
	if prev {
		t.Errorf("kill-switch starts disengaged; prev=true")
	}
	if !g.KillSwitched() {
		t.Errorf("KillSwitched() should be true")
	}

	g.OnEvent(context.Background(), Observation{ExecID: "X", PID: 99, Binary: "/bin/yes", Score: 30, Reason: "test"})

	rows, _ := st.RecentDecisions(10)
	if len(rows) == 0 {
		t.Fatalf("kill-switch must still record audit rows")
	}
	if !contains(rows[0].Outcome, "kill-switch") {
		t.Errorf("decision must annotate kill-switch in outcome: %q", rows[0].Outcome)
	}
	if rows[0].Backend != "kill-switch" {
		t.Errorf("decision must report kill-switch as backend: %q", rows[0].Backend)
	}
	// BPF map should be empty — no real enforcer ran.
	snap, _ := be.Snapshot()
	if len(snap) != 0 {
		t.Errorf("kill-switch must not write to bpfmap, got %d entries", len(snap))
	}
}

func TestGatewaySnapshotJoinsTree(t *testing.T) {
	g, _, pt, _, _ := newTestGateway(t, false)
	pt.Add(&tree.Node{ExecID: "A", PID: 11, Binary: "/bin/a", StartTime: time.Now()})
	pt.Add(&tree.Node{ExecID: "B", PID: 22, Binary: "/bin/b", StartTime: time.Now()})
	g.OnEvent(context.Background(), Observation{ExecID: "A", PID: 11, Binary: "/bin/a", Score: 7})
	g.OnEvent(context.Background(), Observation{ExecID: "B", PID: 22, Binary: "/bin/b", Score: 30})

	snap := g.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len=%d want 2", len(snap))
	}
	// Sorted: severed/quarantined first.
	if snap[0].State != "quarantined" {
		t.Errorf("snapshot not sorted by state desc: %+v", snap)
	}
	if snap[0].Binary == "" || snap[0].PID == 0 {
		t.Errorf("snapshot did not join with tree: %+v", snap[0])
	}
}

func TestGatewayPreviewPolicyMatches(t *testing.T) {
	g, _, pt, _, _ := newTestGateway(t, false)
	pt.Add(&tree.Node{ExecID: "S", PID: 33, Binary: "/bin/bash", StartTime: time.Now()})
	pt.Add(&tree.Node{ExecID: "C", PID: 44, Binary: "/usr/bin/curl", StartTime: time.Now()})
	g.OnEvent(context.Background(), Observation{ExecID: "S", PID: 33, Binary: "/bin/bash", Score: 7})
	g.OnEvent(context.Background(), Observation{ExecID: "C", PID: 44, Binary: "/usr/bin/curl", Score: 30})

	p := policy.Policy{
		APIVersion: policy.APIVersion, Kind: policy.Kind,
		Metadata:   policy.Metadata{Name: "shells"},
		Match:      policy.Match{Binaries: []string{"/bin/bash"}, States: []string{"throttled", "tarpit"}},
		Buckets:    []policy.Bucket{{Dimension: "egress", RatePerSec: 1, Burst: 1}},
	}
	matches, err := g.PreviewPolicy(p)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(matches) != 1 || matches[0].Binary != "/bin/bash" {
		t.Errorf("preview wrong: %+v", matches)
	}
}

func TestGatewaySetThresholdsLogs(t *testing.T) {
	g, _, _, _, _ := newTestGateway(t, false)
	prev := g.SetThresholds(circuit.Config{ThrottleAt: 1, TarpitAt: 2, QuarantineAt: 3, SeverAt: 4})
	if prev.ThrottleAt == 0 {
		t.Errorf("expected non-zero prev")
	}
	now := g.Thresholds()
	if now.ThrottleAt != 1 || now.SeverAt != 4 {
		t.Errorf("thresholds not applied: %+v", now)
	}
}

func TestGatewayDryRunRecordsButDoesNotApply(t *testing.T) {
	g, st, pt, _, be := newTestGateway(t, true) // dry-run on
	pt.Add(&tree.Node{ExecID: "D", PID: 55, Binary: "/bin/yes", StartTime: time.Now()})
	g.OnEvent(context.Background(), Observation{ExecID: "D", PID: 55, Binary: "/bin/yes", Score: 10, Reason: "test"})
	rows, _ := st.RecentDecisions(10)
	if len(rows) == 0 {
		t.Fatalf("dry-run must still record")
	}
	if !rows[0].DryRun {
		t.Errorf("dry-run flag must be true: %+v", rows[0])
	}
	snap, _ := be.Snapshot()
	if len(snap) != 0 {
		t.Errorf("dry-run must not call enforcer; bpfmap len=%d", len(snap))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
