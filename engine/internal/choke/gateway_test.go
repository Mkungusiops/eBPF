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
		Actor: "alice",
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
		Metadata: policy.Metadata{Name: "shells"},
		Match:    policy.Match{Binaries: []string{"/bin/bash"}, States: []string{"throttled", "tarpit"}},
		Buckets:  []policy.Bucket{{Dimension: "egress", RatePerSec: 1, Burst: 1}},
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

// In detect-only mode, manual operator overrides must still reach the
// real enforcer chain — a human "kill this" should not be downgraded to
// "would have killed". Score-driven decisions continue to log only.
func TestGatewayManualBypassesDetectOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pt := tree.New(time.Hour)
	be := bpfmap.NewNoopBackend()
	_ = be.Open()
	real := &enforce.Multi{Backends: []enforce.Enforcer{
		&enforce.Throttler{Backend: be},
	}}
	logger := &enforce.Logger{Prefix: "[enforce-disabled]"}
	g := NewGateway(Config{
		Store: st, Enforcer: logger, Broadcast: &recordingBcast{},
		Tokens: tokens.NewManager(), Tree: pt, BPFMap: be,
		Policies:       policy.NewSet(),
		Enforcing:      false, // detect-only at boot
		RealEnforcer:   real,
		LoggerEnforcer: logger,
	})
	pt.Add(&tree.Node{ExecID: "M", PID: 4242, Binary: "/bin/yes", StartTime: time.Now()})

	// Score-driven: stays logger-only.
	g.OnEvent(context.Background(), Observation{ExecID: "M", PID: 4242, Binary: "/bin/yes", Score: 30, Reason: "auto"})
	rows, _ := st.RecentDecisions(10)
	if len(rows) == 0 || rows[0].Backend != "logger" {
		t.Fatalf("score-driven in detect-only must use logger backend; got %+v", rows)
	}

	// Manual: reaches the real Multi chain.
	if _, err := g.Manual(context.Background(), ManualRequest{
		ExecID: "M", PID: 4242, Binary: "/bin/yes",
		Action: circuit.ActQuarantine, Reason: "operator override",
		Actor: "alice",
	}); err != nil {
		t.Fatalf("manual: %v", err)
	}
	rows, _ = st.RecentDecisions(10)
	if rows[0].Backend != "multi" {
		t.Errorf("manual in detect-only must use real enforcer; backend=%q", rows[0].Backend)
	}
	snap, _ := be.Snapshot()
	if _, ok := snap[4242]; !ok {
		t.Errorf("manual override must drive the real throttler; bpfmap missing pid 4242")
	}
}

// Dry-run is a deliberate global stop. Manual overrides still record audit
// rows but must not reach the kernel — dry-run wraps the active enforcer
// and the manual-bypass logic leaves that wrapper in place.
func TestGatewayManualRespectsDryRunInDetectOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pt := tree.New(time.Hour)
	be := bpfmap.NewNoopBackend()
	_ = be.Open()
	real := &enforce.Multi{Backends: []enforce.Enforcer{&enforce.Throttler{Backend: be}}}
	logger := &enforce.Logger{Prefix: "[enforce-disabled]"}
	g := NewGateway(Config{
		Store: st, Enforcer: logger, Broadcast: &recordingBcast{},
		Tokens: tokens.NewManager(), Tree: pt, BPFMap: be,
		Policies:       policy.NewSet(),
		DryRun:         true,
		Enforcing:      false,
		RealEnforcer:   real,
		LoggerEnforcer: logger,
	})
	pt.Add(&tree.Node{ExecID: "D", PID: 7777, Binary: "/bin/yes", StartTime: time.Now()})

	if _, err := g.Manual(context.Background(), ManualRequest{
		ExecID: "D", PID: 7777, Binary: "/bin/yes",
		Action: circuit.ActQuarantine, Reason: "shadow probe",
		Actor: "alice",
	}); err != nil {
		t.Fatalf("manual: %v", err)
	}
	rows, _ := st.RecentDecisions(10)
	if !rows[0].DryRun {
		t.Errorf("dry-run flag must propagate to manual: %+v", rows[0])
	}
	snap, _ := be.Snapshot()
	if len(snap) != 0 {
		t.Errorf("dry-run must suppress real enforcer on manual; bpfmap entries=%d", len(snap))
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

// The system-critical exemption is matched by EXACT binary path, so a stale or
// wrong path silently protects nothing. This pins the login path specifically:
// it is the one set where being wrong locks the operator out of the host, and
// it has rotted before — the list carried "/usr/sbin/sshd-session" while
// Debian/Ubuntu ship it at "/usr/lib/openssh/sshd-session", so on every
// OpenSSH >= 9.8 box the per-session daemon (the process that actually reads
// credentials, and therefore the one enforcement would kill) was unprotected.
func TestDefaultSystemCriticalCoversTheLoginPath(t *testing.T) {
	have := make(map[string]bool)
	for _, b := range DefaultSystemCriticalBinaries() {
		have[b] = true
	}
	// Every layout we might land on. A redundant entry never matches and costs
	// nothing; a missing one is a lockout.
	for _, required := range []string{
		"/usr/sbin/sshd",
		"/usr/lib/openssh/sshd-session",     // Debian / Ubuntu
		"/usr/lib/openssh/sshd-auth",        //
		"/usr/libexec/openssh/sshd-session", // RHEL family
		"/usr/libexec/openssh/sshd-auth",    //
		"/usr/bin/login",                    // serial-console recovery path
		"/bin/login",                        //
		"/usr/bin/sudo",                     // threat-model EN-1: recovery
		"/usr/bin/su",                       //
	} {
		if !have[required] {
			t.Errorf("login/recovery path %q missing from the system-critical exemption — "+
				"score-driven enforcement would be free to choke it", required)
		}
	}
}

// The exemption must actually take effect, not merely be listed: a score-driven
// transition on a per-session sshd is bypassed, while a manual override on the
// same binary still goes through (an operator can always contain something).
func TestSystemCriticalBypassesScoreDrivenEnforcementOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "sc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pt := tree.New(time.Hour)
	be := bpfmap.NewNoopBackend()
	_ = be.Open()
	g := NewGateway(Config{
		Store: st, Broadcast: &recordingBcast{}, Tokens: tokens.NewManager(),
		Tree: pt, BPFMap: be, Policies: policy.NewSet(), Enforcing: true,
		Enforcer:               &enforce.Multi{Backends: []enforce.Enforcer{&enforce.Throttler{Backend: be}}},
		SystemCriticalBinaries: DefaultSystemCriticalBinaries(),
	})

	const sshBin = "/usr/lib/openssh/sshd-session"
	const pid = uint32(9101)
	pt.Add(&tree.Node{ExecID: "S1", PID: pid, Binary: sshBin, StartTime: time.Now()})

	inMap := func() bool {
		snap, err := be.Snapshot()
		if err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		_, ok := snap[pid]
		return ok
	}

	// Score into QUARANTINE, not sever: the Throttler backend implements the
	// throttle/tarpit/quarantine rungs, and returns ErrUnsupported for sever —
	// so a sever-level score would write no bucket whether or not the exemption
	// worked, and the assertion below would pass vacuously.
	g.OnEvent(context.Background(), Observation{ExecID: "S1", PID: pid, Binary: sshBin, Score: 30})
	if inMap() {
		t.Error("score-driven enforcement wrote a bucket for a system-critical login binary")
	}

	// The operator override is deliberately NOT exempt.
	if _, err := g.Manual(context.Background(), ManualRequest{
		ExecID: "S1", PID: pid, Binary: sshBin,
		Action: circuit.ActThrottle, Reason: "operator decision", Actor: "tester",
	}); err != nil {
		t.Fatalf("manual override on a system-critical binary: %v", err)
	}
	if !inMap() {
		t.Error("manual override on a system-critical binary was bypassed — an operator must always be able to contain")
	}
}
