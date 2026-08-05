package e2e

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/cpclient"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
	"github.com/jeffmk/ebpf-poc-engine/internal/enrollment"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

// THE AUTONOMY INVARIANT (threat-model CH-7, architecture.md).
//
//	"A missed heartbeat never stops enforcement. The cloud is never a
//	 prerequisite for containment."
//
// This is the load-bearing claim of the whole product. If a control-plane
// outage silently disarms every agent then the blast radius of one host going
// down is the entire fleet, and anyone who can reach the console — or merely
// break it — disables protection everywhere without touching a protected
// machine. CH-7 says it is "tested in CI"; until this file, it was not: the
// only end-to-end coverage drove the happy path with the control plane up
// throughout, which a wholly cloud-dependent agent would also pass.
//
// scripts/e2e/agent-autonomy.sh proves the same property against the real rig
// by stopping systemd. This is the CI-runnable half: it takes the control plane
// down for real and requires enforcement, detection and evidence-keeping to
// continue, then requires reconnection and drain to happen unaided.

// recordingEnforcer captures what actually reached the "kernel", so the test can
// assert enforcement HAPPENED rather than that a decision was merely recorded.
type recordingEnforcer struct {
	mu      sync.Mutex
	applied []enforce.Target
	actions []circuit.Action
}

func (r *recordingEnforcer) Name() string { return "recording" }

func (r *recordingEnforcer) Apply(_ context.Context, t enforce.Target, a circuit.Action, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applied = append(r.applied, t)
	r.actions = append(r.actions, a)
	return nil
}

func (r *recordingEnforcer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.applied)
}

func (r *recordingEnforcer) last() (enforce.Target, circuit.Action, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.applied) == 0 {
		return enforce.Target{}, circuit.ActNone, false
	}
	return r.applied[len(r.applied)-1], r.actions[len(r.actions)-1], true
}

// localGateway builds the agent's real choke gateway — the component that turns
// observations into enforcement — wired to a recording enforcer. Nothing here
// touches the network, which is the point being proven.
func localGateway(t *testing.T, enf enforce.Enforcer) *choke.Gateway {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	be := bpfmap.NewNoopBackend()
	_ = be.Open()
	return choke.NewGateway(choke.Config{
		Store: st, Enforcer: enf, RealEnforcer: enf,
		Tokens: tokens.NewManager(), Tree: tree.New(time.Hour), BPFMap: be,
		Policies: policy.NewSet(),
		// The posture an agent is left holding when the console goes away: armed,
		// with the thresholds its last signed policy set.
		Thresholds: circuit.Config{ThrottleAt: 5, TarpitAt: 15, QuarantineAt: 25, SeverAt: 40},
		Enforcing:  true,
	})
}

func TestAgentAutonomyDuringControlPlaneOutage(t *testing.T) {
	sink := ingest.NewMemSink()
	h := newHarness(t, sink)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tok, err := h.tokens.Mint("tenant-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	enf := &recordingEnforcer{}
	gw := localGateway(t, enf)

	buf := uplink.NewBuffer()
	buf.Enqueue(uplink.EventRecord(&store.Event{
		ID: 1, Timestamp: time.Unix(1, 0), EventType: "process_exec", ExecID: "boot-1"}))

	enrolled := make(chan struct{}, 1)
	var once sync.Once
	cfg := cpclient.Config{
		Endpoint: h.addr, ServerName: "127.0.0.1",
		BootstrapToken: tok, CABundlePEM: h.ca.CertPEM(),
		AgentInfo: &ebpfsocv1.AgentInfo{Hostname: "agent-autonomy", AgentVersion: "0.2.0-agent"},
		Buffer:    buf,
		Processor: command.NewProcessor(h.fleetVerifier, &fakeApplier{}, nil),
		Heartbeat: func() *ebpfsocv1.HeartbeatRequest {
			return &ebpfsocv1.HeartbeatRequest{
				AgentInfo:   &ebpfsocv1.AgentInfo{AgentVersion: "0.2.0-agent"},
				BufferDepth: uint64(buf.PendingDepth()),
			}
		},
		DrainInterval: 50 * time.Millisecond, HeartbeatInterval: 50 * time.Millisecond,
		Backoff:    50 * time.Millisecond,
		OnEnrolled: func(*enrollment.Enrolled) { once.Do(func() { close(enrolled) }) },
	}
	go func() { _ = cpclient.Run(ctx, cfg) }()

	select {
	case <-enrolled:
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not enroll")
	}
	waitFor(t, 10*time.Second, "baseline record to drain", func() bool { return sink.Count("tenant-a") >= 1 })

	// ── THE OUTAGE ────────────────────────────────────────────────────────
	h.stop()
	// Let the agent's drain and heartbeat loops actually fail a few times, so
	// what follows is measured against a genuinely unreachable control plane
	// rather than a connection that has not noticed yet.
	time.Sleep(500 * time.Millisecond)
	drainedAtOutage := sink.Count("tenant-a")

	// 1. ENFORCEMENT. The decision path must reach the kernel with no control
	//    plane in existence. This is the invariant itself.
	before := enf.count()
	d := gw.OnEvent(context.Background(), choke.Observation{
		ExecID: "offline-victim", PID: 4021, Binary: "/usr/bin/curl",
		Score: 99, Reason: "credential theft chain, console unreachable",
	})
	if d == nil {
		t.Fatal("no decision while the control plane was down — the gateway stopped scoring without a console")
	}
	if enf.count() == before {
		t.Fatal("AUTONOMY VIOLATED: no enforcement reached the kernel while the control plane was down")
	}
	tgt, act, _ := enf.last()
	if tgt.ExecID != "offline-victim" || act != circuit.ActSever {
		t.Fatalf("enforced %+v/%v, want a sever on offline-victim (score 99 is past the sever threshold)", tgt, act)
	}

	// 2. EVIDENCE. Telemetry produced during the outage must be KEPT, not
	//    dropped — an agent that discards what it saw while disconnected turns a
	//    console outage into a permanent hole in the audit trail.
	const outageRecords = 5
	for i := 2; i <= outageRecords+1; i++ {
		if _, ok := buf.Enqueue(uplink.EventRecord(&store.Event{
			ID: int64(i), Timestamp: time.Unix(int64(i), 0),
			EventType: "process_exec", ExecID: fmt.Sprintf("offline-%d", i),
		})); !ok {
			t.Fatalf("buffer refused record %d during the outage", i)
		}
	}
	if got := buf.PendingDepth(); got < outageRecords {
		t.Fatalf("pending depth %d, want >= %d — evidence was dropped while disconnected", got, outageRecords)
	}
	if sink.Count("tenant-a") != drainedAtOutage {
		t.Fatal("the control plane received records while it was supposed to be down")
	}

	// 3. RECOVERY. Reconnection, drain and re-registration must all happen
	//    unaided — an outage that needs a manual restart on every host is an
	//    outage that takes the fleet with it.
	h.bringUp(t)
	waitFor(t, 30*time.Second, "buffered evidence to drain after reconnect", func() bool {
		return sink.Count("tenant-a") >= outageRecords+1
	})
	if depth := buf.PendingDepth(); depth != 0 {
		t.Fatalf("pending depth %d after reconnect, want 0 — the buffer did not fully drain", depth)
	}
	// Exactly-once through the outage: no loss (checked above) and no duplicates.
	if got := sink.Count("tenant-a"); got != outageRecords+1 {
		t.Fatalf("control plane holds %d records, want %d — the outage duplicated or lost evidence",
			got, outageRecords+1)
	}
	waitFor(t, 30*time.Second, "agent to re-register with no intervention", func() bool {
		return len(h.registry.ListTenant("tenant-a")) >= 1
	})
}

// TestAgentEnforcesBeforeItEverReachesAControlPlane is the stronger form of the
// same claim: a freshly started agent that has NEVER contacted a control plane
// must still contain a threat. Enforcement cannot be something the cloud grants.
func TestAgentEnforcesBeforeItEverReachesAControlPlane(t *testing.T) {
	enf := &recordingEnforcer{}
	gw := localGateway(t, enf)

	d := gw.OnEvent(context.Background(), choke.Observation{
		ExecID: "never-phoned-home", PID: 777, Binary: "/usr/bin/nc",
		Score: 99, Reason: "reverse shell, no control plane configured",
	})
	if d == nil || enf.count() == 0 {
		t.Fatal("an agent with no control plane did not enforce — containment was made conditional on the cloud")
	}
	if tgt, act, _ := enf.last(); act != circuit.ActSever || tgt.ExecID != "never-phoned-home" {
		t.Fatalf("enforced %+v/%v, want a sever on never-phoned-home", tgt, act)
	}
}

// waitFor polls until cond holds, failing with what was being waited on.
func waitFor(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", limit, what)
}
