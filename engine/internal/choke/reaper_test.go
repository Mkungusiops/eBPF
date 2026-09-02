package choke

import (
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

// A choke-map row outliving its process is not a memory leak, it is
// enforcement. Linux recycles PIDs, so a row left behind throttles whatever
// lands on that number next — for a decision taken about something else, with
// nothing in the audit chain to explain it.

func reaperGateway(t *testing.T) (*Gateway, bpfmap.Backend) {
	t.Helper()
	st, err := store.New(t.TempDir() + "/r.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	be := bpfmap.NewNoopBackend()
	if err := be.Open(); err != nil {
		t.Fatal(err)
	}
	g := NewGateway(Config{
		Store: st, Enforcer: &enforce.Multi{}, Tokens: tokens.NewManager(),
		Tree: tree.New(time.Hour), Policies: policy.NewSet(), BPFMap: be,
		Thresholds: circuit.Config{ThrottleAt: 10, TarpitAt: 20, QuarantineAt: 30, SeverAt: 40},
	})
	return g, be
}

func TestReaperRemovesRowsForDeadProcessesAndKeepsLiveOnes(t *testing.T) {
	g, be := reaperGateway(t)
	for _, pid := range []uint32{100, 200, 300} {
		if err := be.Update(pid, bpfmap.PIDBucket{RatePerSec: 50, Burst: 100}); err != nil {
			t.Fatal(err)
		}
	}
	// 200 is still running; the other two are gone.
	alive := func(pid uint32) bool { return pid == 200 }

	if n := g.ReapDeadPIDs(alive); n != 2 {
		t.Fatalf("reaped %d rows, want 2", n)
	}
	snap, err := be.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap[200]; !ok {
		t.Fatal("the reaper deleted a LIVE process's bucket — that silently stops enforcing a decision in force")
	}
	if len(snap) != 1 {
		t.Fatalf("map still holds %d rows, want just the live one", len(snap))
	}
}

func TestReaperWithNoLivenessProbeReapsNothing(t *testing.T) {
	// Fail closed. Unable to prove a PID is dead, deleting its bucket would
	// stop enforcing a live decision — strictly worse than leaking a row.
	g, be := reaperGateway(t)
	if err := be.Update(4242, bpfmap.PIDBucket{RatePerSec: 50, Burst: 100}); err != nil {
		t.Fatal(err)
	}
	g.SetPIDLiveFn(nil)

	if n := g.ReapDeadPIDs(nil); n != 0 {
		t.Fatalf("reaped %d rows with no way to know what is alive", n)
	}
	if snap, _ := be.Snapshot(); len(snap) != 1 {
		t.Fatalf("map holds %d rows, want the row kept", len(snap))
	}
}

func TestReaperFallsBackToTheGatewaysOwnProbe(t *testing.T) {
	// The background sweep passes nil and relies on the probe the host wired.
	g, be := reaperGateway(t)
	if err := be.Update(777, bpfmap.PIDBucket{RatePerSec: 50, Burst: 100}); err != nil {
		t.Fatal(err)
	}
	g.SetPIDLiveFn(func(uint32) bool { return false })

	if n := g.ReapDeadPIDs(nil); n != 1 {
		t.Fatalf("reaped %d, want 1 using the gateway's own probe", n)
	}
}

func TestForgetResolvesThePIDSoTheKernelRowActuallyGoes(t *testing.T) {
	// The operator's Forget button passes exec ids only. It used to call
	// Forget(id, 0), and Delete(0) is a no-op — so the console's view cleared
	// while the kernel kept throttling the process.
	g, be := reaperGateway(t)
	const execID, pid = "exec-abc", uint32(5150)
	g.tree.Add(&tree.Node{ExecID: execID, PID: pid, Binary: "/usr/bin/x"})
	if err := be.Update(pid, bpfmap.PIDBucket{RatePerSec: 50, Burst: 100}); err != nil {
		t.Fatal(err)
	}

	g.Forget(execID, 0) // the shape the manual handler uses

	snap, err := be.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, still := snap[pid]; still {
		t.Fatal("Forget cleared the console's view and left the kernel row in place")
	}
}
