package eventpipe

import (
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// Gateway.Forget deletes the kernel choke-map row, and its doc has always said
// "wire to process_exit events in the engine". It was never wired — the only
// caller was the operator's manual button — so every choked process left its
// bucket behind for the life of the engine. Measured on the live estate as two
// rows still rate-limiting PIDs that no longer existed.

func TestProcessExitReleasesTheKernelChokeRow(t *testing.T) {
	st, err := store.New(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	be := bpfmap.NewNoopBackend()
	if err := be.Open(); err != nil {
		t.Fatal(err)
	}
	gw := choke.NewGateway(choke.Config{
		Store: st, Enforcer: &enforce.Multi{}, Tokens: tokens.NewManager(),
		Tree: tree.New(time.Hour), Policies: policy.NewSet(), BPFMap: be,
		Thresholds: circuit.Config{ThrottleAt: 10, TarpitAt: 20, QuarantineAt: 30, SeverAt: 40},
	})
	const pid = uint32(4021)
	if err := be.Update(pid, bpfmap.PIDBucket{RatePerSec: 50, Burst: 100}); err != nil {
		t.Fatal(err)
	}

	p := &Pipeline{Store: st, Gateway: gw, Tree: tree.New(time.Hour)}
	p.Handle(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{
		ProcessExit: &tetragon.ProcessExit{Process: &tetragon.Process{
			ExecId: "exec-4021", Pid: wrapperspb.UInt32(pid), Binary: "/usr/bin/x",
		}},
	}})

	snap, err := be.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, still := snap[pid]; still {
		t.Fatal("the process exited and its choke row survived — a recycled PID inherits the throttle")
	}
}

func TestProcessExitWithNoGatewayIsHarmless(t *testing.T) {
	// A pipeline with no gateway is what a test and a not-yet-wired startup
	// get. An exit must not panic there.
	p := &Pipeline{}
	p.Handle(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{
		ProcessExit: &tetragon.ProcessExit{Process: &tetragon.Process{ExecId: "x", Pid: wrapperspb.UInt32(1)}},
	}})
}
