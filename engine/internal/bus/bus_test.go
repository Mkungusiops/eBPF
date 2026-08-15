package bus

import (
	"path/filepath"
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

func eventRec(dedup, execID string) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{
		DedupKey: dedup,
		Payload:  &ebpfsocv1.TelemetryRecord_Event{Event: &ebpfsocv1.ProcessEvent{ExecId: execID}},
	}
}

// waitFor polls until cond holds. The deadline is a FAILURE timeout, not a
// performance assertion: the loop returns the instant the condition is met, so
// a generous budget costs a passing test nothing and only bounds how long a
// genuinely broken one takes to report.
//
// It was 3 seconds, which passed normally and failed under -race — the detector
// slows execution enough that the async bus hop ran out of budget. A test that
// fails only when instrumented is why the race gate was never turned on, so the
// budget now has headroom for it, and shrinks to fit `go test -timeout` when
// that is tighter.
// The budget is deliberately far larger than the work: this test drives real
// async I/O (ingest sink → bus → consumer → SQLite), and `go test -race ./...`
// runs package binaries in parallel, so on a loaded or few-core machine the hop
// can be starved for tens of seconds without anything being wrong. A budget
// tuned to the happy path just converts that contention into a false failure —
// which is what a 3-second one did, and why -race stayed out of CI.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	budget := 90 * time.Second
	if d, ok := t.Deadline(); ok {
		if remaining := time.Until(d) - time.Second; remaining < budget {
			budget = remaining
		}
	}
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func TestSubjectIsTenantPartitioned(t *testing.T) {
	m := Message{TenantID: "tenant-a", Record: eventRec("evt:1", "e1")}
	if got := Subject(m); got != "telemetry.tenant-a.event" {
		t.Fatalf("subject = %q, want telemetry.tenant-a.event", got)
	}
	// A dotted tenant id stays a single subject token.
	m2 := Message{TenantID: "a.b", Record: eventRec("evt:1", "e1")}
	if got := Subject(m2); got != "telemetry.a_b.event" {
		t.Fatalf("subject = %q, want telemetry.a_b.event", got)
	}
}

// TestPipelinePreservesTenantThroughBus is the D4c decoupling proof: records
// flow ingest-sink -> bus -> consumer -> central store, and a tenant-scoped read
// still sees only its own rows. Isolation holds across the async hop.
func TestPipelinePreservesTenantThroughBus(t *testing.T) {
	b := NewMemBus()
	defer b.Close()

	cs, err := centralstore.Open(filepath.Join(t.TempDir(), "central.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	stop, err := Consume(b, cs) // bus -> central store
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	sink := NewSink(b) // ingest.Sink -> bus
	put := func(tenant, agent, dedup string) {
		if err := sink.Put(ingest.StampedRecord{TenantID: tenant, AgentID: agent, Record: eventRec(dedup, "e")}); err != nil {
			t.Fatal(err)
		}
	}
	put("tenant-a", "aa", "evt:1")
	put("tenant-a", "aa", "evt:2")
	put("tenant-b", "bb", "evt:1") // identical dedup key, other tenant

	waitFor(t, func() bool {
		n, _ := cs.Count(centralstore.Scope{TenantID: "tenant-a"})
		m, _ := cs.Count(centralstore.Scope{TenantID: "tenant-b"})
		return n == 2 && m == 1
	})

	// Isolation preserved through the bus.
	rowsB, _ := cs.Query(centralstore.Scope{TenantID: "tenant-b"}, 100)
	if len(rowsB) != 1 || rowsB[0].TenantID != "tenant-b" {
		t.Fatalf("tenant-b read through bus = %d rows, first tenant %q — leak", len(rowsB), func() string {
			if len(rowsB) > 0 {
				return rowsB[0].TenantID
			}
			return ""
		}())
	}
}

func TestPublishAfterCloseErrors(t *testing.T) {
	b := NewMemBus()
	_ = b.Close()
	if err := b.Publish(Message{TenantID: "t", Record: eventRec("evt:1", "e")}); err != ErrClosed {
		t.Fatalf("publish after close = %v, want ErrClosed", err)
	}
}
