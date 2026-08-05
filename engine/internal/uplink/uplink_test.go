package uplink

import (
	"fmt"
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// --- converters -----------------------------------------------------------

func TestEventRecord(t *testing.T) {
	e := &store.Event{
		ID: 7, Timestamp: time.Unix(1000, 0), EventType: "process_exec",
		PID: 100, ParentPID: 1, ExecID: "exec-a", Binary: "/bin/bash",
		Args: "-c id", UID: 0, PolicyName: "",
	}
	r := EventRecord(e)
	if r.GetDedupKey() != "evt:7" {
		t.Fatalf("dedup key = %q, want evt:7", r.GetDedupKey())
	}
	ev := r.GetEvent()
	if ev == nil {
		t.Fatal("payload is not a ProcessEvent")
	}
	if ev.GetExecId() != "exec-a" || ev.GetBinary() != "/bin/bash" || ev.GetPid() != 100 || ev.GetParentPid() != 1 {
		t.Fatalf("event fields not mapped: %+v", ev)
	}
	if ev.GetOccurredAt().AsTime().Unix() != 1000 {
		t.Fatalf("timestamp not mapped: %v", ev.GetOccurredAt().AsTime())
	}
}

func TestAlertRecord(t *testing.T) {
	a := &store.Alert{ID: 3, Timestamp: time.Unix(2000, 0), Severity: "critical", Title: "chain", ExecID: "exec-b", Score: 46}
	r := AlertRecord(a)
	if r.GetDedupKey() != "alt:3" {
		t.Fatalf("dedup key = %q, want alt:3", r.GetDedupKey())
	}
	if al := r.GetAlert(); al == nil || al.GetScore() != 46 || al.GetSeverity() != "critical" {
		t.Fatalf("alert fields not mapped: %+v", r.GetAlert())
	}
}

// TestDecisionRecordCarriesChainFields asserts that every field feeding the
// audit chain hash (and the hex hashes themselves) is carried verbatim, so the
// central mirror can re-verify the tamper-evident chain per tenant.
func TestDecisionRecordCarriesChainFields(t *testing.T) {
	d := &store.Decision{
		ID: 42, Timestamp: time.Unix(3000, 0), ExecID: "exec-c", PID: 200,
		Binary: "/usr/bin/sudo", Action: "sever", FromState: "quarantined",
		ToState: "severed", Score: 130, Reason: "priv-esc", DryRun: false,
		Backend: "cgroupv2", Outcome: "ok",
		OriginKind: "ssh", OriginIP: "10.0.0.5", OriginPort: 51000, OriginUser: "root",
		DeviceMAC: "", PrevHash: "aa11", Hash: "bb22",
	}
	r := DecisionRecord(d)
	if r.GetDedupKey() != "dec:42" {
		t.Fatalf("dedup key = %q, want dec:42", r.GetDedupKey())
	}
	dp := r.GetDecision()
	if dp == nil {
		t.Fatal("payload is not a Decision")
	}
	// Chain-hashed fields.
	if dp.GetId() != 42 || dp.GetAction() != "sever" || dp.GetFromState() != "quarantined" ||
		dp.GetToState() != "severed" || dp.GetExecId() != "exec-c" || dp.GetPid() != 200 ||
		dp.GetScore() != 130 || dp.GetDryRun() != false {
		t.Fatalf("chain-hashed fields not mapped faithfully: %+v", dp)
	}
	if dp.GetOccurredAt().AsTime().Unix() != 3000 {
		t.Fatalf("decision timestamp not mapped")
	}
	// Chain link carried verbatim.
	if dp.GetPrevHash() != "aa11" || dp.GetHash() != "bb22" {
		t.Fatalf("chain link not carried verbatim: prev=%q hash=%q", dp.GetPrevHash(), dp.GetHash())
	}
	// Attribution + origin port narrowing (uint16 → uint32).
	if dp.GetOriginKind() != "ssh" || dp.GetOriginIp() != "10.0.0.5" || dp.GetOriginPort() != 51000 {
		t.Fatalf("origin attribution not mapped: %+v", dp)
	}
}

// --- buffer: resume / ack / dedup / backpressure --------------------------

func rec(key string) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{DedupKey: key}
}

func TestBufferSequenceAndDepth(t *testing.T) {
	b := NewBuffer()
	for i, k := range []string{"a", "b", "c"} {
		seq, ok := b.Enqueue(rec(k))
		if !ok || seq != uint64(i+1) {
			t.Fatalf("enqueue %q: seq=%d ok=%v, want seq=%d ok=true", k, seq, ok, i+1)
		}
	}
	if b.PendingDepth() != 3 {
		t.Fatalf("depth = %d, want 3", b.PendingDepth())
	}
}

// TestBufferResumeIsIdempotent: NextBatch without an intervening Ack must return
// the SAME records (a reconnect re-sends; server-side dedup makes it safe).
func TestBufferResumeIsIdempotent(t *testing.T) {
	b := NewBuffer()
	b.Enqueue(rec("a"))
	b.Enqueue(rec("b"))

	first := b.NextBatch(10)
	second := b.NextBatch(10)
	if first == nil || second == nil {
		t.Fatal("expected non-nil batches")
	}
	if first.GetAgentSeq() != second.GetAgentSeq() || len(first.GetRecords()) != len(second.GetRecords()) {
		t.Fatalf("resume not idempotent: first seq=%d n=%d, second seq=%d n=%d",
			first.GetAgentSeq(), len(first.GetRecords()), second.GetAgentSeq(), len(second.GetRecords()))
	}
	if b.PendingDepth() != 2 {
		t.Fatalf("NextBatch must not consume records; depth=%d want 2", b.PendingDepth())
	}
}

// TestBufferAckCumulativeAndResume: Ack frees up to the sequence, and the next
// batch resumes from the remainder.
func TestBufferAckCumulativeAndResume(t *testing.T) {
	b := NewBuffer()
	for _, k := range []string{"a", "b", "c", "d"} {
		b.Enqueue(rec(k))
	}
	batch := b.NextBatch(2) // a,b → agent_seq 2
	if batch.GetAgentSeq() != 2 || len(batch.GetRecords()) != 2 {
		t.Fatalf("first batch = seq %d n %d, want seq 2 n 2", batch.GetAgentSeq(), len(batch.GetRecords()))
	}
	if freed := b.Ack(2); freed != 2 {
		t.Fatalf("Ack(2) freed %d, want 2", freed)
	}
	if b.PendingDepth() != 2 {
		t.Fatalf("depth after ack = %d, want 2", b.PendingDepth())
	}
	next := b.NextBatch(10) // resumes at c,d → agent_seq 4
	if next.GetAgentSeq() != 4 || len(next.GetRecords()) != 2 {
		t.Fatalf("resume batch = seq %d n %d, want seq 4 n 2", next.GetAgentSeq(), len(next.GetRecords()))
	}
	if next.GetRecords()[0].GetDedupKey() != "c" {
		t.Fatalf("resume did not start at oldest un-acked; got %q, want c", next.GetRecords()[0].GetDedupKey())
	}
}

func TestBufferStaleAckIsNoop(t *testing.T) {
	b := NewBuffer()
	b.Enqueue(rec("a"))
	b.Enqueue(rec("b"))
	b.Ack(2)                   // frees both
	if n := b.Ack(2); n != 0 { // replayed ack
		t.Fatalf("stale ack freed %d, want 0", n)
	}
	if n := b.Ack(1); n != 0 { // below floor
		t.Fatalf("below-floor ack freed %d, want 0", n)
	}
}

// TestBufferDedupGuard: buffering the same dedup key twice while pending is a
// no-op; after it is acked, the guard forgets it (bounded memory).
func TestBufferDedupGuard(t *testing.T) {
	b := NewBuffer()
	if _, ok := b.Enqueue(rec("dup")); !ok {
		t.Fatal("first enqueue should succeed")
	}
	if _, ok := b.Enqueue(rec("dup")); ok {
		t.Fatal("second enqueue of same key should be rejected")
	}
	if b.PendingDepth() != 1 {
		t.Fatalf("depth = %d, want 1", b.PendingDepth())
	}
	b.Ack(1)
	if _, ok := b.Enqueue(rec("dup")); !ok {
		t.Fatal("after ack, key should be enqueueable again")
	}
}

func TestBufferBackpressureBatchSize(t *testing.T) {
	b := NewBuffer()
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		b.Enqueue(rec(k))
	}
	if batch := b.NextBatch(2); len(batch.GetRecords()) != 2 {
		t.Fatalf("NextBatch(2) returned %d records, want 2", len(batch.GetRecords()))
	}
	if b.NextBatch(0) != nil {
		t.Fatal("NextBatch(0) should return nil")
	}
	empty := NewBuffer()
	if empty.NextBatch(10) != nil {
		t.Fatal("NextBatch on empty buffer should return nil")
	}
}

// The buffer was unbounded: an agent whose control plane could not ack grew in
// memory until the OOM killer took it, losing the ENTIRE backlog. It now sheds
// the oldest records and counts what it shed, because a security agent that
// drops telemetry silently is worse than one that reports a gap.
func TestBufferEvictsOldestWhenFull(t *testing.T) {
	b := NewBuffer()
	b.MaxRecords(3)

	for i := 0; i < 5; i++ {
		rec := &ebpfsocv1.TelemetryRecord{DedupKey: fmt.Sprintf("evt:%d", i)}
		if _, ok := b.Enqueue(rec); !ok {
			t.Fatalf("record %d refused", i)
		}
	}

	if got := b.PendingDepth(); got != 3 {
		t.Fatalf("PendingDepth = %d, want 3 (the cap)", got)
	}
	if got := b.Dropped(); got != 2 {
		t.Fatalf("Dropped = %d, want 2", got)
	}

	// The NEWEST records are the ones kept — during an outage the recent past
	// is what an operator can still act on.
	batch := b.NextBatch(10)
	if batch == nil {
		t.Fatal("NextBatch returned nil with 3 records buffered")
	}
	var keys []string
	for _, r := range batch.GetRecords() {
		keys = append(keys, r.GetDedupKey())
	}
	want := []string{"evt:2", "evt:3", "evt:4"}
	if len(keys) != len(want) {
		t.Fatalf("kept %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("kept %v, want %v", keys, want)
		}
	}
}

// An evicted record's dedup key must be released, or a recurring event could
// never be re-buffered after its first copy was dropped.
func TestEvictionReleasesDedupKey(t *testing.T) {
	b := NewBuffer()
	b.MaxRecords(1)

	b.Enqueue(&ebpfsocv1.TelemetryRecord{DedupKey: "evt:1"})
	b.Enqueue(&ebpfsocv1.TelemetryRecord{DedupKey: "evt:2"}) // evicts evt:1
	if _, ok := b.Enqueue(&ebpfsocv1.TelemetryRecord{DedupKey: "evt:1"}); !ok {
		t.Fatal("evt:1 was refused after eviction; its dedup key was never released")
	}
}

// Under the cap, nothing is dropped — the common case must be untouched.
func TestBufferBelowCapDropsNothing(t *testing.T) {
	b := NewBuffer()
	b.MaxRecords(100)
	for i := 0; i < 50; i++ {
		b.Enqueue(&ebpfsocv1.TelemetryRecord{DedupKey: fmt.Sprintf("evt:%d", i)})
	}
	if got := b.Dropped(); got != 0 {
		t.Fatalf("Dropped = %d, want 0", got)
	}
	if got := b.PendingDepth(); got != 50 {
		t.Fatalf("PendingDepth = %d, want 50", got)
	}
}
