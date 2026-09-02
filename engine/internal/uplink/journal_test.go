package uplink

import (
	"testing"

	"google.golang.org/protobuf/proto"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// The backlog lived in memory only, while architecture.md described a durable
// queue and this package left the seam for one. On a healthy link that costs
// seconds of telemetry; during a control-plane outage — the case the buffer
// exists for — a restart lost everything the agent held. Every deploy restarts
// every agent, and containment decisions are in that backlog.

// memJournal is a durable store that survives a "restart" in a test.
type memJournal struct {
	rows    map[uint64][]byte
	appends int
	failOn  uint64 // seq whose Append fails
}

func newMemJournal() *memJournal { return &memJournal{rows: map[uint64][]byte{}} }

func (m *memJournal) Append(seq uint64, _ string, payload []byte) error {
	m.appends++
	if seq == m.failOn {
		return errFail
	}
	m.rows[seq] = payload
	return nil
}

func (m *memJournal) DeleteThrough(seq uint64) error {
	for k := range m.rows {
		if k <= seq {
			delete(m.rows, k)
		}
	}
	return nil
}

func (m *memJournal) Load() ([]JournalEntry, error) {
	var out []JournalEntry
	for seq := uint64(1); seq <= 10_000; seq++ { // ordered, oldest first
		if p, ok := m.rows[seq]; ok {
			out = append(out, JournalEntry{Seq: seq, Payload: p})
		}
	}
	return out, nil
}

type failErr struct{}

func (failErr) Error() string { return "journal unavailable" }

var errFail = failErr{}

func jrec(key string) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{DedupKey: key}
}

func TestUnackedRecordsSurviveARestart(t *testing.T) {
	j := newMemJournal()
	b := NewBuffer()
	b.SetJournal(j)
	for _, k := range []string{"a", "b", "c"} {
		b.Enqueue(rec(k))
	}

	// The control plane acked the first only. A restart must not lose b and c.
	b.Ack(1)

	restarted := NewBuffer()
	restarted.SetJournal(j)
	n, err := restarted.Restore()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("restored %d records, want the 2 un-acked ones", n)
	}
	batch := restarted.NextBatch(10)
	if batch == nil || len(batch.GetRecords()) != 2 {
		t.Fatalf("the resumed buffer has nothing to send")
	}
	if batch.GetRecords()[0].GetDedupKey() != "b" {
		t.Fatalf("resumed out of order: first is %q, want b", batch.GetRecords()[0].GetDedupKey())
	}
}

func TestSequencingContinuesAfterARestart(t *testing.T) {
	// Restarting the counter at 1 would re-issue sequence numbers the control
	// plane has already acked, so its CUMULATIVE ack would silently discard
	// fresh records as replays.
	j := newMemJournal()
	b := NewBuffer()
	b.SetJournal(j)
	for _, k := range []string{"a", "b", "c"} {
		b.Enqueue(rec(k))
	}

	restarted := NewBuffer()
	restarted.SetJournal(j)
	if _, err := restarted.Restore(); err != nil {
		t.Fatal(err)
	}
	seq, ok := restarted.Enqueue(jrec("d"))
	if !ok {
		t.Fatal("could not enqueue after restore")
	}
	if seq <= 3 {
		t.Fatalf("new record got seq %d, which the control plane may already have acked", seq)
	}
}

func TestAckedRecordsAreNotReplayed(t *testing.T) {
	j := newMemJournal()
	b := NewBuffer()
	b.SetJournal(j)
	b.Enqueue(jrec("a"))
	b.Enqueue(jrec("b"))
	b.Ack(2) // both acked

	restarted := NewBuffer()
	restarted.SetJournal(j)
	n, _ := restarted.Restore()
	if n != 0 {
		t.Fatalf("restored %d acked records — the agent would resend what the CP already has", n)
	}
}

func TestEvictedRecordsAreDroppedFromTheJournalToo(t *testing.T) {
	// Otherwise the journal grows without bound while memory is capped, and a
	// restart resurrects records the cap deliberately discarded.
	j := newMemJournal()
	b := NewBuffer()
	b.SetJournal(j)
	b.MaxRecords(2)
	for _, k := range []string{"a", "b", "c", "d"} {
		b.Enqueue(rec(k))
	}
	if got := len(j.rows); got != 2 {
		t.Fatalf("journal holds %d rows, want the 2 the cap allows", got)
	}
}

func TestAJournalFailureNeverBlocksTelemetry(t *testing.T) {
	// The record is already in memory and about to be sent. Refusing it
	// because the note about it could not be written would turn a degraded
	// guarantee into a lost event.
	j := newMemJournal()
	j.failOn = 1
	b := NewBuffer()
	b.SetJournal(j)
	if _, ok := b.Enqueue(jrec("a")); !ok {
		t.Fatal("a journal write failure rejected the record")
	}
	if b.PendingDepth() != 1 {
		t.Fatal("the record is not in the send queue")
	}
}

func TestWithNoJournalNothingChanges(t *testing.T) {
	b := NewBuffer()
	b.Enqueue(jrec("a"))
	n, err := b.Restore()
	if err != nil || n != 0 {
		t.Fatalf("restore on a journal-less buffer: n=%d err=%v", n, err)
	}
	if b.PendingDepth() != 1 {
		t.Fatal("the in-memory behaviour changed")
	}
}

func TestACorruptJournalEntryIsSkippedNotFatal(t *testing.T) {
	// Refusing to start because one row will not parse would turn a lost
	// record into an agent that never sends anything again.
	j := newMemJournal()
	good, _ := proto.Marshal(jrec("good"))
	j.rows[1] = []byte{0xff, 0xff, 0xff}
	j.rows[2] = good

	b := NewBuffer()
	b.SetJournal(j)
	n, err := b.Restore()
	if err != nil {
		t.Fatalf("a corrupt entry made restore fail: %v", err)
	}
	if n != 1 {
		t.Fatalf("restored %d, want the one readable record", n)
	}
}
