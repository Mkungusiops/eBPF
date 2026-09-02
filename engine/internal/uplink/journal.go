package uplink

import (
	"log"

	"google.golang.org/protobuf/proto"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// Journal persists the un-acked backlog so a restart does not lose it.
//
// # Why this exists
//
// The Buffer held its backlog in memory only, while architecture.md §2
// described "the local SQLite WAL becomes a durable queue" and this package
// noted that "a durable, store-backed implementation reuses these same
// semantics; the persistence seam is intentionally small". The seam was left
// and the implementation never arrived.
//
// On a healthy link that costs seconds of telemetry. During an outage — the
// one situation the buffer exists for — it costs everything the agent was
// holding, and an agent restart is not a rare event: every deploy restarts
// every agent. Containment decisions are in that backlog, so the tenant's
// audit could silently lose exactly the records an incident review needs, at
// exactly the moment the control plane was unreachable.
//
// An interface rather than a concrete store, so this package keeps no
// dependency on SQLite and a deployment with no journal behaves as before.
type Journal interface {
	// Append records one enqueued record. Payload is the marshalled record.
	Append(seq uint64, dedupKey string, payload []byte) error
	// DeleteThrough removes every record at or below seq. Both acking and
	// eviction remove the OLDEST records, so one operation covers both.
	DeleteThrough(seq uint64) error
	// Load returns the surviving backlog, oldest first.
	Load() ([]JournalEntry, error)
}

// JournalEntry is one persisted record.
type JournalEntry struct {
	Seq     uint64
	Payload []byte
}

// SetJournal attaches durable storage to the buffer.
//
// Best-effort by design: a journal write that fails must never fail the
// enqueue. The record is already in memory and about to be sent, and refusing
// telemetry because the note about it could not be written would turn a
// degraded guarantee into a lost event. Failures are logged, because the
// consequence is quiet — everything works until a restart.
func (b *Buffer) SetJournal(j Journal) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.journal = j
}

// Restore reloads a persisted backlog into the buffer.
//
// Sequence numbering CONTINUES from the highest restored sequence rather than
// restarting at 1. Restarting would re-issue sequence numbers the control
// plane has already acked, so its cumulative ack watermark would silently
// discard fresh records as though they were replays.
//
// Dedup keys are preserved, which is what makes replay safe: the control plane
// dedups on (tenant, agent, dedup_key), so a record that did reach it before
// the restart is ignored rather than double-counted.
func (b *Buffer) Restore() (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.journal == nil {
		return 0, nil
	}
	entries, err := b.journal.Load()
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		rec := &ebpfsocv1.TelemetryRecord{}
		if err := proto.Unmarshal(e.Payload, rec); err != nil {
			// A corrupt row is skipped, not fatal. Refusing to start because
			// one journal entry will not parse would turn a lost record into
			// an agent that never sends anything again.
			log.Printf("[uplink] skipping unreadable journal entry seq=%d: %v", e.Seq, err)
			continue
		}
		b.items = append(b.items, item{seq: e.Seq, rec: rec})
		b.pending[rec.GetDedupKey()] = struct{}{}
		if e.Seq >= b.nextSeq {
			b.nextSeq = e.Seq + 1
		}
	}
	// The cap still applies to a restored backlog: an agent that was offline
	// for a week must not come back holding more than it is allowed to.
	b.evictLocked()
	return len(b.items), nil
}
