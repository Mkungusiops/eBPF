// Package uplink turns the agent's local records (internal/store types) into
// wire-contract telemetry and buffers them for resumable, at-least-once delivery
// to the control plane. It is the agent-side implementation of the delivery
// semantics in docs/plan/wire-contract.md §4.
//
// STRANGLER / autonomy note (Phase 1, Deliverable 2): this is NEW code, not a
// refactor of cmd/engine. It has no network dependency and does not touch the
// enforcement path — enqueuing telemetry can never block or affect containment
// (the autonomy moat, architecture.md §6). The gRPC client that drains a Buffer
// onto TelemetryService is wired when the ingest collector exists (Deliverable 3);
// until then this package is exercised in isolation by its tests.
//
// TENANCY: nothing here carries a tenant_id. Tenant identity is derived from the
// agent's mTLS client certificate at the collector (tenant-isolation-invariant.md
// R1 / Layer 2); the records this package emits deliberately have no tenant field.
package uplink

import (
	"fmt"
	"sync"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// Dedup-key prefixes. Keys are agent-assigned and STABLE across resends so the
// collector can dedup on (agent_id-from-cert, dedup_key) and a replay after a
// reconnect never double-counts (wire-contract.md §4; threat-model.md CH-3).
// The local store's autoincrement ID is a stable, per-agent-unique basis.
const (
	keyPrefixEvent    = "evt:"
	keyPrefixAlert    = "alt:"
	keyPrefixDecision = "dec:"
)

// EventRecord converts a stored process event into a telemetry record.
func EventRecord(e *store.Event) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{
		DedupKey: fmt.Sprintf("%s%d", keyPrefixEvent, e.ID),
		Payload: &ebpfsocv1.TelemetryRecord_Event{Event: &ebpfsocv1.ProcessEvent{
			OccurredAt: timestamppb.New(e.Timestamp),
			EventType:  e.EventType,
			Pid:        e.PID,
			ParentPid:  e.ParentPID,
			ExecId:     e.ExecID,
			Binary:     e.Binary,
			Args:       e.Args,
			Uid:        e.UID,
			PolicyName: e.PolicyName,
		}},
	}
}

// AlertRecord converts a stored alert into a telemetry record.
func AlertRecord(a *store.Alert) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{
		DedupKey: fmt.Sprintf("%s%d", keyPrefixAlert, a.ID),
		Payload: &ebpfsocv1.TelemetryRecord_Alert{Alert: &ebpfsocv1.Alert{
			OccurredAt:  timestamppb.New(a.Timestamp),
			Severity:    a.Severity,
			Title:       a.Title,
			Description: a.Description,
			ExecId:      a.ExecID,
			Score:       int32(a.Score),
		}},
	}
}

// DecisionRecord converts a stored enforcement decision into a telemetry
// record. Every field that feeds the audit chain hash is carried verbatim (see
// the Decision message in proto/ebpfsoc/v1/common.proto) so the central mirror
// can re-verify the tamper-evident chain per tenant — including the hex-encoded
// prev_hash/hash exactly as stored. The chain is never recomputed or modified
// here; this is a faithful copy.
func DecisionRecord(d *store.Decision) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{
		DedupKey: fmt.Sprintf("%s%d", keyPrefixDecision, d.ID),
		Payload: &ebpfsocv1.TelemetryRecord_Decision{Decision: &ebpfsocv1.Decision{
			Id:                d.ID,
			OccurredAt:        timestamppb.New(d.Timestamp),
			Action:            d.Action,
			FromState:         d.FromState,
			ToState:           d.ToState,
			ExecId:            d.ExecID,
			Pid:               d.PID,
			Binary:            d.Binary,
			Score:             int32(d.Score),
			Reason:            d.Reason,
			DryRun:            d.DryRun,
			Backend:           d.Backend,
			Outcome:           d.Outcome,
			OriginKind:        d.OriginKind,
			OriginIp:          d.OriginIP,
			OriginPort:        uint32(d.OriginPort),
			OriginUser:        d.OriginUser,
			OriginFingerprint: d.OriginFingerprint,
			DeviceMac:         d.DeviceMAC,
			DeviceId:          d.DeviceID,
			PrevHash:          d.PrevHash,
			Hash:              d.Hash,
		}},
	}
}

// Buffer is a resumable, in-order outbound queue of telemetry records — the
// in-memory core of the agent's offline buffer (architecture.md §2: "the local
// SQLite WAL becomes a durable queue"). A durable, store-backed implementation
// reuses these same semantics; the persistence seam is intentionally small.
//
// Semantics (wire-contract.md §4):
//   - Enqueue assigns a monotonic sequence and retains the record until acked.
//   - NextBatch returns the oldest un-acked records WITHOUT removing them, so a
//     reconnect simply re-sends the same batch — idempotent because each record
//     carries a stable dedup key (server-side dedup makes the resend harmless).
//   - Ack(throughSeq) is cumulative: it frees every record up to that sequence,
//     matching TelemetryAck.acked_through_seq. On reconnect the agent resumes
//     from the last acked sequence.
//   - PendingDepth is the un-acked count reported as heartbeat buffer_depth.
//
// It is safe for concurrent use.
type Buffer struct {
	mu      sync.Mutex
	nextSeq uint64
	items   []item
	// pending guards against buffering the same dedup key twice while it is
	// still un-acked (belt-and-suspenders alongside server-side dedup). Keys
	// are pruned as records are acked, so this stays bounded.
	pending map[string]struct{}
	// maxRecords caps the un-acked backlog. See MaxRecords.
	maxRecords int
	// dropped counts records evicted by the cap since the process started. It
	// is never reset: a fleet that lost telemetry must keep saying so.
	dropped uint64
}

// DefaultMaxRecords caps the un-acked backlog an agent will hold.
//
// This buffer was previously UNBOUNDED: Enqueue appended without limit, so an
// agent whose control plane could not ack grew in memory for as long as the
// outage lasted. On 2026-08-05 the control plane was unable to serve or ingest
// for ~3.5 hours; these agents survived it (they buffered and drained on
// recovery), but the failure mode scales the wrong way — a longer outage, or a
// busier host, ends in the OOM killer, which loses the entire backlog rather
// than the oldest part of it.
//
// A bounded buffer trades the oldest records for the agent's survival, and
// counts what it traded. 200k records is minutes-to-hours of a normal host's
// telemetry at a few MB of memory, and is the amount worth keeping when the
// alternative is keeping none.
const DefaultMaxRecords = 200_000

type item struct {
	seq uint64
	rec *ebpfsocv1.TelemetryRecord
}

// NewBuffer returns an empty Buffer. Sequences start at 1 (0 means "nothing
// acked yet" for a peer that has never received an ack).
func NewBuffer() *Buffer {
	return &Buffer{nextSeq: 1, pending: make(map[string]struct{}), maxRecords: DefaultMaxRecords}
}

// MaxRecords sets the un-acked backlog cap. A value <= 0 restores the default.
// Intended for tests and for hosts tuned away from the default.
func (b *Buffer) MaxRecords(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n <= 0 {
		n = DefaultMaxRecords
	}
	b.maxRecords = n
}

// Dropped returns how many records the cap has evicted since start. Non-zero
// means this agent's telemetry has holes, which an operator must be able to
// learn — silently losing security telemetry is worse than reporting a gap.
func (b *Buffer) Dropped() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

// Enqueue appends rec and returns its assigned sequence. If a record with the
// same dedup key is already buffered un-acked, it is ignored and ok is false.
func (b *Buffer) Enqueue(rec *ebpfsocv1.TelemetryRecord) (seq uint64, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, dup := b.pending[rec.GetDedupKey()]; dup {
		return 0, false
	}
	seq = b.nextSeq
	b.nextSeq++
	b.items = append(b.items, item{seq: seq, rec: rec})
	b.pending[rec.GetDedupKey()] = struct{}{}
	b.evictLocked()
	return seq, true
}

// evictLocked drops the OLDEST records once the backlog exceeds the cap.
//
// Oldest-first is the deliberate choice: during an outage the newest telemetry
// is the most operationally useful, and the oldest is the most likely to be
// stale by the time anyone can act on it. Every eviction is counted, and its
// dedup key released so the record can be re-enqueued if it recurs.
//
// Caller must hold b.mu.
func (b *Buffer) evictLocked() {
	excess := len(b.items) - b.maxRecords
	if excess <= 0 {
		return
	}
	for _, it := range b.items[:excess] {
		delete(b.pending, it.rec.GetDedupKey())
	}
	b.items = append(b.items[:0], b.items[excess:]...)
	b.dropped += uint64(excess)
}

// NextBatch returns up to maxRecords oldest un-acked records as a batch whose
// agent_seq is the highest sequence it contains, or nil when nothing is pending.
// Records are NOT removed — they remain until Ack — so calling NextBatch again
// after a failed send re-returns the same batch (resumable, idempotent).
func (b *Buffer) NextBatch(maxRecords int) *ebpfsocv1.TelemetryBatch {
	b.mu.Lock()
	defer b.mu.Unlock()
	if maxRecords <= 0 || len(b.items) == 0 {
		return nil
	}
	n := maxRecords
	if n > len(b.items) {
		n = len(b.items)
	}
	recs := make([]*ebpfsocv1.TelemetryRecord, n)
	for i := 0; i < n; i++ {
		recs[i] = b.items[i].rec
	}
	return &ebpfsocv1.TelemetryBatch{
		AgentSeq: b.items[n-1].seq,
		Records:  recs,
	}
}

// Ack frees every record with sequence <= throughSeq (cumulative) and returns
// how many were freed. A stale or duplicate ack (throughSeq below the current
// floor) frees nothing.
func (b *Buffer) Ack(throughSeq uint64) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	cut := 0
	for cut < len(b.items) && b.items[cut].seq <= throughSeq {
		delete(b.pending, b.items[cut].rec.GetDedupKey())
		cut++
	}
	if cut == 0 {
		return 0
	}
	// Retain only the un-acked tail.
	b.items = append(b.items[:0], b.items[cut:]...)
	return cut
}

// PendingDepth returns the number of un-acked records (heartbeat buffer_depth).
func (b *Buffer) PendingDepth() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}
