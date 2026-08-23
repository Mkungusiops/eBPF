// Package findings is the bounded, in-memory record of what the enrichment
// layers have recently found — behavioural anomalies and threat-intel hits.
//
// It is its own package rather than a type inside internal/eventpipe because
// both the pipeline (which writes it) and internal/api (which reads it) need
// the type, and eventpipe already imports api for the broadcast channel. A
// shared leaf package is the only shape that does not create a cycle.
package findings

import (
	"sync"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/intel"
)

// Ring is the recent-enrichment ring the console and the assistant read.
//
// # Why a ring and not a table
//
// Anomaly reasons and indicator hits are ANNOTATIONS on events and alerts that
// are already persisted. The durable record of "this chain was novel and talked
// to a known C2 address" is the alert, whose description carries both. This
// structure exists for one narrower job: answering "what has enrichment
// actually been finding lately", which is how an operator tells a working
// detector from a silent one.
//
// Keeping it in memory and bounded is a deliberate trade. The alternative — a
// third table on the event path — buys durability for data that is a derived
// view of rows already written, at the cost of a write amplification on the one
// path whose latency is containment latency. A ring is O(1), allocation-free
// after warm-up, and loses nothing that cannot be recomputed.
//
// The bound is the point, not an implementation detail: this is fed from an
// unbounded stream, and every unbounded collector in this codebase has had to
// be bounded after the fact.

// Finding is one enrichment result worth showing an operator.
type Finding struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"` // "anomaly" | "intel"
	ExecID string    `json:"exec_id"`
	PID    uint32    `json:"pid"`
	Binary string    `json:"binary"`
	// Points is what this finding contributed to the chain score. Reported
	// because an operator comparing two findings needs to know which one moved
	// the number — and because a finding that contributed 0 (budget spent, or
	// the profile still warming) must not look like one that contributed 12.
	Points int `json:"points"`
	// Reasons are the analyst-readable explanation, already formatted.
	Reasons []string `json:"reasons,omitempty"`
	// Match is set for intel findings.
	Match *intel.Match `json:"match,omitempty"`
	// Agent names the host this came from. Empty on a sensor, where every
	// finding is by definition local; set on the control plane, where a
	// tenant-wide finding is meaningless without knowing which of the tenant's
	// hosts produced it.
	Agent string `json:"agent,omitempty"`
}

// maxFindings bounds the ring. ~2k findings is a few hundred KB and covers well
// over a day on a normal host; on an abnormal one, the newest are what matter.
const maxFindings = 2048

// FindingRing is a fixed-capacity, newest-last ring. Safe for concurrent use:
// written on the event goroutine, read by API handlers.
type Ring struct {
	mu   sync.RWMutex
	buf  []Finding
	next int
	full bool
	// counts are LIFETIME totals, which the ring itself cannot report once it
	// has wrapped. Without them "12 findings" is ambiguous between a quiet host
	// and a host whose ring turned over four times this hour.
	anomalies uint64
	intelHits uint64
}

func NewRing() *Ring { return NewRingSized(maxFindings) }

// NewRingSized returns a ring with an explicit capacity.
//
// The control plane holds one ring PER TENANT, so it needs a smaller one:
// maxFindings per tenant across the cap on profiled tenants would be a
// megabyte-scale allocation for a feature nobody had looked at yet.
func NewRingSized(n int) *Ring {
	if n <= 0 {
		n = maxFindings
	}
	return &Ring{buf: make([]Finding, n)}
}

// Add records a finding.
func (r *Ring) Add(f Finding) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = f
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
	switch f.Kind {
	case "anomaly":
		r.anomalies++
	case "intel":
		r.intelHits++
	}
}

// Recent returns up to limit findings, newest first, optionally filtered by
// kind ("" for all).
func (r *Ring) Recent(kind string, limit int) []Finding {
	if r == nil || limit <= 0 {
		return []Finding{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	n := r.next
	if r.full {
		n = len(r.buf)
	}
	out := make([]Finding, 0, limit)
	for i := 0; i < n && len(out) < limit; i++ {
		// Walk backwards from the most recently written slot.
		idx := (r.next - 1 - i + len(r.buf)) % len(r.buf)
		f := r.buf[idx]
		if f.At.IsZero() {
			continue
		}
		if kind != "" && f.Kind != kind {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Totals returns lifetime counts, which survive the ring wrapping.
func (r *Ring) Totals() (anomalies, intelHits uint64) {
	if r == nil {
		return 0, 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.anomalies, r.intelHits
}
