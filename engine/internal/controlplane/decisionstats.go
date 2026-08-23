package controlplane

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
)

// Enforcement-decision counts for a window — the control plane's counterpart of
// the single-tenant engine's /api/decision-stats (internal/store/decisionstats.go).
//
// WHY THIS EXISTS. Both deployments serve the SAME console bundle, and its
// "Response actions" cell asks for /api/decision-stats first. The engine grew
// the endpoint; the control plane did not, so on the multi-tenant console that
// request 404s and the cell falls back to counting the 200-row page
// /api/decisions serves, filtered to the selected window. A page size is not a
// measurement: measured on the live control plane 2026-08-22, the 200 newest
// decisions for tenant adanian-internal spanned 33 minutes, so any window at
// least that long reports exactly 200. The console marks the fallback
// "≥ … page-limited", which is honest and useless — the number an executive
// reads is still the fetch limit.
//
// NO DENORMALISED COLUMN IS NEEDED HERE, and that is a deliberate departure
// from centralstore/severity.go. Severity earned a column because a 7-day alert
// window is ~10^6 rows, which blew past the 200k scan bound and made every long
// window a floor. Decisions are a different population: one row per ladder
// transition the platform actually performed. Measured on the live store
// 2026-08-22: 431 decision rows in the entire 2,245 MB table, against 388,234
// alerts and 3,090,611 events; 216 of them for the busiest tenant, 42 kB of
// payload all-in. A 14-day read of them (the widest this handler can issue)
// plans as an index scan on telemetry_tenant_kind_at costing 195 shared buffers
// and 1.0 ms, with the RLS predicate pushed into the index condition. Decoding
// those payloads in Go is cheaper than an ALTER TABLE plus a backfill on a live
// multi-gigabyte table, and it needs no migration at all. If decision volume
// ever approaches alert volume, the answer is an `action` column built exactly
// the way severity.go builds its own — not a bigger scan bound.
//
// The read goes through centralstore.RangeQuerier with a Scope, like every
// other read in this package: no SQL lives here (the Layer-3 bypass lint in
// internal/isolationguard forbids it), the scope cannot be empty (ErrNoScope
// fails closed), and on Postgres the query runs inside the RLS transaction that
// supplies the tenant predicate.
type decisionStats struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Total in [From, To).
	Total int `json:"total"`
	// Total in the immediately preceding window of equal length, so the
	// console's delta compares like with like rather than against zero.
	Previous int `json:"previous"`
	// Per-action counts for the current window. Every ladder action is present
	// even at zero, so the console never has to distinguish "none" from
	// "missing" — the rule alertStats already follows for severities.
	Actions map[string]int `json:"actions"`
	// Decisions recorded but not executed because the gateway was in dry-run.
	// Counted separately: reporting a dry-run decision as a response action
	// taken would overstate what the platform actually did.
	DryRun int `json:"dry_run"`
	// Truncated reports that the window held more decisions than the scan
	// bound, so Total is a floor. Stated rather than hidden — an under-count
	// that does not announce itself is the defect this endpoint exists to
	// remove, and shipping one unmarked would just move the lie server-side.
	Truncated bool `json:"truncated"`
}

// decisionLadder is the fixed key set — the four ladder transitions the gateway
// records. Mirrors store.decisionActions on the engine, so both deployments
// answer with the same shape.
var decisionLadder = []string{"throttle", "tarpit", "quarantine", "sever"}

func newDecisionActions() map[string]int {
	m := make(map[string]int, len(decisionLadder))
	for _, a := range decisionLadder {
		m[a] = 0
	}
	return m
}

// decisionScanLimit bounds one window read. Two orders of magnitude above the
// whole fleet's all-time decision count (431 rows, measured), so a truncation
// means the workload has changed shape and Truncated is the signal to add the
// column rather than to raise this number.
const decisionScanLimit = 50_000

// handleDecisionStats serves server-computed enforcement-decision counts.
//
//	?window_min= window length in minutes (default 30, max 7 days)
//	?tenant=     optional; defaults to the operator's primary tenant
func (s *Server) handleDecisionStats(w http.ResponseWriter, r *http.Request) {
	// Layer-4 authorization, and a denial is a 404 so the caller cannot learn
	// whether another tenant exists (§6 side channels).
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	windowMin := intParam(r, "window_min", 30, 60*24*7)
	to := time.Now().UTC()
	span := time.Duration(windowMin) * time.Minute
	from := to.Add(-span)

	ranger, canRange := s.cfg.Store.(centralstore.RangeQuerier)
	if !canRange {
		// A backend that cannot bound a read by time cannot answer this
		// honestly, and guessing from a newest-N read is the bug being fixed.
		// 501 rather than 404 so the logs distinguish "this build has no
		// endpoint" from "this backend cannot serve it"; the console's fallback
		// is the same either way.
		http.Error(w, "decision stats unsupported by this store backend", http.StatusNotImplemented)
		return
	}

	// ONE read covering the window AND the one before it, so the delta is a
	// real comparison rather than a comparison against nothing.
	rows, err := ranger.QueryRange(
		centralstore.Scope{TenantID: tenant, Kind: "decision"},
		from.Add(-span), to, decisionScanLimit)
	if err != nil {
		storeQueryFailed(w, r, tenant, "decision", decisionScanLimit, err)
		return
	}

	out := &decisionStats{
		From: from, To: to,
		Actions:   newDecisionActions(),
		Truncated: len(rows) >= decisionScanLimit,
	}
	for _, row := range rows {
		d := row.Record.GetDecision()
		if d == nil {
			continue
		}
		// Rows are SELECTED by ingest time and CLASSIFIED by occurrence, so
		// this tile agrees with the ledger beneath it (/api/decisions renders
		// occurred_at). An agent replaying its WAL after an outage can carry an
		// old decision into this read; discarding the ones that predate even
		// the comparison window keeps a replay from inflating Previous and
		// inverting the trend arrow.
		at := row.At
		if d.GetOccurredAt() != nil {
			at = d.GetOccurredAt().AsTime()
		}
		switch {
		case at.Before(from.Add(-span)):
			continue
		case at.Before(from):
			out.Previous++
		case at.Before(to):
			out.Total++
			// An action this build does not know about is still counted in the
			// total AND gets its own key. Dropping it would make the parts
			// disagree with the whole, which is the class of defect this file
			// exists to remove.
			if a := d.GetAction(); a != "" {
				out.Actions[a]++
			}
			if d.GetDryRun() {
				out.DryRun++
			}
		}
	}

	if out.Truncated {
		slog.Warn("decision stats truncated: window holds more decisions than the scan bound",
			"tenant", tenant, "window_min", windowMin, "limit", decisionScanLimit)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}
