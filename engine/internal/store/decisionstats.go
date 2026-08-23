package store

import (
	"time"
)

// DecisionStats is a server-computed count of enforcement decisions in a
// window, broken down by action, with the preceding window for a real delta.
//
// WHY THIS EXISTS. The console's "Response actions" cell counted rows in a
// browser buffer capped at 200 (MAX_BUFFERED_DECISIONS), filtered to the
// selected window. On a busy host those 200 rows span only a few minutes, so
// every window at least that long reported exactly 200 — the fetch limit
// rendered as a measurement, on the executive band, beside numbers that were
// genuine. Measured on the live engine 2026-08-21: a 200-row fetch covered
// seven minutes, and the 5m tile read "200 containment decisions".
//
// This is the same defect AlertStats was built to fix for alerts, and the same
// fix: ship counts rather than rows, so the cost is constant in the window
// length rather than linear, and the number is a total rather than a floor.
//
// Decisions are never pruned by retention (deleting the record of what the
// platform did to a host is not a disk-space decision), so this is the one
// aggregation here that can be trusted arbitrarily far back.
type DecisionStats struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Total in [From, To).
	Total int `json:"total"`
	// Total in the immediately preceding window of equal length.
	Previous int `json:"previous"`
	// Per-action counts for the current window. Every ladder action is present
	// even at zero, so the console never has to distinguish "none" from
	// "missing" — the same rule AlertStats follows for severities.
	Actions map[string]int `json:"actions"`
	// Decisions recorded but not executed because the gateway was in dry-run.
	// Counted separately: a dry-run decision is evidence of what WOULD have
	// happened, and reporting it as a response action taken would overstate
	// what the platform actually did.
	DryRun int `json:"dry_run"`
}

// decisionActions is the fixed key set — the four ladder transitions the
// gateway can record. Matches circuit.Action.String().
var decisionActions = []string{"throttle", "tarpit", "quarantine", "sever"}

func newActionCounts() map[string]int {
	m := make(map[string]int, len(decisionActions))
	for _, a := range decisionActions {
		m[a] = 0
	}
	return m
}

// DecisionStats aggregates [from, to) into a total, per-action counts and the
// preceding window's total.
//
// Three indexed aggregates, no row transfer. The decisions table is indexed on
// timestamp (see the migrate() in decisions.go).
func (s *Store) DecisionStats(from, to time.Time) (*DecisionStats, error) {
	if to.Before(from) {
		from, to = to, from
	}
	out := &DecisionStats{
		From:    from,
		To:      to,
		Actions: newActionCounts(),
	}

	rows, err := s.db.Query(rewriteParams(s.dialect, `
		-- dry_run is INTEGER on both dialects, and Postgres will not accept an
		-- integer where it wants a boolean predicate. The explicit <> 0 is
		-- portable to SQLite and Postgres alike.
		SELECT action, COUNT(*), SUM(CASE WHEN dry_run <> 0 THEN 1 ELSE 0 END)
		FROM decisions WHERE timestamp >= ? AND timestamp < ?
		GROUP BY action`), from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var action string
		var n int
		// SUM over an empty group is NULL in SQL; a nullable scan target keeps
		// that from failing the whole query.
		var dry *int
		if err := rows.Scan(&action, &n, &dry); err != nil {
			return nil, err
		}
		// An action this build does not know about is still counted in the
		// total. Dropping it would make the parts disagree with the whole,
		// which is exactly the class of defect this file exists to remove.
		if _, known := out.Actions[action]; known || action != "" {
			out.Actions[action] += n
		}
		out.Total += n
		if dry != nil {
			out.DryRun += *dry
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The preceding window of equal length, so the console's delta compares
	// like with like rather than against zero.
	width := to.Sub(from)
	if err := s.db.QueryRow(rewriteParams(s.dialect, `
		SELECT COUNT(*) FROM decisions WHERE timestamp >= ? AND timestamp < ?`),
		from.Add(-width), from).Scan(&out.Previous); err != nil {
		return nil, err
	}
	return out, nil
}
