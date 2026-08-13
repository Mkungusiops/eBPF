package store

import (
	"time"
)

// AlertStats is a server-computed summary of a time window: how many alerts of
// each severity, the same for the immediately preceding window (so a delta is a
// real comparison), and the window split into equal buckets for the timeline.
//
// WHY THIS EXISTS. The console used to compute every one of these numbers in
// the browser, by filtering a buffer of the most recent N alerts. That works
// only while the buffer spans the selected window — and it does not: at this
// fleet's alert rate a 1000-alert buffer covers roughly twenty minutes, so the
// 30m, 60m and 24h ranges were computed from a fraction of their own window and
// presented as totals. The "vs prior" deltas were worse than incomplete: the
// preceding window fell entirely outside the buffer, so `previous` was zero and
// every delta printed as the full current count (+313 vs prior 24h).
//
// A browser cannot hold a day of telemetry, so the aggregation belongs where
// the data is. This ships counts, not rows: the cost is constant in the window
// length instead of linear.
type AlertStats struct {
	From     time.Time      `json:"from"`
	To       time.Time      `json:"to"`
	Counts   map[string]int `json:"counts"`
	Previous map[string]int `json:"previous"`
	Total    int            `json:"total"`
	Buckets  []AlertBucket  `json:"buckets"`
}

// AlertBucket is one timeline column: the alerts that fall in [At, At+width).
type AlertBucket struct {
	At     time.Time      `json:"at"`
	Counts map[string]int `json:"counts"`
	Total  int            `json:"total"`
}

// severities is the fixed key set. Every map is populated for all of them so
// the console never has to distinguish "zero" from "absent".
var severities = []string{"critical", "high", "medium", "low", "info"}

func newCounts() map[string]int {
	m := make(map[string]int, len(severities))
	for _, s := range severities {
		m[s] = 0
	}
	return m
}

// AlertStats aggregates the window [from, to) into severity counts, the same
// for the preceding window of equal length, and `buckets` equal-width columns.
//
// Three indexed aggregate queries, no row transfer. The alerts table carries
// severity as a column and is indexed on timestamp, so the database does this
// work directly (see idx_alerts_timestamp).
func (s *Store) AlertStats(from, to time.Time, buckets int) (*AlertStats, error) {
	if buckets < 1 {
		buckets = 1
	}
	out := &AlertStats{
		From:     from,
		To:       to,
		Counts:   newCounts(),
		Previous: newCounts(),
		Buckets:  make([]AlertBucket, buckets),
	}

	if err := s.countBySeverity(from, to, out.Counts); err != nil {
		return nil, err
	}
	for _, n := range out.Counts {
		out.Total += n
	}

	// The preceding window of equal length, so "vs prior" compares like with
	// like rather than against whatever happened to be in a buffer.
	span := to.Sub(from)
	if err := s.countBySeverity(from.Add(-span), from, out.Previous); err != nil {
		return nil, err
	}

	width := span / time.Duration(buckets)
	if width <= 0 {
		width = time.Nanosecond
	}
	for i := range out.Buckets {
		out.Buckets[i] = AlertBucket{At: from.Add(time.Duration(i) * width), Counts: newCounts()}
	}

	// One pass over the window's severities+timestamps to fill the buckets.
	// Only two columns are read; the payload never leaves the database.
	rows, err := s.db.Query(rewriteParams(s.dialect, `
		SELECT timestamp, severity FROM alerts WHERE timestamp >= ? AND timestamp < ?`), from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ts time.Time
		var sev string
		if err := rows.Scan(&ts, &sev); err != nil {
			return nil, err
		}
		idx := int(ts.Sub(from) / width)
		if idx < 0 {
			idx = 0
		}
		if idx >= buckets {
			idx = buckets - 1
		}
		if _, known := out.Buckets[idx].Counts[sev]; !known {
			sev = "info" // an unknown severity is still an alert; never drop it
		}
		out.Buckets[idx].Counts[sev]++
		out.Buckets[idx].Total++
	}
	return out, rows.Err()
}

func (s *Store) countBySeverity(from, to time.Time, into map[string]int) error {
	rows, err := s.db.Query(rewriteParams(s.dialect, `
		SELECT severity, COUNT(*) FROM alerts
		WHERE timestamp >= ? AND timestamp < ? GROUP BY severity`), from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return err
		}
		if _, known := into[sev]; !known {
			sev = "info"
		}
		into[sev] += n
	}
	return rows.Err()
}
