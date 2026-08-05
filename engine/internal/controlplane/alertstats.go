package controlplane

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
)

// Alert-window statistics for the console's KPI tiles, posture score, deltas
// and severity timeline.
//
// The console used to compute these in the browser from its buffer of recent
// alerts. That buffer spans roughly twenty minutes on a busy tenant, so every
// range above 30m was computed from a slice of itself and shown as a total —
// and the "vs prior" deltas compared against a preceding window that was never
// loaded at all, which is why a 24h view reported "+313 vs prior" when the true
// answer was unknown. Counts belong where the rows are.
//
// Unlike the single-tenant engine, the central store has no severity column:
// severity lives inside each record's protobuf payload. So this aggregates in
// Go over a TIME-BOUNDED index scan (see centralstore.RangeQuerier and the
// (tenant_id, kind, at DESC) index) rather than in SQL. Bounded by time rather
// than by row count, it cannot silently under-report the way a "newest N rows"
// read does.

type severityCounts map[string]int

var statSeverities = []string{"critical", "high", "medium", "low", "info"}

func newSeverityCounts() severityCounts {
	m := make(severityCounts, len(statSeverities))
	for _, s := range statSeverities {
		m[s] = 0
	}
	return m
}

func (c severityCounts) add(sev string) {
	if _, known := c[sev]; !known {
		sev = "info" // an unrecognised severity is still an alert; never drop it
	}
	c[sev]++
}

type alertBucket struct {
	At     time.Time      `json:"at"`
	Counts severityCounts `json:"counts"`
	Total  int            `json:"total"`
}

type alertStats struct {
	From     time.Time      `json:"from"`
	To       time.Time      `json:"to"`
	Counts   severityCounts `json:"counts"`
	Previous severityCounts `json:"previous"`
	Total    int            `json:"total"`
	Buckets  []alertBucket  `json:"buckets"`
	// Truncated reports that the window held more alerts than the scan limit,
	// so Counts is a floor. Stated rather than hidden — an under-count that
	// does not announce itself is the defect this endpoint exists to remove.
	Truncated bool `json:"truncated"`
}

// statsCacheTTL collapses duplicate work across concurrent console sessions.
// Every open tab polls this on the same cadence; without a cache, N tabs mean N
// identical scans. Short enough that the dashboard still reads as live.
const statsCacheTTL = 10 * time.Second

type statsCacheKey struct {
	tenant    string
	windowMin int
	buckets   int
}

type statsCacheEntry struct {
	at    time.Time
	stats *alertStats
}

type statsCache struct {
	mu      sync.Mutex
	entries map[statsCacheKey]statsCacheEntry
}

func (c *statsCache) get(k statsCacheKey) (*alertStats, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || time.Since(e.at) > statsCacheTTL {
		return nil, false
	}
	return e.stats, true
}

func (c *statsCache) put(k statsCacheKey, s *alertStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[statsCacheKey]statsCacheEntry)
	}
	// Drop expired entries opportunistically; the key space is small (tenants ×
	// the handful of window sizes the UI offers) so this stays bounded.
	for key, e := range c.entries {
		if time.Since(e.at) > statsCacheTTL {
			delete(c.entries, key)
		}
	}
	c.entries[k] = statsCacheEntry{at: time.Now(), stats: s}
}

// handleAlertStats serves server-computed alert counts for a window.
//
//	?window_min= window length in minutes (default 30, max 7 days)
//	?buckets=    timeline columns (default 30, max 240)
func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	windowMin := intParam(r, "window_min", 30, 60*24*7)
	buckets := intParam(r, "buckets", 30, 240)

	key := statsCacheKey{tenant: tenant, windowMin: windowMin, buckets: buckets}
	if cached, hit := s.stats.get(key); hit {
		writeJSON(w, 200, cached)
		return
	}

	ranger, canRange := s.cfg.Store.(centralstore.RangeQuerier)
	if !canRange {
		// A backend without range reads cannot answer this honestly, and
		// guessing from a row-count read is the bug this replaces.
		http.Error(w, "alert stats unsupported by this store backend", http.StatusNotImplemented)
		return
	}

	to := time.Now().UTC()
	span := time.Duration(windowMin) * time.Minute
	from := to.Add(-span)

	// One scan covering BOTH the window and the one before it, so the delta is
	// a real comparison rather than a comparison against nothing.
	const scanLimit = 200_000
	rows, err := ranger.QueryRange(centralstore.Scope{TenantID: tenant, Kind: "alert"}, from.Add(-span), to, scanLimit)
	if err != nil {
		storeQueryFailed(w, r, tenant, "alert", scanLimit, err)
		return
	}

	out := &alertStats{
		From: from, To: to,
		Counts: newSeverityCounts(), Previous: newSeverityCounts(),
		Buckets:   make([]alertBucket, buckets),
		Truncated: len(rows) >= scanLimit,
	}
	width := span / time.Duration(buckets)
	if width <= 0 {
		width = time.Nanosecond
	}
	for i := range out.Buckets {
		out.Buckets[i] = alertBucket{At: from.Add(time.Duration(i) * width), Counts: newSeverityCounts()}
	}

	for _, row := range rows {
		a := row.Record.GetAlert()
		if a == nil {
			continue
		}
		at := row.At
		if a.GetOccurredAt() != nil {
			at = a.GetOccurredAt().AsTime()
		}
		switch {
		case at.Before(from):
			out.Previous.add(a.GetSeverity())
		case at.Before(to):
			out.Counts.add(a.GetSeverity())
			out.Total++
			idx := int(at.Sub(from) / width)
			if idx < 0 {
				idx = 0
			}
			if idx >= buckets {
				idx = buckets - 1
			}
			out.Buckets[idx].Counts.add(a.GetSeverity())
			out.Buckets[idx].Total++
		}
	}

	if out.Truncated {
		slog.Warn("alert stats truncated: window holds more alerts than the scan limit",
			"tenant", tenant, "window_min", windowMin, "limit", scanLimit)
	}
	s.stats.put(key, out)
	writeJSON(w, 200, out)
}

// intParam reads a named positive integer query parameter, falling back to def
// and clamping to max.
func intParam(r *http.Request, name string, def, max int) int {
	v := def
	if q := r.URL.Query().Get(name); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			v = n
		}
	}
	if v > max {
		v = max
	}
	return v
}
