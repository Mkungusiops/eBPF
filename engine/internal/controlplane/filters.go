package controlplane

import (
	"net/http"
	"strings"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
)

// Server-side filtering for the tenant-scoped /api/alerts and /api/events.
//
// The same defect as internal/api/filters.go and for the same reason: the
// assistant's tools advertise severity / host / exec_id / binary / policy /
// free-text / since, and these handlers read none of them. Measured live on
// this control plane — `since` a year in the future returned fifty alerts.
//
// A filter that is accepted and ignored is worse than one that is refused. The
// model believes it narrowed the question, the answer is narrated as narrow,
// and the provenance trace shows the narrow URL, so the analyst checking the
// work sees exactly what they expect.
//
// FILTERING NEVER WIDENS SCOPE. It runs over rows the tenant predicate has
// already returned, so it can only ever remove rows from a set the caller was
// entitled to. `host` here means the AGENT, which on this deployment is a real
// field and a real question — unlike the single-tenant engine, where there is
// only one host.

type cpAlertFilter struct {
	severity string
	agent    string
	execID   string
	q        string
	since    time.Time
}

func parseCPAlertFilter(r *http.Request) cpAlertFilter {
	q := r.URL.Query()
	return cpAlertFilter{
		severity: strings.ToLower(strings.TrimSpace(q.Get("severity"))),
		agent:    strings.TrimSpace(q.Get("host")),
		execID:   strings.TrimSpace(q.Get("exec_id")),
		q:        strings.ToLower(strings.TrimSpace(q.Get("q"))),
		since:    parseCPSince(q.Get("since")),
	}
}

func (f cpAlertFilter) active() bool {
	return f.severity != "" || f.agent != "" || f.execID != "" || f.q != "" || !f.since.IsZero()
}

func (f cpAlertFilter) match(agentID string, a *ebpfsocv1.Alert, at time.Time) bool {
	if a == nil {
		return false
	}
	if f.severity != "" && !strings.EqualFold(a.GetSeverity(), f.severity) {
		return false
	}
	if f.agent != "" && !strings.EqualFold(agentID, f.agent) {
		return false
	}
	if f.execID != "" && a.GetExecId() != f.execID {
		return false
	}
	if !f.since.IsZero() && at.Before(f.since) {
		return false
	}
	if f.q != "" {
		if !strings.Contains(strings.ToLower(a.GetTitle()+" "+a.GetDescription()), f.q) {
			return false
		}
	}
	return true
}

type cpEventFilter struct {
	agent  string
	binary string
	policy string
	q      string
	since  time.Time
}

func parseCPEventFilter(r *http.Request) cpEventFilter {
	q := r.URL.Query()
	return cpEventFilter{
		agent:  strings.TrimSpace(q.Get("host")),
		binary: strings.TrimSpace(q.Get("binary")),
		policy: strings.TrimSpace(q.Get("policy")),
		q:      strings.ToLower(strings.TrimSpace(q.Get("q"))),
		since:  parseCPSince(q.Get("since")),
	}
}

func (f cpEventFilter) active() bool {
	return f.agent != "" || f.binary != "" || f.policy != "" || f.q != "" || !f.since.IsZero()
}

func (f cpEventFilter) match(agentID string, e *ebpfsocv1.ProcessEvent, at time.Time) bool {
	if e == nil {
		return false
	}
	if f.agent != "" && !strings.EqualFold(agentID, f.agent) {
		return false
	}
	if f.binary != "" && e.GetBinary() != f.binary {
		return false
	}
	if f.policy != "" && !strings.EqualFold(e.GetPolicyName(), f.policy) {
		return false
	}
	if !f.since.IsZero() && at.Before(f.since) {
		return false
	}
	if f.q != "" {
		if !strings.Contains(strings.ToLower(e.GetBinary()+" "+e.GetArgs()), f.q) {
			return false
		}
	}
	return true
}

// parseCPSince mirrors the engine's: unreadable is treated as absent, because
// refusing a console poll over a malformed timestamp is worse than serving the
// unfiltered window. The tool layer validates before this is ever reached.
func parseCPSince(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

// cpOverFetch is how many rows to read before filtering, so a narrow filter
// over a busy tenant still finds its matches instead of reporting none.
//
// Capped hard. An unbounded scan over `telemetry` is the exact shape that took
// this control plane down on 2026-08-05.
func cpOverFetch(limit int, active bool) int {
	if !active {
		return limit
	}
	n := limit * 20
	if n > 4000 {
		n = 4000
	}
	if n < limit {
		n = limit
	}
	return n
}

// rowAt is the timestamp a filter compares against, preferring the record's own
// occurred-at over the ingest time.
func rowAt(row centralstore.Row, occurred time.Time) time.Time {
	if !occurred.IsZero() {
		return occurred
	}
	return row.At
}
