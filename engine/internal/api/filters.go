package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// Server-side filtering for /api/alerts and /api/events.
//
// # Why this exists
//
// The assistant's list_alerts and list_events tools ADVERTISE these parameters
// to the model: severity, host, exec_id, binary, policy, free text, since. The
// handlers read none of them. Every one was accepted, ignored, and answered
// with the unfiltered newest-N — measured on the live engine, `since` set to a
// date a year in the FUTURE returned fifty alerts.
//
// That is not a missing feature, it is the tool contract lying. The model asks
// for "critical alerts on web-01 since 10:00", receives fifty alerts of every
// severity from any time, and narrates them as though they were filtered. The
// provenance trace shows the filtered URL, so an analyst checking the work sees
// exactly what they expected to see. internal/assistant/tools_soc.go already
// carries a long comment about this happening once with alert_statistics'
// `span`: "no amount of prompting can fix it and the trace looks correct."
//
// Filtering in the STORE would be better for large windows and is the eventual
// shape. It is done here, over the rows the handler already loaded, because
// that is a change confined to the read path with no schema or query-plan risk
// — and because the honesty problem is urgent while the performance one is not.
// The bound is unchanged: callers still get at most `limit` rows, they are just
// now the right ones.

// alertFilter is the parsed query for /api/alerts.
type alertFilter struct {
	severity string
	host     string
	execID   string
	q        string
	since    time.Time
}

func parseAlertFilter(r *http.Request) alertFilter {
	q := r.URL.Query()
	return alertFilter{
		severity: strings.ToLower(strings.TrimSpace(q.Get("severity"))),
		host:     strings.TrimSpace(q.Get("host")),
		execID:   strings.TrimSpace(q.Get("exec_id")),
		q:        strings.ToLower(strings.TrimSpace(q.Get("q"))),
		since:    parseSince(q.Get("since")),
	}
}

func (f alertFilter) active() bool {
	return f.severity != "" || f.host != "" || f.execID != "" || f.q != "" || !f.since.IsZero()
}

func (f alertFilter) match(a store.Alert) bool {
	if f.severity != "" && !strings.EqualFold(a.Severity, f.severity) {
		return false
	}
	if f.execID != "" && a.ExecID != f.execID {
		return false
	}
	if !f.since.IsZero() && a.Timestamp.Before(f.since) {
		return false
	}
	// Host is accepted but this deployment is single-host: every alert belongs
	// to this engine. Matching it against the engine's own identity would be
	// answering a question the caller did not ask, so an explicit host that is
	// not this host matches NOTHING rather than everything — a filter that
	// silently widens is the defect this file exists to remove.
	if f.host != "" && !strings.EqualFold(f.host, localHostLabel) {
		return false
	}
	if f.q != "" {
		hay := strings.ToLower(a.Title + " " + a.Description)
		if !strings.Contains(hay, f.q) {
			return false
		}
	}
	return true
}

// eventFilter is the parsed query for /api/events.
type eventFilter struct {
	host   string
	binary string
	policy string
	q      string
	since  time.Time
}

func parseEventFilter(r *http.Request) eventFilter {
	q := r.URL.Query()
	return eventFilter{
		host:   strings.TrimSpace(q.Get("host")),
		binary: strings.TrimSpace(q.Get("binary")),
		policy: strings.TrimSpace(q.Get("policy")),
		q:      strings.ToLower(strings.TrimSpace(q.Get("q"))),
		since:  parseSince(q.Get("since")),
	}
}

func (f eventFilter) active() bool {
	return f.host != "" || f.binary != "" || f.policy != "" || f.q != "" || !f.since.IsZero()
}

func (f eventFilter) match(e store.Event) bool {
	if f.binary != "" && e.Binary != f.binary {
		return false
	}
	if f.policy != "" && !strings.EqualFold(e.PolicyName, f.policy) {
		return false
	}
	if !f.since.IsZero() && e.Timestamp.Before(f.since) {
		return false
	}
	if f.host != "" && !strings.EqualFold(f.host, localHostLabel) {
		return false
	}
	if f.q != "" {
		hay := strings.ToLower(e.Binary + " " + e.Args)
		if !strings.Contains(hay, f.q) {
			return false
		}
	}
	return true
}

// localHostLabel is what a caller may name to mean "this engine".
//
// A single-tenant engine has exactly one host, and it does not know its own
// fleet name. Accepting these two spellings covers the useful case without
// pretending to a fleet-wide index this deployment does not have.
const localHostLabel = "local"

// parseSince reads an RFC3339 timestamp, returning the zero time when absent or
// unreadable.
//
// Unreadable is treated as ABSENT rather than as an error, deliberately: this is
// the read path for a live console, and refusing a dashboard poll over a
// malformed timestamp is worse than serving the unfiltered window. The tool
// layer validates before it ever reaches here, so a bad value means a hand-typed
// URL, not the assistant.
func parseSince(raw string) time.Time {
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

// filterAlerts applies f, preserving order and the caller's limit.
func filterAlerts(in []store.Alert, f alertFilter, limit int) []store.Alert {
	if !f.active() {
		return in
	}
	out := make([]store.Alert, 0, len(in))
	for _, a := range in {
		if f.match(a) {
			out = append(out, a)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// filterEvents applies f, preserving order and the caller's limit.
func filterEvents(in []store.Event, f eventFilter, limit int) []store.Event {
	if !f.active() {
		return in
	}
	out := make([]store.Event, 0, len(in))
	for _, e := range in {
		if f.match(e) {
			out = append(out, e)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// overFetch is how many rows to load before filtering.
//
// A filtered request still has to return up to `limit` MATCHING rows, so the
// handler must read past the newest `limit` to find them — otherwise
// "severity=critical" over a window whose newest fifty rows are all medium
// returns nothing and reads as "there are no criticals". Bounded rather than
// unbounded: this is a scan, and an unbounded one on a live console is the
// shape that has already taken a control plane down here.
func overFetch(limit, cap int) int {
	n := limit * 20
	if n > cap {
		n = cap
	}
	if n < limit {
		n = limit
	}
	return n
}
