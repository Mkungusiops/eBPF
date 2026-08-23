package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// Every filter the assistant ADVERTISES must actually filter.
//
// These parameters were accepted and ignored for one release: `since` set a
// year into the future returned fifty alerts. That is the tool contract lying,
// and it is worse than a missing feature — the model narrows the question, gets
// an unfiltered answer, and the provenance trace shows the narrowed URL, so an
// analyst checking the work sees exactly what they expect to see.

var base = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func alerts() []store.Alert {
	return []store.Alert{
		{Timestamp: base, Severity: "critical", Title: "curl pipe to shell", Description: "chain", ExecID: "e1"},
		{Timestamp: base.Add(-2 * time.Hour), Severity: "medium", Title: "file read", Description: "/etc/passwd", ExecID: "e2"},
		{Timestamp: base.Add(-4 * time.Hour), Severity: "high", Title: "setuid", Description: "privilege escalation", ExecID: "e3"},
	}
}

func events() []store.Event {
	return []store.Event{
		{Timestamp: base, Binary: "/usr/bin/curl", Args: "-fsSL https://x", PolicyName: ""},
		{Timestamp: base.Add(-2 * time.Hour), Binary: "/bin/bash", Args: "-c id", PolicyName: "privilege-escalation"},
		{Timestamp: base.Add(-4 * time.Hour), Binary: "/bin/cat", Args: "/etc/shadow", PolicyName: "sensitive-file-access"},
	}
}

func filterFor(t *testing.T, query string) alertFilter {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/alerts?"+query, nil)
	return parseAlertFilter(r)
}

func eventFilterFor(t *testing.T, query string) eventFilter {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/events?"+query, nil)
	return parseEventFilter(r)
}

func TestAlertSeverityFilterActuallyFilters(t *testing.T) {
	got := filterAlerts(alerts(), filterFor(t, "severity=critical"), 50)
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("severity=critical returned %d rows: %+v", len(got), got)
	}
}

func TestAlertSinceFilterActuallyFilters(t *testing.T) {
	// The measured failure: a future timestamp returned everything.
	future := base.Add(24 * time.Hour).Format(time.RFC3339)
	if got := filterAlerts(alerts(), filterFor(t, "since="+future), 50); len(got) != 0 {
		t.Fatalf("since=<tomorrow> returned %d alerts; nothing has happened yet", len(got))
	}
	recent := base.Add(-time.Hour).Format(time.RFC3339)
	if got := filterAlerts(alerts(), filterFor(t, "since="+recent), 50); len(got) != 1 {
		t.Fatalf("since=<1h ago> returned %d alerts, want 1", len(got))
	}
}

func TestAlertExecIDAndTextFiltersActuallyFilter(t *testing.T) {
	if got := filterAlerts(alerts(), filterFor(t, "exec_id=e3"), 50); len(got) != 1 || got[0].ExecID != "e3" {
		t.Fatalf("exec_id returned %+v", got)
	}
	if got := filterAlerts(alerts(), filterFor(t, "q=privilege"), 50); len(got) != 1 {
		t.Fatalf("free text returned %d rows", len(got))
	}
	if got := filterAlerts(alerts(), filterFor(t, "q=zzzznomatch"), 50); len(got) != 0 {
		t.Fatalf("a term matching nothing returned %d rows", len(got))
	}
}

// A host this engine is not must match NOTHING. Silently widening to "all
// alerts" is the exact behaviour being removed.
func TestAlertHostFilterDoesNotSilentlyWiden(t *testing.T) {
	if got := filterAlerts(alerts(), filterFor(t, "host=some-other-box"), 50); len(got) != 0 {
		t.Fatalf("host=<not this engine> returned %d alerts", len(got))
	}
	if got := filterAlerts(alerts(), filterFor(t, "host=local"), 50); len(got) != 3 {
		t.Fatalf("host=local returned %d alerts, want all 3", len(got))
	}
}

func TestEventFiltersActuallyFilter(t *testing.T) {
	if got := filterEvents(events(), eventFilterFor(t, "binary=/bin/bash"), 50); len(got) != 1 {
		t.Fatalf("binary returned %d rows", len(got))
	}
	if got := filterEvents(events(), eventFilterFor(t, "policy=sensitive-file-access"), 50); len(got) != 1 {
		t.Fatalf("policy returned %d rows", len(got))
	}
	if got := filterEvents(events(), eventFilterFor(t, "q=shadow"), 50); len(got) != 1 {
		t.Fatalf("free text returned %d rows", len(got))
	}
	future := base.Add(24 * time.Hour).Format(time.RFC3339)
	if got := filterEvents(events(), eventFilterFor(t, "since="+future), 50); len(got) != 0 {
		t.Fatalf("since=<tomorrow> returned %d events", len(got))
	}
}

// No filter must behave exactly as before: the whole set, untouched.
func TestNoFilterIsUnchanged(t *testing.T) {
	if got := filterAlerts(alerts(), filterFor(t, ""), 50); len(got) != 3 {
		t.Fatalf("an unfiltered request returned %d of 3 alerts", len(got))
	}
	if got := filterEvents(events(), eventFilterFor(t, ""), 50); len(got) != 3 {
		t.Fatalf("an unfiltered request returned %d of 3 events", len(got))
	}
}

// The limit is still the caller's bound after filtering.
func TestFilteringRespectsTheLimit(t *testing.T) {
	if got := filterAlerts(alerts(), filterFor(t, "host=local"), 2); len(got) != 2 {
		t.Fatalf("limit=2 returned %d rows", len(got))
	}
}

// Over-fetch must stay bounded — an unbounded scan on a live console is the
// shape that has already taken a control plane down here.
func TestOverFetchIsBounded(t *testing.T) {
	if got := overFetch(200, 2000); got > 2000 {
		t.Fatalf("over-fetch %d exceeds its cap", got)
	}
	if got := overFetch(5000, 2000); got != 5000 {
		t.Fatalf("over-fetch must never return fewer than the limit, got %d", got)
	}
}
