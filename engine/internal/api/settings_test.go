package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// A settings surface's failure mode is saving something and not applying it.
// These pin the properties that make it honest.

type fakeReloader struct {
	got  []store.Suppression
	hits map[int64]int64
}

func (f *fakeReloader) SetSuppressions(r []store.Suppression) { f.got = r }
func (f *fakeReloader) SuppressionHits() map[int64]int64      { return f.hits }

func settingsServer(t *testing.T) (*Server, *store.Store, *fakeReloader) {
	t.Helper()
	st, err := store.New(t.TempDir() + "/s.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := &fakeReloader{hits: map[int64]int64{}}
	prev := suppressionSink
	suppressionSink = f
	t.Cleanup(func() { suppressionSink = prev })
	return &Server{store: st, auth: &Auth{}}, st, f
}

func post(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleSettingsSuppressions(rec, httptest.NewRequest(http.MethodPost, "/api/settings/suppressions", strings.NewReader(body)))
	return rec
}

func TestAddingASuppressionReachesTheRunningScorer(t *testing.T) {
	// The whole point. A suppression that persists and does not apply until a
	// restart is a setting that looks like it worked and did nothing.
	s, _, f := settingsServer(t)

	rec := post(t, s, `{"binary":"/opt/backup/agent","reason":"our backup agent reads credential paths"}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(f.got) != 1 || f.got[0].Binary != "/opt/backup/agent" {
		t.Fatalf("the live scorer was not updated: %+v", f.got)
	}
}

func TestASuppressionIsAudited(t *testing.T) {
	// Narrowing what the platform detects is what an attacker with console
	// access would want to do quietly. It belongs in the tamper-evident chain,
	// not a log line.
	s, st, _ := settingsServer(t)
	post(t, s, `{"binary":"/opt/backup/agent","reason":"expected on this estate"}`)

	rows, err := st.RecentDecisions(10)
	if err != nil {
		t.Fatal(err)
	}
	var found *store.Decision
	for i := range rows {
		if rows[i].Action == "suppression-add" {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatal("adding a suppression wrote no audit row")
	}
	if found.Hash == "" {
		t.Error("the row is not hash-chained, so it is not tamper-evident")
	}
	if !strings.Contains(found.ToState, "/opt/backup/agent") {
		t.Errorf("the row must name what was suppressed, got %q", found.ToState)
	}
}

func TestRemovingSomethingThatWasNeverThereIsNotSuccess(t *testing.T) {
	// "Removed" about a rule that never existed is the small lie that makes an
	// operator stop trusting the surface.
	s, _, _ := settingsServer(t)
	rec := httptest.NewRecorder()
	s.handleSettingsSuppressions(rec, httptest.NewRequest(http.MethodDelete, "/api/settings/suppressions?id=999", nil))
	if rec.Code == 200 {
		t.Fatal("deleting a non-existent suppression reported success")
	}
}

func TestHitsAreAbsentRatherThanZeroWhenUnknown(t *testing.T) {
	// A zero next to a rule reads as "this rule does nothing" and invites
	// deleting a rule that may be working. Unknown must not render as zero —
	// the same discipline the sensor-health panel uses for evidence loss.
	s, _, f := settingsServer(t)
	post(t, s, `{"binary":"/opt/backup/agent","reason":"expected"}`)
	f.hits = nil // pipeline present but reporting nothing

	rec := httptest.NewRecorder()
	s.handleSettingsSuppressions(rec, httptest.NewRequest(http.MethodGet, "/api/settings/suppressions", nil))
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)

	if got["hits_known"] != false {
		t.Fatalf("hits_known = %v, want false", got["hits_known"])
	}
	list := got["suppressions"].([]any)
	if _, present := list[0].(map[string]any)["hits"]; present {
		t.Error("hits must be ABSENT when unknown, not 0")
	}
}

func TestTheResponseStatesWhatASuppressionDoesNotDo(t *testing.T) {
	// An operator reasonably reads "suppress" as "this host stops watching
	// that binary". It does not: only the score is withheld.
	s, _, _ := settingsServer(t)
	rec := httptest.NewRecorder()
	s.handleSettingsSuppressions(rec, httptest.NewRequest(http.MethodGet, "/api/settings/suppressions", nil))
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	effect, _ := got["effect"].(string)
	for _, want := range []string{"still recorded", "contained by hand"} {
		if !strings.Contains(effect, want) {
			t.Errorf("the effect note should mention %q, got %q", want, effect)
		}
	}
}

// The candidate list must not offer things the engine already ignores.
//
// Measured on the live estate, raw volume ranking put the auth stack on top —
// sshd-session 64,612 events, sudo 38,301, unix_chkpwd 11,726 — every one of
// which the scorer already suppresses. Offering them gains the operator
// nothing and invites a broad rule on sshd that reads like disabling detection
// on the login path.
func TestCandidatesExcludeWhatTheScorerAlreadyIgnores(t *testing.T) {
	in := []store.SuppressionCandidate{
		{Binary: "/usr/lib/openssh/sshd-session", Policy: "sensitive-file-access", Events: 64612},
		{Binary: "/usr/sbin/unix_chkpwd", Policy: "sensitive-file-access", Events: 11726},
		{Binary: "/opt/backup/agent", Policy: "sensitive-file-access", Events: 4120},
	}
	got := withoutAlreadyHandled(in, 8)

	for _, c := range got {
		if strings.Contains(c.Binary, "sshd") || strings.Contains(c.Binary, "unix_chkpwd") {
			t.Errorf("%q is already suppressed by the scorer and must not be offered", c.Binary)
		}
	}
	if len(got) != 1 || got[0].Binary != "/opt/backup/agent" {
		t.Fatalf("the genuinely actionable candidate was lost: %+v", got)
	}
}

func TestCandidateFilterTrimsToTheRequestedCount(t *testing.T) {
	// Over-fetching then filtering is what lets the list stay full after the
	// already-handled ones are dropped; without the trim it would return all
	// of them.
	in := make([]store.SuppressionCandidate, 0, 20)
	for i := 0; i < 20; i++ {
		in = append(in, store.SuppressionCandidate{Binary: "/opt/app", Policy: "outbound-connections", Events: i})
	}
	if got := withoutAlreadyHandled(in, 8); len(got) != 8 {
		t.Fatalf("got %d candidates, want 8", len(got))
	}
}

// The page must not suggest a rule its own validator would reject, or one that
// can only ever fire once. Both of these turn up on a real host.
func TestCandidatesExcludePathsThatCannotBeMatched(t *testing.T) {
	in := []store.SuppressionCandidate{
		{Binary: "/proc/self/fd/9", Policy: "sensitive-file-access", Events: 1787},
		{Binary: "/usr/lib/systemd/systemd-logind (deleted)", Policy: "sensitive-file-access", Events: 3268},
		{Binary: "/usr/bin/runc", Policy: "sensitive-file-access", Events: 13948},
	}
	got := withoutAlreadyHandled(in, 8)
	if len(got) != 1 || got[0].Binary != "/usr/bin/runc" {
		t.Fatalf("unsuppressable paths were offered: %+v", got)
	}
}
