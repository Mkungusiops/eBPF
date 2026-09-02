package store

import (
	"path/filepath"
	"testing"
	"time"
)

// The candidate query is the whole reason the settings page is usable: without
// it an operator faces an empty text field asking for an absolute path they do
// not know. The first version referenced a `score` column that does not exist
// on events and a `ts` column that is actually `timestamp`. It errored, the
// caller swallowed the error, and the page reported "nothing noisy here" on a
// host producing thousands of findings.
func TestCandidatesActuallyQueryTheSchema(t *testing.T) {
	st, err := New(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		if _, err := st.InsertEvent(&Event{
			Timestamp: now, EventType: "process_kprobe", Binary: "/opt/backup/agent",
			PolicyName: "sensitive-file-access", ExecID: "e1",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.InsertEvent(&Event{
		Timestamp: now, EventType: "process_kprobe", Binary: "/usr/bin/quiet",
		PolicyName: "privilege-escalation", ExecID: "e2",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := st.SuppressionCandidates(now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("the candidate query does not match the schema: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no candidates from a store with scored kprobe events")
	}
	// Noisiest first — that is the ordering the page depends on.
	if got[0].Binary != "/opt/backup/agent" || got[0].Events != 5 {
		t.Fatalf("expected the noisiest binary first, got %+v", got[0])
	}
}

func TestCandidatesSkipEventsWithNoDetection(t *testing.T) {
	// A bare exec with no policy attached is not something anyone would think
	// to suppress; offering it is noise on the page meant to reduce noise.
	st, _ := New(filepath.Join(t.TempDir(), "c.db"))
	defer st.Close()
	now := time.Now().UTC()
	_, _ = st.InsertEvent(&Event{Timestamp: now, EventType: "process_exec", Binary: "/bin/ls", ExecID: "e3"})

	got, err := st.SuppressionCandidates(now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if c.Binary == "/bin/ls" {
			t.Fatal("an event with no detection was offered as a candidate")
		}
	}
}

func TestAlreadySuppressedCandidatesAreMarked(t *testing.T) {
	// Re-offering a binary the operator has already handled makes the list
	// look like nothing happened.
	st, _ := New(filepath.Join(t.TempDir(), "c.db"))
	defer st.Close()
	now := time.Now().UTC()
	_, _ = st.InsertEvent(&Event{Timestamp: now, EventType: "process_kprobe",
		Binary: "/opt/backup/agent", PolicyName: "sensitive-file-access", ExecID: "e1"})
	if _, err := st.AddSuppression(&Suppression{
		Binary: "/opt/backup/agent", Policy: "sensitive-file-access", Reason: "expected here",
	}); err != nil {
		t.Fatal(err)
	}

	got, _ := st.SuppressionCandidates(now.Add(-time.Hour), 10)
	if len(got) == 0 || !got[0].Suppressed {
		t.Fatalf("an already-suppressed candidate was not marked: %+v", got)
	}
}
