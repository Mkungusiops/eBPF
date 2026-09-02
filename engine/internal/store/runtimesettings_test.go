package store

import "testing"

// The ladder could be changed at runtime and was read from config at startup,
// so a reboot silently undid an operator's change. The obvious fix — "stored
// always wins" — trades that for a worse bug: a deploy that changes the
// configured ladder would then be ignored forever, which is the stale
// systemd drop-in that made this estate run an eight-day-old command line.
//
// These pin the rule that avoids both: last deliberate change wins.

func settingsStore(t *testing.T) *Store {
	t.Helper()
	st, err := New(t.TempDir() + "/rs.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestWithNoOverrideTheConfiguredValueStands(t *testing.T) {
	st := settingsStore(t)
	got, note := st.EffectiveRuntimeSetting("choke.thresholds", "20/50/120/200")
	if got != "20/50/120/200" || note != "" {
		t.Fatalf("got %q note %q, want the configured value and no note", got, note)
	}
}

func TestAnOverrideSurvivesRestartWhileTheDeployIsUnchanged(t *testing.T) {
	// The bug being fixed: an operator tightened the ladder during an incident
	// and an unattended restart loosened it again with nothing saying so.
	st := settingsStore(t)
	if err := st.PutRuntimeSetting(RuntimeSetting{
		Key: "choke.thresholds", Value: "10/20/30/40",
		ConfigAtSet: "20/50/120/200", Actor: "op-adanian",
	}); err != nil {
		t.Fatal(err)
	}
	got, note := st.EffectiveRuntimeSetting("choke.thresholds", "20/50/120/200")
	if got != "10/20/30/40" {
		t.Fatalf("got %q — the operator's change was undone by a restart", got)
	}
	if note == "" {
		t.Fatal("an override in force must be stated, or the effective ladder is unexplained")
	}
}

func TestALaterDeploySupersedesAnEarlierOverride(t *testing.T) {
	// The other half. Without this, one runtime change would pin the ladder
	// forever and every future deploy would be silently ignored.
	st := settingsStore(t)
	if err := st.PutRuntimeSetting(RuntimeSetting{
		Key: "choke.thresholds", Value: "10/20/30/40",
		ConfigAtSet: "20/50/120/200", Actor: "op-adanian",
	}); err != nil {
		t.Fatal(err)
	}
	// The deploy has since changed the configured ladder.
	got, note := st.EffectiveRuntimeSetting("choke.thresholds", "5/15/25/35")
	if got != "5/15/25/35" {
		t.Fatalf("got %q — a stale override pinned the ladder against a newer deploy", got)
	}
	if note == "" {
		t.Fatal("a superseded override must be reported, not dropped in silence")
	}
}

func TestNeverSetIsDistinctFromSetToTheSameValue(t *testing.T) {
	// An override equal to the configured value produces no note, because
	// there is nothing to explain — but it must still be stored, so a later
	// deploy can tell it apart from "never touched".
	st := settingsStore(t)
	if err := st.PutRuntimeSetting(RuntimeSetting{
		Key: "k", Value: "same", ConfigAtSet: "same",
	}); err != nil {
		t.Fatal(err)
	}
	if got, note := st.EffectiveRuntimeSetting("k", "same"); got != "same" || note != "" {
		t.Fatalf("got %q note %q", got, note)
	}
	if _, err := st.RuntimeSettingFor("k"); err != nil {
		t.Fatalf("the override was not stored: %v", err)
	}
	if _, err := st.RuntimeSettingFor("never-set"); err == nil {
		t.Fatal("a key that was never set must be distinguishable from one set to an empty value")
	}
}
