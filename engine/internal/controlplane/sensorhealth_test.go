package controlplane

import "testing"

// The agent has fingerprinted its kernel policy set on every heartbeat since
// the field existed, and nothing rendered it — so a host that quietly lost a
// detection looked identical to one with nothing to report.
func TestDriftIsCountedAcrossFreshAgents(t *testing.T) {
	agents := []sensorAgent{
		{AgentID: "a", Fresh: true, PolicyVersion: "aaa"},
		{AgentID: "b", Fresh: true, PolicyVersion: "aaa"},
		{AgentID: "c", Fresh: true, PolicyVersion: "bbb"},
	}
	got := driftVersions(agents)
	if len(got) != 2 {
		t.Fatalf("distinct versions = %d, want 2 — these hosts run different detections", len(got))
	}
	if got["aaa"] != 2 || got["bbb"] != 1 {
		t.Fatalf("counts wrong: %v", got)
	}
}

// A stale row's fingerprint describes whatever it was running when it stopped
// reporting. Folding it in would report drift that may have healed, or hide
// drift that has not.
func TestStaleAgentsDoNotVoteOnDrift(t *testing.T) {
	agents := []sensorAgent{
		{AgentID: "a", Fresh: true, PolicyVersion: "aaa"},
		{AgentID: "b", Fresh: false, PolicyVersion: "ancient"},
	}
	got := driftVersions(agents)
	if len(got) != 1 {
		t.Fatalf("distinct versions = %d, want 1 — a stale agent must not create drift", len(got))
	}
}

// An agent that has not reported a fingerprint contributes nothing rather than
// an empty-string "version" that would look like a third detection set.
func TestMissingFingerprintIsNotAVersion(t *testing.T) {
	got := driftVersions([]sensorAgent{{AgentID: "a", Fresh: true, PolicyVersion: ""}})
	if len(got) != 0 {
		t.Fatalf("got %v, want no versions", got)
	}
}
