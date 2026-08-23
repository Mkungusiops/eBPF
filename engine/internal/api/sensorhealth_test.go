package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The trust surface is the worst possible place to round an unknown up to a
// reassuring number. These pin what it must never claim.

func sensorHealth(t *testing.T) map[string]any {
	t.Helper()
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleSensorHealth(rec, httptest.NewRequest(http.MethodGet, "/api/sensor-health", nil))
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad JSON: %v — %s", err, rec.Body.String())
	}
	return got
}

func TestSensorHealthNeverClaimsNoEvidenceLost(t *testing.T) {
	// The control plane reports dropped_records from agent heartbeats. The
	// engine has no such counter, and a zero would assert that nothing has
	// been lost — a claim this build cannot support. Absent, not zero.
	got := sensorHealth(t)
	if _, present := got["dropped_records"]; present {
		t.Fatal("dropped_records must be ABSENT, not zero — this build cannot measure evidence loss")
	}
	if got["evidence_loss_known"] != false {
		t.Fatalf("evidence_loss_known should say plainly that it is unknown, got %v", got["evidence_loss_known"])
	}
}

func TestSensorHealthDoesNotReportMissingWhenTheKernelIsUnreadable(t *testing.T) {
	// In a test environment `docker exec tetragon` fails, so the kernel is
	// unreadable. "Missing" and "unknown" are different answers: listing every
	// expected policy as missing would raise a false coverage alarm on a host
	// that may be perfectly covered.
	got := sensorHealth(t)
	agents, _ := got["agents"].([]any)
	if len(agents) != 1 {
		t.Fatalf("expected exactly one agent (this host), got %d", len(agents))
	}
	a := agents[0].(map[string]any)

	if a["kernel_observable"] != false {
		t.Skip("this machine can reach a Tetragon container; the unreadable-kernel path is not exercised here")
	}
	missing, _ := a["missing_policies"].([]any)
	if len(missing) != 0 {
		t.Fatalf("kernel unreadable, yet %d policies reported missing: %v", len(missing), missing)
	}
	// Status is NOT asserted to be "unknown" here. A definite failure outranks
	// an uncertainty: in this environment Tetragon is also unreachable, which
	// is known-bad, and reporting "unknown" would understate it. What must
	// hold is that the uncertainty is still SAID, so nobody reads a clean
	// coverage figure off a host whose kernel could not be read.
	// Issues carry a code alongside the prose now, so the console can attach a
	// remedy to each finding instead of leaving the operator to infer one.
	issues, _ := a["issues"].([]any)
	var saidUnknown bool
	for _, raw := range issues {
		i, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("issue is %T, want an object with code and detail", raw)
		}
		if contains(i["detail"].(string), "coverage on this host is unknown") {
			saidUnknown = true
			if i["code"] != "kernel-unreadable" {
				t.Errorf("code = %v, want kernel-unreadable — the console keys its remedy off this", i["code"])
			}
		}
	}
	if !saidUnknown {
		t.Fatalf("the unreadable kernel must be stated in issues, got %v", issues)
	}
}

// With the kernel readable and everything else healthy, an unreadable-kernel
// caveat must NOT appear — the honest-uncertainty path must not be permanently
// on, or it becomes noise nobody reads.
func TestSensorHealthStatusIsUnknownOnlyForUncertainty(t *testing.T) {
	got := sensorHealth(t)
	agents, _ := got["agents"].([]any)
	a := agents[0].(map[string]any)
	if a["kernel_observable"] == true && a["status"] == "unknown" {
		t.Fatal("the kernel was readable, so the status must be a definite answer, not unknown")
	}
}

func TestSensorHealthStatesItsScopeIsOneHost(t *testing.T) {
	// The same 1/1 that means "coverage estimate" on the control plane means
	// "this machine" here. Without saying so, an operator reads full estate
	// coverage off a single-host console.
	got := sensorHealth(t)
	caveat, _ := got["coverage_caveat"].(string)
	if caveat == "" {
		t.Fatal("a coverage caveat is required — 1/1 is otherwise read as estate coverage")
	}
	for _, want := range []string{"ONE host", "invisible"} {
		if !contains(caveat, want) {
			t.Fatalf("caveat %q should mention %q", caveat, want)
		}
	}
}

func contains(h, n string) bool {
	return len(h) >= len(n) && (func() bool {
		for i := 0; i+len(n) <= len(h); i++ {
			if h[i:i+len(n)] == n {
				return true
			}
		}
		return false
	})()
}

// ── Enforcement posture ──────────────────────────────────────────────────────
//
// The panel's status was computed from detection facts alone: kernel readable,
// policies loaded, Tetragon up. No branch read an enforcement mechanism, so a
// host reported a green "ok" while saying nothing about whether it could
// contain anything at all.

func hasCode(list []issue, code string) bool {
	for _, i := range list {
		if i.Code == code {
			return true
		}
	}
	return false
}

func healthyPosture() SystemInfo {
	return SystemInfo{
		ChokeDryRun:     func() bool { return false },
		ChokeKillSwitch: func() bool { return false },
		ChokeAutoMode:   func() string { return "detect-only" },
		CgroupAvailable: func() bool { return true },
		CgroupDegraded:  func() []string { return nil },
	}
}

func TestAManualSeverStillLandsInDetectOnly(t *testing.T) {
	// The most damaging thing this panel could say is that an operator's own
	// containment action will not work, when it will. The gateway routes a
	// manual action through the real enforcer even in detect-only; only
	// dry-run and the kill-switch stop it. An earlier draft of this feature
	// was going to claim the opposite.
	c, issues, notes := assessContainment(healthyPosture())

	if !c.ManualLands {
		t.Fatal("a detect-only host must still report that a pressed action lands")
	}
	if c.Kill != capYes {
		t.Fatalf("kill = %q, want yes — SIGKILL does not depend on the ladder being armed", c.Kill)
	}
	if hasCode(issues, noteManualOnly) {
		t.Fatal("detect-only must not be raised as a fault — it is the documented safe default")
	}
	if !hasCode(notes, noteManualOnly) {
		t.Fatal("...but it must be STATED: silence reads as 'the ladder will contain for you'")
	}
}

func TestDryRunIsAFaultBecauseEvenAPressedActionIsShadow(t *testing.T) {
	info := healthyPosture()
	info.ChokeDryRun = func() bool { return true }
	c, issues, _ := assessContainment(info)

	if c.ManualLands || c.Verdict != "none" {
		t.Fatalf("dry-run must read as nothing-lands, got manual=%v verdict=%q", c.ManualLands, c.Verdict)
	}
	if !hasCode(issues, issueContainmentShadowed) {
		t.Fatal("dry-run must be a fault: the operator's own action does nothing")
	}
}

func TestARefusedKernelLimitIsAFault(t *testing.T) {
	// True on every host on this estate today: choke-quarantined/cpu.max is
	// written as 100µs, below the kernel's 1ms floor, so every kernel refuses
	// it. Logged once at boot and surfaced nowhere until now.
	info := healthyPosture()
	info.CgroupDegraded = func() []string { return []string{"choke-quarantined/cpu.max: invalid argument"} }
	c, issues, _ := assessContainment(info)

	if !hasCode(issues, issueEnforcementDegraded) {
		t.Fatal("a kernel-refused limit must be raised")
	}
	if c.Verdict != "partial-degraded" {
		t.Fatalf("verdict = %q, want partial-degraded", c.Verdict)
	}
	if c.Freeze == capNo {
		t.Fatal("a refused CPU cap must not be reported as freeze being gone — quarantine still freezes")
	}
}

func TestAnAbsentNetworkPlaneIsANoteNotAFault(t *testing.T) {
	// No deploy path on this estate ships choke.o. Alarming on an intended
	// configuration trains operators to ignore the panel.
	info := healthyPosture()
	info.BPFBackend = "noop"
	_, issues, notes := assessContainment(info)

	if hasCode(issues, noteNoNetworkChoke) {
		t.Fatal("an undeployed optional plane must not be a fault")
	}
	if !hasCode(notes, noteNoNetworkChoke) {
		t.Fatal("...but it must be stated: throttle and tarpit do not touch the network")
	}
}

func TestATcPlaneAttachedToNothingIsAFault(t *testing.T) {
	// The failure that looks healthy: a loaded program with zero links.
	info := healthyPosture()
	info.DevicePlane = func() string { return "tc" }
	info.DeviceLinks = func() int { return 0 }
	_, issues, _ := assessContainment(info)

	if !hasCode(issues, issueDevicePlaneDetached) {
		t.Fatal("tc with zero links must be raised — it records and touches nothing")
	}
}

func TestUnreadablePostureNeverReadsAsFull(t *testing.T) {
	// Nil closures mean this deployment cannot tell. An unmeasured mechanism
	// must never be counted as a working one.
	c, _, _ := assessContainment(SystemInfo{})
	if c.Verdict == "full" {
		t.Fatalf("verdict = full on a deployment that could read nothing: %+v", c)
	}
}
