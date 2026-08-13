package heartbeat

import (
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

func TestRegistryRecordAndGet(t *testing.T) {
	r := NewRegistry()
	req := &ebpfsocv1.HeartbeatRequest{
		AgentInfo:            &ebpfsocv1.AgentInfo{AgentVersion: "0.2.0-agent", Kernel: "6.8.0"},
		DataPlane:            &ebpfsocv1.DataPlaneState{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING},
		BufferDepth:          42,
		AppliedPolicyVersion: "pol-7",
	}
	r.Record("tenant-a", "agent-1", req)

	rec, ok := r.Get("tenant-a", "agent-1")
	if !ok {
		t.Fatal("record not found")
	}
	if rec.Version != "0.2.0-agent" || rec.Kernel != "6.8.0" || rec.BufferDepth != 42 ||
		rec.AppliedPolicyVersion != "pol-7" || rec.Mode != ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING {
		t.Fatalf("record fields not mapped: %+v", rec)
	}
	if rec.LastSeen.IsZero() {
		t.Fatal("LastSeen not set")
	}
}

// TestRegistrySeparatesTenants: same agent id under two tenants are distinct
// registry entries (isolation fixture).
func TestRegistrySeparatesTenants(t *testing.T) {
	r := NewRegistry()
	r.Record("tenant-a", "agent-1", &ebpfsocv1.HeartbeatRequest{})
	r.Record("tenant-b", "agent-1", &ebpfsocv1.HeartbeatRequest{})
	if r.Count() != 2 {
		t.Fatalf("count = %d, want 2 (same agent id, different tenants must not collide)", r.Count())
	}
	if _, ok := r.Get("tenant-a", "agent-1"); !ok {
		t.Fatal("tenant-a entry missing")
	}
	if _, ok := r.Get("tenant-c", "agent-1"); ok {
		t.Fatal("unknown tenant should not be found")
	}
}

// The console reports enforcement mode from the engine's half of a host's
// posture. Tetragon is the other half and enforces independently, so these
// pin the exact condition threat-model EN-3 names: the operator is told
// "detect-only" while a kernel authority is armed to kill.
func TestKernelPostureDivergence(t *testing.T) {
	kp := func(name, mode string, enabled bool) *ebpfsocv1.KernelPolicy {
		return &ebpfsocv1.KernelPolicy{Name: name, Mode: mode, Enabled: enabled}
	}
	detect := ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY
	enforce := ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING

	cases := []struct {
		name          string
		mode          ebpfsocv1.EnforcementMode
		pols          []*ebpfsocv1.KernelPolicy
		wantEnforcing bool
		wantDiverged  bool
	}{
		{
			// The shipped posture: every policy declares policy-mode monitor, so
			// Tetragon suppresses enforcing actions in-kernel and the engine's
			// mode is the whole truth.
			name: "monitor policies do not count as a kernel authority",
			mode: detect,
			pols: []*ebpfsocv1.KernelPolicy{kp("sensitive-file-access", "monitor", true)},
		},
		{
			// The regression that cost a host lockout and three hosts of broken
			// packages: console says detect-only, kernel kills anyway.
			name:          "enforce policy while engine is detect-only is divergence",
			mode:          detect,
			pols:          []*ebpfsocv1.KernelPolicy{kp("hand-loaded", "enforce", true)},
			wantEnforcing: true,
			wantDiverged:  true,
		},
		{
			// Both authorities armed is a deliberate posture, not a lie to the
			// operator — so it is not divergence, even though it is enforcing.
			name:          "enforce policy while engine enforces is not divergence",
			mode:          enforce,
			pols:          []*ebpfsocv1.KernelPolicy{kp("hand-loaded", "enforce", true)},
			wantEnforcing: true,
		},
		{
			// A disabled policy cannot fire, so it must not raise an alarm that
			// operators would learn to dismiss.
			name: "disabled enforce policy is not armed",
			mode: detect,
			pols: []*ebpfsocv1.KernelPolicy{kp("hand-loaded", "enforce", false)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := Record{Mode: tc.mode, KernelPolicies: tc.pols}
			if got := rec.KernelEnforcing(); got != tc.wantEnforcing {
				t.Errorf("KernelEnforcing() = %v, want %v", got, tc.wantEnforcing)
			}
			if got := rec.Diverged(); got != tc.wantDiverged {
				t.Errorf("Diverged() = %v, want %v", got, tc.wantDiverged)
			}
		})
	}
}

// Enforcing actions that already fired are evidence, not risk: something was
// killed with no engine decision, so no audit row exists for it. Post actions
// are healthy detection and must never be counted as enforcement — doing so
// would make every working host look like it was killing things.
func TestKernelEnforceActionsCountsOnlyEnforcement(t *testing.T) {
	rec := Record{KernelPolicies: []*ebpfsocv1.KernelPolicy{
		{Name: "a", EnforceActions: 2, SuppressedActions: 9},
		{Name: "b", EnforceActions: 3},
		{Name: "c"},
	}}
	if got := rec.KernelEnforceActions(); got != 5 {
		t.Fatalf("KernelEnforceActions() = %d, want 5 (suppressed actions are not enforcement)", got)
	}
}

// An agent that predates the field, or cannot reach Tetragon, reports nothing.
// Silence must not read as a clean host — it is absence of evidence.
func TestNoKernelPoliciesIsNotProofOfSafety(t *testing.T) {
	rec := Record{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY}
	if rec.KernelEnforcing() || rec.Diverged() {
		t.Fatal("an agent reporting no policies must not be treated as an armed host either")
	}
	if len(rec.KernelPolicies) != 0 {
		t.Fatal("fixture should have no policies")
	}
}
