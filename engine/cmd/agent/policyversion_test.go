package main

import (
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

func kp(name, mode string, enabled bool) *ebpfsocv1.KernelPolicy {
	return &ebpfsocv1.KernelPolicy{Name: name, Mode: mode, Enabled: enabled}
}

// Tetragon does not promise an order. Without sorting, the same fleet-wide
// policy set fingerprints differently per host and every agent looks drifted —
// which is worse than no signal, because it trains operators to ignore it.
func TestPolicyVersionIsOrderIndependent(t *testing.T) {
	a := policyVersion([]*ebpfsocv1.KernelPolicy{
		kp("outbound-connections", "monitor", true),
		kp("sensitive-file-access", "monitor", true),
		kp("privilege-escalation", "monitor", true),
	})
	b := policyVersion([]*ebpfsocv1.KernelPolicy{
		kp("privilege-escalation", "monitor", true),
		kp("outbound-connections", "monitor", true),
		kp("sensitive-file-access", "monitor", true),
	})
	if a != b {
		t.Fatalf("same set, different order: %q vs %q", a, b)
	}
	if a == "" {
		t.Fatal("a non-empty policy set must produce a version")
	}
}

// Drift is the whole point: any difference in the effective set must change the
// fingerprint, or a host running something else looks identical to its peers.
func TestPolicyVersionDetectsDrift(t *testing.T) {
	base := []*ebpfsocv1.KernelPolicy{
		kp("outbound-connections", "monitor", true),
		kp("sensitive-file-access", "monitor", true),
	}
	v := policyVersion(base)

	cases := []struct {
		name string
		set  []*ebpfsocv1.KernelPolicy
	}{
		{"a policy went missing", base[:1]},
		{"an extra policy appeared", append(append([]*ebpfsocv1.KernelPolicy{}, base...), kp("rogue", "monitor", true))},
		// The same policies in enforce mode is a different and far more
		// dangerous posture; it must not hash the same.
		{"mode changed to enforce", []*ebpfsocv1.KernelPolicy{
			kp("outbound-connections", "enforce", true),
			kp("sensitive-file-access", "monitor", true),
		}},
		{"a policy was disabled", []*ebpfsocv1.KernelPolicy{
			kp("outbound-connections", "monitor", false),
			kp("sensitive-file-access", "monitor", true),
		}},
	}
	for _, c := range cases {
		if got := policyVersion(c.set); got == v {
			t.Fatalf("%s: fingerprint unchanged (%q) — drift would be invisible", c.name, got)
		}
	}
}

// An agent that cannot read Tetragon must report no version rather than a
// fingerprint of nothing, which would collide with every other broken agent and
// look like consensus.
func TestPolicyVersionEmptyWhenUnknown(t *testing.T) {
	if got := policyVersion(nil); got != "" {
		t.Fatalf("expected empty version for an unknown set, got %q", got)
	}
}
