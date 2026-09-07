package controlplane

import (
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

// A TARGETED ladder is not the tenant's policy.
//
// handleChokeThresh stores an untargeted ladder as the tenant's, so an agent
// enrolling tomorrow inherits it instead of the deploy default. A ladder aimed
// at two hosts must NOT be stored: the operator changed two hosts, and writing
// it as policy hands the same thresholds to every agent that enrols afterwards
// — the opposite of the scope they asked for.
//
// The failure is silent. The write succeeds either way, the response looks the
// same to a reader who ignores stored_for_tenant, and the damage only shows up
// when a new agent starts on thresholds nobody chose for it. So the test has to
// watch the store itself, through the storeTenantThresholds seam, rather than
// infer from the response.

// captureThresholdStore swaps the tenant-policy store for a recorder and
// restores it afterwards.
func captureThresholdStore(t *testing.T, ok bool) *[]circuit.Config {
	t.Helper()
	writes := []circuit.Config{}
	restore := storeTenantThresholds
	storeTenantThresholds = func(_ *Server, _ string, cfg circuit.Config, _, _ string) (bool, error) {
		writes = append(writes, cfg)
		return ok, nil
	}
	t.Cleanup(func() { storeTenantThresholds = restore })
	return &writes
}

func TestATargetedLadderIsNeverStoredAsTheTenantsPolicy(t *testing.T) {
	s := targetingServer(t)
	writes := captureThresholdStore(t, true)

	code, body := fleetWrite(t, s, s.handleChokeThresh, "PUT", "/api/fleet/thresholds?tenant=acme",
		map[string]any{"throttle_at": 20, "tarpit_at": 50, "quarantine_at": 120, "sever_at": 200,
			"reason": "agent-a runs a noisy build", "targets": []string{"agent-a"}})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	if len(*writes) != 0 {
		t.Fatalf("a ladder aimed at agent-a was stored as tenant policy (%v) — every agent that enrols "+
			"next will inherit thresholds that were only ever meant for one host", *writes)
	}
	// And the response says so, rather than letting the console imply the
	// tenant's ladder moved.
	if stored, _ := body["stored_for_tenant"].(bool); stored {
		t.Fatalf("stored_for_tenant reported true for a targeted write: %v", body)
	}
	// The hosts named still got the ladder — refusing to store it is not
	// refusing to apply it.
	if n := s.dispatcher.Pending("agent-a"); n != 1 {
		t.Fatalf("agent-a has %d queued commands, want the targeted ladder", n)
	}
	if n := s.dispatcher.Pending("agent-b"); n != 0 {
		t.Fatalf("the targeted ladder reached agent-b (%d queued)", n)
	}
}

func TestAnUntargetedLadderIsStoredAsTheTenantsPolicy(t *testing.T) {
	s := targetingServer(t)
	writes := captureThresholdStore(t, true)

	code, body := fleetWrite(t, s, s.handleChokeThresh, "PUT", "/api/fleet/thresholds?tenant=acme",
		map[string]any{"throttle_at": 20, "tarpit_at": 50, "quarantine_at": 120, "sever_at": 200,
			"reason": "fleet ladder"})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	if len(*writes) != 1 {
		t.Fatalf("a fleet-wide ladder was applied but not stored (%d store calls) — the next agent to "+
			"enrol starts on the deployed default", len(*writes))
	}
	if got := (*writes)[0]; got.SeverAt != 200 || got.ThrottleAt != 20 {
		t.Fatalf("stored %+v, want the ladder the operator sent", got)
	}
	if stored, _ := body["stored_for_tenant"].(bool); !stored {
		t.Fatalf("the ladder was stored and the response denies it: %v", body)
	}
}

// TestStoredForTenantIsFalseWhenThereIsNowhereToStoreIt. A deployment with no
// central store cannot make a ladder the tenant's policy, and must not claim it
// did — "applied to 3 agents" and "this is the tenant's ladder now" are
// different claims, and only one of them survives a new enrolment.
func TestStoredForTenantIsFalseWhenThereIsNowhereToStoreIt(t *testing.T) {
	s := targetingServer(t)
	captureThresholdStore(t, false) // the store declines, as a Postgres-less deploy does

	_, body := fleetWrite(t, s, s.handleChokeThresh, "PUT", "/api/fleet/thresholds?tenant=acme",
		map[string]any{"throttle_at": 20, "tarpit_at": 50, "quarantine_at": 120, "sever_at": 200,
			"reason": "fleet ladder"})
	if stored, _ := body["stored_for_tenant"].(bool); stored {
		t.Fatalf("stored_for_tenant claimed a write that never happened: %v", body)
	}
}
