package controlplane

import "testing"

// A preset is a ladder change, and it lasts exactly as long as one.
//
// handleChokeThresh reports `stored_for_tenant`, and the console reads it to
// warn that a ladder aimed at named hosts is not the tenant's policy and will
// be pushed back over those hosts by reconcileLadders within about two
// minutes. A preset moves the same thresholds on the same agents through the
// same reconciler — and this handler's response said nothing at all, so the
// operator saw "Containment applied", then saw containment come off, with
// nothing anywhere connecting the two.
//
// The two writes now answer the same question with the same key, so the
// console can treat them identically instead of carrying a durability warning
// for one of them and silence for the other.

func TestPresetReportsItsDurabilityLikeTheLadderDoes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"targeted", map[string]any{"name": "containment", "reason": "IR-4821", "targets": []string{"agent-a"}}},
		{"untargeted", map[string]any{"name": "default", "reason": "routine"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := targetingServer(t)
			code, body := fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme", tc.body)
			if code != 200 {
				t.Fatalf("status %d: %v", code, body)
			}
			stored, ok := body["stored_for_tenant"]
			if !ok {
				t.Fatalf("the preset response carries no stored_for_tenant, so the console cannot tell "+
					"an operator that the reconciler will undo this: %v", body)
			}
			asBool, isBool := stored.(bool)
			if !isBool {
				t.Fatalf("stored_for_tenant = %#v, want a boolean — the console reads this field "+
					"strictly and treats anything else as no statement at all", stored)
			}
			// False, and truthfully so: nothing in this handler writes the
			// preset's ladder to the tenant's policy, so claiming otherwise
			// would be the same untrue reading pointed the other way.
			if asBool {
				t.Fatalf("stored_for_tenant claimed the preset became the tenant's policy; nothing "+
					"here stores it: %v", body)
			}
		})
	}
}

// The durability fact is an ADDITION. A response that lost a key the console
// already summarises renders "0/0 hosts succeeded" in a green toast, which is
// how this handler's last defect showed up.
func TestPresetKeepsEveryKeyTheConsoleAlreadyReads(t *testing.T) {
	s := targetingServer(t)
	code, body := fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
		map[string]any{"name": "containment", "reason": "IR-4821", "targets": []string{"agent-a"}})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	for _, key := range []string{"ok", "preset", "applied", "total", "detail", "hosts"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("the response dropped the existing %q key: %v", key, body)
		}
	}
}
