package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

func presetGateway(t *testing.T) *choke.Gateway {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "preset.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return choke.NewGateway(choke.Config{Store: st})
}

// ApplyPreset returned "not yet supported (Phase 1)" long after Phase 1
// shipped, so a dual-control approval for a fleet containment preset ran to
// completion and every agent acked REJECTED.
func TestApplyPresetActuallyAppliesOnARealAgent(t *testing.T) {
	g := presetGateway(t)
	a := gatewayApplier{gw: g}

	before := g.Thresholds()
	if err := a.ApplyPreset("containment"); err != nil {
		t.Fatalf("containment preset rejected on a real agent: %v", err)
	}
	after := g.Thresholds()
	if after == before {
		t.Fatal("preset reported success but changed no thresholds")
	}
	if after.ThrottleAt >= before.ThrottleAt {
		t.Errorf("containment should choke sooner: throttle_at %d -> %d",
			before.ThrottleAt, after.ThrottleAt)
	}
}

func TestApplyPresetRejectsAnUnknownName(t *testing.T) {
	a := gatewayApplier{gw: presetGateway(t)}
	if err := a.ApplyPreset("not-a-preset"); err == nil {
		t.Fatal("an unknown preset must be refused, not silently ignored")
	}
}

// THE GUARDRAIL. threat-model EN-1: the worst outcome of an enforcement bug is
// locking every operator out of the host. A validly signed command must be able
// to WIDEN the exemption list and must never be able to narrow it below the
// safe minimum.
func TestSetProtectedListCannotStripTheLoginPath(t *testing.T) {
	g := presetGateway(t)
	a := gatewayApplier{gw: g}

	// A command that names only one unrelated binary — an attempt, deliberate
	// or accidental, to replace the list with something that omits sshd/sudo.
	if err := a.SetProtectedList([]string{"/usr/bin/myapp"}, nil); err != nil {
		t.Fatalf("SetProtectedList: %v", err)
	}

	got := strings.Join(g.SystemCriticalList(), " ")
	for _, must := range []string{"sudo", "sshd", "login"} {
		if !strings.Contains(got, must) {
			t.Errorf("%q was stripped from the exemption list by a remote command — "+
				"this is the sudo-lockout defense and it must survive", must)
		}
	}
	if !strings.Contains(got, "/usr/bin/myapp") {
		t.Error("the command's own binary was not added; widening must still work")
	}
}

func TestSetProtectedListWithNoGatewayIsAnError(t *testing.T) {
	var a gatewayApplier
	if err := a.SetProtectedList([]string{"/bin/x"}, nil); err == nil {
		t.Fatal("an agent with no gateway must report it, not silently succeed")
	}
	if err := a.ApplyPreset("containment"); err == nil {
		t.Fatal("an agent with no gateway must report it, not silently succeed")
	}
}
