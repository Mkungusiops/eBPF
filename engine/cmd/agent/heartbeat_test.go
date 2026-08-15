package main

import (
	"path/filepath"
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// A kill-switched host must not report UNSPECIFIED to the fleet console.
//
// Gateway.Mode() returns a fourth value, Mode("kill-switched"), outside the
// three declared constants. It hit gatewayMode's default and went on the wire
// as UNSPECIFIED — for the single posture an operator most needs to see.
// deviceGatewayMode already handled this; its twin did not.
func TestKillSwitchedHostReportsDetectOnlyNotUnspecified(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "hb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	g := choke.NewGateway(choke.Config{Store: st})
	g.SetKillSwitch(true)

	if got := g.Mode(); got != choke.Mode("kill-switched") {
		t.Fatalf("precondition: Mode() = %q, want kill-switched", got)
	}
	got := gatewayMode(g)
	if got == ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		t.Fatal("a kill-switched host reported UNSPECIFIED — the fleet mode column is wrong " +
			"for the one posture that matters most")
	}
	if got != ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY {
		t.Errorf("gatewayMode = %v, want DETECT_ONLY (nothing is being applied)", got)
	}
}
