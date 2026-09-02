package command

import (
	"strings"
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// The auto-revert window MUST be bound by the signature.
//
// Canonical() defines what the signature covers, and the rule this codebase
// works to is that every field which changes what a command DOES must be in it.
// An auto-revert changes exactly that: the same jail with and without one is a
// temporary containment versus a permanent one.
//
// Unbound, anything sitting between the control plane and the agent could strip
// revert_after_seconds from a validly signed command and turn a thirty-minute
// hold into an indefinite one — with the signature still verifying, and the
// audit row still reading "operator asked for thirty minutes".
func TestCanonicalBindsTheRevertWindow(t *testing.T) {
	jail := func(secs uint32) string {
		return string(Canonical(&ebpfsocv1.Command{
			Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{
				ExecId: "e1", Pid: 4021, Tier: "quarantine", RevertAfterSeconds: secs}},
		}))
	}
	permanent, temporary := jail(0), jail(1800)
	if permanent == temporary {
		t.Fatal("a jail with an auto-revert canonicalises identically to one without — " +
			"the window can be stripped in flight and the signature still verifies")
	}
	if !strings.Contains(temporary, "1800") {
		t.Fatalf("the window is not in the canonical form: %q", temporary)
	}
	// Two different windows must differ too, or one can be swapped for another.
	if jail(60) == jail(3600) {
		t.Fatal("a one-minute and a one-hour revert canonicalise identically")
	}
}

// A command signed before this field existed must still canonicalise to the
// bytes it was signed with, or every queued command breaks on upgrade.
func TestCanonicalIsUnchangedWhenNoRevertIsSet(t *testing.T) {
	got := string(Canonical(&ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{
			ExecId: "e1", Pid: 4021, Tier: "quarantine"}},
	}))
	if strings.Contains(got, "revert") {
		t.Fatalf("an unset window still appears in the canonical form: %q", got)
	}
}
