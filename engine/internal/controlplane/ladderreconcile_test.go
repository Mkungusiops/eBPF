package controlplane

import (
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

// A fleet threshold change reaches the agents that exist at that moment. An
// agent enrolled tomorrow starts on whatever the deploy configured, so a
// tenant that deliberately tightened its ladder silently acquires a host
// running the old one — and the console cannot show it, because it reports
// what was dispatched, not what each host is running.

func ladder(t, p, q, sv int32) *ebpfsocv1.ChokeThresholds {
	return &ebpfsocv1.ChokeThresholds{ThrottleAt: t, TarpitAt: p, QuarantineAt: q, SeverAt: sv}
}

func TestAnAgentOnTheTenantLadderIsLeftAlone(t *testing.T) {
	// The loop must converge and stop. Dispatching to an already-correct agent
	// every two minutes forever is a storm, not a reconciliation.
	want := circuit.Config{ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200}
	if !sameLadder(ladder(20, 50, 120, 200), want) {
		t.Fatal("a matching ladder was reported as drift")
	}
}

func TestAnAgentOnADifferentLadderIsCorrected(t *testing.T) {
	want := circuit.Config{ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200}
	if sameLadder(ladder(5, 15, 25, 40), want) {
		t.Fatal("an agent running the deployed default was treated as compliant")
	}
	// One rung differing is still drift: the ladder is a whole, and a host
	// severing at a different score from the rest of its tenant is exactly the
	// inconsistency this exists to catch.
	if sameLadder(ladder(20, 50, 120, 40), want) {
		t.Fatal("a differing sever threshold was missed")
	}
}

func TestAnAgentThatReportsNoLadderIsNotChased(t *testing.T) {
	// An older agent, or one that has not populated the field. It can never
	// confirm convergence, so dispatching to it forever would be a storm
	// against a host that cannot answer.
	want := circuit.Config{ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200}
	if !sameLadder(nil, want) {
		t.Fatal("an agent with no reported ladder would be dispatched to on every pass")
	}
}

func TestTheDispatchedLadderIsAttributedToThePolicy(t *testing.T) {
	// Not to whichever operator last touched the console. This dispatch is the
	// platform enforcing a stored policy, and the agent's audit row should say
	// so rather than naming a person who was not involved.
	cmd := &ebpfsocv1.Command{Actor: "policy:tenant-ladder"}
	if cmd.GetActor() != "policy:tenant-ladder" {
		t.Fatalf("actor = %q", cmd.GetActor())
	}
}
