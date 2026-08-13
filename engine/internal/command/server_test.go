package command

import (
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// TestEnqueueGivesEachAgentItsOwnCommandID: fanning one action out to several
// agents must produce one dispatch per agent.
//
// Enqueue used to reuse an already-set command id and mutate the command in
// place, so a caller sending the same *Command to two agents got the SAME id
// back twice. Every agent's ack then collided on one key: only one was ever
// observed, and it was attributed to whichever agent was enqueued last. A
// control plane fanning containment across a tenant could not tell which host
// actually enforced — it could report the wrong agent, or miss an APPLIED
// entirely and conclude nothing had been contained.
func TestEnqueueGivesEachAgentItsOwnCommandID(t *testing.T) {
	s, _, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(s, time.Minute)

	cmd := &ebpfsocv1.Command{Action: &ebpfsocv1.Command_Jail{
		Jail: &ebpfsocv1.Jail{ExecId: "e1", Pid: 4021, Tier: "sever"}}}
	idA := d.Enqueue("agent-a", cmd)
	idB := d.Enqueue("agent-b", cmd)

	if idA == idB {
		t.Fatalf("both agents got command id %q — their acks would collide on one key", idA)
	}
	if cmd.GetCommandId() != "" {
		t.Fatalf("Enqueue mutated the caller's command (id=%q); the queued copies alias it",
			cmd.GetCommandId())
	}
	// Each agent's queued command must carry its own id and a signature over it.
	for agent, want := range map[string]string{"agent-a": idA, "agent-b": idB} {
		q := d.dequeue(agent)
		if len(q) != 1 {
			t.Fatalf("%s queue = %d commands, want 1", agent, len(q))
		}
		if got := q[0].GetCommandId(); got != want {
			t.Fatalf("%s queued id = %q, want %q", agent, got, want)
		}
		if len(q[0].GetSignature()) == 0 {
			t.Fatalf("%s command is unsigned", agent)
		}
	}
	// Acks must stay distinguishable.
	d.recordAck(&ebpfsocv1.CommandAck{CommandId: idA, Status: ebpfsocv1.CommandAck_STATUS_APPLIED})
	d.recordAck(&ebpfsocv1.CommandAck{CommandId: idB, Status: ebpfsocv1.CommandAck_STATUS_NOT_TARGET})
	a, _ := d.Ack(idA)
	b, _ := d.Ack(idB)
	if a.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED || b.GetStatus() != ebpfsocv1.CommandAck_STATUS_NOT_TARGET {
		t.Fatalf("acks collided: a=%v b=%v", a.GetStatus(), b.GetStatus())
	}
}
