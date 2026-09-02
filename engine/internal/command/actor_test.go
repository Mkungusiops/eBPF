package command

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// The actor lands in a tamper-evident audit row as verified fact. Outside the
// signature, anyone on the path could rename the operator on a validly-signed
// command and the chain would attest to it — an attributable action whose
// attribution can be rewritten is worse than an anonymous one, because it
// accuses a specific person.

func thresholdCmd(actor string) *ebpfsocv1.Command {
	return &ebpfsocv1.Command{
		CommandId: "cmd-1", Actor: actor,
		Action: &ebpfsocv1.Command_SetThresholds{SetThresholds: &ebpfsocv1.SetThresholds{
			ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200}},
	}
}

func TestRenamingTheActorBreaksTheSignature(t *testing.T) {
	p, s, _ := newProc(t)
	cmd := sign(s, &ebpfsocv1.Command{
		CommandId: "c-actor", Actor: "op-adanian",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action: &ebpfsocv1.Command_SetThresholds{SetThresholds: &ebpfsocv1.SetThresholds{
			ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200}},
	})
	if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("setup: %v %s", ack.GetStatus(), ack.GetDetail())
	}

	// Rewrite the operator in flight, leaving the signature untouched.
	cmd.Actor = "op-attacker"
	cmd.CommandId = "c-actor-2" // fresh id, so this is not a replay rejection
	cmd.Signature = signing.Signer(s).Sign(Canonical(&ebpfsocv1.Command{
		CommandId: "c-actor-2", Actor: "op-adanian",
		ExpiresAt: cmd.ExpiresAt, Action: cmd.Action}))

	if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_REJECTED {
		t.Fatalf("a renamed operator was accepted (%v) — the audit row would name the wrong person "+
			"and the chain would attest to it", ack.GetStatus())
	}
}

func TestStrippingTheActorBreaksTheSignature(t *testing.T) {
	// The other direction: an operator's action must not be laundered into an
	// anonymous one.
	a := string(Canonical(thresholdCmd("op-adanian")))
	if a == string(Canonical(thresholdCmd(""))) {
		t.Fatal("an actor can be stripped from a signed command without breaking it")
	}
}

func TestAnActorlessCommandIsByteIdenticalToBeforeTheFieldExisted(t *testing.T) {
	// Wire compatibility. Binding the actor unconditionally would make every
	// command from a control plane that predates this field fail verification
	// on an agent that carries it, and the reverse. Only non-empty changes it.
	got := string(Canonical(thresholdCmd("")))
	want := "id=cmd-1;exp=0;thresholds=20,50,120,200"
	if got != want {
		t.Fatalf("canonical = %q, want the pre-existing encoding %q", got, want)
	}
}

// auditingApplier is a fakeApplier that also records config changes.
type auditingApplier struct {
	fakeApplier
	rows     []string
	failNext error
}

func (a *auditingApplier) SetThresholds(t1, t2, t3, t4 int32) error {
	if a.failNext != nil {
		return a.failNext
	}
	return a.fakeApplier.SetThresholds(t1, t2, t3, t4)
}

func (a *auditingApplier) AuditConfigCommand(action, detail, actor string) {
	a.rows = append(a.rows, action+"|"+detail+"|"+actor)
}

func procWith(t *testing.T, ap Applier) (*Processor, signing.Signer) {
	t.Helper()
	s, v, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return NewProcessor(v, ap, []string{"sudo", "sshd", "systemd"}), s
}

func TestEveryConfigChangeIsAuditedWithItsOperator(t *testing.T) {
	// Six commands change how enforcement BEHAVES fleet-wide and the agent
	// recorded none of them. An operator could arm every host in a tenant,
	// drop the ladder so ordinary activity reaches a sever, or switch
	// detection off, and the hosts' own ledgers would show nothing — while
	// the single-tenant engine audited the identical actions.
	// A factory per case: the oneof wrapper implements an UNEXPORTED interface
	// method, so an action cannot be held in a field declared outside its own
	// package.
	cases := []struct {
		name  string
		build func(*ebpfsocv1.Command)
		want  string
	}{
		{"mode", func(c *ebpfsocv1.Command) {
			c.Action = &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{
				Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING}}
		}, "set-mode"},
		{"kill-switch", func(c *ebpfsocv1.Command) {
			c.Action = &ebpfsocv1.Command_KillSwitch{KillSwitch: &ebpfsocv1.KillSwitch{
				HaltAllEnforcement: true, Reason: "stop everything"}}
		}, "kill-switch"},
		{"thresholds", func(c *ebpfsocv1.Command) {
			c.Action = &ebpfsocv1.Command_SetThresholds{SetThresholds: &ebpfsocv1.SetThresholds{
				ThrottleAt: 20, TarpitAt: 50, QuarantineAt: 120, SeverAt: 200}}
		}, "set-thresholds"},
		{"preset", func(c *ebpfsocv1.Command) {
			c.Action = &ebpfsocv1.Command_ApplyPreset{ApplyPreset: &ebpfsocv1.ApplyPreset{
				Preset: "containment"}}
		}, "apply-preset"},
		{"protect-list", func(c *ebpfsocv1.Command) {
			c.Action = &ebpfsocv1.Command_UpdateProtectedList{
				UpdateProtectedList: &ebpfsocv1.UpdateProtectedList{ProtectedBinaries: []string{"/opt/x"}}}
		}, "protect-list"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ap := &auditingApplier{}
			p, s := procWith(t, ap)
			cmd := &ebpfsocv1.Command{
				CommandId: "audit-" + tc.name + string(rune('a'+i)),
				Actor:     "op-adanian",
				ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
			}
			tc.build(cmd)
			sign(s, cmd)
			if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
				t.Fatalf("not applied: %v %s", ack.GetStatus(), ack.GetDetail())
			}
			if len(ap.rows) != 1 {
				t.Fatalf("%d audit rows, want 1 — this change left no trace on the host", len(ap.rows))
			}
			if !strings.HasPrefix(ap.rows[0], tc.want+"|") {
				t.Fatalf("row %q does not name the action %q", ap.rows[0], tc.want)
			}
			if !strings.HasSuffix(ap.rows[0], "|op-adanian") {
				t.Fatalf("row %q does not name the operator", ap.rows[0])
			}
		})
	}
}

func TestContainmentIsNotDoubleAudited(t *testing.T) {
	// Jail already produces a decision row through the gateway. Recording it
	// here too would double-count containment in the audit a review reads.
	ap := &auditingApplier{}
	p, s := procWith(t, ap)
	cmd := sign(s, &ebpfsocv1.Command{
		CommandId: "jail-1", Actor: "op",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action:    &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{ExecId: "e", Pid: 1, Tier: "throttle"}},
	})
	if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("not applied: %s", ack.GetDetail())
	}
	if len(ap.rows) != 0 {
		t.Fatalf("containment was audited twice: %v", ap.rows)
	}
}

func TestARefusedChangeIsNotAudited(t *testing.T) {
	// A row written before the apply would claim a change the applier refused
	// — and SetThresholds refuses a ladder that would sever everything, so
	// this is a live case, not a hypothetical.
	ap := &auditingApplier{failNext: errors.New("ladder must be strictly ascending")}
	p, s := procWith(t, ap)
	cmd := sign(s, &ebpfsocv1.Command{
		CommandId: "bad-ladder", Actor: "op-adanian",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action: &ebpfsocv1.Command_SetThresholds{SetThresholds: &ebpfsocv1.SetThresholds{
			ThrottleAt: 200, TarpitAt: 50, QuarantineAt: 120, SeverAt: 20}},
	})
	if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_REJECTED {
		t.Fatalf("status = %v, want REJECTED", ack.GetStatus())
	}
	if len(ap.rows) != 0 {
		t.Fatalf("a refused change was recorded as applied: %v", ap.rows)
	}
}
