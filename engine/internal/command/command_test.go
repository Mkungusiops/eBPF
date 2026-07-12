package command

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

type fakeApplier struct {
	mode          ebpfsocv1.EnforcementMode
	protectedBins []string
	killHalt      bool
	setModeCalls  int
	jailCalls     int
}

func (f *fakeApplier) SetMode(m ebpfsocv1.EnforcementMode) error {
	f.mode = m
	f.setModeCalls++
	return nil
}
func (f *fakeApplier) Jail(string, uint32, string) error       { f.jailCalls++; return nil }
func (f *fakeApplier) Thaw(string, uint32) error               { return nil }
func (f *fakeApplier) SetThresholds(_, _, _, _ int32) error    { return nil }
func (f *fakeApplier) ApplyPreset(string) error                { return nil }
func (f *fakeApplier) KillSwitch(halt bool, _ string) error    { f.killHalt = halt; return nil }
func (f *fakeApplier) SetProtectedList(bins, _ []string) error { f.protectedBins = bins; return nil }

// sign fills in a command's signature over its canonical bytes.
func sign(s signing.Signer, c *ebpfsocv1.Command) *ebpfsocv1.Command {
	c.Signature = s.Sign(Canonical(c))
	return c
}

func newProc(t *testing.T) (*Processor, signing.Signer, *fakeApplier) {
	t.Helper()
	s, v, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	fa := &fakeApplier{}
	return NewProcessor(v, fa, []string{"sudo", "sshd", "systemd"}), s, fa
}

func TestValidSetModeApplied(t *testing.T) {
	p, s, fa := newProc(t)
	cmd := sign(s, &ebpfsocv1.Command{
		CommandId: "c1",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action:    &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING}},
	})
	ack := p.Handle(cmd)
	if ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("status = %v, want APPLIED (%s)", ack.GetStatus(), ack.GetDetail())
	}
	if fa.mode != ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING || fa.setModeCalls != 1 {
		t.Fatalf("applier not invoked correctly: mode=%v calls=%d", fa.mode, fa.setModeCalls)
	}
}

func TestExpiredRejected(t *testing.T) {
	p, s, fa := newProc(t)
	cmd := sign(s, &ebpfsocv1.Command{
		CommandId: "c2",
		ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)), // already expired
		Action:    &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING}},
	})
	if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_EXPIRED {
		t.Fatalf("status = %v, want EXPIRED", ack.GetStatus())
	}
	if fa.setModeCalls != 0 {
		t.Fatal("expired command must not be applied")
	}
}

func TestBadSignatureRejected(t *testing.T) {
	p, _, fa := newProc(t)
	cmd := &ebpfsocv1.Command{
		CommandId: "c3",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action:    &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING}},
		Signature: []byte("not-a-real-signature"),
	}
	if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_REJECTED {
		t.Fatalf("status = %v, want REJECTED", ack.GetStatus())
	}
	if fa.setModeCalls != 0 {
		t.Fatal("unsigned command must not be applied")
	}
}

// TestProtectedListGuardrail is the sudo-lockout defense: a validly-signed
// command that tries to set the protected list to just ["myapp"] must NOT be
// able to strip the always-protected minimum — the applier receives the union.
func TestProtectedListGuardrail(t *testing.T) {
	p, s, fa := newProc(t)
	cmd := sign(s, &ebpfsocv1.Command{
		CommandId: "c4",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action:    &ebpfsocv1.Command_UpdateProtectedList{UpdateProtectedList: &ebpfsocv1.UpdateProtectedList{ProtectedBinaries: []string{"myapp"}}},
	})
	if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("status = %v (%s), want APPLIED", ack.GetStatus(), ack.GetDetail())
	}
	got := map[string]bool{}
	for _, b := range fa.protectedBins {
		got[b] = true
	}
	for _, must := range []string{"sudo", "sshd", "systemd", "myapp"} {
		if !got[must] {
			t.Fatalf("applied protected set %v missing %q — guardrail failed", fa.protectedBins, must)
		}
	}
}

// TestKillSwitchHaltsThenUnhalts: engaging the kill-switch halts enforcement;
// while halted, re-arming commands are rejected; unhalting restores them.
func TestKillSwitchHaltsThenUnhalts(t *testing.T) {
	p, s, fa := newProc(t)
	setEnforcing := func(id string) *ebpfsocv1.Command {
		return sign(s, &ebpfsocv1.Command{
			CommandId: id,
			ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
			Action:    &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING}},
		})
	}
	killSwitch := func(id string, halt bool) *ebpfsocv1.Command {
		return sign(s, &ebpfsocv1.Command{
			CommandId: id,
			ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
			Action:    &ebpfsocv1.Command_KillSwitch{KillSwitch: &ebpfsocv1.KillSwitch{HaltAllEnforcement: halt, Reason: "test"}},
		})
	}

	if ack := p.Handle(killSwitch("k1", true)); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("kill-switch engage status = %v", ack.GetStatus())
	}
	if !p.Halted() || !fa.killHalt {
		t.Fatal("kill-switch should have engaged")
	}
	// Re-arm attempt while halted → rejected, applier untouched.
	if ack := p.Handle(setEnforcing("s1")); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_REJECTED {
		t.Fatalf("re-arm while halted status = %v, want REJECTED", ack.GetStatus())
	}
	if fa.setModeCalls != 0 {
		t.Fatal("no enforcement command should apply while halted")
	}
	// Unhalt, then re-arm succeeds.
	if ack := p.Handle(killSwitch("k2", false)); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("unhalt status = %v", ack.GetStatus())
	}
	if p.Halted() {
		t.Fatal("kill-switch should be released")
	}
	if ack := p.Handle(setEnforcing("s2")); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("re-arm after unhalt status = %v", ack.GetStatus())
	}
	if fa.setModeCalls != 1 {
		t.Fatalf("expected exactly one applied SetMode after unhalt, got %d", fa.setModeCalls)
	}
}
