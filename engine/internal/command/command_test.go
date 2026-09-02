package command

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/policyapply"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

type fakeApplier struct {
	mode          ebpfsocv1.EnforcementMode
	protectedBins []string
	killHalt      bool
	killPlane     ebpfsocv1.Plane
	setModeCalls  int
	jailCalls     int
	// lastRevert records the auto-revert window the applier was handed, so a
	// test can prove the window survived the wire rather than only that a jail
	// happened.
	lastRevert time.Duration
}

func (f *fakeApplier) SetMode(m ebpfsocv1.EnforcementMode, p ebpfsocv1.Plane) error {
	f.mode = m
	f.setModeCalls++
	return nil
}
func (f *fakeApplier) Jail(_ string, _ uint32, _ string, revertAfter time.Duration) error {
	f.jailCalls++
	f.lastRevert = revertAfter
	return nil
}
func (f *fakeApplier) Thaw(string, uint32) error            { return nil }
func (f *fakeApplier) SetThresholds(_, _, _, _ int32) error { return nil }
func (f *fakeApplier) ApplyPreset(string) error             { return nil }
func (f *fakeApplier) KillSwitch(halt bool, _ string, p ebpfsocv1.Plane) error {
	f.killHalt, f.killPlane = halt, p
	return nil
}
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

// ─────────── Multi-agent containment honesty ─────────────────────────────
//
// A Jail/Thaw may be dispatched to several agents at once because the control
// plane cannot always tell which one is running the target. An agent that is
// not running it must no-op AND SAY SO: a no-op reported as APPLIED tells the
// operator a threat is contained while the process keeps running elsewhere.

// owningApplier answers ownership questions from a fixed grade.
type owningApplier struct {
	fakeApplier
	match ebpfsocv1.CommandAck_TargetMatch
}

func (o *owningApplier) OwnsTarget(string, uint32) ebpfsocv1.CommandAck_TargetMatch { return o.match }

func newOwningProc(t *testing.T, match ebpfsocv1.CommandAck_TargetMatch) (*Processor, signing.Signer, *owningApplier) {
	t.Helper()
	s, v, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	oa := &owningApplier{match: match}
	return NewProcessor(v, oa, []string{"sudo"}), s, oa
}

func jailCmd(s signing.Signer, id, execID string, pid uint32, tier string) *ebpfsocv1.Command {
	return sign(s, &ebpfsocv1.Command{
		CommandId: id,
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{
			ExecId: execID, Pid: pid, Tier: tier}},
	})
}

// TestJailNotTargetIsNotApplied: the core fix. An agent that disowns the target
// must not run the enforcer at all — on a sever the enforcer is a SIGKILL, so
// deciding after the fact would already have killed a same-numbered local PID.
func TestJailNotTargetIsNotApplied(t *testing.T) {
	p, s, oa := newOwningProc(t, ebpfsocv1.CommandAck_TARGET_MATCH_NONE)
	ack := p.Handle(jailCmd(s, "j1", "someone-elses-exec", 4021, "sever"))

	if ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_NOT_TARGET {
		t.Fatalf("status = %v (%s), want NOT_TARGET", ack.GetStatus(), ack.GetDetail())
	}
	if oa.jailCalls != 0 {
		t.Fatal("enforcer ran for a target this agent does not own — a sever here SIGKILLs an unrelated local process")
	}
	if ack.GetStatus() == ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatal("a no-op must never report APPLIED")
	}
}

// TestThawNotTargetIsNotApplied: same rule on the release path, so a thaw that
// touched nothing is not reported as having released the process.
func TestThawNotTargetIsNotApplied(t *testing.T) {
	p, s, _ := newOwningProc(t, ebpfsocv1.CommandAck_TARGET_MATCH_NONE)
	cmd := sign(s, &ebpfsocv1.Command{
		CommandId: "t1",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action:    &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{ExecId: "not-mine", Pid: 4021}},
	})
	if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_NOT_TARGET {
		t.Fatalf("status = %v, want NOT_TARGET", ack.GetStatus())
	}
}

// TestJailAckCarriesMatchGrade: the owner applies, and the ack reports HOW it
// knew. The control plane needs the grade — an exec_id match is proof of
// ownership, a pid match is a coincidence it must not act irreversibly on.
func TestJailAckCarriesMatchGrade(t *testing.T) {
	for _, tc := range []struct {
		name  string
		match ebpfsocv1.CommandAck_TargetMatch
	}{
		{"definitive", ebpfsocv1.CommandAck_TARGET_MATCH_EXEC_ID},
		{"weak", ebpfsocv1.CommandAck_TARGET_MATCH_PID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, s, oa := newOwningProc(t, tc.match)
			ack := p.Handle(jailCmd(s, "j-"+tc.name, "mine", 4021, "quarantine"))
			if ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
				t.Fatalf("status = %v (%s), want APPLIED", ack.GetStatus(), ack.GetDetail())
			}
			if ack.GetTargetMatch() != tc.match {
				t.Fatalf("target_match = %v, want %v", ack.GetTargetMatch(), tc.match)
			}
			if oa.jailCalls != 1 {
				t.Fatalf("jail calls = %d, want 1", oa.jailCalls)
			}
		})
	}
}

// TestApplierWithoutOwnershipKeepsApplying: an Applier that cannot answer the
// ownership question (simulators, older builds) must keep its previous
// behavior rather than start refusing every command.
func TestApplierWithoutOwnershipKeepsApplying(t *testing.T) {
	p, s, fa := newProc(t)
	ack := p.Handle(jailCmd(s, "j2", "whatever", 4021, "throttle"))
	if ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("status = %v, want APPLIED", ack.GetStatus())
	}
	if ack.GetTargetMatch() != ebpfsocv1.CommandAck_TARGET_MATCH_UNSPECIFIED {
		t.Fatalf("target_match = %v, want UNSPECIFIED (the claim is ungraded, not proven)", ack.GetTargetMatch())
	}
	if fa.jailCalls != 1 {
		t.Fatalf("jail calls = %d, want 1", fa.jailCalls)
	}
}

// End-to-end over the REAL applier, not the fake one above.
//
// The fake has always returned nil for ApplyPreset and SetProtectedList, so
// every test here passed while the shipping agent returned "not yet supported"
// — the suite proved the command channel's plumbing and never that a preset
// reached a gateway. That gap is exactly how a dual-control-approved fleet
// preset came to ack REJECTED on every real host.
func TestSignedPresetReachesTheGatewayEndToEnd(t *testing.T) {
	s, v, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	applied := make(chan string, 1)
	p := NewProcessor(v, &recordingApplier{onPreset: func(n string) error {
		applied <- n
		return nil
	}}, []string{"sudo", "sshd", "systemd"})

	cmd := sign(s, &ebpfsocv1.Command{
		CommandId: "preset-1",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action:    &ebpfsocv1.Command_ApplyPreset{ApplyPreset: &ebpfsocv1.ApplyPreset{Preset: "containment"}},
	})
	ack := p.Handle(cmd)
	if ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("preset acked %v (%s) — an approved fleet preset must reach the agent",
			ack.GetStatus(), ack.GetDetail())
	}
	select {
	case got := <-applied:
		if got != "containment" {
			t.Errorf("applier received preset %q, want containment", got)
		}
	default:
		t.Fatal("ack said APPLIED but the applier was never called")
	}
}

// The union happens in the processor AND in the gateway. This asserts the
// processor half: whatever a signed command asks for, the always-protected
// minimum is added before it reaches the applier.
func TestProcessorUnionsTheAlwaysProtectedMinimum(t *testing.T) {
	s, v, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []string, 1)
	p := NewProcessor(v, &recordingApplier{onProtected: func(bins []string) error {
		got <- bins
		return nil
	}}, []string{"sudo", "sshd", "systemd"})

	cmd := sign(s, &ebpfsocv1.Command{
		CommandId: "prot-1",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action: &ebpfsocv1.Command_UpdateProtectedList{
			UpdateProtectedList: &ebpfsocv1.UpdateProtectedList{ProtectedBinaries: []string{"/usr/bin/myapp"}},
		},
	})
	if ack := p.Handle(cmd); ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("protected-list acked %v (%s)", ack.GetStatus(), ack.GetDetail())
	}
	bins := <-got
	joined := strings.Join(bins, " ")
	for _, must := range []string{"sudo", "sshd", "systemd"} {
		if !strings.Contains(joined, must) {
			t.Errorf("%q missing — the sudo-lockout minimum was not unioned in", must)
		}
	}
}

// recordingApplier implements Applier, defaulting every method to a no-op so a
// test can override only the one it cares about.
type recordingApplier struct {
	onPreset    func(string) error
	onProtected func([]string) error
}

func (r *recordingApplier) SetMode(ebpfsocv1.EnforcementMode, ebpfsocv1.Plane) error { return nil }
func (r *recordingApplier) Jail(string, uint32, string, time.Duration) error         { return nil }
func (r *recordingApplier) Thaw(string, uint32) error                                { return nil }
func (r *recordingApplier) SetThresholds(_, _, _, _ int32) error                     { return nil }
func (r *recordingApplier) KillSwitch(bool, string, ebpfsocv1.Plane) error           { return nil }
func (r *recordingApplier) ApplyPreset(n string) error {
	if r.onPreset != nil {
		return r.onPreset(n)
	}
	return nil
}
func (r *recordingApplier) SetProtectedList(bins, _ []string) error {
	if r.onProtected != nil {
		return r.onProtected(bins)
	}
	return nil
}

// A signed command whose target PLANE is outside the signature can be
// retargeted in flight and still verify. On the kill switch — the one control
// that exists to stop everything — that means an operator's process-plane halt
// lands on the device plane while process enforcement keeps killing.
func TestPlaneIsCoveredBySignature(t *testing.T) {
	proc := &ebpfsocv1.Command{
		CommandId: "c1",
		Action: &ebpfsocv1.Command_KillSwitch{KillSwitch: &ebpfsocv1.KillSwitch{
			HaltAllEnforcement: true, Reason: "break glass", Plane: ebpfsocv1.Plane_PLANE_PROCESS,
		}},
	}
	dev := &ebpfsocv1.Command{
		CommandId: "c1",
		Action: &ebpfsocv1.Command_KillSwitch{KillSwitch: &ebpfsocv1.KillSwitch{
			HaltAllEnforcement: true, Reason: "break glass", Plane: ebpfsocv1.Plane_PLANE_DEVICE,
		}},
	}
	if string(Canonical(proc)) == string(Canonical(dev)) {
		t.Fatal("a process-plane and a device-plane kill switch sign identically — the plane can be flipped in flight")
	}

	pm := &ebpfsocv1.Command{CommandId: "c2", Action: &ebpfsocv1.Command_SetMode{
		SetMode: &ebpfsocv1.SetMode{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, Plane: ebpfsocv1.Plane_PLANE_PROCESS}}}
	dm := &ebpfsocv1.Command{CommandId: "c2", Action: &ebpfsocv1.Command_SetMode{
		SetMode: &ebpfsocv1.SetMode{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, Plane: ebpfsocv1.Plane_PLANE_DEVICE}}}
	if string(Canonical(pm)) == string(Canonical(dm)) {
		t.Fatal("SetMode signs identically across planes — arming one plane could be redirected to the other")
	}
}

// An action this build cannot canonicalise must be unsignable and unverifiable,
// not silently signed over "id=…;exp=…" alone.
func TestUnknownActionIsNotSignable(t *testing.T) {
	if got := Canonical(&ebpfsocv1.Command{CommandId: "c3"}); got != nil {
		t.Fatalf("Canonical of an actionless command = %q, want nil so signing fails closed", got)
	}
}

// ── ApplyPolicy: the ack gate ────────────────────────────────────────────────
//
// Command_ApplyPolicy had no test at all, which is how a one-word change to an
// outcome code silently inverted the ack for every successful removal. These
// drive the gate itself, not the predicate it calls — the predicate can be
// correct while the gate ignores it.

// policyApplier is a fakeApplier that also satisfies PolicyApplier, returning
// whatever per-policy outcomes a test asks for.
type policyApplier struct {
	fakeApplier
	outcomes map[string]string
	err      error
	gotDocs  []string
	gotRm    []string
}

func (p *policyApplier) ApplyPolicies(docs []*ebpfsocv1.PolicyDoc, remove []string) (map[string]string, error) {
	for _, d := range docs {
		p.gotDocs = append(p.gotDocs, d.GetName())
	}
	p.gotRm = append(p.gotRm, remove...)
	return p.outcomes, p.err
}

func policyProc(t *testing.T, pa *policyApplier) (*Processor, signing.Signer) {
	t.Helper()
	s, v, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return NewProcessor(v, pa, []string{"sudo"}), s
}

func policyCmd(t *testing.T, s signing.Signer, docs []*ebpfsocv1.PolicyDoc, remove []string) *ebpfsocv1.Command {
	t.Helper()
	return sign(s, &ebpfsocv1.Command{
		CommandId: "p1",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action: &ebpfsocv1.Command_ApplyPolicy{ApplyPolicy: &ebpfsocv1.ApplyPolicy{
			Policies: docs, Remove: remove, Reason: "test"}},
	})
}

// The regression that prompted all of this: a removal reports "removed", not
// "ok". Testing the literal acked every SUCCESSFUL removal as REJECTED — the
// operator was told their removal failed while the policy was gone from the
// kernel.
func TestSuccessfulRemovalAcksApplied(t *testing.T) {
	pa := &policyApplier{outcomes: map[string]string{"old-policy": policyapply.Removed}}
	p, s := policyProc(t, pa)

	a := p.Handle(policyCmd(t, s, nil, []string{"old-policy"}))

	if a.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("a successful removal acked %v (%q), want APPLIED", a.GetStatus(), a.GetDetail())
	}
	if len(pa.gotRm) != 1 || pa.gotRm[0] != "old-policy" {
		t.Fatalf("the removal did not reach the applier: %v", pa.gotRm)
	}
}

func TestSuccessfulApplyAcksApplied(t *testing.T) {
	pa := &policyApplier{outcomes: map[string]string{"p": policyapply.OK}}
	p, s := policyProc(t, pa)

	a := p.Handle(policyCmd(t, s, []*ebpfsocv1.PolicyDoc{{Name: "p", Yaml: "y", Mode: "monitor"}}, nil))

	if a.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("acked %v (%q), want APPLIED", a.GetStatus(), a.GetDetail())
	}
}

// A partial application must not ack as applied: four policies where two
// loaded leaves the host matching neither the old set nor the requested one.
func TestPartialApplyAcksRejectedAndNamesTheFailures(t *testing.T) {
	pa := &policyApplier{outcomes: map[string]string{
		"good":   policyapply.OK,
		"gone":   policyapply.Removed,
		"broken": "failed: symbol not found",
	}}
	p, s := policyProc(t, pa)

	a := p.Handle(policyCmd(t, s, []*ebpfsocv1.PolicyDoc{{Name: "good", Yaml: "y"}}, nil))

	if a.GetStatus() != ebpfsocv1.CommandAck_STATUS_REJECTED {
		t.Fatalf("a partial apply acked %v, want REJECTED", a.GetStatus())
	}
	if !strings.Contains(a.GetDetail(), "broken") {
		t.Fatalf("the ack must name the failure, got %q", a.GetDetail())
	}
	// The ones that worked are not noise in the failure list.
	if strings.Contains(a.GetDetail(), "good") || strings.Contains(a.GetDetail(), "gone") {
		t.Fatalf("successful policies were listed as failures: %q", a.GetDetail())
	}
}

// Live-but-not-durable is NOT success. The policy is running now and vanishes
// at the next Tetragon restart, and an ack calling that "applied" hides the one
// fact the operator has to act on.
func TestLiveButNotDurableAcksRejected(t *testing.T) {
	pa := &policyApplier{outcomes: map[string]string{
		"p": policyapply.NotDurable + "/etc/tetragon/tetragon.tp.d is not present",
	}}
	p, s := policyProc(t, pa)

	a := p.Handle(policyCmd(t, s, []*ebpfsocv1.PolicyDoc{{Name: "p", Yaml: "y"}}, nil))

	if a.GetStatus() != ebpfsocv1.CommandAck_STATUS_REJECTED {
		t.Fatalf("a non-durable policy acked %v, want REJECTED — it is lost on the next restart", a.GetStatus())
	}
	if !strings.Contains(a.GetDetail(), "NOT durable") {
		t.Fatalf("the ack should carry the durability warning, got %q", a.GetDetail())
	}
}

// An agent with no Tetragon must say "I cannot", which is a different answer
// from "I tried and failed".
func TestApplyPolicyOnAnApplierThatCannotAcksRejected(t *testing.T) {
	p, s, _ := newProc(t) // plain fakeApplier — not a PolicyApplier
	a := p.Handle(policyCmd(t, s, []*ebpfsocv1.PolicyDoc{{Name: "p", Yaml: "y"}}, nil))

	if a.GetStatus() != ebpfsocv1.CommandAck_STATUS_REJECTED {
		t.Fatalf("acked %v, want REJECTED", a.GetStatus())
	}
	if !strings.Contains(a.GetDetail(), "cannot apply detection policy") {
		t.Fatalf("detail %q should distinguish inability from failure", a.GetDetail())
	}
}

// ── UpdateSuppressions ───────────────────────────────────────────────────────
//
// A suppression narrows what a fleet detects. The signature has to bind every
// field that decides WHAT IS SILENCED, or an attacker could widen a legitimate
// rule from "this binary under this detection" to "this binary always" without
// breaking it.

type suppressionApplier struct {
	fakeApplier
	got []*ebpfsocv1.Suppression
	err error
}

func (s *suppressionApplier) SetSuppressions(r []*ebpfsocv1.Suppression) error {
	s.got = r
	return s.err
}

func suppressionCmd(t *testing.T, s signing.Signer, rules []*ebpfsocv1.Suppression) *ebpfsocv1.Command {
	t.Helper()
	return sign(s, &ebpfsocv1.Command{
		CommandId: "s1",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Action: &ebpfsocv1.Command_UpdateSuppressions{UpdateSuppressions: &ebpfsocv1.UpdateSuppressions{
			Suppressions: rules, Reason: "expected on this estate"}},
	})
}

func TestSuppressionsReachTheApplier(t *testing.T) {
	sa := &suppressionApplier{}
	s, v, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := NewProcessor(v, sa, []string{"sudo"})

	a := p.Handle(suppressionCmd(t, s, []*ebpfsocv1.Suppression{
		{Binary: "/opt/backup/agent", Reason: "reads credential paths nightly"},
	}))
	if a.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("acked %v (%q)", a.GetStatus(), a.GetDetail())
	}
	if len(sa.got) != 1 || sa.got[0].GetBinary() != "/opt/backup/agent" {
		t.Fatalf("the rule did not reach the applier: %+v", sa.got)
	}
}

func TestTheSignatureBindsWhatIsSilenced(t *testing.T) {
	// Widening the scope of a signed suppression must invalidate it. Without
	// the policy field in the canonical form, "silence this binary under
	// privilege-escalation" could be edited in flight into "silence it always".
	s, _, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	narrow := suppressionCmd(t, s, []*ebpfsocv1.Suppression{
		{Binary: "/usr/bin/cfgmgr", Policy: "privilege-escalation", Reason: "scheduled"},
	})
	// Same command, scope widened by dropping the policy narrowing.
	widened := &ebpfsocv1.Command{
		CommandId: narrow.CommandId, ExpiresAt: narrow.ExpiresAt, Signature: narrow.Signature,
		Action: &ebpfsocv1.Command_UpdateSuppressions{UpdateSuppressions: &ebpfsocv1.UpdateSuppressions{
			Suppressions: []*ebpfsocv1.Suppression{{Binary: "/usr/bin/cfgmgr", Reason: "scheduled"}},
			Reason:       "expected on this estate"}},
	}
	if string(Canonical(narrow)) == string(Canonical(widened)) {
		t.Fatal("widening a suppression did not change the signed bytes — the scope is not bound")
	}
}

func TestAnAgentThatCannotSuppressSaysSo(t *testing.T) {
	// "I cannot" is a different answer from "I did", and an operator watching
	// a fleet needs to tell them apart.
	p, s, _ := newProc(t) // plain fakeApplier, no SetSuppressions
	a := p.Handle(suppressionCmd(t, s, []*ebpfsocv1.Suppression{{Binary: "/x", Reason: "y"}}))
	if a.GetStatus() != ebpfsocv1.CommandAck_STATUS_REJECTED {
		t.Fatalf("acked %v, want REJECTED", a.GetStatus())
	}
}
