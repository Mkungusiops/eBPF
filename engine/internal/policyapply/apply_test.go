package policyapply

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
)

// fakeSensors records the call order and lets each RPC be failed on demand.
// The order is the point of several tests below, so it is captured rather than
// just counted.
type fakeSensors struct {
	calls    []string
	addErr   error
	delErr   error
	modeErr  error
	lastYAML string
	lastMode tetragon.TracingPolicyMode
	deleted  []string
	listResp *tetragon.ListTracingPoliciesResponse
	listErr  error
}

func (f *fakeSensors) AddTracingPolicy(_ context.Context, in *tetragon.AddTracingPolicyRequest, _ ...grpc.CallOption) (*tetragon.AddTracingPolicyResponse, error) {
	f.calls = append(f.calls, "add")
	f.lastYAML = in.GetYaml()
	return nil, f.addErr
}

func (f *fakeSensors) DeleteTracingPolicy(_ context.Context, in *tetragon.DeleteTracingPolicyRequest, _ ...grpc.CallOption) (*tetragon.DeleteTracingPolicyResponse, error) {
	f.calls = append(f.calls, "delete")
	f.deleted = append(f.deleted, in.GetName())
	return nil, f.delErr
}

// listed is what List should return; empty by default.
func (f *fakeSensors) ListTracingPolicies(_ context.Context, _ *tetragon.ListTracingPoliciesRequest, _ ...grpc.CallOption) (*tetragon.ListTracingPoliciesResponse, error) {
	f.calls = append(f.calls, "list")
	return f.listResp, f.listErr
}

func (f *fakeSensors) ConfigureTracingPolicy(_ context.Context, in *tetragon.ConfigureTracingPolicyRequest, _ ...grpc.CallOption) (*tetragon.ConfigureTracingPolicyResponse, error) {
	f.calls = append(f.calls, "configure")
	if in.Mode != nil {
		f.lastMode = *in.Mode
	}
	return nil, f.modeErr
}

const body = "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\n"

func TestApplyDeletesBeforeAdding(t *testing.T) {
	// Tetragon's AddTracingPolicy is CREATE-ONLY. Without the delete, a policy
	// whose content changed keeps running the version loaded when the daemon
	// started: the file and the kernel diverge silently and the fix has no
	// effect. This is the single most consequential ordering in the package.
	f := &fakeSensors{}
	out := Apply(context.Background(), f, t.TempDir(), []Doc{{Name: "p", YAML: body, Mode: "monitor"}}, nil)

	if got := strings.Join(f.calls, ","); got != "delete,add,configure" {
		t.Fatalf("call order was %q, want delete,add,configure", got)
	}
	if out["p"] != OK {
		t.Fatalf("outcome %q, want %q", out["p"], OK)
	}
}

func TestApplyIgnoresTheExpectedDeleteFailure(t *testing.T) {
	// The common case is a policy that does not exist yet, where the delete
	// legitimately fails and the add must still run.
	f := &fakeSensors{delErr: errors.New("policy not found")}
	out := Apply(context.Background(), f, t.TempDir(), []Doc{{Name: "p", YAML: body}}, nil)

	if out["p"] != OK {
		t.Fatalf("a failing pre-delete blocked the add: %q", out["p"])
	}
}

func TestApplyReportsTetragonsOwnWords(t *testing.T) {
	// A rejected kprobe symbol or an exhausted BPF map is something the
	// operator can only act on in the daemon's own words.
	f := &fakeSensors{addErr: errors.New("symbol __x64_sys_nope not found")}
	out := Apply(context.Background(), f, t.TempDir(), []Doc{{Name: "p", YAML: body}}, nil)

	if !strings.Contains(out["p"], "__x64_sys_nope") {
		t.Fatalf("the daemon's error was lost: %q", out["p"])
	}
}

func TestApplySetsModeExplicitly(t *testing.T) {
	f := &fakeSensors{}
	Apply(context.Background(), f, t.TempDir(), []Doc{{Name: "p", YAML: body, Mode: "monitor"}}, nil)
	if f.lastMode != tetragon.TracingPolicyMode_TP_MODE_MONITOR {
		t.Fatalf("mode was %v, want monitor", f.lastMode)
	}
}

func TestApplyDistinguishesLiveFromDurable(t *testing.T) {
	// A policy that loaded but could not be persisted is genuinely both useful
	// now and at risk later. Collapsing that into "ok" or "failed" is the lie
	// this outcome exists to prevent.
	f := &fakeSensors{}
	out := Apply(context.Background(), f, "/definitely/not/a/dir", []Doc{{Name: "p", YAML: body}}, nil)

	if !strings.HasPrefix(out["p"], NotDurable) {
		t.Fatalf("outcome %q should report live-but-not-durable", out["p"])
	}
	if strings.Contains(f.calls[len(f.calls)-1], "delete") {
		t.Fatal("the policy should have been left LOADED — it is live, just not persisted")
	}
}

func TestApplyKeepsGoingAfterOneBadPolicy(t *testing.T) {
	// One rejected policy must not stop the others, and the operator has to be
	// able to tell which one it was.
	f := &fakeSensors{}
	out := Apply(context.Background(), f, t.TempDir(), []Doc{
		{Name: "good-a", YAML: body},
		{Name: "no-body"},
		{Name: "good-b", YAML: body},
	}, nil)

	if out["good-a"] != OK || out["good-b"] != OK {
		t.Fatalf("a bad sibling broke the good ones: %v", out)
	}
	if !strings.Contains(out["no-body"], "rejected") {
		t.Fatalf("the empty policy should be rejected by name: %v", out)
	}
}

func TestRemoveDeletesTheFileBeforeUnloading(t *testing.T) {
	// If the file survives a successful unload, Tetragon reloads the policy at
	// its next restart and the operator's removal silently undoes itself.
	dir := t.TempDir()
	if err := WriteDurable(dir, "p", body); err != nil {
		t.Fatal(err)
	}
	f := &fakeSensors{}
	out := Apply(context.Background(), f, dir, nil, []string{"p"})

	if out["p"] != "removed" {
		t.Fatalf("outcome %q, want removed", out["p"])
	}
	if fileExists(DurablePath(dir, "p")) {
		t.Fatal("the durable copy survived — the policy would come back on the next restart")
	}
}

func TestRemoveReportsAFailedUnload(t *testing.T) {
	f := &fakeSensors{delErr: errors.New("no such policy")}
	out := Apply(context.Background(), f, t.TempDir(), nil, []string{"p"})
	if !strings.Contains(out["p"], "remove failed") {
		t.Fatalf("a failed unload was reported as %q", out["p"])
	}
}

func TestConfigureModeRefusesAnUnknownWord(t *testing.T) {
	// "enforce" is the difference between a detection and a kill, so a mode
	// that is neither known word is refused rather than guessed.
	f := &fakeSensors{}
	if err := ConfigureMode(context.Background(), f, "p", "audit"); err == nil {
		t.Fatal("an unknown mode should be refused, not guessed")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// The ack gate in internal/command decides APPLIED versus REJECTED from these
// codes. It originally tested the literal "ok", so when a removal began
// reporting "removed" every SUCCESSFUL removal acked as REJECTED — the console
// told the operator their removal had failed while the policy was in fact gone.
// One predicate, pinned here, is what keeps the two in step.
func TestSucceededCoversEverySuccessCode(t *testing.T) {
	for _, ok := range []string{OK, Removed} {
		if !Succeeded(ok) {
			t.Errorf("%q is a success and must ack as applied", ok)
		}
	}
	// Live-but-not-durable is NOT success: the policy vanishes at the next
	// restart, and an ack calling that "applied" hides the one fact the
	// operator has to act on.
	for _, notOK := range []string{
		NotDurable + "no such directory",
		"failed: symbol not found",
		"remove failed: no such policy",
		"rejected: a policy needs both a name and a body",
		"loaded, but mode not set: boom",
		"",
	} {
		if Succeeded(notOK) {
			t.Errorf("%q must not ack as applied", notOK)
		}
	}
}

// Every code Apply can emit must be classifiable — a code the gate has never
// heard of silently becomes "rejected".
func TestEverySuccessPathReportsASucceededCode(t *testing.T) {
	dir := t.TempDir()
	f := &fakeSensors{}
	out := Apply(context.Background(), f, dir, []Doc{{Name: "p", YAML: body, Mode: "monitor"}}, nil)
	if !Succeeded(out["p"]) {
		t.Fatalf("a fully successful apply reported %q, which the ack gate treats as a failure", out["p"])
	}
	out = Apply(context.Background(), f, dir, nil, []string{"p"})
	if !Succeeded(out["p"]) {
		t.Fatalf("a successful removal reported %q, which the ack gate treats as a failure", out["p"])
	}
}

// ── Replace must not destroy a working detection ─────────────────────────────
//
// A replace is delete-then-add. If the add fails, the host has lost the policy
// it had. That was survivable while pushes were mostly NEW policies; editing an
// existing detection makes replace the normal path, so every rejected edit
// would silently strip a live detection off the host.

// restoringSensors fails the FIRST add and succeeds the second (the rollback),
// recording every body it was given so the test can prove the right one came
// back.
type restoringSensors struct {
	fakeSensors
	adds         []string
	failFirstAdd bool
	failRollback bool
}

func (r *restoringSensors) AddTracingPolicy(_ context.Context, in *tetragon.AddTracingPolicyRequest, _ ...grpc.CallOption) (*tetragon.AddTracingPolicyResponse, error) {
	r.adds = append(r.adds, in.GetYaml())
	if len(r.adds) == 1 && r.failFirstAdd {
		return nil, errors.New("symbol __x64_sys_typo not found")
	}
	if len(r.adds) == 2 && r.failRollback {
		return nil, errors.New("BPF memory exhausted")
	}
	return nil, nil
}

const priorBody = "apiVersion: cilium.io/v1alpha1\n# THE WORKING ORIGINAL\n"

func TestFailedReplaceRestoresThePreviousVersion(t *testing.T) {
	dir := t.TempDir()
	if err := WriteDurable(dir, "p", priorBody); err != nil {
		t.Fatal(err)
	}
	f := &restoringSensors{failFirstAdd: true}

	out := Apply(context.Background(), f, dir, []Doc{{Name: "p", YAML: "broken"}}, nil)

	if len(f.adds) != 2 {
		t.Fatalf("expected a rollback add, got %d add call(s)", len(f.adds))
	}
	if f.adds[1] != priorBody {
		t.Fatalf("rolled back to the wrong body: %q", f.adds[1])
	}
	if !strings.Contains(out["p"], "restored") {
		t.Fatalf("outcome %q must say the host is still covered", out["p"])
	}
	if strings.Contains(out["p"], FailedAndLost) {
		t.Fatalf("a successful rollback must not read as a loss: %q", out["p"])
	}
}

func TestAFailedRollbackIsReportedAsALoss(t *testing.T) {
	// The worst case, and the one that must never render as a plain "failed":
	// the old detection is gone, the new one did not load, and the host is now
	// less protected than before the operator touched it.
	dir := t.TempDir()
	if err := WriteDurable(dir, "p", priorBody); err != nil {
		t.Fatal(err)
	}
	f := &restoringSensors{failFirstAdd: true, failRollback: true}

	out := Apply(context.Background(), f, dir, []Doc{{Name: "p", YAML: "broken"}}, nil)

	if !strings.HasPrefix(out["p"], FailedAndLost) {
		t.Fatalf("outcome %q must be flagged as a LOST detection", out["p"])
	}
	if !strings.Contains(out["p"], "no longer watching") {
		t.Fatalf("the outcome must state the consequence plainly: %q", out["p"])
	}
	// And it must not ack as success.
	if Succeeded(out["p"]) {
		t.Fatal("a lost detection must never ack as applied")
	}
}

func TestAFailedFirstPushLosesNothing(t *testing.T) {
	// No previous version means nothing was destroyed. Saying "the previous
	// version was lost" here would send an operator hunting for a detection
	// that never existed.
	f := &restoringSensors{failFirstAdd: true}
	out := Apply(context.Background(), f, t.TempDir(), []Doc{{Name: "new", YAML: "broken"}}, nil)

	if len(f.adds) != 1 {
		t.Fatalf("nothing to roll back, so there should be one add; got %d", len(f.adds))
	}
	if !strings.Contains(out["new"], "nothing was lost") {
		t.Fatalf("outcome %q should make clear no detection was destroyed", out["new"])
	}
}

func TestASuccessfulReplaceDoesNotRollBack(t *testing.T) {
	dir := t.TempDir()
	_ = WriteDurable(dir, "p", priorBody)
	f := &restoringSensors{}

	out := Apply(context.Background(), f, dir, []Doc{{Name: "p", YAML: "new-body"}}, nil)

	if len(f.adds) != 1 || f.adds[0] != "new-body" {
		t.Fatalf("a clean replace should add exactly the new body once, got %v", f.adds)
	}
	if out["p"] != OK {
		t.Fatalf("outcome %q, want ok", out["p"])
	}
}

// ── The gRPC read path ───────────────────────────────────────────────────────
//
// The engine wrote policy over gRPC and read it back by shelling out to
// `docker exec tetragon tetra tracingpolicy list` — no timeout, hardcoded
// container name, and needing the docker socket (root-on-host) for a read the
// already-open connection answers. This is the mapping that replaces it.

func TestListMapsKernelStateFaithfully(t *testing.T) {
	f := &fakeSensors{listResp: &tetragon.ListTracingPoliciesResponse{
		Policies: []*tetragon.TracingPolicyStatus{
			{
				Name:  "sensitive-file-access",
				State: tetragon.TracingPolicyState_TP_STATE_ENABLED,
				Mode:  tetragon.TracingPolicyMode_TP_MODE_MONITOR,
				Stats: &tetragon.TracingPolicyStats{ActionCounters: &tetragon.TracingPolicyActionCounters{
					Post: 1207, Signal: 0, Override: 0,
				}},
			},
			{
				Name:  "disabled-one",
				State: tetragon.TracingPolicyState_TP_STATE_DISABLED,
				Mode:  tetragon.TracingPolicyMode_TP_MODE_ENFORCE,
			},
		},
	}}

	got, err := List(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d policies, want 2", len(got))
	}
	if !got[0].Enabled || got[0].Mode != "monitor" || got[0].Posts != 1207 {
		t.Fatalf("first policy mapped as %+v", got[0])
	}
	if got[1].Enabled {
		t.Fatalf("a DISABLED policy must not read as enabled: %+v", got[1])
	}
	if got[1].Mode != "enforce" {
		t.Fatalf("mode mapped as %q, want enforce", got[1].Mode)
	}
}

func TestListDoesNotCountPostsAsEnforcement(t *testing.T) {
	// Post is reporting. Counting it as enforcement would make every healthy
	// detection look like it was killing things.
	f := &fakeSensors{listResp: &tetragon.ListTracingPoliciesResponse{
		Policies: []*tetragon.TracingPolicyStatus{{
			Name:  "p",
			State: tetragon.TracingPolicyState_TP_STATE_ENABLED,
			Stats: &tetragon.TracingPolicyStats{ActionCounters: &tetragon.TracingPolicyActionCounters{
				Post: 5000, Signal: 2, Override: 1,
			}},
		}},
	}}
	got, err := List(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Enforces != 3 {
		t.Fatalf("enforces = %d, want 3 (signal+override, not post)", got[0].Enforces)
	}
	if got[0].Posts != 5000 {
		t.Fatalf("posts = %d, want 5000", got[0].Posts)
	}
}

func TestListSurfacesAnError(t *testing.T) {
	// Must not return an empty slice with a nil error: the caller would read
	// "no policies loaded" and report the host as undefended.
	f := &fakeSensors{listErr: errors.New("connection refused")}
	got, err := List(context.Background(), f)
	if err == nil {
		t.Fatal("a failed list must return an error, not an empty policy set")
	}
	if got != nil {
		t.Fatalf("got %v, want nil on error", got)
	}
}
