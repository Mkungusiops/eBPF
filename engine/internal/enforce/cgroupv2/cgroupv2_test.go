package cgroupv2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

// fakeRoot constructs a directory tree that looks enough like cgroup v2
// for IsCgroupV2 / Setup / MoveTo to succeed. Real cgroup operations
// can't be tested without root + a real kernel mount; this fixture
// covers the file-layout side of the manager.
func fakeRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.controllers"),
		[]byte("cpu memory io pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"),
		[]byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestIsCgroupV2(t *testing.T) {
	if IsCgroupV2(t.TempDir()) {
		t.Errorf("empty dir must not be detected as cgroup v2")
	}
	if !IsCgroupV2(fakeRoot(t)) {
		t.Errorf("fake root must be detected as cgroup v2")
	}
}

func TestSetupCreatesAllTiersWithLimits(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	for _, name := range []string{NameThrottled, NameTarpit, NameQuarantined} {
		dir := filepath.Join(root, name)
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("missing cgroup dir %s: %v", dir, err)
		}
		// cpu.max and pids.max are always written
		for _, f := range []string{"cpu.max", "pids.max"} {
			b, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				t.Errorf("missing %s/%s: %v", dir, f, err)
				continue
			}
			if len(b) == 0 {
				t.Errorf("%s/%s should not be empty", dir, f)
			}
		}
	}
}

func TestSetupIdempotent(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(); err != nil {
		t.Errorf("second Setup must succeed; got %v", err)
	}
}

func TestMoveToWritesPID(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := m.MoveTo(1234, circuit.ActThrottle); err != nil {
		t.Fatalf("MoveTo: %v", err)
	}
	procs, err := os.ReadFile(filepath.Join(root, NameThrottled, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(procs) != "1234" {
		t.Errorf("cgroup.procs=%q want %q", string(procs), "1234")
	}
}

func TestMoveToQuarantineWritesFreeze(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := m.MoveTo(2222, circuit.ActQuarantine); err != nil {
		t.Fatalf("MoveTo: %v", err)
	}
	freeze, err := os.ReadFile(filepath.Join(root, NameQuarantined, "cgroup.freeze"))
	if err != nil {
		t.Fatalf("freeze file: %v", err)
	}
	if string(freeze) != "1" {
		t.Errorf("cgroup.freeze=%q want %q", string(freeze), "1")
	}
}

func TestMoveToRefusesPID0(t *testing.T) {
	m := NewManager(fakeRoot(t))
	_ = m.Setup()
	if err := m.MoveTo(0, circuit.ActThrottle); err == nil {
		t.Errorf("MoveTo(0) must error")
	}
}

func TestMoveToRejectsUnsupportedAction(t *testing.T) {
	m := NewManager(fakeRoot(t))
	_ = m.Setup()
	err := m.MoveTo(1, circuit.ActSever)
	if err == nil {
		t.Errorf("MoveTo(Sever) must error (Severer's job)")
	}
}

func TestThawClearsFreeze(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	_ = m.MoveTo(7777, circuit.ActQuarantine)
	if err := m.Thaw(); err != nil {
		t.Fatalf("Thaw: %v", err)
	}
	freeze, _ := os.ReadFile(filepath.Join(root, NameQuarantined, "cgroup.freeze"))
	if string(freeze) != "0" {
		t.Errorf("Thaw didn't clear freeze: got %q", string(freeze))
	}
}

func TestInhabitantsReadsAllTiers(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	// Pretend two pids live in throttled.
	_ = os.WriteFile(filepath.Join(root, NameThrottled, "cgroup.procs"),
		[]byte("100\n200\n"), 0o644)
	got, err := m.Inhabitants()
	if err != nil {
		t.Fatal(err)
	}
	if len(got[NameThrottled]) != 2 || got[NameThrottled][0] != 100 {
		t.Errorf("throttled pids wrong: %v", got[NameThrottled])
	}
}

func TestSetupRejectsNonCgroupV2(t *testing.T) {
	m := NewManager(t.TempDir())
	if err := m.Setup(); err == nil {
		t.Errorf("Setup must reject non-cgroup-v2 root")
	}
}

// A kernel that refuses one limit must NOT cost us enforcement. This is the
// regression for the OrbStack case: cpu.max returns EINVAL on a kernel without
// CFS bandwidth control, Setup aborted on the first tier, the remaining tiers
// were never created, and the whole engine silently fell back to detect-only.
func TestSetupSurvivesRefusedLimit(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)

	// Make cpu.max unwritable for one tier by pre-creating it as a directory:
	// the kernel's EINVAL and this EISDIR both surface as a failed write.
	if err := os.MkdirAll(filepath.Join(root, NameQuarantined, "cpu.max"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := m.Setup(); err != nil {
		t.Fatalf("a refused limit must not fail Setup, got: %v", err)
	}

	// Every tier still exists — including the ones after the failure, and the
	// release tier that MoveTo(ActNone) depends on.
	for _, name := range []string{NamePristine, NameThrottled, NameTarpit, NameQuarantined} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Errorf("tier %s missing after a refused limit: %v", name, err)
		}
	}

	// And the degradation is reported rather than swallowed.
	d := m.Degraded()
	if len(d) == 0 {
		t.Fatal("Degraded() must report the refused limit, got none")
	}
	found := false
	for _, entry := range d {
		if strings.Contains(entry, NameQuarantined) && strings.Contains(entry, "cpu.max") {
			found = true
		}
	}
	if !found {
		t.Errorf("Degraded() should name the refused knob, got %v", d)
	}

	// Idempotent: a second Setup must not double-count.
	before := len(m.Degraded())
	if err := m.Setup(); err != nil {
		t.Fatalf("second setup: %v", err)
	}
	if len(m.Degraded()) != before {
		t.Errorf("Degraded() grew across Setup calls: %d -> %d", before, len(m.Degraded()))
	}
}

// Release is a real per-process move into the limit-free pristine tier.
func TestMoveToReleaseUsesPristineTier(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := m.MoveTo(4242, circuit.ActNone); err != nil {
		t.Fatalf("release must be supported, got: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(root, NamePristine, "cgroup.procs"))
	if err != nil {
		t.Fatalf("release did not write cgroup.procs: %v", err)
	}
	if strings.TrimSpace(string(b)) != "4242" {
		t.Errorf("pristine cgroup.procs = %q, want 4242", strings.TrimSpace(string(b)))
	}
	// The release tier must be limit-free — moving here is what "unconstrained"
	// means, so a cpu.max/pids.max written here would defeat the point.
	for _, f := range []string{"cpu.max", "pids.max"} {
		if _, err := os.Stat(filepath.Join(root, NamePristine, f)); err == nil {
			t.Errorf("pristine tier must not carry a %s limit", f)
		}
	}
}

// The quarantine freeze flag is tier-wide but the ladder is per-process:
// releasing a process moves it OUT of the cgroup and never cleared the flag, so
// after the first quarantine the tier stayed frozen for the life of the host.
// Measured on all three production hosts: freeze=1 with zero pids.
//
// Empty-and-frozen suspends nothing. What it costs is falsifiability — the next
// quarantine's freeze write lands on an already-frozen tier, so a failed write
// is indistinguishable from a successful one.

func TestSetupClearsResidualFreezeOnEmptyTier(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	q := filepath.Join(root, NameQuarantined)
	// Exactly the production residue: frozen, nobody in it.
	if err := os.WriteFile(filepath.Join(q, "cgroup.freeze"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(q, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := m.Setup(); err != nil { // a restart
		t.Fatal(err)
	}

	freeze, err := os.ReadFile(filepath.Join(q, "cgroup.freeze"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(freeze)) != "0" {
		t.Errorf("cgroup.freeze=%q after restart with an empty tier, want %q", string(freeze), "0")
	}
}

func TestSetupLeavesFreezeWhenTierStillHoldsSomeone(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := m.MoveTo(4242, circuit.ActQuarantine); err != nil {
		t.Fatal(err)
	}

	if err := m.Setup(); err != nil { // a restart while a process is held
		t.Fatal(err)
	}

	freeze, _ := os.ReadFile(filepath.Join(root, NameQuarantined, "cgroup.freeze"))
	if strings.TrimSpace(string(freeze)) != "1" {
		t.Fatalf("restart unfroze a tier that still holds a process: freeze=%q — that releases a contained process", string(freeze))
	}
}

func TestReleaseClearsFreezeOnceTierEmpties(t *testing.T) {
	root := fakeRoot(t)
	m := NewManager(root)
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := m.MoveTo(777, circuit.ActQuarantine); err != nil {
		t.Fatal(err)
	}
	// The kernel removes a pid from its previous cgroup when it joins another;
	// the fake root does not, so empty it explicitly to model the release.
	if err := os.WriteFile(filepath.Join(root, NameQuarantined, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := m.MoveTo(777, circuit.ActThrottle); err != nil {
		t.Fatal(err)
	}

	freeze, _ := os.ReadFile(filepath.Join(root, NameQuarantined, "cgroup.freeze"))
	if strings.TrimSpace(string(freeze)) != "0" {
		t.Errorf("cgroup.freeze=%q after the last process left quarantine, want %q", string(freeze), "0")
	}
}
