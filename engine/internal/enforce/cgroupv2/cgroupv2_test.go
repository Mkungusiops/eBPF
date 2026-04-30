package cgroupv2

import (
	"os"
	"path/filepath"
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
