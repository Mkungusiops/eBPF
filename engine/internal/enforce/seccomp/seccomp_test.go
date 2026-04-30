package seccomp

import (
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
)

func TestCompileBuildsValidFilter(t *testing.T) {
	policies := []policy.Policy{
		{
			Metadata:     policy.Metadata{Name: "p1"},
			DenySyscalls: []string{"ptrace", "mount"},
		},
		{
			Metadata:     policy.Metadata{Name: "p2"},
			DenySyscalls: []string{"ptrace", "init_module"}, // duplicate ptrace -> dedup
		},
	}
	f, warnings, err := Compile(ArchAMD64, policies)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(f.Denied) != 3 {
		t.Errorf("denied=%d want 3 (ptrace, mount, init_module)", len(f.Denied))
	}
	// last instruction must be RET ALLOW
	last := f.Insns[len(f.Insns)-1]
	if last.K != secRetAllow {
		t.Errorf("last insn K=%#x want secRetAllow", last.K)
	}
	// raw bytes round-trip
	b := f.Bytes()
	if len(b) != 8*len(f.Insns) {
		t.Errorf("Bytes() len=%d want %d", len(b), 8*len(f.Insns))
	}
}

func TestCompileEmptyDeniesIsError(t *testing.T) {
	_, _, err := Compile(ArchAMD64, []policy.Policy{{Metadata: policy.Metadata{Name: "x"}}})
	if err == nil {
		t.Fatal("compile must refuse empty filter")
	}
}

func TestCompileWarnsOnUnknownSyscall(t *testing.T) {
	pols := []policy.Policy{{
		Metadata:     policy.Metadata{Name: "p"},
		DenySyscalls: []string{"ptrace", "totally_made_up_syscall"},
	}}
	f, warnings, err := Compile(ArchAMD64, pols)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "totally_made_up_syscall") {
		t.Fatalf("expected warning for unknown syscall, got %v", warnings)
	}
	if len(f.Denied) != 1 {
		t.Errorf("known syscall must still be in filter, got Denied=%v", f.Denied)
	}
}

func TestCompileSortsDeniesDeterministically(t *testing.T) {
	pols := []policy.Policy{{
		Metadata:     policy.Metadata{Name: "p"},
		DenySyscalls: []string{"mount", "ptrace", "bpf"},
	}}
	f, _, err := Compile(ArchAMD64, pols)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(f.Denied); i++ {
		if f.Denied[i-1] >= f.Denied[i] {
			t.Errorf("Denied not sorted ascending: %v", f.Denied)
		}
	}
}
