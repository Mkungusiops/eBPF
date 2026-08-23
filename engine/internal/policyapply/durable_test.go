package policyapply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A pushed policy that is live but not durable is lost on the next Tetragon
// restart. The write must be atomic — a torn file in the load directory is a
// policy the daemon refuses at startup, turning a routine restart into the
// silent loss of one detection.
func TestDurableWriteIsAtomicAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()

	if err := WriteDurable(dir, "sensitive-file-access", "apiVersion: cilium.io/v1alpha1\n"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "sensitive-file-access.yaml"))
	if err != nil {
		t.Fatalf("policy not persisted: %v", err)
	}
	if !strings.HasPrefix(string(body), "apiVersion:") {
		t.Fatalf("unexpected content %q", body)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("a temp file survived: %s — a torn file here breaks Tetragon's next startup", e.Name())
		}
	}
}

// A policy name is a filename. Anything path-shaped must be refused rather than
// written somewhere unexpected as root.
func TestDurableWriteRefusesPathTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../escape", "a/b", ".."} {
		if err := WriteDurable(dir, bad, "x"); err == nil {
			t.Fatalf("wrote a policy named %q — that is a path, not a name", bad)
		}
	}
}

// A missing directory means the bind mount is absent. Writing anyway would
// produce a file inside the process's own filesystem that Tetragon never reads,
// while reporting success — the worst outcome available.
func TestDurableWriteFailsWhenTheMountIsMissing(t *testing.T) {
	err := WriteDurable(filepath.Join(t.TempDir(), "does-not-exist"), "p", "x")
	if err == nil {
		t.Fatal("expected a failure when the policy directory is absent")
	}
	if !strings.Contains(err.Error(), "bind-mounted") {
		t.Fatalf("the error should name the likely cause, got: %v", err)
	}
}

// An unconfigured directory is the engine's case when it has no Tetragon mount:
// it must report, not write somewhere arbitrary.
func TestDurableWriteRefusesAnEmptyDir(t *testing.T) {
	if err := WriteDurable("", "p", "x"); err == nil {
		t.Fatal("expected a failure when no durable directory is configured")
	}
}
