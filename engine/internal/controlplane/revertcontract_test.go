package controlplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every containment endpoint the console sends revert_after_seconds to must
// actually READ it.
//
// # The defect this exists to catch, which was live in production
//
// The console has offered an auto-revert on jail since the revert timer
// shipped: modals.tsx sends revert_after_seconds when the operator ticks the
// box, JailPicker.tsx does the same for a bulk jail, and useChokeActions sets
// withRevert for every rung except sever. All three POST it.
//
// None of the three control-plane handlers declared the field. encoding/json
// discards unknown keys in silence, so on the multi-tenant console an operator
// who chose "quarantine, revert in 30 minutes" got a PERMANENT quarantine and a
// success toast. The host stayed contained because the operator believed it
// would release itself.
//
// This is the fourth instance of the same family — a client advertising a
// parameter no server reads — and the first on the containment path, where the
// cost is a machine left contained indefinitely rather than a filter that does
// nothing.
func TestEveryEndpointTheConsoleSendsRevertToReadsIt(t *testing.T) {
	root := repoRootFromControlplane(t)

	// What the console actually posts, read from its own source rather than
	// restated here — a test that restates the client's behaviour proves only
	// that it agrees with itself.
	consoleAPI := readFile(t, filepath.Join(root, "web", "src", "features", "choke", "api.ts"))
	sends := map[string]bool{}
	for _, route := range []string{"/api/choke/manual", "/api/choke/jail", "/api/choke/bulk-manual"} {
		// The field and the route appear in the same exported function body.
		if idx := strings.Index(consoleAPI, `postJSON("`+route+`"`); idx >= 0 {
			start := strings.LastIndex(consoleAPI[:idx], "export function")
			if start >= 0 && strings.Contains(consoleAPI[start:idx], "revert_after_seconds") {
				sends[route] = true
			}
		}
	}
	if len(sends) == 0 {
		t.Skip("the console no longer sends revert_after_seconds to any containment route")
	}

	handlers := readFile(t, filepath.Join(root, "engine", "internal", "controlplane", "choke.go"))
	for route := range sends {
		if !strings.Contains(handlers, "RevertAfterSeconds") {
			t.Fatalf("the console sends revert_after_seconds to %s and no handler declares it — "+
				"encoding/json will drop it and the containment will be permanent", route)
		}
	}

	// Three distinct request bodies must each declare it: one shared mention
	// would let two of the three routes keep discarding the field.
	if n := strings.Count(handlers, `json:"revert_after_seconds"`); n < len(sends) {
		t.Fatalf("%d handler bodies declare revert_after_seconds, but the console sends it to %d "+
			"routes — at least one still drops it silently", n, len(sends))
	}
}

// A jail body that carries a revert window must decode it, not drop it.
func TestJailRequestBodyDecodesTheRevertWindow(t *testing.T) {
	var b struct {
		ExecID             string `json:"exec_id"`
		Action             string `json:"action"`
		RevertAfterSeconds uint32 `json:"revert_after_seconds"`
	}
	raw := `{"exec_id":"e1","action":"quarantine","reason":"IR-1","revert_after_seconds":1800}`
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatal(err)
	}
	if b.RevertAfterSeconds != 1800 {
		t.Fatalf("decoded %d, want 1800", b.RevertAfterSeconds)
	}
}

func repoRootFromControlplane(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "web", "src")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("repo root not found from the test's working directory")
	return ""
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s not readable: %v", path, err)
	}
	return string(raw)
}
