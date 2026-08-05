package mitre_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/mitre"
)

// metadataName pulls `name:` out of a tracing policy's metadata block — the
// two-space indent is what distinguishes it from the nested names further down
// each YAML (matchBinaries entries, selectors).
var metadataName = regexp.MustCompile(`(?m)^ {2}name:\s*"?([a-zA-Z0-9._-]+)"?`)

// TestEveryShippedPolicyIsMapped is the guard on the defect this package was
// created for: the console derives ATT&CK coverage by joining
// event.policy_name → policy.mitre, so a policy that ships without a mapping
// produces telemetry that can never be attributed to a technique. The console
// renders that as "no techniques observed", which is indistinguishable from a
// quiet window — a silent blind spot rather than a visible gap.
//
// `override-credential-read` shipped unmapped for exactly this reason.
func TestEveryShippedPolicyIsMapped(t *testing.T) {
	// engine/internal/mitre → repo root.
	dir := filepath.Join("..", "..", "..", "policies")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read policy dir: %v", err)
	}

	found := 0
	for _, entry := range entries {
		// Only the top level: policies/choke/* are choke-gateway policies (a
		// different DSL) and describe enforcement, not detection.
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		match := metadataName.FindSubmatch(body)
		if match == nil {
			t.Errorf("%s: no metadata.name found", entry.Name())
			continue
		}
		found++
		name := string(match[1])
		meta, ok := mitre.Lookup(name)
		if !ok {
			t.Errorf("policy %q (%s) has no ATT&CK mapping: telemetry from it can never be attributed", name, entry.Name())
			continue
		}
		if meta.Technique == "" || !strings.HasPrefix(meta.Technique, "T") {
			t.Errorf("policy %q maps to %q, want a \"Txxxx Name\" technique", name, meta.Technique)
		}
		if meta.Tactic == "" {
			t.Errorf("policy %q has a technique but no tactic", name)
		}
		if meta.File != entry.Name() {
			t.Errorf("policy %q points at file %q, but ships as %q", name, meta.File, entry.Name())
		}
	}

	if found == 0 {
		t.Fatal("no tracing policies found; the mapping guard would pass vacuously")
	}
}

// TestUnmappedPolicyYieldsNothing pins the deliberate behaviour for a policy
// this build has never heard of: report no technique rather than guess one. A
// fleet can load policies newer than the server reading their telemetry.
func TestUnmappedPolicyYieldsNothing(t *testing.T) {
	if _, ok := mitre.Lookup("some-future-policy"); ok {
		t.Fatal("unknown policy reported as mapped")
	}
	if got := mitre.Technique("some-future-policy"); got != "" {
		t.Fatalf("Technique(unknown) = %q, want empty", got)
	}
	if got := mitre.Tactic("some-future-policy"); got != "" {
		t.Fatalf("Tactic(unknown) = %q, want empty", got)
	}
}
