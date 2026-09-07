package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/api/openapi.yaml is what an integrating team builds against, and it is
// generated from this package's handler doc comments and decoded structs (see
// scripts/ci/gen-openapi.py). That makes it easy to fix a wire contract in the
// code and leave the published one describing the old behaviour — which is how
// the targeting defect reached the console in the first place: the spec
// documented the fleet writes as {name, reason}, so the selected-host list the
// console was sending appeared in no contract anywhere.
//
// This test pins the published spec to the contract the handlers now enforce.
// It fails when a regeneration drops the targeting semantics from a fleet write
// — the fix is to restore the handler doc comment (or the decoded struct field)
// and re-run ./scripts/ci/gen-openapi.py, not to edit the YAML.
func TestOpenAPIDocumentsFleetWriteTargeting(t *testing.T) {
	spec := findOpenAPISpec(t)
	if spec == "" {
		t.Skip("docs/api/openapi.yaml not found; run ./scripts/ci/gen-openapi.py")
	}
	raw, err := os.ReadFile(spec)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	for _, path := range []string{
		"/api/fleet/preset",
		"/api/fleet/thresholds",
		"/api/fleet/kill-switch",
		"/api/fleet/thaw",
		"/api/fleet/device-jail",
	} {
		t.Run(path, func(t *testing.T) {
			block := openAPIPathBlock(doc, path)
			if block == "" {
				t.Fatalf("%s is not in the spec at all", path)
			}
			if !strings.Contains(block, "targets") {
				t.Errorf("%s does not document \"targets\" anywhere. An operator "+
					"scoping a write to one host is following a contract that is "+
					"published nowhere; regenerate the spec after documenting it.", path)
			}
		})
	}

	// The engine's own fan-out handlers are the ones this package owns, so their
	// doc comments — the only place the generator can learn about a body it
	// never decodes into a struct — must carry the whole rule, refusals
	// included.
	for _, path := range []string{"/api/fleet/kill-switch", "/api/fleet/device-jail"} {
		// The generator re-wraps descriptions at 74 columns, so a phrase can
		// straddle a line break. Collapse whitespace before matching, or this
		// test fails on formatting rather than on meaning.
		block := strings.Join(strings.Fields(openAPIPathBlock(doc, path)), " ")
		for _, want := range []string{
			"every peer in the hosts file", // absent/null is still estate-wide
			"exactly those peers",          // a named list is not a hint
			"refused 400",                  // empty list, unknown name, unreadable body
			"stripped",                     // targets never reaches the peer
		} {
			if !strings.Contains(block, want) {
				t.Errorf("%s does not publish %q — the fan-out's refusals are "+
					"invisible to an integrator, who will read a 400 as an outage", path, want)
			}
		}
	}
}

// openAPIPathBlock returns the YAML under one path key, up to the next path key.
// The spec has no anchors or merges, so this is enough to keep one path's
// assertions from passing on a neighbour's text.
func openAPIPathBlock(doc, path string) string {
	start := strings.Index(doc, "\n  \""+path+"\":\n")
	if start < 0 {
		return ""
	}
	rest := doc[start+1:]
	if next := strings.Index(rest[1:], "\n  \"/"); next >= 0 {
		return rest[:next+1]
	}
	return rest
}

// findOpenAPISpec walks up from the package directory to the repo root.
func findOpenAPISpec(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		p := filepath.Join(dir, "docs", "api", "openapi.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
