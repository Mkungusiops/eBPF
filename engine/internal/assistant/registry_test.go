package assistant

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// This file is the ratchet. It is the exit criterion for the assistant work:
// "a tool that mutates cannot be registered, proven by a failing test rather
// than a convention". Same role as internal/isolationguard.

func TestRegisterRejectsEveryContainmentEndpoint(t *testing.T) {
	// Every containment path, attempted as a READ tool. These are the paths an
	// LLM must never reach even to look at, because a GET here is the operator
	// surface for an action, and admitting one normalises the category.
	for _, p := range containmentPaths {
		r := NewRegistry()
		err := r.Register(NewReadTool("probe", "d", p, nil, nil))
		if !errors.Is(err, ErrContainment) {
			t.Errorf("registering a tool for containment path %s: got %v, want ErrContainment", p, err)
		}
		if len(r.List()) != 0 {
			t.Errorf("registry admitted a containment tool for %s", p)
		}
	}
}

func TestRegisterRejectsAnythingOffTheAllowlist(t *testing.T) {
	// A denylist alone fails open. A path nobody predicted must be refused by
	// default, not admitted by default.
	//
	// `/api/policies` used to be in this list and is now legitimately
	// allowlisted — the assistant needs it to answer ATT&CK coverage questions.
	// It was replaced rather than deleted: this test is only worth anything if
	// it keeps probing paths the engine really serves and the assistant really
	// must not reach.
	for _, p := range []string{
		"/api/run-attack",    // mutating, and it launches attack simulations
		"/api/whoami",        // the caller's identity is not the model's business
		"/api/choke/state",   // reachable-looking, deliberately not allowlisted
		"/api/telemetry",     // the raw firehose
		"/api/verify-chain",  // audit-chain verification, not an analyst read
		"/api/admin/command", // the command plane
		"/",                  // the console shell itself
		"/api/../api/choke/jail",
	} {
		r := NewRegistry()
		if err := r.Register(NewReadTool("probe", "d", p, nil, nil)); err == nil {
			t.Errorf("registry admitted an un-allowlisted path %s", p)
		}
	}
}

func TestEveryRegisteredToolIsGET(t *testing.T) {
	// The real registry, as wired in production.
	r := DefaultTools()
	tools := r.List()
	if len(tools) == 0 {
		t.Fatal("DefaultTools registered nothing — the assistant would be useless and this test vacuous")
	}
	for _, tl := range tools {
		if tl.Method() != http.MethodGet {
			t.Errorf("tool %s uses %s; every assistant tool must be GET", tl.Name, tl.Method())
		}
		if !allowlisted(tl.Path()) {
			t.Errorf("tool %s targets un-allowlisted %s", tl.Name, tl.Path())
		}
		for _, c := range containmentPaths {
			if strings.HasPrefix(tl.Path(), c) {
				t.Errorf("tool %s targets containment path %s", tl.Name, tl.Path())
			}
		}
	}
}

// TestDenylistCoversEveryContainmentRoute is the direction that actually
// protects us over time.
//
// The danger is not a tool pointed at a path we already know is dangerous — the
// checks above cover that. It is a NEW containment route being added months
// from now by someone who has never opened this package, and the allowlist
// quietly not covering it. This test reads the SERVED API surface and fails if
// a containment-shaped route exists that containmentPaths does not name.
func TestDenylistCoversEveryContainmentRoute(t *testing.T) {
	spec := findOpenAPI(t)
	if spec == "" {
		t.Skip("docs/api/openapi.yaml not found; run `make api-docs`")
	}
	raw, err := os.ReadFile(spec) //nolint:gosec // repo-relative test fixture
	if err != nil {
		t.Fatalf("reading %s: %v", spec, err)
	}

	// Paths in the generated spec are QUOTED: `  "/api/choke/jail":`. The quotes
	// are not optional decoration — an earlier version of this regex omitted
	// them, matched nothing, and the test passed while covering zero routes.
	// A completeness test that silently checks an empty set is worse than no
	// test, so TestRatchetItselfIsLoadBearing below asserts it matches.
	pathLine := regexp.MustCompile(`(?m)^\s{2}"?(/[^"\s:]+)"?:`)
	dangerous := regexp.MustCompile(`sever|quarantine|kill-switch|jail|bulk|thaw|preset|threshold|forget|annotate|policy/preview|policies/push|settings/|/mode$|device-mode`)

	known := map[string]bool{}
	for _, p := range containmentPaths {
		known[p] = true
	}

	var missing []string
	for _, m := range pathLine.FindAllStringSubmatch(string(raw), -1) {
		p := m[1]
		if !dangerous.MatchString(p) || known[p] {
			continue
		}
		// Only mutating routes matter; a read-only "/api/choke/processes" is
		// allowed to exist and is on the read allowlist.
		if isMutating(string(raw), p) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		t.Errorf("containment routes not covered by containmentPaths: %v\n"+
			"A new containment endpoint was added without updating internal/assistant. "+
			"Add it to containmentPaths so the assistant can never be pointed at it.", missing)
	}
}

// isMutating reports whether the spec block for path p declares a mutating verb.
func isMutating(spec, p string) bool {
	i := strings.Index(spec, "\n  \""+p+"\":")
	if i < 0 {
		i = strings.Index(spec, "\n  "+p+":")
	}
	if i < 0 {
		return false
	}
	rest := spec[i+1:]
	// The block ends at the next path at the same indent.
	if j := regexp.MustCompile(`(?m)^\s{2}"?/[^"\s:]+"?:`).FindStringIndex(rest[1:]); j != nil {
		rest = rest[:j[0]+1]
	}
	return regexp.MustCompile(`(?m)^\s{4}(post|put|patch|delete):`).MatchString(rest)
}

func findOpenAPI(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 6; i++ {
		p := filepath.Join(dir, "docs", "api", "openapi.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

func TestReadOnlyClientRefusesMutatingRequests(t *testing.T) {
	// The third layer: even a request built by hand inside this package cannot
	// mutate. This is what makes read-only structural rather than procedural.
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewReadOnlyClient(5*time.Second, nil)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req, err := http.NewRequest(m, srv.URL+"/api/choke/jail", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err == nil {
			// Reached only on a FAILING assertion — the transport is supposed
			// to refuse every one of these — but close it anyway so the failure
			// mode is one clean error rather than an error plus a leaked
			// connection that makes the next subtest flaky.
			_ = resp.Body.Close()
			t.Errorf("%s was allowed through the read-only client", m)
		}
	}
	if reached {
		t.Error("a mutating request reached the server; the transport guard did not hold")
	}

	// A GET must still work, or the guard is useless in a different way.
	resp, err := c.Get(srv.URL + "/api/alerts")
	if err != nil {
		t.Errorf("GET through the read-only client failed: %v", err)
	} else {
		_ = resp.Body.Close()
	}
}

func TestRegistryRejectsDuplicates(t *testing.T) {
	r := NewRegistry()
	tl := NewReadTool("alerts", "d", "/api/alerts", nil, nil)
	if err := r.Register(tl); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(tl); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate registration: got %v, want ErrDuplicate", err)
	}
}

func TestListIsStablySorted(t *testing.T) {
	// An unstable tool order changes the prompt, which changes the answer to an
	// unchanged question. During an incident that is indistinguishable from the
	// data having changed.
	r := DefaultTools()
	first := r.List()
	for i := 0; i < 8; i++ {
		got := r.List()
		for j := range got {
			if got[j].Name != first[j].Name {
				t.Fatalf("tool order is not stable: %s != %s", got[j].Name, first[j].Name)
			}
		}
	}
}

func TestAPIKeyIsNeverInConfigStruct(t *testing.T) {
	// Config carries the NAME of the env var, never the key. This test exists
	// because "just add an APIKey field" is the obvious refactor and it would
	// put a live credential into anything that serialises Config — config
	// files, support bundles, /api/version.
	cfg := DefaultConfig()
	if cfg.APIKeyEnv != "OPEN_WEIGHT_API_KEY" {
		t.Errorf("APIKeyEnv = %q", cfg.APIKeyEnv)
	}
	t.Setenv("OPEN_WEIGHT_API_KEY", "ow_test_value")
	if got := cfg.APIKey(); got != "ow_test_value" {
		t.Errorf("APIKey() = %q", got)
	}
	// And redaction must actually redact.
	if out := redact("upstream said ow_test_value is bad", "ow_test_value"); strings.Contains(out, "ow_test_value") {
		t.Errorf("redact left the key in place: %q", out)
	}
}

func TestDisabledByDefault(t *testing.T) {
	// A security product must not acquire an outbound dependency on a
	// third-party inference endpoint because someone upgraded.
	if DefaultConfig().Enabled() {
		t.Error("assistant is enabled by default; it must be opt-in")
	}
}

// TestRatchetItselfIsLoadBearing guards the guard.
//
// TestDenylistCoversEveryContainmentRoute passed for a while against ZERO
// parsed paths, because its regex did not allow for the quoted keys the
// generator emits. It was green, and it was checking nothing. A completeness
// check that silently examines an empty set is worse than no check, because it
// buys confidence it has not earned.
//
// So: assert the parse actually sees the surface, and that a denylist with a
// hole in it is detected.
func TestRatchetItselfIsLoadBearing(t *testing.T) {
	spec := findOpenAPI(t)
	if spec == "" {
		t.Skip("docs/api/openapi.yaml not found; run `make api-docs`")
	}
	raw, err := os.ReadFile(spec) //nolint:gosec // repo-relative test fixture
	if err != nil {
		t.Fatal(err)
	}
	pathLine := regexp.MustCompile(`(?m)^\s{2}"?(/[^"\s:]+)"?:`)
	found := pathLine.FindAllStringSubmatch(string(raw), -1)
	if len(found) < 50 {
		t.Fatalf("parsed only %d paths from the spec; the regex has stopped matching "+
			"and every completeness check built on it is vacuous", len(found))
	}

	// Every path this package claims is containment must actually appear in the
	// served surface. A stale entry is harmless; a MISSING one is the failure.
	inSpec := map[string]bool{}
	for _, m := range found {
		inSpec[m[1]] = true
	}
	for _, c := range containmentPaths {
		if !inSpec[c] {
			t.Errorf("containmentPaths names %s, which the API does not serve — "+
				"the denylist has drifted from reality", c)
		}
	}

	// And the mutating-verb detector must actually detect.
	if !isMutating(string(raw), "/api/choke/jail") {
		t.Error("isMutating says /api/choke/jail is not mutating; the block parser is broken")
	}
	if isMutating(string(raw), "/api/alerts") {
		t.Error("isMutating says /api/alerts IS mutating; the block parser over-reaches")
	}
}

func TestExactlyOneConversationalAgentExists(t *testing.T) {
	// THE BUG THIS PINS: the sidebar routed free text through explain-chain,
	// whose instruction is "explain this process chain" regardless of what was
	// typed. An analyst who said "Hello" received an unrelated incident
	// analysis, on both the single-tenant and multi-tenant consoles.
	//
	// A chat surface needs exactly one agent to select. Zero and it falls back
	// to a button again; more than one and the choice is arbitrary.
	var conversational []string
	for _, a := range Agents() {
		if a.Conversational {
			conversational = append(conversational, a.ID)
		}
	}
	if len(conversational) != 1 {
		t.Fatalf("found %d conversational agents (%v); a chat surface needs exactly one to select",
			len(conversational), conversational)
	}
}

func TestConversationalAgentIsOfferedFirst(t *testing.T) {
	// Belt and braces for a client that selects by position rather than by flag.
	// The ordering is cheap; a console picking a task agent is not.
	all := Agents()
	if len(all) == 0 {
		t.Fatal("no agents — this test is vacuous")
	}
	if !all[0].Conversational {
		t.Errorf("Agents()[0] is %q, which is not conversational; a client that "+
			"takes the first agent would get a fixed-task button", all[0].ID)
	}
}

func TestTaskAgentsStateTheirTaskAndTheConversationalOneDoesNot(t *testing.T) {
	// The structural difference between a button and a chat agent: a button
	// carries a fixed TASK that overrides the question. If the conversational
	// agent ever grows one, it stops answering what was asked.
	for _, a := range Agents() {
		answersTheQuestion := strings.Contains(a.Instructions, "Answer the analyst's question")
		if a.Conversational && !answersTheQuestion {
			t.Errorf("conversational agent %q does not instruct the model to answer the "+
				"question; it will substitute a task of its own", a.ID)
		}
		if !a.Conversational && answersTheQuestion {
			t.Errorf("task agent %q claims to answer free questions; it is rendered as a "+
				"one-click button with no composer", a.ID)
		}
	}
}
