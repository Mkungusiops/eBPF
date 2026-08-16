package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Tool is one read-only capability offered to the model.
//
// method is UNEXPORTED and there is no exported constructor that sets anything
// but GET. This is the first of the three read-only layers described in doc.go:
// a caller outside this package cannot express "a tool that POSTs", so the
// unsafe state is not merely rejected, it is unrepresentable.
type Tool struct {
	// Name is what the model calls. Stable: it appears in saved transcripts.
	Name string
	// Description tells the model when to reach for it. Written for a reader
	// who cannot see the code.
	Description string
	// Params is the JSON Schema for the tool's arguments.
	Params map[string]any

	// method is always http.MethodGet. See NewReadTool.
	method string
	// path is the engine endpoint this tool reads.
	path string
	// build turns validated arguments into the request's variable parts.
	//
	// It returns a PATH SUFFIX and a QUERY separately rather than one string,
	// because /api/process/{exec_id} needs the former and /api/alerts needs the
	// latter. Collapsing them into one return forced a sentinel to tell them
	// apart, which is the kind of cleverness that later becomes a path-traversal
	// bug. The suffix is appended to the tool's fixed path and is expected to be
	// already escaped by the builder.
	build func(args map[string]any) (suffix, query string, err error)
}

// Method and Path expose the immutable request shape for auditing and tests.
func (t Tool) Method() string { return t.method }
func (t Tool) Path() string   { return t.path }

// NewReadTool is the ONLY way to construct a Tool. It hard-codes GET.
//
// There is deliberately no NewWriteTool, and no exported field that would let a
// caller change the method afterwards. Adding one would defeat the entire
// package: see doc.go.
func NewReadTool(name, description, path string, params map[string]any, build func(map[string]any) (string, string, error)) Tool {
	if params == nil {
		params = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	if build == nil {
		build = func(map[string]any) (string, string, error) { return "", "", nil }
	}
	return Tool{
		Name:        name,
		Description: description,
		Params:      params,
		method:      http.MethodGet,
		path:        path,
		build:       build,
	}
}

// Containment endpoints. Registering a tool against any of these is a build
// failure, not a runtime error.
//
// This list is asserted COMPLETE against the served API surface by
// TestDenylistCoversEveryContainmentRoute: adding a new containment route
// without adding it here breaks the build. That direction matters — the danger
// is not a tool pointed at a known-bad path, it is a NEW bad path appearing and
// nobody remembering this package exists.
var containmentPaths = []string{
	"/api/choke/kill-switch",
	"/api/choke/device-kill-switch",
	"/api/fleet/kill-switch",
	"/api/choke/jail",
	"/api/choke/device-jail",
	"/api/fleet/device-jail",
	"/api/choke/bulk-manual",
	"/api/choke/manual",
	"/api/choke/thaw",
	"/api/choke/device-thaw",
	"/api/choke/device-mode",
	"/api/choke/mode",
	"/api/choke/preset",
	"/api/choke/thresholds",
	"/api/choke/forget",
	"/api/choke/annotate",
	"/api/choke/policy/preview",
	// Fleet-wide variants. These were MISSED by the hand-written list and found
	// by TestDenylistCoversEveryContainmentRoute once its regex was fixed —
	// which is the entire argument for having that test. They are the most
	// dangerous entries here: a fleet preset or threshold change applies across
	// every host at once.
	"/api/fleet/preset",
	"/api/fleet/thaw",
	"/api/fleet/thresholds",
}

// Errors from Register. Distinct so the ratchet test can assert WHICH rule
// fired rather than merely that registration failed.
var (
	ErrNotReadOnly    = errors.New("assistant: tool is not read-only")
	ErrContainment    = errors.New("assistant: tool targets a containment endpoint")
	ErrNotAllowlisted = errors.New("assistant: tool path is not on the read allowlist")
	ErrDuplicate      = errors.New("assistant: tool already registered")
)

// readAllowlist is a positive list, which is the half that survives a mistake.
// A denylist alone fails open: a containment route added tomorrow under a name
// nobody predicted would pass a denylist check and be reachable. Requiring an
// explicit allowlist entry means a new endpoint is invisible to the assistant
// until someone deliberately adds it here.
var readAllowlist = []string{
	"/api/alerts",
	"/api/alert-stats",
	"/api/events",
	"/api/decisions",
	"/api/process/",
	"/api/choke/processes",
	"/api/mitre",
}

// Registry holds the tools the model may call. Safe for concurrent use.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

func NewRegistry() *Registry { return &Registry{tools: make(map[string]Tool)} }

// Register admits a tool, or refuses with a reason.
//
// Every check is a hard failure. There is no "warn and continue": a tool that
// looked unsafe and was registered anyway is the outcome this package exists to
// make impossible.
func (r *Registry) Register(t Tool) error {
	if t.method != http.MethodGet {
		return fmt.Errorf("%w: %s uses %s", ErrNotReadOnly, t.Name, t.method)
	}
	for _, p := range containmentPaths {
		if t.path == p || strings.HasPrefix(t.path, p+"/") {
			return fmt.Errorf("%w: %s -> %s", ErrContainment, t.Name, t.path)
		}
	}
	if !allowlisted(t.path) {
		return fmt.Errorf("%w: %s -> %s", ErrNotAllowlisted, t.Name, t.path)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.tools[t.Name]; dup {
		return fmt.Errorf("%w: %s", ErrDuplicate, t.Name)
	}
	r.tools[t.Name] = t
	return nil
}

// MustRegister panics on refusal. Used at wiring time so a mistake fails the
// process at startup rather than surfacing mid-incident.
func (r *Registry) MustRegister(t Tool) {
	if err := r.Register(t); err != nil {
		panic(err)
	}
}

func allowlisted(path string) bool {
	for _, p := range readAllowlist {
		if path == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}

// List returns the registered tools, name-sorted for a stable prompt. An
// unstable tool order changes the prompt, which changes the model's output for
// an unchanged question — and an assistant whose answer drifts with map
// iteration order cannot be reasoned about during an incident.
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// Call executes a registered tool against the engine's own API.
//
// The doer is expected to be readOnlyClient (see provider.go), which is the
// third read-only layer: even if this function were changed to build a POST,
// the transport refuses it.
func (r *Registry) Call(ctx context.Context, doer *http.Client, base, cookie, name string, args map[string]any) (json.RawMessage, error) {
	t, ok := r.Get(name)
	if !ok {
		return nil, fmt.Errorf("assistant: unknown tool %q", name)
	}
	suffix, q, err := t.build(args)
	if err != nil {
		return nil, fmt.Errorf("assistant: tool %s: %w", name, err)
	}
	// A builder must never be able to walk out of its own endpoint. Even though
	// every suffix is escaped at construction, re-check here: this is the only
	// place a tool's fixed path and its variable part are joined.
	if strings.Contains(suffix, "..") || strings.Contains(suffix, "/") {
		return nil, fmt.Errorf("assistant: tool %s: illegal path suffix %q", name, suffix)
	}
	url := strings.TrimRight(base, "/") + t.path + suffix
	if q != "" {
		url += "?" + q
	}
	req, err := http.NewRequestWithContext(ctx, t.method, url, nil)
	if err != nil {
		return nil, err
	}
	// The asking analyst's session. Without it these calls are unauthenticated
	// and the engine correctly refuses them; with it the assistant inherits the
	// caller's authorization exactly. See Runner.Cookie.
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("assistant: tool %s: upstream %d", name, resp.StatusCode)
	}
	var out json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("assistant: tool %s: %w", name, err)
	}
	return out, nil
}
