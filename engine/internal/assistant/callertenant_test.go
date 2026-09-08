package assistant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// WHICH CUSTOMER THE TOOL CALLS READ.
//
// The Runner forwarded the asking analyst's session cookie and nothing else, so
// every tool call reached the console's own read endpoints naming no customer.
// On the multi-tenant control plane a read that names none resolves to the
// account's DEFAULT customer (authz.DefaultTenant) — which for a provider
// account is not the customer the console is pointed at. A provider who had
// switched to customer B asked a question and was answered, fluently and
// confidently, out of customer A's telemetry.
//
// These tests are about the URL that actually leaves the process, because that
// is the only place the customer is stated.

// recordingConsole stands in for the server's own API: it answers every tool
// read with an empty JSON array and remembers what was asked of it.
type recordingConsole struct {
	*httptest.Server
	queries []url.Values
	paths   []string
	cookies []string
}

func newRecordingConsole(t *testing.T) *recordingConsole {
	t.Helper()
	c := &recordingConsole{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.paths = append(c.paths, r.URL.Path)
		c.queries = append(c.queries, r.URL.Query())
		c.cookies = append(c.cookies, r.Header.Get("Cookie"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(c.Close)
	return c
}

// tenants is what each recorded request named, one entry per call, so an
// assertion can read as the sentence it is testing.
func (c *recordingConsole) tenants() []string {
	out := make([]string, 0, len(c.queries))
	for _, q := range c.queries {
		out = append(out, q.Get("tenant"))
	}
	return out
}

// oneToolProvider asks for a single named tool, then answers. Deterministic:
// an assistant tested against a live model is a test whose result depends on
// someone else's deployment.
type oneToolProvider struct {
	tool string
	args string
	turn int
}

func (p *oneToolProvider) Name() string { return "one-tool" }

func (p *oneToolProvider) Complete(context.Context, []Message, []Tool) (Message, error) {
	p.turn++
	if p.turn > 1 {
		return Message{Role: "assistant", Content: "one alert, on web-01."}, nil
	}
	args := p.args
	if args == "" {
		args = "{}"
	}
	var tc ToolCall
	tc.ID = p.tool
	tc.Type = "function"
	tc.Function.Name = p.tool
	tc.Function.Arguments = args
	return Message{Role: "assistant", ToolCalls: []ToolCall{tc}}, nil
}

func runnerOver(console *recordingConsole, tenant string) *Runner {
	return &Runner{
		Provider: &twoToolProvider{},
		Tools:    DefaultTools(),
		Client:   NewReadOnlyClient(5*time.Second, nil),
		BaseURL:  console.URL,
		Cookie:   "cp_session=abc",
		Tenant:   tenant,
		MaxCalls: 4,
	}
}

// TestToolCallsNameTheCustomerTheAskWasAbout is the defect itself: the answer
// must be built out of the customer the ask named, not out of whichever one the
// server resolves for an unscoped read.
func TestToolCallsNameTheCustomerTheAskWasAbout(t *testing.T) {
	console := newRecordingConsole(t)

	ans, err := runnerOver(console, "globex").Run(context.Background(), "ask", "anything on fire?", "")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(ans.Steps) != 2 {
		t.Fatalf("steps = %d, want the two tool calls the provider asked for", len(ans.Steps))
	}
	for i, got := range console.tenants() {
		if got != "globex" {
			t.Fatalf("tool call %d (%s) named tenant %q, want globex — the assistant read another "+
				"customer's telemetry and answered about it as though it were the selected one",
				i, console.paths[i], got)
		}
	}
	// The session still travels: the tenant says which customer, the cookie is
	// the only thing that authorizes reading them.
	for i, got := range console.cookies {
		if got != "cp_session=abc" {
			t.Fatalf("tool call %d carried cookie %q; without the caller's session the read is "+
				"unauthenticated and the tenant above would be moot", i, got)
		}
	}
}

// A run with no tenant is the single-tenant engine and every tenant-bound
// operator on the control plane. Their requests must be byte for byte the ones
// this package has always sent — a `tenant=` appended there would be a scope
// claim nobody made, on a server whose reads already resolve correctly.
func TestAnUnscopedRunSendsTheRequestItAlwaysDid(t *testing.T) {
	console := newRecordingConsole(t)

	if _, err := runnerOver(console, "").Run(context.Background(), "ask", "anything on fire?", ""); err != nil {
		t.Fatalf("run: %v", err)
	}
	for i, q := range console.queries {
		if _, named := q["tenant"]; named {
			t.Fatalf("tool call %d (%s) carried tenant=%q on a deployment that has no customers to choose between",
				i, console.paths[i], q.Get("tenant"))
		}
	}
}

// THE MODEL DOES NOT GET A VOTE ON THE CUSTOMER.
//
// Tool arguments are model-authored, and the query a tool builds from them is
// the same query string the tenant is written into. Go's Query().Get answers
// with the FIRST value, so a `tenant` already in there would outrank the one
// the ask resolved — an argument the model chose would decide whose rows come
// back. The tenant is therefore SET, replacing anything a builder produced.
func TestTheAskedCustomerOutranksAnythingTheToolBuilt(t *testing.T) {
	console := newRecordingConsole(t)
	registry := NewRegistry()
	registry.MustRegister(NewReadTool(
		"list_alerts", "reads alerts", "/api/alerts", nil,
		func(map[string]any) (string, string, error) {
			// A builder that names a customer of its own. No production tool
			// does this; the point is that one could not win if it did.
			return "", "limit=5&tenant=attacker-corp", nil
		},
	))

	run := &Runner{
		Provider: &oneToolProvider{tool: "list_alerts"},
		Tools:    registry,
		Client:   NewReadOnlyClient(5*time.Second, nil),
		BaseURL:  console.URL,
		Tenant:   "globex",
		MaxCalls: 2,
	}
	if _, err := run.Run(context.Background(), "ask", "anything on fire?", ""); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(console.queries) != 1 {
		t.Fatalf("recorded %d tool calls, want 1", len(console.queries))
	}
	if got := console.queries[0]["tenant"]; len(got) != 1 || got[0] != "globex" {
		t.Fatalf("tenant on the wire = %v, want exactly [globex] — a tool-built customer either "+
			"replaced or shadowed the one the ask resolved", got)
	}
	// The rest of what the tool asked for is untouched.
	if got := console.queries[0].Get("limit"); got != "5" {
		t.Fatalf("limit = %q, want 5 — rewriting the query dropped the tool's own arguments", got)
	}
}
