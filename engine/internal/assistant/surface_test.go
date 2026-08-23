package assistant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests pin three defects that were live in production and were invisible
// in every existing test, because each one produced a CONFIDENT, WELL-FORMED,
// WRONG answer rather than an error.

// TestAlertStatisticsAsksTheWindowTheServerActuallyReads is the important one.
//
// The tool advertised a `span` argument ("24h", "7d") and put it on the query
// string verbatim. Neither server has ever read `span` — both read `window_min`,
// in minutes — so every trend answer was computed over the server's 30-minute
// default while the model believed it had asked for a day, and narrated it that
// way. The trace looked right. The citation looked right. The window was wrong.
//
// No prompt can fix that, which is why it is pinned here rather than trusted to
// review.
func TestAlertStatisticsAsksTheWindowTheServerActuallyReads(t *testing.T) {
	tl, ok := DefaultTools().Get("alert_statistics")
	if !ok {
		t.Fatal("alert_statistics is not registered")
	}

	for _, tc := range []struct {
		span    string
		wantMin string
	}{
		{"", "1440"}, // default is a day, and it is REQUESTED, not assumed
		{"30m", "30"},
		{"6h", "360"},
		{"24h", "1440"},
		{"7d", "10080"},
		{"90d", "10080"}, // clamped to what the endpoint will honour
	} {
		args := map[string]any{}
		if tc.span != "" {
			args["span"] = tc.span
		}
		_, query, err := tl.build(args)
		if err != nil {
			t.Fatalf("span %q: %v", tc.span, err)
		}
		q, err := url.ParseQuery(query)
		if err != nil {
			t.Fatalf("span %q: unparseable query %q", tc.span, query)
		}
		if got := q.Get("window_min"); got != tc.wantMin {
			t.Errorf("span %q: window_min = %q, want %q", tc.span, got, tc.wantMin)
		}
		if q.Has("span") {
			t.Errorf("span %q: the tool still sends `span`, which no server reads", tc.span)
		}
	}
}

// An unreadable span must be an ERROR the model sees, never a silent fallback.
// Quietly substituting a different window is exactly how the original bug
// produced confident answers about the wrong day.
func TestAlertStatisticsRefusesAnUnreadableSpan(t *testing.T) {
	tl, _ := DefaultTools().Get("alert_statistics")
	for _, bad := range []string{"yesterday", "-3h", "0h", "lots"} {
		if _, _, err := tl.build(map[string]any{"span": bad}); err == nil {
			t.Errorf("span %q was accepted; the model would be told a window it did not get", bad)
		}
	}
}

// TestEveryAllowlistedPathIsServed catches the /api/mitre class of defect: an
// entry on the read allowlist for a route that does not exist.
//
// A phantom allowlist entry is not harmless. `/api/mitre` sat here for months
// while the shared prompt told the model to reason about ATT&CK coverage, so
// the model was invited to answer from a capability nothing could deliver.
func TestEveryAllowlistedPathIsServed(t *testing.T) {
	spec := findOpenAPI(t)
	if spec == "" {
		t.Skip("docs/api/openapi.yaml not found; run `make api-docs`")
	}
	raw, err := readFile(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range readAllowlist {
		// A prefix entry (/api/process/) appears in the spec with its parameter
		// segment, so match the stem.
		stem := strings.TrimSuffix(p, "/")
		if !strings.Contains(raw, `"`+stem+`"`) && !strings.Contains(raw, `"`+stem+`/`) {
			t.Errorf("read allowlist names %s, which the API does not serve — "+
				"the assistant is allowed to reach a route that does not exist", p)
		}
	}
}

// TestEveryToolPathIsAllowlisted and its converse: no allowlist entry should be
// dead weight either. A path nobody reads is a widened surface bought for
// nothing.
func TestNoAllowlistEntryIsUnused(t *testing.T) {
	used := map[string]bool{}
	for _, tl := range DefaultTools().List() {
		used[tl.Path()] = true
	}
	for _, p := range readAllowlist {
		if !used[p] {
			t.Errorf("read allowlist names %s but no tool reads it — remove it, or the "+
				"assistant's reachable surface is wider than its actual capability", p)
		}
	}
}

// TestEverySurfaceOffersTheConversationalAgent.
//
// Whatever else a panel offers, the analyst must always be able to just ask.
// A surface whose agent list came back without the conversational agent would
// hand the console a composer wired to a fixed-task button — the original bug,
// reintroduced through the filter rather than through list position.
func TestEverySurfaceOffersTheConversationalAgent(t *testing.T) {
	for _, id := range append(SurfaceIDs(), "", "an-unknown-surface") {
		list := AgentsFor(id)
		if len(list) == 0 {
			t.Errorf("surface %q offers no agents at all", id)
			continue
		}
		if !list[0].Conversational {
			t.Errorf("surface %q offers %q first, which is a fixed-task button", id, list[0].ID)
		}
		var n int
		for _, a := range list {
			if a.Conversational {
				n++
			}
		}
		if n != 1 {
			t.Errorf("surface %q offers %d conversational agents, want exactly 1", id, n)
		}
	}
}

// The assurance surfaces must offer an agent that can actually be answered
// there. This is the defect the surface work exists to close: Devices and Choke
// Assurance mounted an assistant whose every button asked about a process
// chain, over panels that have no process chain on screen.
func TestAssuranceSurfacesOfferAnAgentThatFitsThem(t *testing.T) {
	for surface, wantAgent := range map[string]string{
		"devices":           "assess-device-exposure",
		"devices-assurance": "assess-device-exposure",
		"choke-assurance":   "assess-containment",
	} {
		var found bool
		for _, a := range AgentsFor(surface) {
			if a.ID == wantAgent {
				found = true
			}
			// And the inverse: a process-chain button must not appear where
			// there is no process.
			if a.ID == "explain-chain" {
				t.Errorf("surface %q offers explain-chain; there is no process chain on that panel", surface)
			}
		}
		if !found {
			t.Errorf("surface %q does not offer %q", surface, wantAgent)
		}
	}
}

// TestSurfaceBriefingReachesTheModel proves the framing is actually delivered.
// A briefing that is computed and dropped is worse than none, because the code
// reads as though the model knows where it is.
func TestSurfaceBriefingReachesTheModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	p := &capturingProvider{}
	run := &Runner{
		Provider: p,
		Tools:    DefaultTools(),
		Client:   NewReadOnlyClient(5*time.Second, nil),
		BaseURL:  srv.URL,
		Surface:  "devices-assurance",
		MaxCalls: 2,
	}
	if _, err := run.Run(context.Background(), "ask", "what is exposed?", ""); err != nil {
		t.Fatal(err)
	}
	if len(p.seen) == 0 {
		t.Fatal("provider was never called")
	}
	system := p.seen[0][0]
	if system.Role != "system" {
		t.Fatalf("first message is %q, not the system prompt", system.Role)
	}
	if !strings.Contains(system.Content, "Devices Assurance") {
		t.Error("the surface briefing never reached the model; it does not know which panel it is on")
	}
	// The agent's own task must still be present — the briefing frames, it does
	// not replace.
	if !strings.Contains(system.Content, "Answer the analyst's question") {
		t.Error("the surface briefing displaced the agent's instructions")
	}
}

// TestAgentInstructionsOutrankTheSurfaceBriefing pins an ORDERING that shipped
// backwards for one afternoon and re-broke a fixed bug.
//
// With the briefing appended AFTER the agent's instructions it was the last
// thing the model read, so on the Devices Assurance panel "Hello" returned a
// device-plane posture report: the briefing's "lead with the arming state"
// outranked the `ask` agent's explicit greeting clause. That is exactly the
// defect f451eb1 fixed, reintroduced through a different door — and it was
// invisible to every unit test, because the prompt was still perfectly
// well-formed.
//
// The rule: WHERE YOU ARE is context and reads first. WHAT TO DO is the task
// and reads last, so it wins.
func TestAgentInstructionsOutrankTheSurfaceBriefing(t *testing.T) {
	for _, id := range SurfaceIDs() {
		sf, ok := SurfaceFor(id)
		if !ok {
			t.Fatalf("surface %q did not resolve", id)
		}
		for _, ag := range AgentsFor(id) {
			// The REAL builder, not a copy of it. A test that reassembles the
			// prompt itself proves only that the test agrees with the test.
			system := (&Runner{Surface: id}).systemPrompt(ag)
			brief := strings.Index(system, sf.Briefing)
			task := strings.LastIndex(system, "TASK:")
			if brief < 0 {
				t.Errorf("surface %q agent %q: briefing missing", id, ag.ID)
				continue
			}
			if task < 0 {
				t.Errorf("surface %q agent %q: no TASK: in the instructions", id, ag.ID)
				continue
			}
			if brief > task {
				t.Errorf("surface %q agent %q: the panel briefing reads AFTER the agent's task, "+
					"so it outranks it — this is how \"Hello\" became a posture report", id, ag.ID)
			}
		}
	}
}

// An unknown surface must degrade, not fail. The console and the engine deploy
// separately and will skew.
func TestUnknownSurfaceDegradesRatherThanFailing(t *testing.T) {
	if _, ok := SurfaceFor("a-panel-from-a-newer-console"); ok {
		t.Fatal("an unknown surface resolved")
	}
	if got := AgentsFor("a-panel-from-a-newer-console"); len(got) == 0 {
		t.Error("an unknown surface offered no agents; a version skew would break the assistant")
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

type capturingProvider struct{ seen [][]Message }

func (c *capturingProvider) Name() string { return "capturing" }

func (c *capturingProvider) Complete(_ context.Context, msgs []Message, _ []Tool) (Message, error) {
	snapshot := make([]Message, len(msgs))
	copy(snapshot, msgs)
	c.seen = append(c.seen, snapshot)
	// First turn: call a tool, so the answer counts as grounded. Second turn:
	// answer.
	if len(c.seen) == 1 {
		var m Message
		var tc ToolCall
		tc.ID = "1"
		tc.Type = "function"
		tc.Function.Name = "list_devices"
		tc.Function.Arguments = "{}"
		m.Role = "assistant"
		m.ToolCalls = []ToolCall{tc}
		return m, nil
	}
	return Message{Role: "assistant", Content: "ok"}, nil
}

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p) //nolint:gosec // repo-relative test fixture
	return string(b), err
}

// TestEveryAgentCarriesTheCitationRule pins a clause that encodes a MEASURED
// production failure, so it cannot be tidied away by someone shortening the
// prompt.
//
// On the live rig, asked how many critical alerts there were in 24 hours,
// gpt-oss:120b answered "...policy_stats shows no single rule dominates" having
// called exactly one tool: alert_statistics. It never ran policy_stats.
//
// Answer.Grounded was true, and correctly so — the answer WAS built on a real
// read. Grounding catches "the model read nothing"; it cannot catch "the model
// read one thing and attributed a second claim to a source it never opened".
// That second failure is the more dangerous one on a SOC console, because it
// arrives wearing a citation.
func TestEveryAgentCarriesTheCitationRule(t *testing.T) {
	for _, a := range Agents() {
		if !strings.Contains(a.Instructions, "NEVER CITE A TOOL YOU DID NOT CALL") {
			t.Errorf("agent %q has lost the citation rule; it may attribute claims to tools it never ran", a.ID)
		}
	}
}

// TestSurfaceBriefingsDescribeRatherThanInstruct is the durable guard for a bug
// that survived a prompt reorder.
//
// The briefings originally carried imperatives — "lead with the arming state",
// "start from process_tree" — duplicated from the task agents that already say
// so. The effect was that "Hello" on the Devices Assurance panel returned a
// device-plane posture report, because the briefing's instruction outranked the
// `ask` agent's explicit greeting clause.
//
// Moving the briefing earlier in the prompt did NOT fix it. That is the lesson:
// the problem was never ordering. An instruction competes with an instruction
// wherever it sits, so the fix is to stop putting instructions in the half that
// is supposed to be context.
//
//	surface  → where you are, and what you can read here   (context)
//	agent    → what to do, and when not to do it           (behaviour)
func TestSurfaceBriefingsDescribeRatherThanInstruct(t *testing.T) {
	// Second-person and imperative openers that tell the model HOW to answer.
	// Deliberately a short, high-signal list: a briefing has to describe a panel
	// and name some tools, and almost nothing else it might legitimately say
	// looks like these.
	banned := []string{
		"lead with", "start with", "start from", "answer with",
		"do not answer", "be explicit", "say so", "use this for",
		"rather than", "before saying", "so lead", "check this before",
	}
	for _, id := range SurfaceIDs() {
		sf, _ := SurfaceFor(id)
		low := strings.ToLower(sf.Briefing)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("surface %q briefing contains the instruction %q — briefings describe "+
					"WHERE the analyst is and WHAT can be read there; how to answer belongs to "+
					"the agent, or it overrides clauses like the greeting exception", id, b)
			}
		}
		// A briefing that names no tool is not doing its other job.
		if !strings.Contains(low, "tools that read this subject") {
			t.Errorf("surface %q briefing names no tools for its subject", id)
		}
	}
}

// TestAGreetingSurvivesTheGroundingGuard covers a conflict between two rules
// that were each individually correct.
//
// The `ask` agent is told to greet a greeting like a colleague would, which
// requires calling no tools. An answer with no tool calls was then treated as
// ungrounded and replaced with a refusal. Measured live: typing "Hello" returned
// "The assistant could not ground an answer in this engine's data… an unverified
// answer is not evidence." The operator is scolded for saying hello by something
// that looks broken.
func TestAGreetingSurvivesTheGroundingGuard(t *testing.T) {
	ans := runNoToolAnswer(t, "ask", "Hi — fairly quiet right now. What do you want to look at?")
	if strings.Contains(ans.Content, "could not ground") {
		t.Errorf("a claimless greeting was refused: %q", ans.Content)
	}
	// It is still reported as ungrounded, because it IS. The flag stays honest;
	// only the replacement is skipped.
	if ans.Grounded {
		t.Error("a tool-free answer reported itself grounded")
	}
}

// The half that matters more: anything that could be mistaken for evidence is
// still refused. A single digit is enough to disqualify a reply, because every
// fact this assistant could fabricate carries one.
func TestAnUngroundedCLAIMIsStillRefused(t *testing.T) {
	for _, content := range []string{
		"There are 12 critical alerts on web-01 right now.",
		"Host db-02 shows a suspicious chain scoring 117.",
		"No alerts fired between 09:00 and 10:00.",
	} {
		ans := runNoToolAnswer(t, "ask", content)
		if !strings.Contains(ans.Content, "could not ground") {
			t.Errorf("an ungrounded factual claim was returned to the analyst: %q", ans.Content)
		}
	}
	// And a long tool-free reply is refused even with no digits: length means
	// it is an answer, not a greeting.
	long := strings.Repeat("the estate appears calm and nothing looks unusual ", 12)
	if ans := runNoToolAnswer(t, "ask", long); !strings.Contains(ans.Content, "could not ground") {
		t.Error("a long tool-free narrative was returned rather than refused")
	}
}

// A TASK agent must never return a chat reply instead of doing its job.
func TestTaskAgentsNeverGetTheConversationalExemption(t *testing.T) {
	ans := runNoToolAnswer(t, "summarise-incident", "Hello there.")
	if !strings.Contains(ans.Content, "could not ground") {
		t.Errorf("a task agent returned an ungrounded chat reply: %q", ans.Content)
	}
}

// runNoToolAnswer drives a full Run against a provider that never calls a tool,
// so the grounding path is exercised end to end rather than by calling the
// helper directly.
func runNoToolAnswer(t *testing.T, agentID, content string) Answer {
	t.Helper()
	run := &Runner{
		Provider: &silentProvider{content: content},
		Tools:    DefaultTools(),
		Client:   NewReadOnlyClient(5*time.Second, nil),
		BaseURL:  "http://127.0.0.1:1",
		MaxCalls: 3,
	}
	ans, err := run.Run(context.Background(), agentID, "hello", "")
	if err != nil {
		t.Fatal(err)
	}
	return ans
}

// silentProvider answers without ever calling a tool — including after the
// retry the runner issues, which is the path that reaches the guard.
type silentProvider struct{ content string }

func (p *silentProvider) Name() string { return "silent" }
func (p *silentProvider) Complete(context.Context, []Message, []Tool) (Message, error) {
	return Message{Role: "assistant", Content: p.content}, nil
}
