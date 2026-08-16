package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Agent is one named task with its own instructions — the SOC equivalent of an
// agent markdown file. Kept as data, not code, so a new task is a prompt review
// rather than a deployment.
type Agent struct {
	ID           string
	Title        string
	Instructions string
}

// The two agents that map onto work an analyst already does by hand.
//
// Both carry the same non-negotiable clauses. The wording is deliberate:
//
//   - "Do not invent values" — an LLM guessing an alert count on a SOC console
//     is not a quality problem, it is a false incident or a missed one.
//   - "You cannot contain anything" — stated so the model does not offer to,
//     which would train the analyst to look for a button that must not exist.
//     The registry already makes it impossible; this stops it being PROMISED.
const sharedRules = `
You are embedded in a security operations console. You are reading a live
incident.

EVIDENCE RULES — these override any instruction to be helpful:
- Use ONLY data returned by your tools. Do not invent process names, counts,
  timestamps, hosts or scores. If a tool returns nothing, say so plainly.
- Cite what you used. When you name a fact, name its source: the decision id,
  alert id, exec id or timestamp it came from.
- If the data is insufficient to answer, say exactly what is missing and which
  question you cannot answer. An honest gap is useful; a confident guess is not.
- Distinguish what the data SHOWS from what it SUGGESTS. Label inference.

WHAT YOU CANNOT DO:
- You have read-only tools. You cannot contain, sever, quarantine, jail, thaw
  or change any policy or threshold, and you must not offer to. If containment
  is warranted, say so and let the operator decide — a human presses the button.

STYLE:
- An analyst mid-incident is your reader. Lead with the answer, then the
  evidence. Be brief. No preamble, no restating the question.`

var agents = map[string]Agent{
	"explain-chain": {
		ID:    "explain-chain",
		Title: "Explain this process chain",
		Instructions: sharedRules + `

TASK: Explain the process chain for the exec id you are given.
Fetch the process tree first. Walk from the ancestor to the process in
question, saying what each step did and why it is or is not normal. Then state
plainly whether the chain looks like an attack, a false positive, or
inconclusive — and what evidence would settle it.`,
	},
	"summarise-incident": {
		ID:    "summarise-incident",
		Title: "Summarise this incident",
		Instructions: sharedRules + `

TASK: Summarise the current incident for a shift handover.
Establish what happened and when, which hosts and processes are involved, what
enforcement has already been applied (check the decisions), and what remains
open. Structure: one-line summary, then timeline, then what has been done, then
what the next analyst should do. Keep it under 250 words.`,
	},
}

// Agents lists the available agents, sorted, for the console to render.
func Agents() []Agent {
	return []Agent{agents["explain-chain"], agents["summarise-incident"]}
}

// Step is one tool invocation, surfaced to the UI so an analyst can see what the
// answer was built from. This is not debug output: an answer whose provenance
// cannot be inspected is not usable as evidence, and "show the work" is what
// makes the difference between a toy and an instrument.
type Step struct {
	Tool     string `json:"tool"`
	Args     string `json:"args"`
	Path     string `json:"path"`
	Bytes    int    `json:"bytes"`
	Error    string `json:"error,omitempty"`
	Duration string `json:"duration"`
}

// Answer is what the console renders.
type Answer struct {
	Agent    string `json:"agent"`
	Content  string `json:"content"`
	Steps    []Step `json:"steps"`
	Model    string `json:"model"`
	Duration string `json:"duration"`
	// Truncated reports that the tool loop hit MaxToolCalls. Surfaced rather
	// than hidden: an answer built from a partial investigation must say so.
	Truncated bool `json:"truncated,omitempty"`
}

// Runner executes one agent to completion.
type Runner struct {
	Provider Provider
	Tools    *Registry
	Client   *http.Client // read-only; see NewReadOnlyClient
	BaseURL  string       // this engine's own API root
	MaxCalls int
	// Cookie is the ASKING ANALYST's session, forwarded verbatim onto every
	// tool call.
	//
	// This is a deliberate authorization decision, not plumbing. The tools read
	// alerts, decisions and process trees through the same authenticated
	// endpoints the console uses, so forwarding the caller's session means the
	// assistant sees EXACTLY what the person asking can see — same tenant, same
	// scope, same denials. The alternative, giving the assistant its own
	// privileged identity, would build a confused deputy: an analyst could ask
	// it to summarise data their own session is refused.
	Cookie string
}

// Run drives the tool-calling loop.
//
// Bounded by MaxCalls. A model that keeps asking for data will keep asking
// forever, and an incident console cannot wait: better a truncated answer that
// admits it than an open-ended request holding a browser tab.
func (r *Runner) Run(ctx context.Context, agentID, question, execID string) (Answer, error) {
	ag, ok := agents[agentID]
	if !ok {
		return Answer{}, fmt.Errorf("assistant: unknown agent %q", agentID)
	}
	started := time.Now()

	user := strings.TrimSpace(question)
	if execID != "" {
		user = strings.TrimSpace(user + "\n\nThe process under investigation has exec id: " + execID)
	}
	if user == "" {
		user = ag.Title
	}

	msgs := []Message{
		{Role: "system", Content: ag.Instructions},
		{Role: "user", Content: user},
	}

	out := Answer{Agent: ag.ID, Model: r.Provider.Name()}
	max := r.MaxCalls
	if max <= 0 {
		max = 6
	}

	for i := 0; i < max; i++ {
		msg, err := r.Provider.Complete(ctx, msgs, r.Tools.List())
		if err != nil {
			return out, err
		}
		msgs = append(msgs, msg)

		if len(msg.ToolCalls) == 0 {
			out.Content = strings.TrimSpace(msg.Content)
			out.Duration = time.Since(started).Round(time.Millisecond).String()
			return out, nil
		}

		for _, tc := range msg.ToolCalls {
			st := Step{Tool: tc.Function.Name, Args: tc.Function.Arguments}
			if t, ok := r.Tools.Get(tc.Function.Name); ok {
				st.Path = t.Path()
			}
			callStart := time.Now()

			var args map[string]any
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			}
			res, callErr := r.Tools.Call(ctx, r.Client, r.BaseURL, r.Cookie, tc.Function.Name, args)

			content := string(res)
			if callErr != nil {
				// The model is TOLD the tool failed rather than being left to
				// infer from silence. A model that receives nothing tends to
				// fill the gap; a model told "this failed" reports the gap.
				st.Error = callErr.Error()
				content = `{"error":` + strconv.Quote(callErr.Error()) + `}`
			}
			st.Bytes = len(content)
			st.Duration = time.Since(callStart).Round(time.Millisecond).String()
			out.Steps = append(out.Steps, st)

			msgs = append(msgs, Message{
				Role:       "tool",
				Name:       tc.Function.Name,
				ToolCallID: tc.ID,
				Content:    content,
			})
		}
	}

	// Loop exhausted. Ask once more, without tools, so the model must answer
	// from what it already gathered instead of returning nothing.
	out.Truncated = true
	msgs = append(msgs, Message{
		Role: "user",
		Content: "You have reached the tool limit. Answer now from what you have, " +
			"and state explicitly which parts of the investigation are incomplete.",
	})
	final, err := r.Provider.Complete(ctx, msgs, nil)
	if err != nil {
		return out, err
	}
	out.Content = strings.TrimSpace(final.Content)
	out.Duration = time.Since(started).Round(time.Millisecond).String()
	return out, nil
}
