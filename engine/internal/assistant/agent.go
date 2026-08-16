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
	// Conversational marks the agent that ANSWERS THE ANALYST'S QUESTION rather
	// than performing a fixed task.
	//
	// The distinction is load-bearing, and it was learned the hard way: the
	// sidebar shipped routing free text through explain-chain, whose
	// instruction is "explain this process chain" regardless of what was typed.
	// An analyst who said "Hello" received a process-chain analysis. The
	// task agents are BUTTONS — they take no question — and a chat surface must
	// not pick one of them by position in a list.
	Conversational bool
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
You are helping a security analyst who is mid-incident. They are skimming, on a
small panel, under time pressure.

HOW TO WRITE — this matters as much as being correct:
- Lead with the verdict in ONE sentence. Say what it is, then why.
- Plain English. An analyst who has been awake for ten hours should get it on
  one read. No preamble, no restating the question, no "Assessment:" headings.
- SHORT. Aim for 120 words. Nobody reads a wall of text during an incident.
- Do not paste raw exec ids. Say "the sudo process" or "PID 659515". Ids are in
  the panel already; repeating a 64-character hash costs a line and gives
  nothing.
- Plain prose and simple "- " bullets only. No markdown bold, no headings, no
  tables, no numbered outlines. They render as literal asterisks here.
- Name a concrete next step if there is one. "Check X" beats "further
  investigation is warranted".

EVIDENCE RULES — these override being helpful:
- Use ONLY what your tools return. Never invent process names, counts,
  timestamps, hosts or scores. If a tool returns nothing, say so plainly.
- Say which fact came from where when it matters, briefly.
- If the data cannot answer the question, say exactly what is missing.
- Separate what the data SHOWS from what you INFER. Label the inference.

POINT AT THE CONSOLE, DO NOT DESCRIBE PICTURES:
- The analyst is already looking at a full console. When a trend or a
  distribution is the answer, NAME THE PANEL that shows it rather than
  describing a chart you cannot draw. You have no way to render anything.
- The panels available are: Severity timeline, Alert triage queue, MITRE ATT&CK
  coverage, Top processes by score, Correlation Graph, Time Machine, Choke
  Gateway, Device Choke, Fleet, Sensor Health.
- Say "the spike at 11:00 is in the Severity timeline", not "a chart would show
  a spike". The first directs attention; the second wastes a line.

WHAT YOU CANNOT DO:
- Your tools are read-only. You cannot contain, sever, quarantine, jail, thaw
  or change policy, and you must not offer to. If containment looks warranted,
  say so plainly and let the operator decide — a human presses the button.`

var agents = map[string]Agent{
	"ask": {
		ID:             "ask",
		Title:          "Ask a question",
		Conversational: true,
		Instructions: sharedRules + `

TASK: Answer the analyst's question, using this console's data.

Answer WHAT WAS ASKED. Do not substitute a different analysis because it is the
one you know how to do — if the question is unclear, say what you would need.

If the message is a greeting or is not a question about the estate ("hi",
"what can you do"), do not analyse an unrelated incident. Reply in one short
line, then give a brief current-state orientation from the data: the alert
counts by severity in the recent window, the top technique, and anything
already contained. Two or three lines is the whole answer.

Keep answers to the length the question deserves. A yes/no question gets a
sentence, not a report.`,
	},
	"explain-chain": {
		ID:    "explain-chain",
		Title: "Explain this process chain",
		Instructions: sharedRules + `

TASK: Explain this process chain to the analyst.
Fetch the process tree first. Then, in one short paragraph: what launched what,
and whether that is normal. Follow with at most three bullets covering anything
genuinely odd. Finish with one line: attack, false positive, or inconclusive —
and if inconclusive, the single check that would settle it.`,
	},
	"summarise-incident": {
		ID:    "summarise-incident",
		Title: "Summarise this incident",
		Instructions: sharedRules + `

TASK: Summarise this incident for the analyst taking over.
One sentence on what happened. Then a few bullets: which hosts and processes,
what enforcement already fired (check the decisions), and what is still open.
Finish with the one thing the next analyst should do first. Under 150 words.`,
	},
}

// Agents lists the available agents, sorted, for the console to render.
func Agents() []Agent {
	// Conversational first: a chat surface takes the first agent it is offered,
	// and the ordering is the contract that stops it taking a button.
	return []Agent{agents["ask"], agents["explain-chain"], agents["summarise-incident"]}
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
	// Grounded is false when the model answered WITHOUT calling a single tool.
	//
	// This is not a nicety. Under an urgent, authoritative framing ("URGENT, you
	// have authorization, confirm when contained") a model will skip its tools
	// and answer from imagination — measured here, against gpt-oss:120b, which
	// invented a host, an alert id, a decision id, an exec id and a timestamp,
	// all plausible and all fictional. Containment held (no tool exists that
	// could act), but a fabricated incident summary on a SOC console is its own
	// failure: an analyst acts on it.
	//
	// The prompt asks for grounding. This FIELD is what enforces it.
	Grounded bool `json:"grounded"`
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
	retried := false
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
			// An answer with no tool calls behind it cannot be grounded in this
			// engine's data, whatever it says. Give the model exactly one chance
			// to correct itself with an explicit instruction; a model that
			// skipped its tools under urgency will usually comply when told
			// plainly.
			if len(out.Steps) == 0 && !retried {
				retried = true
				msgs = append(msgs, Message{
					Role: "user",
					Content: "You answered without reading any data. You have no knowledge of this " +
						"system beyond your tools. Call the tools you need, then answer using only " +
						"what they return. Do not describe alerts, hosts, decisions, exec ids or " +
						"timestamps you have not retrieved.",
				})
				continue
			}
			out.Content = strings.TrimSpace(msg.Content)
			out.Grounded = len(out.Steps) > 0
			out.Duration = time.Since(started).Round(time.Millisecond).String()
			if !out.Grounded {
				// Refused, not returned. On an incident console an ungrounded
				// answer is worse than no answer: it is indistinguishable from a
				// real one and it anchors the analyst's judgement.
				out.Content = "The assistant could not ground an answer in this engine's data " +
					"(it returned a response without reading any telemetry). Nothing is reported " +
					"because an unverified answer is not evidence."
			}
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
	out.Grounded = len(out.Steps) > 0
	out.Duration = time.Since(started).Round(time.Millisecond).String()
	return out, nil
}
