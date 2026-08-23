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
	// Surfaces names the console panels that offer this agent as a button.
	// Empty means every surface.
	//
	// This is what stops the panel-button row becoming a menu of everything.
	// "Explain this process chain" is the right button over a process tree and
	// a nonsense one over a device inventory, and an operator who is offered a
	// button that cannot apply learns to distrust the row rather than to read
	// it. The server filters, not the console, so the rule lives next to the
	// instructions it applies to.
	Surfaces []string
}

// appliesTo reports whether this agent should be offered on a surface.
func (a Agent) appliesTo(surface string) bool {
	if len(a.Surfaces) == 0 || surface == "" {
		return true
	}
	for _, s := range a.Surfaces {
		if s == surface {
			return true
		}
	}
	return false
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
- NEVER CITE A TOOL YOU DID NOT CALL. Do not write "policy_stats shows...",
  "the decisions show..." or "the fleet reports..." unless that tool ran in THIS
  conversation and you are quoting what it returned. If you want to say
  something a tool would settle, either call it or say plainly that you have not
  checked. Attributing a claim to a source you never read is the most damaging
  thing you can do here: it is indistinguishable from evidence, and the analyst
  has no way to know the difference without opening the trace.
- CALL THE TOOL BEFORE THE CLAIM. If answering needs two reads, do two reads.
  A confident one-tool answer to a question that needed three is not efficient,
  it is unfounded.
- Say which fact came from where when it matters, briefly.
- If the data cannot answer the question, say exactly what is missing.
- Separate what the data SHOWS from what you INFER. Label the inference.
- ABSENCE OF EVIDENCE IS NOT EVIDENCE. "No threat-intel match" means the address
  is not in the feeds this deployment has loaded — check threat_intel_status
  before treating that as clean. "No behavioural anomaly" means nothing when the
  baseline reports ready=false; that is "still learning", not "all normal".

TWO KINDS OF EVIDENCE, AND THEY ARE NOT EQUAL:
- A THREAT-INTEL MATCH is external corroboration: someone else saw this address
  or file being used maliciously. It is the strongest signal here. Lead with it.
- A BEHAVIOURAL ANOMALY is this deployment's own observation that something has
  not happened here before. Strong, but it is unusualness, not malice — a
  software update makes a host do many things for the first time. Say which one
  you are relying on; an analyst treats them differently and should.
- A rule hit is a pattern match. It says a shape was recognised, not that the
  behaviour was unusual here. When the baseline says a rule-flagged process is
  routine on this host, that is a false-positive signal worth stating.

HOLDING A CONVERSATION:
- You can see the messages before this one. Use them. If the analyst says "that
  host", "it", "the second one" or "what about yesterday", resolve it from what
  was already said instead of asking them to repeat themselves.
- Do NOT re-run tools to re-establish something you established a moment ago
  unless the analyst is asking whether it has CHANGED. Re-fetching the same
  counts to answer "are you sure?" wastes the wait and tells them nothing new.
- If a follow-up is genuinely ambiguous, ask ONE short clarifying question. Do
  not guess and do not answer a different question because it is answerable.

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

GREETINGS AND SMALL TALK. If the message is a greeting or a meta question
("hi", "hello", "what can you do"), then FOR THAT MESSAGE ONLY the rules above
about leading with a verdict and using no preamble DO NOT APPLY. They are
written for incident analysis and produce a wall of alert statistics in reply
to someone saying hello, which reads as if you did not understand them.

Instead: greet them back in a few words, like a colleague would. Then offer at
most two short sentences of orientation — roughly how busy it is right now and
whether anything needs attention — and invite the actual question. Under 40
words in total. Do not open with numbers.

NEVER SHOW ARITHMETIC. Write "180 critical alerts", never "84+66+13+17=180" or
"80-66-19". The analyst wants the figure, not your working.

Keep every answer to the length the question deserves. A yes/no question gets a
sentence, not a report.

QUESTIONS ABOUT THE PLATFORM ITSELF. If the analyst asks what something MEANS
rather than what is happening — what a tarpit does, what the baseline is, what
severity is derived from — answer it from explain_platform. That is a question
about this product, not about the estate, and answering it does not need
telemetry. Do not refuse it for lack of data and do not invent the answer.`,
	},
	"explain-chain": {
		ID:       "explain-chain",
		Title:    "Explain this process chain",
		Surfaces: []string{"alert-drill", "process-action", "graph", "choke-process"},
		Instructions: sharedRules + `

TASK: Explain this process chain to the analyst.
Fetch the process tree first. Then, in one short paragraph: what launched what,
and whether that is normal. Follow with at most three bullets covering anything
genuinely odd. Finish with one line: attack, false positive, or inconclusive —
and if inconclusive, the single check that would settle it.`,
	},
	"summarise-incident": {
		ID:       "summarise-incident",
		Title:    "Summarise this incident",
		Surfaces: []string{"alert-drill", "process-action", "graph", "kpi-drill", "choke-process"},
		Instructions: sharedRules + `

TASK: Summarise this incident for the analyst taking over.
One sentence on what happened. Then a few bullets: which hosts and processes,
what enforcement already fired (check the decisions), and what is still open.
Finish with the one thing the next analyst should do first. Under 150 words.`,
	},
	// The two assurance agents. These exist because the Choke Assurance and
	// Devices panels were mounting an assistant whose every button asked about
	// a process chain — over surfaces that have no process chain on screen.
	"assess-containment": {
		ID:       "assess-containment",
		Title:    "Would containment actually work?",
		Surfaces: []string{"choke-assurance", "choke-process"},
		Instructions: sharedRules + `

TASK: Report whether this deployment could actually contain something right now.
This is an ASSURANCE question, not an incident question. The analyst is not
asking what happened; they are asking whether the machinery works.

Check, in this order: fleet_state for each host's enforcement mode, then
list_choked_processes for what is being held, then list_decisions for whether
recent enforcement actually reported success rather than merely being sent.

Lead with a one-line verdict: armed, partially armed, or audit-only. Then name
any host whose posture differs from the rest — an estate where one sensor is in
monitor mode has a hole exactly the size of that host, and that is the finding
worth surfacing. If a decision was issued but never acknowledged applied, say so
plainly; an unacknowledged containment is not a containment.`,
	},
	"assess-device-exposure": {
		ID:       "assess-device-exposure",
		Title:    "Assess device exposure",
		Surfaces: []string{"devices", "devices-assurance"},
		Instructions: sharedRules + `

TASK: Report what the device fleet looks like and what is exposed.
Start with device_plane_state, because whether the data plane is ARMED or
AUDIT-ONLY changes the meaning of everything else on this panel — an audit-only
plane shows severed devices that are not actually severed.

Then list_devices for the inventory and device_flows for what has been talking
to what. Lead with the plane's arming state in the first sentence. Follow with
the devices that stand out: unknown, newly seen, or talking to somewhere they
should not. If a device is marked severed, say whether the plane state supports
that being real.`,
	},
}

// Agents lists every available agent, for a caller that wants the full set.
func Agents() []Agent { return AgentsFor("") }

// AgentsFor lists the agents offered on one console surface.
//
// The order is fixed and the conversational agent is always first. That
// ordering is a CONTRACT, not a presentation choice: a chat client that selects
// by list position rather than by the Conversational flag gets the right agent
// anyway. Both belts exist because the wrong one shipped once — see
// TestConversationalAgentIsOfferedFirst.
func AgentsFor(surface string) []Agent {
	order := []string{
		"ask",
		"explain-chain",
		"summarise-incident",
		"assess-containment",
		"assess-device-exposure",
	}
	out := make([]Agent, 0, len(order))
	for _, id := range order {
		if a, ok := agents[id]; ok && a.appliesTo(surface) {
			out = append(out, a)
		}
	}
	return out
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
	// Derived reports an answer that read nothing THIS TURN but is continuing a
	// conversation whose earlier answers did.
	//
	// It exists because grounding and conversation memory were, briefly,
	// mutually exclusive. Once prior turns reach the model, a follow-up like
	// "are you sure?", "which one again?" or "say that more simply" is
	// answerable from the conversation — so no tool runs, so the answer was
	// ungrounded, so it was REPLACED with "the assistant could not ground an
	// answer in this engine's data". The analyst asked a reasonable follow-up
	// and was told the assistant had failed.
	//
	// The resolution is not to weaken grounding. Grounded still means exactly
	// "this turn read telemetry" and is never set on inheritance. Derived says
	// why an ungrounded answer was nonetheless returned rather than refused,
	// and the console labels it, so an analyst can always tell a fresh reading
	// from a restatement of one.
	//
	// Only ever set for a conversational agent continuing a grounded thread. A
	// task agent has a fixed job and must do it against live data every time.
	Derived bool `json:"derived,omitempty"`
	// NoClaim reports a reply that says NOTHING ABOUT THE ESTATE — a greeting,
	// or a question back to the analyst.
	//
	// Grounding exists to stop unverified claims reaching an analyst. A reply
	// that makes no claim has nothing to verify, so the warning does not apply
	// to it — and showing one anyway is its own failure. Measured on the live
	// rig: an analyst typed "Hello" and got back a red "Not grounded in
	// telemetry — treat as unverified" above a friendly question. Being warned
	// that a greeting might be fabricated teaches an operator to ignore the
	// banner, which is the one thing that banner cannot afford.
	//
	// Grounded stays strictly "this turn read telemetry" and is never set here.
	// This is the flag that tells the console the difference between "unverified"
	// and "nothing to verify".
	NoClaim bool `json:"no_claim,omitempty"`
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
	// OnStep is called as each tool call COMPLETES, before the model has
	// written a word.
	//
	// This is what makes streaming worth building here. The latency in an answer
	// is not token generation, it is the tool loop: five reads against the
	// engine's own API, each a few hundred milliseconds, before the model has
	// anything to say. A spinner held for fifteen seconds reads as "hung", and
	// AssistantPanel's own design notes say progress must be NAMED rather than
	// spun — but until this hook existed there was nothing to name it with.
	//
	// Optional. Nil means the run behaves exactly as it always has, which is
	// what keeps the non-streaming endpoint a single code path with this one
	// rather than a fork.
	OnStep func(Step)
	// HistoryGrounded reports that at least one assistant turn in History was
	// itself grounded in tool output.
	//
	// The control plane reads it from the chat store, where every stored answer
	// carries its own grounded flag — so it is a server-side fact there. The
	// single-tenant engine takes it from the request alongside the history it
	// cannot otherwise obtain; forging it there lets an analyst suppress a
	// refusal in their own session and nothing more, because it can never widen
	// what a tool may read.
	HistoryGrounded bool
	// History is the conversation so far, oldest first, EXCLUDING the question
	// being asked now.
	//
	// Empty means a one-shot ask, which is what every drill-panel button sends
	// and what this package did for every request until it existed. Sanitised
	// by the caller through SanitiseHistory — see history.go for what is
	// stripped and why a forged "system" turn in here would be a prompt
	// rewrite rather than a conversation.
	History []Message
	// Surface is WHICH CONSOLE PANEL asked. See surface.go.
	//
	// It changes only what the model is told, never what it may read. Framing,
	// not authorization — so an unknown value degrades to a generic briefing
	// rather than failing the request, which matters because the console and
	// the engine are deployed separately and will skew.
	Surface string
}

// assertsNothing reports whether a tool-free answer is safe to hand back: it
// makes no claim about the estate, so there is nothing to ground.
//
// # The conflict this resolves
//
// Two rules in this package were mutually exclusive and both were right.
//
// The `ask` agent is told to greet a greeting like a colleague would — a few
// words, no numbers, no wall of alert statistics (that is what f451eb1 fixed).
// Answering "Hello" correctly therefore requires calling NO tools.
//
// But an answer with no tool calls behind it is treated as ungrounded and
// REPLACED with a refusal. So the analyst typed "Hello" and got back "The
// assistant could not ground an answer in this engine's data… an unverified
// answer is not evidence." Measured on the live rig, and it is worse than it
// sounds: the operator is scolded for saying hello by a tool that appears to be
// malfunctioning.
//
// The resolution is not to weaken grounding. It is to notice that grounding
// protects against UNVERIFIED CLAIMS, and a reply that claims nothing has
// nothing to verify. "Hi — quiet right now, what do you need?" cannot mislead an
// analyst about the estate, because it says nothing about the estate.
//
// Deliberately conservative, because the cost of being wrong here is a
// fabricated incident summary getting through:
//
//   - Short. A greeting is short by instruction; anything long is an answer.
//   - No digits at all. Every fact this assistant could invent — a count, a
//     score, a PID, a timestamp, a technique id — contains one. This single
//     check is what makes the rule safe rather than clever.
//   - Conversational agents only. A task agent has a fixed job and must never
//     return a chat reply instead of doing it.
//
// An answer that fails any of these is refused exactly as before.
func assertsNothing(content string) bool {
	const maxWords = 60
	if len(strings.Fields(content)) > maxWords {
		return false
	}
	return !strings.ContainsAny(content, "0123456789")
}

// systemPrompt assembles the system message: the surface briefing, then the
// agent's instructions.
//
// A method rather than three lines inside Run so the ORDERING has exactly one
// definition and a test can assert the real one. A test that rebuilds the
// prompt itself proves only that the test agrees with itself.
func (r *Runner) systemPrompt(ag Agent) string {
	s, ok := SurfaceFor(r.Surface)
	if !ok {
		return ag.Instructions
	}
	return "WHERE YOU ARE: the " + s.Label + " panel.\n" + s.Briefing +
		"\n\nThat is the context. Your instructions follow, and they take precedence.\n" +
		ag.Instructions
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

	// The surface briefing goes FIRST in the system message, before the agent's
	// own instructions.
	//
	// System rather than user, because it is standing context about where the
	// analyst is sitting, not something they said — putting it in the user turn
	// makes the model answer it as though it were the question.
	//
	// FIRST, and this ordering is not cosmetic. It shipped the other way round
	// for one afternoon and re-broke a fixed bug: with the briefing appended
	// last, "Hello" on the Devices Assurance panel returned a device-plane
	// posture report, because the briefing's "lead with the arming state" was
	// the last thing the model read and it outranked the `ask` agent's explicit
	// greeting clause. That is precisely the defect f451eb1 fixed, reintroduced
	// through a different door.
	//
	// The briefing describes WHERE the analyst is. The agent's instructions say
	// WHAT TO DO, including when not to do it. Where-you-are is context and must
	// read first; what-to-do is the task and must read last, so it wins.
	// System prompt, then the conversation so far, then the new question.
	//
	// History sits BETWEEN them rather than being folded into the question,
	// because the model has to be able to tell what the analyst is asking NOW
	// from what they asked ten minutes ago. Flattening a thread into one user
	// turn produces answers to the wrong message in it — usually the first,
	// which is the one with the most words.
	msgs := make([]Message, 0, len(r.History)+2)
	msgs = append(msgs, Message{Role: "system", Content: r.systemPrompt(ag)})
	msgs = append(msgs, SanitiseHistory(r.History)...)
	msgs = append(msgs, Message{Role: "user", Content: user})

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
			// A conversational reply that asserts nothing is FINISHED, and must
			// not be nudged.
			//
			// This guard is the fix for a greeting that came back as an incident
			// report. The nudge below is an order — "call the tools you need" —
			// and a model given it will obey, so "Hello" produced a wall of
			// alert statistics on one deployment and, on the other, a
			// clarifying question wearing a red "unverified" banner. Both were
			// the nudge overriding the agent's own explicit instruction to greet
			// a greeting like a colleague would.
			//
			// Checked BEFORE the retry rather than after it, because after is
			// too late: by then the model has already been told to go and read
			// telemetry, and the greeting is gone.
			noClaim := ag.Conversational && assertsNothing(strings.TrimSpace(msg.Content))

			// An answer with no tool calls behind it cannot be grounded in this
			// engine's data, whatever it says. Give the model exactly one chance
			// to correct itself with an explicit instruction; a model that
			// skipped its tools under urgency will usually comply when told
			// plainly.
			if len(out.Steps) == 0 && !retried && !noClaim {
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
			// A tool-free answer is acceptable in exactly two cases, both
			// narrow, both conversational-agent-only:
			//
			//   assertsNothing   it claims nothing about the estate (a greeting)
			//   Derived          it restates a conversation that WAS grounded
			//
			// The retry above has already run by this point, so the model has
			// been told once to go and read something. Reaching here means it
			// answered from the thread deliberately.
			out.Derived = ag.Conversational && !out.Grounded && r.HistoryGrounded
			out.NoClaim = !out.Grounded && ag.Conversational && assertsNothing(out.Content)
			if !out.Grounded && !out.Derived && !out.NoClaim {
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
			if r.OnStep != nil {
				r.OnStep(st)
			}

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
