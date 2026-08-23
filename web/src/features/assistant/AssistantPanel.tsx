/**
 * Analyst Assistant — grounded answers inside the investigation, never a chat page.
 *
 * The design decisions, and why each one is the way it is:
 *
 * 1. THE READ-ONLY GUARANTEE IS VISIBLE. A badge states it, permanently, next
 *    to the title. Three layers in the engine make containment impossible for
 *    the model; none of that is worth anything to the analyst who cannot see
 *    it. Trust in an operations tool is a UI property, not only a code one.
 *
 * 2. NO BLANK PROMPT. The primary affordance is two buttons naming tasks an
 *    analyst already does by hand. A blank box asks the operator to guess what
 *    the tool is good at, which is why blank-prompt features in enterprise
 *    consoles go unused. Free text is available, secondary, for power users.
 *
 * 3. THE WORK IS SHOWN. Every answer carries the tool calls that produced it —
 *    endpoint, arguments, bytes, timing. An answer an analyst cannot verify is
 *    not evidence, and during an incident an unverifiable answer is worse than
 *    none because it still anchors judgement.
 *
 * 4. PROGRESS IS NAMED, NOT SPUN. A tool-calling answer takes 5-20s. A bare
 *    spinner for 20 seconds reads as "hung". Naming the step reads as "working".
 *
 * 5. FAILURE IS CONTAINED. Disabled, unreachable and errored are three distinct
 *    states with three distinct treatments, and none of them is a red banner:
 *    an optional feature that is switched off is not a fault, and colouring it
 *    like one teaches operators to ignore the colour that means an incident.
 */
import { useState } from "react";
import {
  AlertTriangle,
  Ban,
  ChevronDown,
  ChevronRight,
  Loader2,
  Maximize2,
  Send,
  Sparkles,
  X
} from "lucide-react";
import { AnswerText } from "./AnswerText";
import { useAssistant } from "./useAssistant";
import { useAssistantChat } from "./AssistantChatProvider";
import type { AssistantApi, AssistantSurface } from "./api";
import "./assistant.css";

export interface AssistantPanelProps {
  /** Injected; defaults to the real client. */
  api?: AssistantApi;
  /** The process under investigation, when the panel is opened from one. */
  execId?: string;
  /** Shown above the actions so the analyst knows what "this" refers to. */
  subjectLabel?: string;
  /**
   * Which of the console's panels this is.
   *
   * subjectLabel is for the ANALYST and never leaves the browser; this is for
   * the MODEL. The two were conflated, which is how a panel could announce
   * "Investigating the device fleet" to the operator while the assistant behind
   * it had no idea it was looking at devices — and no device tool either.
   */
  surface?: AssistantSurface;
}

export function AssistantPanel({ api, execId, subjectLabel, surface }: AssistantPanelProps) {
  const { capability, answer, running, error, liveSteps, conversationalAgent, ask, cancel } = useAssistant({
    api,
    execId,
    surface
  });
  const assistantChat = useAssistantChat();
  const [question, setQuestion] = useState("");
  const [traceOpen, setTraceOpen] = useState(false);

  // Capability not yet known. Render nothing rather than a skeleton: this panel
  // is an aid inside a denser surface, and a placeholder that resolves to
  // "unavailable" is churn in the analyst's peripheral vision.
  if (!capability) return null;

  if (!capability.enabled) {
    return (
      <section className="asst asst--off" aria-label="Analyst assistant">
        <header className="asst__head">
          <Sparkles size={14} aria-hidden />
          <h3>Analyst Assistant</h3>
        </header>
        <p className="asst__off-text">
          Not configured on this deployment.
          {capability.reason ? <span className="asst__dim"> {capability.reason}</span> : null}
        </p>
      </section>
    );
  }

  const busy = running !== null;

  const submitFreeText = () => {
    const q = question.trim();
    if (!q || busy || !conversationalAgent) return;
    // THE CONVERSATIONAL AGENT, selected by flag.
    //
    // This used to be a hard-coded `summarise-incident`, so every typed question
    // on all eight panels was answered with an incident summary regardless of
    // what was asked — "is this host compromised?" returned a handover report.
    // It is the same defect that was found and fixed in the sidebar, which had
    // hard-coded a different agent; only the sidebar was fixed. The evidence
    // rules the old comment was protecting are in sharedRules and apply to every
    // agent, so nothing is given up by routing correctly.
    ask(conversationalAgent, q);
    setQuestion("");
  };

  return (
    <section className="asst" aria-label="Analyst assistant">
      <header className="asst__head">
        <Sparkles size={14} aria-hidden />
        <h3>Analyst Assistant</h3>
        {/* The guarantee, stated where it is read. */}
        <span className="asst__ro" title="This assistant has read-only tools. It cannot contain, sever, quarantine or change policy.">
          <Ban size={11} aria-hidden />
          Read-only
        </span>
        {/* Continuity (platform-assistant.md §5). The drill assistant and the
            sidebar must be ONE conversation opened wider — two surfaces that
            look alike but forget each other teach the operator that neither
            remembers. The subject travels with the handover so the wider view
            opens already knowing what is under investigation.

            Absent when no provider is mounted, which is how this stays safe in
            tests and in any entry that has not adopted the shell. */}
        {assistantChat ? (
          <button
            type="button"
            className="asst__expand"
            onClick={() => assistantChat.openAssistant({ execId, surface })}
            title="Continue this investigation in the assistant sidebar"
          >
            <Maximize2 size={11} aria-hidden />
            Expand
          </button>
        ) : null}
      </header>

      {subjectLabel ? (
        <p className="asst__subject">
          Investigating <strong>{subjectLabel}</strong>
        </p>
      ) : null}

      <div className="asst__actions">
        {/* Task agents only. The conversational agent takes a typed question and
            has no fixed job, so rendering it as a one-click button would promise
            an action it cannot perform — it belongs in the sidebar, which has a
            composer. */}
        {capability.agents.filter((a) => !a.conversational).map((a) => (
          <button
            key={a.id}
            type="button"
            className="asst__action"
            disabled={busy}
            onClick={() => ask(a.id)}
          >
            {running === a.id ? <Loader2 size={13} className="asst__spin" aria-hidden /> : null}
            {a.title}
          </button>
        ))}
      </div>

      <div className="asst__ask">
        <input
          className="asst__input"
          placeholder="Ask about this incident…"
          value={question}
          disabled={busy}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            // Enter sends. Cmd/Ctrl+Enter too, because analysts arrive from
            // tools where that is the send key and muscle memory is not
            // something to correct.
            if (e.key === "Enter") submitFreeText();
          }}
          aria-label="Ask the analyst assistant a question"
        />
        <button
          type="button"
          className="asst__send"
          disabled={busy || !question.trim() || !conversationalAgent}
          onClick={submitFreeText}
          aria-label="Send question"
        >
          <Send size={13} aria-hidden />
        </button>
      </div>

      {busy ? (
        <div className="asst__running" role="status" aria-live="polite">
          <Loader2 size={13} className="asst__spin" aria-hidden />
          {/* Named, not spun. The last completed read is the honest answer to
              "what is it doing", and it changes every few hundred ms, which is
              what distinguishes working from hung. */}
          <span>
            {liveSteps.length
              ? `Read ${liveSteps[liveSteps.length - 1].tool} · ${liveSteps.length} source${liveSteps.length === 1 ? "" : "s"} so far`
              : "Reading telemetry…"}
          </span>
          <button type="button" className="asst__cancel" onClick={cancel}>
            <X size={11} aria-hidden /> Cancel
          </button>
        </div>
      ) : null}

      {error ? (
        <div className="asst__error" role="alert">
          <AlertTriangle size={13} aria-hidden />
          <span>{error}</span>
        </div>
      ) : null}

      {answer ? (
        <article className="asst__answer">
          {answer.grounded === false && answer.derived !== true && answer.no_claim !== true ? (
            <p className="asst__ungrounded" role="alert">
              <AlertTriangle size={12} aria-hidden />
              Not grounded in telemetry — treat as unverified.
            </p>
          ) : null}

          {answer.derived === true ? (
            <p className="asst__derived">
              <AlertTriangle size={12} aria-hidden />
              From earlier in this conversation — nothing re-read just now.
            </p>
          ) : null}

          {answer.truncated ? (
            <p className="asst__warn">
              <AlertTriangle size={12} aria-hidden />
              Tool limit reached — this answer is based on a partial investigation.
            </p>
          ) : null}

          <AnswerText content={answer.content} />

          {answer.steps.length > 0 ? (
            <div className="asst__trace">
              <button
                type="button"
                className="asst__trace-toggle"
                onClick={() => setTraceOpen((v) => !v)}
                aria-expanded={traceOpen}
              >
                {traceOpen ? <ChevronDown size={12} aria-hidden /> : <ChevronRight size={12} aria-hidden />}
                {answer.steps.length} source{answer.steps.length === 1 ? "" : "s"} consulted
              </button>
              {traceOpen ? (
                <ol className="asst__steps">
                  {answer.steps.map((s, i) => (
                    <li key={`${s.tool}-${i}`} className={s.error ? "asst__step asst__step--err" : "asst__step"}>
                      <code>{s.tool}</code>
                      <span className="asst__dim">{s.path}</span>
                      {s.args && s.args !== "{}" ? <span className="asst__args">{s.args}</span> : null}
                      <span className="asst__dim">
                        {s.error ? s.error : `${s.bytes} B · ${s.duration}`}
                      </span>
                    </li>
                  ))}
                </ol>
              ) : null}
            </div>
          ) : null}

          {/* Provenance footer: which model, how long. An answer whose origin is
              unrecorded cannot be re-examined during a post-incident review. */}
          <footer className="asst__meta">
            {answer.model} · {answer.duration}
          </footer>
        </article>
      ) : null}
    </section>
  );
}
