/**
 * ChatSidebar — the platform assistant, reachable from anywhere.
 *
 * Design: docs/plan/platform-assistant.md §5.
 *
 * IT OPENS; IT DOES NOT NAVIGATE. An analyst mid-triage must not lose the alert
 * queue to ask a question. That is why this is a slide-over layered on the
 * current route rather than an OpenSurface: the surfaces are mutually exclusive
 * overlays, so routing the assistant through them would close whatever the
 * analyst was reading — the precise failure the design forbids.
 *
 * It renders answers through AnswerText, the same renderer the drill panels use.
 * One renderer means one place to get escaping right (ai-and-console-reuse.md
 * §7a): model output is never treated as markup.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Loader2,
  Pin,
  Plus,
  Radar,
  Search,
  Send,
  Shield,
  Sparkles,
  Trash2,
  X
} from "lucide-react";
import { AnswerText } from "./AnswerText";
import { parseSteps, type ChatMessage } from "./chatApi";
import { groupChats } from "./chatGroups";
import { useChats, type UseChatsOptions } from "./useChats";
import { enrichmentSummaryText, useEnrichmentSummary } from "../common/enrichmentSummary";
import "./assistant.css";

export interface ChatSidebarProps extends UseChatsOptions {
  open: boolean;
  onClose: () => void;
  /**
   * Exec id carried in from a drill panel, so a question asked about a process
   * arrives with its subject already attached (step 5 continuity).
   */
  execId?: string;
  /** A question to send on open, handed over from a drill panel. */
  initialQuestion?: string;
  /** Tenant or host this console is showing, displayed as a scope chip. */
  scopeLabel?: string;
  /**
   * Opens the Behaviour & Reputation panel, when the surrounding route has one.
   *
   * That panel left the side menu and is now reached from here, so this link is
   * its entry point. Undefined on a route that has no such panel — the link is
   * then not offered at all, rather than offered and inert.
   */
  onOpenFindings?: () => void;
}

/** Named starters. A bare prompt makes an analyst invent the question. */
const STARTERS = [
  "What changed in the last hour?",
  "Which hosts look most at risk right now?",
  "Summarise today's containment actions"
];

const WIDTH_KEY = "assistant.sidebarWidth";
const MIN_W = 340;
const MAX_W = 760;

export function ChatSidebar({
  open,
  onClose,
  execId,
  initialQuestion,
  scopeLabel,
  surface,
  onOpenFindings,
  chatApi,
  assistantApi
}: ChatSidebarProps) {
  const chat = useChats({ chatApi, assistantApi, active: open, surface });
  const [draft, setDraft] = useState("");
  const [listOpen, setListOpen] = useState(true);
  const [width, setWidth] = useState<number>(() => readWidth());
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  const handedOver = useRef<string | undefined>(undefined);

  // Escape closes. A slide-over that traps an analyst is worse than none at all
  // during an incident.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  // Continuity: a question handed over from a drill panel is sent once, not on
  // every render, and not again if the analyst reopens the sidebar.
  useEffect(() => {
    if (!open || !initialQuestion) return;
    if (handedOver.current === initialQuestion) return;
    handedOver.current = initialQuestion;
    void chat.send(initialQuestion, undefined, execId);
  }, [open, initialQuestion, execId, chat]);

  // Keep the newest turn in view. Assigning scrollTop rather than calling
  // scrollTo(): a property every environment implements, including jsdom.
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [chat.messages.length, chat.sending]);

  const submit = useCallback(
    (text: string) => {
      if (!text.trim()) return;
      setDraft("");
      if (inputRef.current) inputRef.current.style.height = "auto";
      void chat.send(text, undefined, execId);
    },
    [chat, execId]
  );

  // Drag-to-resize, persisted. The plan asks for a remembered width, and an
  // analyst who widens the panel to read a process tree should not have to do
  // it again on the next incident.
  const startResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const move = (ev: MouseEvent) => {
      const next = clamp(window.innerWidth - ev.clientX);
      setWidth(next);
    };
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      // Persist on release, not on every pixel of the drag.
      try {
        window.localStorage.setItem(WIDTH_KEY, String(clamp(width)));
      } catch {
        /* private browsing; the width simply does not persist */
      }
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  }, [width]);

  // Keyboard resize, because a drag handle that only responds to a mouse is not
  // an accessible control.
  const keyResize = useCallback((e: React.KeyboardEvent) => {
    const step = e.shiftKey ? 64 : 16;
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    e.preventDefault();
    setWidth((w) => {
      const next = clamp(e.key === "ArrowLeft" ? w + step : w - step);
      try {
        window.localStorage.setItem(WIDTH_KEY, String(next));
      } catch {
        /* ignore */
      }
      return next;
    });
  }, []);

  if (!open) return null;

  const groups = groupChats(chat.chats);

  return (
    <>
      <div className="chat-scrim" onClick={onClose} aria-hidden />
      <aside
        className="chat"
        role="complementary"
        aria-label="Platform assistant"
        style={{ ["--chat-w" as string]: `${width}px` }}
      >
        <button
          type="button"
          className="chat__grip"
          aria-label="Resize assistant panel"
          onMouseDown={startResize}
          onKeyDown={keyResize}
        />

        <header className="chat__head">
          <Sparkles size={15} className="chat__spark" aria-hidden />
          <h2>Assistant</h2>
          {scopeLabel ? <span className="chat__scope">{scopeLabel}</span> : null}
          <span
            className="asst__ro"
            title="This assistant has read-only tools. It cannot contain, sever, quarantine or change policy."
          >
            <Shield size={11} aria-hidden />
            Read-only
          </span>
          <button type="button" className="chat__close" onClick={onClose} aria-label="Close assistant">
            <X size={15} />
          </button>
        </header>

        <HistoryBanner status={chat.status} reason={chat.reason} />

        <EnrichmentStrip open={open} onOpenFindings={onOpenFindings} />

        <section className="chat__list-wrap">
          <button
            type="button"
            className="chat__list-toggle"
            onClick={() => setListOpen((v) => !v)}
            aria-expanded={listOpen}
          >
            {listOpen ? <ChevronDown size={12} aria-hidden /> : <ChevronRight size={12} aria-hidden />}
            Conversations
          </button>
          {listOpen ? (
            <>
              <div className="chat__tools">
                <div className="chat__search">
                  <Search size={12} aria-hidden />
                  <input
                    type="search"
                    value={chat.query}
                    placeholder="Search titles and messages"
                    aria-label="Search conversations"
                    onChange={(e) => chat.setQuery(e.target.value)}
                  />
                </div>
                <button
                  type="button"
                  className="chat__new"
                  onClick={() => {
                    chat.select(null);
                    inputRef.current?.focus();
                  }}
                >
                  <Plus size={12} aria-hidden />
                  New
                </button>
              </div>

              <div className="chat__scroll">
                {groups.map((g) => (
                  <div key={g.label}>
                    <p className="chat__group">
                      {g.pinned ? <Pin size={9} aria-hidden /> : null}
                      {g.label}
                    </p>
                    <ul className="chat__list">
                      {g.chats.map((c) => (
                        <li
                          key={c.id}
                          className={c.id === chat.activeId ? "chat__item chat__item--on" : "chat__item"}
                        >
                          <button
                            type="button"
                            className="chat__item-open"
                            onClick={() => chat.select(c.id)}
                          >
                            {c.pinned_at ? <Pin size={10} className="chat__pin-on" aria-hidden /> : null}
                            <span className="chat__item-title">{c.title}</span>
                          </button>
                          <button
                            type="button"
                            className="chat__item-act"
                            aria-label={c.pinned_at ? `Unpin ${c.title}` : `Pin ${c.title}`}
                            onClick={() => void chat.pin(c.id, !c.pinned_at)}
                          >
                            <Pin size={11} />
                          </button>
                          <button
                            type="button"
                            className="chat__item-act"
                            aria-label={`Delete ${c.title}`}
                            onClick={() => void chat.remove(c.id)}
                          >
                            <Trash2 size={11} />
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
                {groups.length === 0 && chat.status === "ready" ? (
                  <p className="chat__empty">
                    {chat.query ? "No conversation matches that." : "No conversations yet."}
                  </p>
                ) : null}
              </div>
            </>
          ) : null}
        </section>

        <div className="chat__thread" ref={scrollRef}>
          {execId ? (
            <p className="asst__subject">
              About process <strong>{execId.slice(0, 12)}</strong>
            </p>
          ) : null}

          {chat.messages.length === 0 && !chat.sending ? (
            <div className="chat__starters">
              <p className="chat__starters-lead">Ask about anything the console can read.</p>
              {STARTERS.map((s) => (
                <button key={s} type="button" className="chat__starter" onClick={() => submit(s)}>
                  {s}
                </button>
              ))}
            </div>
          ) : null}

          {chat.messages.map((m) => (
            <Turn key={m.id} message={m} />
          ))}

          {chat.sending ? (
            <div className="asst__running" role="status" aria-live="polite">
              <Loader2 size={13} className="asst__spin" aria-hidden />
              {/* Named, not spun — the same rule the drill panel follows. The
                  last completed read changes every few hundred milliseconds,
                  which is what tells an analyst the run is alive. */}
              <span>
                {chat.liveSteps.length
                  ? `Read ${chat.liveSteps[chat.liveSteps.length - 1].tool} · ${chat.liveSteps.length} source${chat.liveSteps.length === 1 ? "" : "s"} so far`
                  : "Reading the console…"}
              </span>
              <button type="button" className="asst__cancel" onClick={chat.cancel}>
                Stop
              </button>
            </div>
          ) : null}

          {chat.askError ? (
            <div className="asst__error" role="alert">
              <AlertTriangle size={13} aria-hidden />
              <span>{chat.askError}</span>
            </div>
          ) : null}
        </div>

        <form
          className="chat__composer"
          onSubmit={(e) => {
            e.preventDefault();
            submit(draft);
          }}
        >
          <div className="chat__composer-box">
            <textarea
              ref={inputRef}
              className="chat__input"
              rows={1}
              value={draft}
              placeholder="Ask the assistant"
              aria-label="Ask the assistant"
              onChange={(e) => {
                setDraft(e.target.value);
                // Grow with the content: an analyst pasting a process chain
                // should see what they are about to send.
                e.target.style.height = "auto";
                e.target.style.height = `${Math.min(e.target.scrollHeight, 132)}px`;
              }}
              onKeyDown={(e) => {
                // Enter sends, Shift+Enter breaks the line — the convention
                // every operator already has in their fingers.
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  submit(draft);
                }
              }}
            />
            <button
              type="submit"
              className="chat__send"
              disabled={chat.sending || !draft.trim()}
              aria-label="Send"
            >
              <Send size={13} aria-hidden />
            </button>
          </div>
          <p className="chat__hint">
            <kbd>Enter</kbd> to send · <kbd>Shift</kbd>+<kbd>Enter</kbd> for a new line
          </p>
        </form>
      </aside>
    </>
  );
}

function clamp(w: number): number {
  return Math.max(MIN_W, Math.min(MAX_W, Math.round(w)));
}

function readWidth(): number {
  try {
    const raw = window.localStorage.getItem(WIDTH_KEY);
    const n = raw ? Number(raw) : NaN;
    return Number.isFinite(n) ? clamp(n) : 460;
  } catch {
    return 460;
  }
}

/**
 * The three non-error states, said plainly.
 *
 * "disabled" gets no warning styling at all: an optional feature this
 * deployment did not switch on is not a fault, and dressing it as one teaches
 * operators that the console's warnings do not mean anything.
 */
function HistoryBanner({ status, reason }: { status: string; reason: string | null }) {
  if (status === "ready" || status === "loading") return null;
  if (status === "disabled") {
    return (
      <p className="chat__note">
        <Shield size={12} aria-hidden />
        <span>
          History is off on this deployment — answers work, they just are not saved.
          {reason ? <span className="asst__dim"> {reason}</span> : null}
        </span>
      </p>
    );
  }
  return (
    <p className="chat__note chat__note--warn">
      <AlertTriangle size={12} aria-hidden />
      <span>Past conversations could not be loaded. You can still ask.</span>
    </p>
  );
}

function Turn({ message }: { message: ChatMessage }) {
  const [traceOpen, setTraceOpen] = useState(false);
  const steps = parseSteps(message.steps);

  if (message.role === "user") {
    return <p className="chat__q">{message.content}</p>;
  }

  return (
    <article
      className={
        message.grounded === false && message.derived !== true && message.no_claim !== true
          ? "asst__answer chat__a chat__a--ungrounded"
          : "asst__answer chat__a"
      }
    >
      {/* An answer the engine could not ground is the one an analyst most needs
          flagged. Measured behaviour, not a theoretical case: under urgent
          framing the model fabricated an entire incident. */}
      {message.grounded === false && message.derived !== true && message.no_claim !== true ? (
        <p className="asst__ungrounded" role="alert">
          <AlertTriangle size={12} aria-hidden />
          Not grounded in telemetry — treat as unverified.
        </p>
      ) : null}

      {/* A restatement of an already-verified thread. Deliberately NOT the red
          unverified banner — the analyst asked a follow-up and got an honest
          answer to it — but still labelled, because a restatement can be stale
          in a way a fresh reading is not. */}
      {message.derived === true ? (
        <p className="asst__derived">
          <AlertTriangle size={12} aria-hidden />
          From earlier in this conversation — nothing re-read just now.
        </p>
      ) : null}

      <AnswerText content={message.content} />

      <div className="chat__meta">
        {steps.length > 0 ? (
          <div className="asst__trace">
            <button
              type="button"
              className="asst__trace-toggle"
              onClick={() => setTraceOpen((v) => !v)}
              aria-expanded={traceOpen}
            >
              {traceOpen ? <ChevronDown size={12} aria-hidden /> : <ChevronRight size={12} aria-hidden />}
              {steps.length} source{steps.length === 1 ? "" : "s"} consulted
            </button>
            {traceOpen ? (
              <ol className="asst__steps">
                {steps.map((s, i) => (
                  <li key={`${s.tool}-${i}`} className={s.error ? "asst__step asst__step--err" : "asst__step"}>
                    <code>{s.tool}</code>
                    <span className="asst__dim">{s.path}</span>
                    <span className="asst__dim">{s.error ? s.error : `${s.bytes} B · ${s.duration}`}</span>
                  </li>
                ))}
              </ol>
            ) : null}
          </div>
        ) : null}
        {message.model ? <span>{message.model}</span> : null}
      </div>
    </article>
  );
}

/**
 * Whether the detector is alive, stated as a fact — plus the way into the
 * evidence.
 *
 * This strip is the price of taking Behaviour & Intel out of the side menu. The
 * panel showed one thing at a glance that a conversation cannot: an empty
 * finding list means the layer is OFF, or the baseline is STILL LEARNING, or NO
 * INDICATORS are loaded, and those are not interchangeable. An analyst who has
 * to ask a question to discover that their detector is switched off will not
 * ask, because nothing prompts them to.
 *
 * So it is not something the assistant says when questioned. It is on screen
 * whenever the sidebar is open, next to the link that opens the full findings.
 */
function EnrichmentStrip({ open, onOpenFindings }: { open: boolean; onOpenFindings?: () => void }) {
  const summary = useEnrichmentSummary(open);
  const text = enrichmentSummaryText(summary);
  // Nothing known yet, and nothing to link to: say nothing rather than render an
  // empty bar that looks like a failed load.
  if (!text && !onOpenFindings) return null;
  const warn = summary.unavailable || summary.baselineReady === false || summary.indicators === 0;

  return (
    <div className={warn ? "chat__enrich is-warn" : "chat__enrich"}>
      <Radar size={12} aria-hidden />
      <span className="chat__enrich-text">{text || "Behaviour & reputation"}</span>
      {onOpenFindings ? (
        <button type="button" onClick={onOpenFindings}>
          View the findings
        </button>
      ) : null}
    </div>
  );
}
