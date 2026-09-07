import { useCallback, useEffect, useRef, useState } from "react";
import {
  createAssistantApi,
  type AssistantAgent,
  type AssistantAvailability,
  type AssistantAnswer,
  type AssistantApi,
  type AssistantCapability,
  type AssistantStep,
  type AssistantSurface
} from "./api";

/**
 * The console's own reports for the two states no server can report about
 * itself: a body it could not read, and a read that never arrived.
 *
 * Both carry `enabled: false` because there is nothing to run, but neither is
 * the DISABLED state. "Not configured on this deployment" is a fact about the
 * deployment and sends an operator to their platform team; these two are facts
 * about this console's conversation with the server and send them somewhere
 * else entirely. `availability` is what keeps them apart at the renderer — the
 * reason string alone was not enough, because the panel ignored it and printed
 * the disabled sentence over the top of all three.
 */
const UNREADABLE_REASON = "the capability response could not be read — it was not the documented { enabled, agents } shape";

function unreadable(reason: string): AssistantCapability {
  return { enabled: false, agents: [], availability: "unreadable", reason };
}

function isAgent(value: unknown): value is AssistantAgent {
  const a = value as AssistantAgent | null;
  return !!a && typeof a === "object" && typeof a.id === "string" && a.id !== "";
}

/**
 * Normalise whatever the server actually sent into the shape the panel renders,
 * and label WHICH of the five availability states it represents.
 *
 * Exported because the chat sidebar reads the capability too, through
 * `useChats`. That read used to be `cap.agents ?? []` behind a bare catch, which
 * collapsed a rejected read, a degraded 502 body and a body of the wrong shape
 * into one empty list — and then reported all three as a deployment with no
 * assistant configured.
 *
 * The capability body is the one assistant response nothing else validates —
 * `capability()` casts the parsed JSON straight to AssistantCapability, so the
 * TYPE says `agents: AssistantAgent[]` while the VALUE is whatever arrived. A
 * body that omits `agents` (an older engine, a proxy's rewritten JSON, a field
 * that gains `omitempty`) then throws inside a render and takes the whole SOC
 * route down with it — from the code path whose own comment promises the
 * assistant "must never take the drill panel down with it".
 *
 * The three non-crash judgements it makes, and why each is what it is:
 *
 *  - `enabled: false` is DISABLED, however sparse the rest of the body. The
 *    server has told us why it is off and an empty agent list follows.
 *  - `enabled: true` with `agents: null` is NO-AGENTS, not unreadable. Both
 *    servers marshal a nil slice as an explicit null (no `omitempty` on the
 *    field), so this is the wire shape of "the assistant is on and this surface
 *    publishes nothing" — a reachable server saying something true, and an
 *    operator who is told instead that the response was unreadable goes hunting
 *    for a transport fault that does not exist.
 *  - `enabled: true` with the key ABSENT, or holding something that is neither
 *    a list nor null, or holding a list from which not one usable agent
 *    survives, is UNREADABLE: the body claims the assistant is running and then
 *    withholds the one field that would let us run it.
 */
export function readCapability(raw: unknown): AssistantCapability {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return unreadable(UNREADABLE_REASON);
  const cap = raw as Partial<AssistantCapability>;

  // The client already degrades a failed HTTP read into a capability body; that
  // verdict is preserved rather than re-derived, because from here a transport
  // failure and a deployment with no assistant look identical — which is the
  // conflation this function exists to prevent.
  if (cap.availability === "unreachable") {
    return {
      enabled: false,
      agents: [],
      availability: "unreachable",
      reason: typeof cap.reason === "string" ? cap.reason : undefined
    };
  }

  if (typeof cap.enabled !== "boolean") return unreadable(UNREADABLE_REASON);

  if (cap.enabled) {
    // Read through `unknown`, not through the declared type: the field is typed
    // AssistantAgent[] and the whole point here is that the value need not be
    // one, and specifically may be an explicit null.
    const agentsField: unknown = (raw as { agents?: unknown }).agents;
    const hasAgentsKey = "agents" in raw;
    if (hasAgentsKey && agentsField === null) {
      // Enabled, reachable, nothing published for this surface.
      return {
        enabled: true,
        agents: [],
        availability: "no-agents",
        model: typeof cap.model === "string" ? cap.model : undefined,
        reason: typeof cap.reason === "string" ? cap.reason : undefined
      };
    }
    if (!Array.isArray(agentsField)) {
      return unreadable(
        hasAgentsKey
          ? "the capability response could not be read — it says the assistant is enabled and sent an agent list that is not a list"
          : "the capability response could not be read — it says the assistant is enabled but omits the agent list"
      );
    }
    const usable = agentsField.filter(isAgent);
    if (agentsField.length > 0 && usable.length === 0) {
      return unreadable(
        "the capability response could not be read — not one entry in its agent list had a usable id"
      );
    }
    return {
      enabled: true,
      agents: usable,
      // An empty list from an enabled server is the same operator fact as an
      // explicit null: on, reachable, nothing for this surface. Rendering the
      // full panel for it offers a composer whose send button can never fire.
      availability: usable.length > 0 ? "ready" : "no-agents",
      model: typeof cap.model === "string" ? cap.model : undefined,
      reason: typeof cap.reason === "string" ? cap.reason : undefined
    };
  }

  return {
    enabled: false,
    agents: Array.isArray(cap.agents) ? cap.agents.filter(isAgent) : [],
    availability: "disabled",
    model: typeof cap.model === "string" ? cap.model : undefined,
    reason: typeof cap.reason === "string" ? cap.reason : undefined
  };
}

/**
 * ONE sentence per availability state, shared by every surface that has to
 * explain why the assistant is not answering.
 *
 * It lives here rather than inside a renderer because there are two renderers:
 * the drill panel and the chat sidebar. When the panel owned this map privately,
 * the sidebar kept its own single sentence — "No assistant agent is available on
 * this deployment." — and printed it for a rejected capability read, a 502 the
 * client degraded, an enabled server publishing nothing for the surface, and a
 * body it could not parse alike. That is a claim about the DEPLOYMENT made from
 * a console-to-server fault: the operator is sent to their platform team to
 * change a setting that may already be correct, mid-incident, from the one text
 * box they type into. Two vocabularies is how that distinction gets lost again,
 * so there is one.
 *
 * `where` only changes the noun for the surface with nothing published; every
 * other state is a fact about the service and reads identically wherever it is
 * shown.
 */
export function assistantOffText(
  availability: AssistantAvailability | undefined,
  where: "panel" | "chat" = "panel"
): string {
  const here = where === "chat" ? "this conversation" : "this panel";
  switch (availability) {
    case "no-agents":
      return `Enabled here, but ${here} has no assistant agents published for it.`;
    case "unreadable":
      return "The assistant service answered in a shape this console does not understand.";
    case "unreachable":
      return "The console could not reach the assistant service, so whether one is configured here is unknown.";
    case "disabled":
    default:
      // The only state that is genuinely a fact about the deployment, and so
      // the only one allowed to send an operator to their platform team.
      return "Not configured on this deployment.";
  }
}

export interface UseAssistantOptions {
  /** Injected for tests; defaults to the real client so call sites need nothing. */
  api?: AssistantApi;
  /** Exec id of the process under investigation, when there is one. */
  execId?: string;
  /** Which console panel this assistant is mounted on. */
  surface?: AssistantSurface;
}

export interface AssistantState {
  capability: AssistantCapability | null;
  answer: AssistantAnswer | null;
  /** The agent currently running, so the UI can mark which button is busy. */
  running: string | null;
  /**
   * Tool calls completed SO FAR in the run currently in flight.
   *
   * The panel's own design notes say progress must be named rather than spun,
   * because a bare spinner held for the fifteen seconds a tool loop takes reads
   * as "hung". Until the stream existed there was nothing to name it with and
   * the panel showed a fixed "Reading telemetry…" string that was true of every
   * run and informative about none.
   */
  liveSteps: AssistantStep[];
  error: string | null;
  /**
   * The agent that takes a typed QUESTION, or null while capability is loading.
   *
   * Exposed rather than left for each call site to work out, because working it
   * out is exactly what went wrong: the panel hard-coded `summarise-incident`
   * for free text, so an analyst who typed "is this host compromised?" received
   * an incident summary instead of an answer. The sidebar had the same bug with
   * a different hard-coded agent and was fixed alone. One derivation, used by
   * both, is what stops it happening a third time.
   */
  conversationalAgent: string | null;
  ask: (agentId: string, question?: string) => void;
  cancel: () => void;
  reset: () => void;
}

/**
 * All assistant state, in one hook, with no rendering opinion.
 *
 * Two behaviours worth calling out, both learned from bugs already fixed in
 * this console:
 *
 *  - Every request carries an AbortSignal, and a new ask cancels the one in
 *    flight. `useFleetSnapshot` shipping without one is on the Tier 1 fix list;
 *    it matters more here because a tool-calling answer can run for 20 seconds
 *    and an analyst WILL click twice.
 *  - Nothing is set on an unmounted component. A drill panel closes the moment
 *    an analyst moves on, which is exactly when a slow answer lands.
 */
export function useAssistant({ api, execId, surface }: UseAssistantOptions = {}): AssistantState {
  const clientRef = useRef<AssistantApi>(api ?? createAssistantApi());
  const [capability, setCapability] = useState<AssistantCapability | null>(null);
  const [answer, setAnswer] = useState<AssistantAnswer | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [liveSteps, setLiveSteps] = useState<AssistantStep[]>([]);

  const inFlight = useRef<AbortController | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      inFlight.current?.abort();
    };
  }, []);

  // Capability once per mount. A failure here is not surfaced as an error:
  // capability() already degrades to an unreachable report with a reason, and
  // readCapability labels a 200 whose body is not the shape the type claims.
  useEffect(() => {
    const ctl = new AbortController();
    clientRef.current
      .capability(surface, ctl.signal)
      .then((cap) => {
        if (mounted.current) setCapability(readCapability(cap));
      })
      .catch(() => {
        // A rejected read is UNREACHABLE, never disabled: we never got an
        // answer, so we have learned nothing about whether this deployment
        // configured an assistant.
        if (mounted.current) {
          setCapability({
            enabled: false,
            agents: [],
            availability: "unreachable",
            reason: "the capability request failed"
          });
        }
      });
    return () => ctl.abort();
  }, [surface]);

  const cancel = useCallback(() => {
    inFlight.current?.abort();
    inFlight.current = null;
    if (mounted.current) setRunning(null);
  }, []);

  const reset = useCallback(() => {
    cancel();
    if (mounted.current) {
      setAnswer(null);
      setError(null);
    }
  }, [cancel]);

  const ask = useCallback(
    (agentId: string, question?: string) => {
      inFlight.current?.abort();
      const ctl = new AbortController();
      inFlight.current = ctl;

      setRunning(agentId);
      setError(null);
      setLiveSteps([]);
      // The previous answer is cleared on a NEW question. Leaving it visible
      // beside a spinner invites reading a stale answer as the new one — on an
      // incident console that is a wrong conclusion, not a cosmetic issue.
      setAnswer(null);

      const client = clientRef.current;
      const req = { agent: agentId, question, execId, surface, signal: ctl.signal };
      // Stream when the client can, so the analyst watches the investigation
      // happen. Fall back otherwise — a buffering proxy or an older engine must
      // degrade to the request/response answer, not to no answer.
      const run = client.askStream
        ? client.askStream({
            ...req,
            onStep: (step) => {
              if (mounted.current && !ctl.signal.aborted) setLiveSteps((prev) => [...prev, step]);
            }
          })
        : client.ask(req);

      run
        .then((res) => {
          if (!mounted.current || ctl.signal.aborted) return;
          setAnswer(res);
          setRunning(null);
        })
        .catch((err: unknown) => {
          if (!mounted.current || ctl.signal.aborted) return;
          setError(err instanceof Error ? err.message : "the assistant failed");
          setRunning(null);
        });
    },
    [execId, surface]
  );

  // Selected on the FLAG, never on list position. Both belts, because the
  // position version shipped once and turned "Hello" into a process-chain
  // analysis.
  // readCapability guarantees the array, but the optional chain stays: this
  // line is the one that crashed the route, and it costs nothing to make it
  // survive a future caller that sets capability from somewhere else.
  const conversationalAgent =
    capability?.agents?.find((a) => a.conversational)?.id ?? capability?.agents?.[0]?.id ?? null;

  return { capability, answer, running, error, liveSteps, conversationalAgent, ask, cancel, reset };
}
