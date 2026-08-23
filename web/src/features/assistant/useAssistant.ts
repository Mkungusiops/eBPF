import { useCallback, useEffect, useRef, useState } from "react";
import {
  createAssistantApi,
  type AssistantAnswer,
  type AssistantApi,
  type AssistantCapability,
  type AssistantStep,
  type AssistantSurface
} from "./api";

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
  // capability() already degrades to { enabled: false } with a reason.
  useEffect(() => {
    const ctl = new AbortController();
    clientRef.current
      .capability(surface, ctl.signal)
      .then((cap) => {
        if (mounted.current) setCapability(cap);
      })
      .catch(() => {
        if (mounted.current) {
          setCapability({ enabled: false, agents: [], reason: "unavailable" });
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
  const conversationalAgent =
    capability?.agents.find((a) => a.conversational)?.id ?? capability?.agents[0]?.id ?? null;

  return { capability, answer, running, error, liveSteps, conversationalAgent, ask, cancel, reset };
}
