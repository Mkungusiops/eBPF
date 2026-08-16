import { useCallback, useEffect, useRef, useState } from "react";
import {
  createAssistantApi,
  type AssistantAnswer,
  type AssistantApi,
  type AssistantCapability
} from "./api";

export interface UseAssistantOptions {
  /** Injected for tests; defaults to the real client so call sites need nothing. */
  api?: AssistantApi;
  /** Exec id of the process under investigation, when there is one. */
  execId?: string;
}

export interface AssistantState {
  capability: AssistantCapability | null;
  answer: AssistantAnswer | null;
  /** The agent currently running, so the UI can mark which button is busy. */
  running: string | null;
  error: string | null;
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
export function useAssistant({ api, execId }: UseAssistantOptions = {}): AssistantState {
  const clientRef = useRef<AssistantApi>(api ?? createAssistantApi());
  const [capability, setCapability] = useState<AssistantCapability | null>(null);
  const [answer, setAnswer] = useState<AssistantAnswer | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

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
      .capability(ctl.signal)
      .then((cap) => {
        if (mounted.current) setCapability(cap);
      })
      .catch(() => {
        if (mounted.current) {
          setCapability({ enabled: false, agents: [], reason: "unavailable" });
        }
      });
    return () => ctl.abort();
  }, []);

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
      // The previous answer is cleared on a NEW question. Leaving it visible
      // beside a spinner invites reading a stale answer as the new one — on an
      // incident console that is a wrong conclusion, not a cosmetic issue.
      setAnswer(null);

      clientRef.current
        .ask({ agent: agentId, question, execId, signal: ctl.signal })
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
    [execId]
  );

  return { capability, answer, running, error, ask, cancel, reset };
}
