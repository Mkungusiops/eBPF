/**
 * AssistantApi — the injected seam for the analyst assistant.
 *
 * Written injected from the FIRST commit, deliberately. The audit found only
 * one of four routes could be unit-tested without network stubbing, and the
 * assistant is landing inside SOC — the route with seven components still
 * fetching directly. New code that copies that shape makes the problem bigger;
 * new code with its own seam is testable on day one and gives the SOC
 * conversion a worked example to copy.
 *
 * The interface names no transport type. A fake is an object literal.
 */

/** One tool invocation the answer was built from. */
export interface AssistantStep {
  tool: string;
  args: string;
  path: string;
  bytes: number;
  error?: string;
  duration: string;
}

export interface AssistantAnswer {
  agent: string;
  content: string;
  steps: AssistantStep[];
  model: string;
  duration: string;
  /** True when the tool loop hit its bound — the investigation is partial. */
  truncated?: boolean;
  /**
   * False when the engine could not ground the answer in telemetry — the model
   * replied without reading anything. Measured behaviour under urgent framing,
   * not a theoretical case, so the UI must make it unmistakable.
   */
  grounded?: boolean;
}

export interface AssistantAgent {
  id: string;
  title: string;
}

/**
 * Capability report. `enabled: false` is a normal, expected state — the
 * assistant is opt-in and most deployments will not configure it. The console
 * renders an explanation, never an error: a disabled optional feature is not a
 * fault, and showing a red banner for one trains operators to ignore red.
 */
export interface AssistantCapability {
  enabled: boolean;
  model?: string;
  agents: AssistantAgent[];
  /** Why it is unavailable, when it is. Shown verbatim to the operator. */
  reason?: string;
}

export interface AssistantAskRequest {
  agent: string;
  question?: string;
  execId?: string;
  signal?: AbortSignal;
}

export interface AssistantApi {
  capability(signal?: AbortSignal): Promise<AssistantCapability>;
  ask(req: AssistantAskRequest): Promise<AssistantAnswer>;
}

export class AssistantError extends Error {
  constructor(
    message: string,
    readonly status?: number
  ) {
    super(message);
    this.name = "AssistantError";
  }
}

type Requester = (path: string, init?: RequestInit) => Promise<Response>;

const defaultRequest: Requester = (path, init) =>
  fetch(path, { credentials: "same-origin", ...init });

/**
 * The real client. `request` is injectable so a test can drive the whole hook
 * without a network or a Vite proxy — and because a proxy returns its own 502
 * when the backend is absent, a try/catch cannot tell "down" from "broken".
 */
export function createAssistantApi(request: Requester = defaultRequest): AssistantApi {
  return {
    async capability(signal) {
      const res = await request("/api/assistant", { signal });
      if (!res.ok) {
        // Treat any failure as "unavailable" rather than throwing. The
        // assistant is an aid; it must never take the drill panel down with it.
        return { enabled: false, agents: [], reason: `unavailable (HTTP ${res.status})` };
      }
      return (await res.json()) as AssistantCapability;
    },

    async ask({ agent, question, execId, signal }) {
      const res = await request("/api/assistant/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent, question, exec_id: execId }),
        signal
      });
      if (!res.ok) {
        let detail = `HTTP ${res.status}`;
        try {
          const body = (await res.json()) as { error?: string };
          if (body?.error) detail = body.error;
        } catch {
          /* a non-JSON error body is still an error; keep the status */
        }
        throw new AssistantError(detail, res.status);
      }
      return (await res.json()) as AssistantAnswer;
    }
  };
}
