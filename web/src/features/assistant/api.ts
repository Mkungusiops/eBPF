import { readCookie } from "../../lib/api";
import {
  pendingTenantHydration,
  tenantScopeApplies,
  tenantScopedPath,
  tenantScopeRefusal
} from "../../lib/tenantScope";
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
  /**
   * True when the answer restates a conversation whose earlier answers WERE
   * grounded, without reading anything new this turn.
   *
   * A distinct state from `grounded`, not a softer synonym for it. "Are you
   * sure?" and "which one again?" are answerable from the thread, and before
   * this existed they were replaced with the ungrounded refusal — the analyst
   * asked a reasonable follow-up and was told the assistant had failed. The
   * label still has to appear, because a restatement and a fresh reading are
   * different evidence and only one of them reflects the estate right now.
   */
  derived?: boolean;
  /**
   * True when the reply says nothing about the estate — a greeting, or a
   * question back to the analyst.
   *
   * "Unverified" and "nothing to verify" are different states and only one of
   * them deserves a warning. An analyst who typed "Hello" and got back a red
   * "Not grounded in telemetry — treat as unverified" is being told a greeting
   * might be fabricated, which teaches them to ignore the banner that exists
   * for genuinely ungrounded claims.
   */
  no_claim?: boolean;
}

export interface AssistantAgent {
  id: string;
  title: string;
  /**
   * True for the agent that ANSWERS A QUESTION rather than performing a fixed
   * task. The others are buttons: their instructions say "explain this process
   * chain" and they ignore whatever was typed.
   *
   * The sidebar must select on this flag, never on list position — picking
   * agents[0] is what made "Hello" return a process-chain analysis.
   */
  conversational?: boolean;
}

/**
 * What the console actually knows about the assistant — five facts an operator
 * acts on DIFFERENTLY, and which were collapsed into one sentence.
 *
 *  - "ready"       on, with agents published for this surface.
 *  - "no-agents"   on and reachable, but this surface has none. There is
 *                  nothing for the platform team to switch on; the surface
 *                  itself is unwired. Both servers marshal a nil slice as
 *                  `"agents": null` (no `omitempty`), so this is a real wire
 *                  shape, not a hypothetical one.
 *  - "disabled"    the deployment never configured an assistant — ask the
 *                  platform team to configure one.
 *  - "unreadable"  a 200 whose body was not the documented shape. The server
 *                  answered and the console could not understand it: a defect
 *                  to report, not a setting to change.
 *  - "unreachable" the capability read itself failed (HTTP error, network,
 *                  a proxy's own 502). We do not know whether this deployment
 *                  has an assistant at all, and must not claim it has none.
 *
 * The distinction is the whole point: "not configured on this deployment" sends
 * an operator to their platform team, and telling them that when the console
 * merely failed to READ the server sends them to the wrong place with a wrong
 * fact.
 */
export type AssistantAvailability = "ready" | "no-agents" | "disabled" | "unreadable" | "unreachable";

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
  /**
   * Which of the five states above this report is.
   *
   * Set by the client and by the hook that normalise the wire body, never by
   * the server — the server cannot know that its own answer was unreadable or
   * that it never arrived. Optional because every existing fake in the suite
   * builds a capability literal without it; a consumer that meets one falls
   * back to reading `enabled` and `agents`, which is what it did before.
   */
  availability?: AssistantAvailability;
}

/**
 * Which console panel the assistant was opened from.
 *
 * There are eight, and until this existed all eight sent an identical request:
 * the model could not tell a device inventory from a process tree from a KPI
 * tile. The engine uses it for two things — which task buttons to offer, and a
 * short briefing folded into the system prompt.
 *
 * It is FRAMING, NOT AUTHORIZATION. The caller's session still decides what may
 * be read; a wrong value here mis-frames an answer and can do nothing else.
 */
export type AssistantSurface =
  | "alert-drill"
  | "process-action"
  | "graph"
  | "kpi-drill"
  | "choke-process"
  | "choke-assurance"
  | "devices"
  | "devices-assurance"
  | "behaviour";

/**
 * One prior turn, replayed so the assistant can hold a conversation.
 *
 * Only the role and the text. Tool traces are deliberately NOT sent back: the
 * server refuses to replay a tool result it did not itself produce, because a
 * forged one would launder a fabricated figure into the transcript as though a
 * tool had returned it.
 */
export interface AssistantHistoryMessage {
  role: "user" | "assistant";
  content: string;
  /**
   * Whether that answer was grounded when it arrived. Sent so a follow-up on a
   * verified thread is not refused for reading nothing new.
   *
   * The multi-tenant control plane ignores this and uses its own stored flag.
   * The single-tenant engine has no chat store, so it trusts the console —
   * which at worst lets an analyst suppress a refusal in their own session,
   * and can never widen what a tool may read.
   */
  grounded?: boolean;
}

export interface AssistantAskRequest {
  agent: string;
  question?: string;
  execId?: string;
  /**
   * The conversation so far, oldest first, excluding the question being asked.
   *
   * Sent by the CHAT surface only. Until this existed, the engine built every
   * request from the system prompt and the new question alone — so "what about
   * that host?" had no referent and every message was the analyst's first.
   *
   * The multi-tenant control plane IGNORES this and loads the thread from its
   * own chat store instead, which is strictly better: it is what was actually
   * said, and the same ownership check that guards the write guards the read.
   * Sending it costs nothing there and is what makes the single-tenant engine,
   * which has no history store at all, conversational too.
   */
  history?: AssistantHistoryMessage[];
  /**
   * Conversation to record this exchange in.
   *
   * OMITTED MEANS INCOGNITO and nothing is stored — the default, and deliberately
   * so: an analyst may ask about a live breach before it is classified, and the
   * safe default for an unclassified question is to leave no record. The drill
   * panels pass nothing; only the history sidebar supplies an id.
   */
  chatId?: string;
  /** Which panel asked. See AssistantSurface. */
  surface?: AssistantSurface;
  /**
   * True for a sustained conversation in the history sidebar, false or absent
   * for a drill panel's one-shot question.
   *
   * It selects between the two models a deployment may have configured, and
   * nothing else — it cannot widen what the assistant may read. The control
   * plane IGNORES it and reads the model off the stored chat instead, which is
   * a fact the server owns; the single-tenant engine has no chat store, so
   * there it is the only signal available.
   */
  conversation?: boolean;
  signal?: AbortSignal;
}

export interface AssistantApi {
  capability(surface?: AssistantSurface, signal?: AbortSignal): Promise<AssistantCapability>;
  ask(req: AssistantAskRequest): Promise<AssistantAnswer>;
  /**
   * The same ask, with each tool call reported as it completes.
   *
   * OPTIONAL on the interface, deliberately. Every existing fake in the test
   * suite is an object literal with `capability` and `ask`; requiring a third
   * method would have made this change a rewrite of tests that are about
   * something else. Callers fall back to `ask`, which is also what happens when
   * a proxy in the path buffers the stream — an assistant that only works over
   * SSE stops working the first time it meets an unhelpful reverse proxy.
   */
  askStream?(req: AssistantAskRequest & { onStep: (step: AssistantStep) => void }): Promise<AssistantAnswer>;
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

export type Requester = (path: string, init?: RequestInit) => Promise<Response>;

/** The methods lib/api.ts treats as writes. One definition for both rules below. */
function isUnsafe(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

/**
 * The transport every assistant request goes out on — asks, streams and chat
 * history alike.
 *
 * It is a raw fetch rather than lib/api.ts's funnel because its callers need
 * the Response itself: `askStream` reads an SSE body the funnel would have
 * parsed, and `capability` has to inspect a failing status rather than be
 * handed a thrown ApiError — treating an unreachable server as a configured-off
 * one is the distinction that sends an operator to the wrong team. So this
 * deliberately MIRRORS the funnel instead, importing its rules from
 * lib/tenantScope rather than restating them — the same shape
 * features/choke/api.ts's apiBlob takes, and for the same reason.
 *
 * ── The CSRF token
 *
 * The console protects every unsafe method with a double-submit token, so an
 * assistant POST without the header is rejected before it reaches the handler —
 * which is exactly what happened: the panel rendered, the buttons worked, and
 * every ask came back "csrf token missing or invalid". readCookie is the
 * console's shared helper (lib/api.ts); reusing it keeps one definition of
 * where the token lives.
 *
 * ── WHICH CUSTOMER THE QUESTION IS ABOUT
 *
 * This client used to issue its own unscoped fetches, and it was the last
 * surface under the provider banner that answered about the wrong customer: the
 * control plane resolves a request that names no tenant to the account's
 * DEFAULT customer, so a provider who had switched the console to customer B
 * asked a question and got a paragraph built entirely out of customer A's
 * telemetry. Worse than a wrong table, because prose carries no column header
 * and gets pasted into a handover. Scoping the client is only half of it — see
 * assistantScope in controlplane/assistant.go for the other end.
 *
 * ── The barrier, and the refusal
 *
 * The selection takes two round trips (whoami, then the roster) to become
 * trustworthy, so a request sent inside that window names no customer and is
 * answered about the default one. An ask waits for the boot driver exactly as
 * every panel read does; only a path that WOULD have carried the selection
 * waits, so the single-tenant engine and every tenant-bound operator wait for
 * nothing.
 *
 * And when hydration settles WITHOUT confirming the customer, the funnel refuses
 * unsafe methods. An ask is a POST, and it is kept inside that rule rather than
 * carved out of it. It is not containment, but it is not a read of rows either:
 * it spends a customer's inference budget, writes a turn into a conversation,
 * and returns an answer an analyst quotes — and there is no honest caption for
 * "this is about whichever customer the server picked for a console that was
 * told to point elsewhere". A refused ask says so in a sentence the panel
 * renders; an unconfirmed one would have looked exactly like a good answer. In
 * THAT state — and only that one, since a confirmed selection is named on these
 * paths like any other — the history GETs beside it still go out, unscoped, for
 * the reason every panel read does: the server's own default is a real scope,
 * and a sidebar that renders nothing teaches an analyst nothing.
 */
export const assistantRequest: Requester = async (path, init) => {
  const headers = new Headers(init?.headers);
  const method = (init?.method ?? "GET").toUpperCase();
  if (isUnsafe(method) && !headers.has("X-CSRF-Token")) {
    const csrf = readCookie("csrf_token");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  if (tenantScopeApplies(path)) {
    const hydrating = pendingTenantHydration();
    if (hydrating) await hydrating;
    if (isUnsafe(method)) {
      const refusal = tenantScopeRefusal();
      // No status: nothing left the browser, so there is no HTTP answer to
      // report. The message is written for an operator and is rendered verbatim.
      if (refusal) throw new AssistantError(refusal);
    }
  }
  // Scoped at the moment the request goes out, not when the caller built the
  // path, for the reason lib/api.ts gives: a path scoped early and sent late
  // would carry the customer the operator has already switched away from — and
  // after the wait above, which is when the selection is finally knowable.
  return fetch(tenantScopedPath(path), { credentials: "same-origin", ...init, headers });
};

/**
 * The real client. `request` is injectable so a test can drive the whole hook
 * without a network or a Vite proxy — and because a proxy returns its own 502
 * when the backend is absent, a try/catch cannot tell "down" from "broken".
 */
export function createAssistantApi(request: Requester = assistantRequest): AssistantApi {
  return {
    async capability(surface, signal) {
      // The surface scopes the agent list the server returns, so each panel is
      // offered the buttons that can actually be answered there.
      const path = surface ? `/api/assistant?surface=${encodeURIComponent(surface)}` : "/api/assistant";
      const res = await request(path, { signal });
      if (!res.ok) {
        // Treat any failure as "unavailable" rather than throwing. The
        // assistant is an aid; it must never take the drill panel down with it.
        //
        // "unreachable", NOT "disabled": a read that failed says nothing about
        // whether this deployment configured an assistant, and reporting it as
        // an unconfigured deployment sends the operator to their platform team
        // to fix a setting that may already be correct.
        return {
          enabled: false,
          agents: [],
          availability: "unreachable",
          reason: `unavailable (HTTP ${res.status})`
        };
      }
      return (await res.json()) as AssistantCapability;
    },

    async ask({ agent, question, execId, chatId, surface, history, conversation, signal }) {
      const res = await request("/api/assistant/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent, question, exec_id: execId, chat_id: chatId, surface, history, conversation }),
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
    },

    async askStream({ agent, question, execId, chatId, surface, history, conversation, onStep, signal }) {
      const res = await request("/api/assistant/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent, question, exec_id: execId, chat_id: chatId, surface, history, conversation }),
        signal
      });
      if (!res.ok || !res.body) {
        let detail = `HTTP ${res.status}`;
        try {
          const body = (await res.json()) as { error?: string };
          if (body?.error) detail = body.error;
        } catch {
          /* a non-JSON error body is still an error; keep the status */
        }
        throw new AssistantError(detail, res.status);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let answer: AssistantAnswer | null = null;
      let failure: string | null = null;

      // SSE frames are separated by a blank line and a chunk boundary can fall
      // anywhere, including mid-frame. Buffer until a complete frame is present
      // rather than parsing per chunk — the per-chunk version works on
      // loopback, where frames arrive whole, and corrupts under any real latency.
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let split = buffer.indexOf("\n\n");
        while (split !== -1) {
          const frame = buffer.slice(0, split);
          buffer = buffer.slice(split + 2);
          const event = /^event: (.*)$/m.exec(frame)?.[1] ?? "";
          const data = /^data: (.*)$/m.exec(frame)?.[1] ?? "";
          if (data) {
            try {
              const parsed: unknown = JSON.parse(data);
              if (event === "step") onStep(parsed as AssistantStep);
              else if (event === "answer") answer = parsed as AssistantAnswer;
              else if (event === "error") failure = (parsed as { error?: string }).error ?? "the assistant failed";
            } catch {
              /* A malformed frame costs one progress line, not the answer. */
            }
          }
          split = buffer.indexOf("\n\n");
        }
      }

      if (failure) throw new AssistantError(failure);
      // NEITHER an answer NOR an error means the connection dropped mid-run.
      // Silence must never be read as success: the panel would render an empty
      // answer as though the assistant had found nothing to say.
      if (!answer) throw new AssistantError("the assistant stream ended without an answer");
      return answer;
    }
  };
}
