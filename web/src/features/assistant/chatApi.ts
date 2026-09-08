import { AssistantError, assistantRequest, type AssistantStep, type Requester } from "./api";

/**
 * ChatApi — the injected seam for assistant conversation history.
 *
 * Separate from AssistantApi on purpose. Asking a question and remembering the
 * answer are different capabilities with different failure modes: a deployment
 * can have a working model and no history (no Postgres), or history and no model
 * (no inference endpoint). Two interfaces let the UI report those two states
 * honestly instead of collapsing them into "assistant broken".
 *
 * Injected from the first commit for the reason recorded in api.ts — and
 * reinforced since: the CSRF bug there shipped past seven green tests because
 * every one of them injected a fake and the real transport was never exercised.
 * chatApi.test.ts drives the PATHS AND BODIES this module builds over a
 * captured requester; what the shared transport then does to them — the CSRF
 * header, the customer on the query string, the wait for the boot driver — is
 * covered over a stubbed fetch in src/test/assistantScope.test.ts, because a
 * seam that is only ever driven with a fake covers nothing that actually goes
 * on the wire.
 */

/** One stored conversation. Mirrors chatstore.Chat's wire format. */
export interface Chat {
  id: string;
  title: string;
  mode: string;
  pinned_at?: string | null;
  created_at: string;
  updated_at: string;
}

/** One stored turn. Mirrors chatstore.Message's wire format. */
export interface ChatMessage {
  id: string;
  chat_id: string;
  role: "user" | "assistant";
  content: string;
  model?: string;
  /** The answer's tool trace as a JSON string, exactly as stored. */
  steps?: string;
  /**
   * Always present on the wire, never optional-by-omission. An answer the
   * engine could not ground must not be indistinguishable from one that was
   * never assessed — see the Go-side test that pins this.
   */
  grounded: boolean;
  /**
   * True when the answer restated an already-grounded conversation rather than
   * reading anything new. Rendered as its own, softer notice — it is not an
   * unverified answer, but it is not a fresh reading either.
   */
  derived?: boolean;
  /** True when the reply makes no claim about the estate (a greeting). */
  no_claim?: boolean;
  created_at: string;
}

/**
 * Availability of history, as distinct from availability of the assistant.
 *
 * `enabled: false` is normal: history needs Postgres, and a single-tenant engine
 * deployment has none. The sidebar still works — it just cannot remember, and it
 * says so rather than showing an error.
 */
export interface ChatAvailability {
  enabled: boolean;
  reason?: string;
}

export interface ChatApi {
  listChats(query?: string, signal?: AbortSignal): Promise<Chat[]>;
  createChat(title?: string, mode?: string): Promise<Chat>;
  listMessages(chatId: string, signal?: AbortSignal): Promise<ChatMessage[]>;
  renameChat(chatId: string, title: string): Promise<void>;
  pinChat(chatId: string, pinned: boolean): Promise<void>;
  deleteChat(chatId: string): Promise<void>;
}

/**
 * HISTORY_DISABLED is the status the control plane returns when this deployment
 * has no chat store. It is a normal condition, so it is modelled as a typed
 * error the hook can branch on rather than a message it has to string-match.
 */
export const HISTORY_DISABLED = 503;

async function fail(res: Response): Promise<never> {
  let detail = `HTTP ${res.status}`;
  try {
    const body = (await res.json()) as { error?: string };
    if (body?.error) detail = body.error;
  } catch {
    /* a non-JSON error body is still an error; keep the status */
  }
  throw new AssistantError(detail, res.status);
}

/**
 * The same transport the asks go out on (api.ts), not a second copy of it.
 *
 * It used to be a copy — identical CSRF logic, duplicated — and a duplicate is
 * how one of two request paths ends up missing the rule the other one gained.
 *
 * IT MEANS THESE PATHS CARRY A `tenant` THE CHAT ROUTES DO NOT READ, and that
 * is deliberate rather than an oversight to tidy up. Chat history is
 * per-OPERATOR: controlplane/chat.go's scopeFor builds the scope from the
 * verified session and explicitly never from anything the client sent, so the
 * parameter is inert on every one of these endpoints. The alternative is an
 * exemption list living inside this feature, beside the one lib/tenantScope
 * already keeps (UNSCOPED_PATHS) — and two lists is how a request ends up
 * exempt from the rule nobody remembered the second list existed to state.
 *
 * IT ALSO MEANS THE UNSAFE ONES ARE REFUSED WHEN THE CUSTOMER IS UNCONFIRMED,
 * which needs saying because a create, rename or delete here is about an
 * OPERATOR'S OWN conversation and not about a customer at all — so the refusal
 * sentence that transport throws ("...the write was not sent. Pick a customer
 * and try again") would be a wrong explanation if an operator ever read it.
 * They do not: useChats swallows every one of these failures deliberately —
 * createChat falls back to an incognito ask, and rename, pin and delete are
 * `.catch(() => undefined)` — so the only refusal that reaches a screen is the
 * ask's own, where the sentence is exactly true. That is what makes ONE rule
 * for the whole transport the cheaper correct answer here; if a chat write is
 * ever surfaced to the operator, this is the comment that says why the message
 * it would show is wrong.
 */
export function createChatApi(request: Requester = assistantRequest): ChatApi {
  const json = { "Content-Type": "application/json" };
  return {
    async listChats(query, signal) {
      // Search and list are one endpoint: an empty query IS the list, so the
      // sidebar has a single code path and cannot render two different shapes.
      const qs = query ? `?q=${encodeURIComponent(query)}` : "";
      const res = await request(`/api/assistant/chats${qs}`, { signal });
      if (!res.ok) return fail(res);
      const body = (await res.json()) as { chats?: Chat[] };
      return body.chats ?? [];
    },

    async createChat(title, mode) {
      const res = await request("/api/assistant/chats", {
        method: "POST",
        headers: json,
        body: JSON.stringify({ Title: title ?? "", Mode: mode ?? "" })
      });
      if (!res.ok) return fail(res);
      return (await res.json()) as Chat;
    },

    async listMessages(chatId, signal) {
      const res = await request(`/api/assistant/chats/${encodeURIComponent(chatId)}`, { signal });
      if (!res.ok) return fail(res);
      const body = (await res.json()) as { messages?: ChatMessage[] };
      return body.messages ?? [];
    },

    async renameChat(chatId, title) {
      const res = await request(`/api/assistant/chats/${encodeURIComponent(chatId)}`, {
        method: "PATCH",
        headers: json,
        body: JSON.stringify({ title })
      });
      if (!res.ok) await fail(res);
    },

    async pinChat(chatId, pinned) {
      const res = await request(`/api/assistant/chats/${encodeURIComponent(chatId)}`, {
        method: "PATCH",
        headers: json,
        body: JSON.stringify({ pinned })
      });
      if (!res.ok) await fail(res);
    },

    async deleteChat(chatId) {
      const res = await request(`/api/assistant/chats/${encodeURIComponent(chatId)}`, {
        method: "DELETE"
      });
      if (!res.ok) await fail(res);
    }
  };
}

/**
 * parseSteps recovers a stored answer's tool trace.
 *
 * Stored as an opaque JSON string so the database never has to understand the
 * assistant's internals. A trace that will not parse is not an error worth
 * showing an analyst — the answer is still the answer — so this degrades to an
 * empty list and the disclosure simply does not appear.
 */
export function parseSteps(steps?: string): AssistantStep[] {
  if (!steps) return [];
  try {
    const parsed: unknown = JSON.parse(steps);
    return Array.isArray(parsed) ? (parsed as AssistantStep[]) : [];
  } catch {
    return [];
  }
}
