import { readCookie } from "../../lib/api";
import { AssistantError, type AssistantStep } from "./api";

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
 * chatApi.test.ts drives THIS module's defaultRequest for that reason.
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

type Requester = (path: string, init?: RequestInit) => Promise<Response>;

/** Same CSRF contract as api.ts; see the comment there for why it exists. */
const defaultRequest: Requester = (path, init) => {
  const headers = new Headers(init?.headers);
  const method = (init?.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD" && !headers.has("X-CSRF-Token")) {
    const csrf = readCookie("csrf_token");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  return fetch(path, { credentials: "same-origin", ...init, headers });
};

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

export function createChatApi(request: Requester = defaultRequest): ChatApi {
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
