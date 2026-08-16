import { useCallback, useEffect, useRef, useState } from "react";
import { createAssistantApi, type AssistantAgent, type AssistantApi } from "./api";
import { createChatApi, HISTORY_DISABLED, type Chat, type ChatApi, type ChatMessage } from "./chatApi";
import { AssistantError } from "./api";

export interface UseChatsOptions {
  /** Injected for tests; defaults to the real clients so call sites need nothing. */
  chatApi?: ChatApi;
  assistantApi?: AssistantApi;
  /** Only load history once the sidebar is actually open. */
  active?: boolean;
}

/**
 * The three failure states, kept DISTINCT and none of them an error
 * (platform-assistant.md §5). Collapsing them is the easy mistake and it
 * produces a red banner on a healthy deployment that simply has the feature
 * switched off — which trains operators to ignore red.
 */
export type HistoryStatus =
  /** Still finding out. */
  | "loading"
  /** Working. */
  | "ready"
  /** This deployment has no chat store. Not a fault. */
  | "disabled"
  /** The store is configured but did not answer. A fault, but only of history. */
  | "unavailable";

export interface ChatsState {
  status: HistoryStatus;
  reason: string | null;
  chats: Chat[];
  activeId: string | null;
  messages: ChatMessage[];
  /** The agent currently answering, so the composer can show progress. */
  sending: boolean;
  /** An error from THIS exchange — never from history bookkeeping. */
  askError: string | null;
  query: string;
  setQuery: (q: string) => void;
  select: (chatId: string | null) => void;
  send: (question: string, agent?: string, execId?: string) => Promise<void>;
  rename: (chatId: string, title: string) => Promise<void>;
  pin: (chatId: string, pinned: boolean) => Promise<void>;
  remove: (chatId: string) => Promise<void>;
  cancel: () => void;
}


export function useChats({ chatApi, assistantApi, active = true }: UseChatsOptions = {}): ChatsState {
  const chatsRef = useRef<ChatApi>(chatApi ?? createChatApi());
  const askRef = useRef<AssistantApi>(assistantApi ?? createAssistantApi());

  const [status, setStatus] = useState<HistoryStatus>("loading");
  const [reason, setReason] = useState<string | null>(null);
  const [chats, setChats] = useState<Chat[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [sending, setSending] = useState(false);
  const [askError, setAskError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  /**
   * Agents the SERVER says exist. Never a hardcoded id.
   *
   * This is not caution, it is a bug already paid for: the sidebar shipped
   * asking for an agent called "triage", which has never existed — the registry
   * defines explain-chain and summarise-incident. Every question came back "the
   * assistant could not complete this request", and nothing in the frontend
   * could have caught it, because an invented string type-checks perfectly.
   *
   * Deriving the id from the capability endpoint makes the drift impossible
   * rather than merely unlikely.
   */
  const [agents, setAgents] = useState<AssistantAgent[] | null>(null);
  /**
   * The in-flight capability lookup, so send() can WAIT for it.
   *
   * A drill panel hands its question over the moment the sidebar opens, which
   * is before the agent list has arrived. Reading the state alone made that
   * handover fail with "still checking" and drop the question silently — the
   * continuity path failing exactly when it is used.
   */
  const agentsPending = useRef<Promise<AssistantAgent[]> | null>(null);

  const mounted = useRef(true);
  const inFlight = useRef<AbortController | null>(null);
  /**
   * Conversations this session just created, whose transcript we already hold.
   *
   * Without this, sending the first question races itself: creating the chat
   * sets activeId, whose effect fetches the (empty) transcript and overwrites
   * the question the analyst can see on screen. It looked exactly like a
   * dropped message.
   */
  const locallyCreated = useRef<Set<string>>(new Set());

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      inFlight.current?.abort();
    };
  }, []);

  // Classify a failure ONCE, here, so every call site branches on a status
  // rather than re-deciding what a 503 means.
  const classify = useCallback((err: unknown) => {
    if (err instanceof AssistantError && err.status === HISTORY_DISABLED) {
      setStatus("disabled");
      setReason(err.message);
      return;
    }
    setStatus("unavailable");
    setReason(err instanceof Error ? err.message : "history is unavailable");
  }, []);

  // Chat list. Re-runs on search; the query is the only input, and an empty
  // query is the plain list.
  useEffect(() => {
    if (!active) return;
    const ctl = new AbortController();
    // Debounced so typing a search does not issue a request per keystroke.
    const t = setTimeout(() => {
      chatsRef.current
        .listChats(query || undefined, ctl.signal)
        .then((list) => {
          if (!mounted.current || ctl.signal.aborted) return;
          setChats(list);
          setStatus("ready");
          setReason(null);
        })
        .catch((err: unknown) => {
          if (!mounted.current || ctl.signal.aborted) return;
          classify(err);
        });
    }, query ? 200 : 0);
    return () => {
      clearTimeout(t);
      ctl.abort();
    };
  }, [active, query, classify]);

  // Messages for the selected conversation.
  useEffect(() => {
    if (!activeId) {
      setMessages([]);
      return;
    }
    // A conversation we opened ourselves has no stored transcript worth
    // fetching, and fetching it would clobber the turn already on screen.
    if (locallyCreated.current.has(activeId)) return;
    const ctl = new AbortController();
    chatsRef.current
      .listMessages(activeId, ctl.signal)
      .then((msgs) => {
        if (!mounted.current || ctl.signal.aborted) return;
        setMessages(msgs);
      })
      .catch(() => {
        // A conversation that will not load is empty, not broken. The analyst
        // can still ask; losing the transcript must not block the composer.
        if (mounted.current && !ctl.signal.aborted) setMessages([]);
      });
    return () => ctl.abort();
  }, [activeId]);

  // Capability once per mount, for the agent list. A failure here is not shown
  // as an error: the ask itself will report honestly if there is no agent.
  useEffect(() => {
    if (!active) return;
    const ctl = new AbortController();
    const pending = askRef.current
      .capability(ctl.signal)
      .then((cap) => cap.agents ?? [])
      .catch(() => [] as AssistantAgent[]);
    agentsPending.current = pending;
    void pending.then((list) => {
      if (mounted.current && !ctl.signal.aborted) setAgents(list);
    });
    return () => ctl.abort();
  }, [active]);

  const select = useCallback((chatId: string | null) => {
    setActiveId(chatId);
    setAskError(null);
  }, []);

  const cancel = useCallback(() => {
    inFlight.current?.abort();
    inFlight.current = null;
    if (mounted.current) setSending(false);
  }, []);

  const send = useCallback(
    async (question: string, agent?: string, execId?: string) => {
      const text = question.trim();
      if (!text) return;

      // Prefer the caller's choice, else the first agent the SERVER reports.
      // Awaiting the lookup rather than reading state means a question handed
      // over on open is not dropped for arriving a few hundred ms early.
      const known = agents ?? (await agentsPending.current) ?? [];
      // The CONVERSATIONAL agent, by flag. The task agents ignore the question
      // entirely, so falling back to the first in the list is how "Hello"
      // returned a process-chain analysis.
      const agentId = agent ?? known.find((a) => a.conversational)?.id ?? known[0]?.id;
      if (!agentId) {
        setAskError("No assistant agent is available on this deployment.");
        return;
      }

      // A new question cancels the one in flight. A tool-calling answer runs for
      // twenty seconds and an analyst WILL send twice.
      inFlight.current?.abort();
      const ctl = new AbortController();
      inFlight.current = ctl;
      setSending(true);
      setAskError(null);

      // Ensure a conversation exists BEFORE asking, so the exchange has
      // somewhere to be recorded. When history is off this stays null and the
      // ask is simply incognito — the assistant still answers.
      let chatId = activeId;
      if (!chatId && status === "ready") {
        try {
          const created = await chatsRef.current.createChat(text.slice(0, 60));
          if (!mounted.current || ctl.signal.aborted) return;
          chatId = created.id;
          locallyCreated.current.add(created.id);
          setActiveId(created.id);
          // Dedupe on the way in. React silently misrenders a list with
          // duplicate keys, and "the server returned a chat we already hold"
          // is not a case worth trusting never to happen.
          setChats((prev) => [created, ...prev.filter((c) => c.id !== created.id)]);
        } catch {
          // Could not open a conversation: ask anyway, unrecorded. Losing the
          // history copy must never cost the analyst their answer.
          chatId = null;
        }
      }

      // Show the question immediately. The answer can take twenty seconds and a
      // composer that empties into nothing reads as a dropped message.
      const optimistic: ChatMessage = {
        id: `pending-${Date.now()}`,
        chat_id: chatId ?? "",
        role: "user",
        content: text,
        grounded: false,
        created_at: new Date().toISOString()
      };
      setMessages((prev) => [...prev, optimistic]);

      try {
        const answer = await askRef.current.ask({
          agent: agentId,
          question: text,
          execId,
          chatId: chatId ?? undefined,
          signal: ctl.signal
        });
        if (!mounted.current || ctl.signal.aborted) return;
        setMessages((prev) => [
          ...prev,
          {
            id: `answer-${Date.now()}`,
            chat_id: chatId ?? "",
            role: "assistant",
            content: answer.content,
            model: answer.model,
            steps: JSON.stringify(answer.steps ?? []),
            // The engine's judgement, carried through verbatim. Defaulting this
            // to true would make every answer look verified.
            grounded: answer.grounded === true,
            created_at: new Date().toISOString()
          }
        ]);
      } catch (err: unknown) {
        if (!mounted.current || ctl.signal.aborted) return;
        setAskError(err instanceof Error ? err.message : "the assistant failed");
      } finally {
        if (mounted.current && !ctl.signal.aborted) setSending(false);
      }
    },
    [activeId, status, agents]
  );

  // History bookkeeping. These update the list optimistically and refetch
  // nothing: a rename that fails leaves the sidebar showing the old title on the
  // next open, which is a better outcome than a spinner over a chat list.
  const rename = useCallback(async (chatId: string, title: string) => {
    setChats((prev) => prev.map((c) => (c.id === chatId ? { ...c, title } : c)));
    await chatsRef.current.renameChat(chatId, title).catch(() => undefined);
  }, []);

  const pin = useCallback(async (chatId: string, pinned: boolean) => {
    setChats((prev) =>
      prev.map((c) => (c.id === chatId ? { ...c, pinned_at: pinned ? new Date().toISOString() : null } : c))
    );
    await chatsRef.current.pinChat(chatId, pinned).catch(() => undefined);
  }, []);

  const remove = useCallback(
    async (chatId: string) => {
      setChats((prev) => prev.filter((c) => c.id !== chatId));
      if (activeId === chatId) {
        setActiveId(null);
        setMessages([]);
      }
      await chatsRef.current.deleteChat(chatId).catch(() => undefined);
    },
    [activeId]
  );

  return {
    status,
    reason,
    chats,
    activeId,
    messages,
    sending,
    askError,
    query,
    setQuery,
    select,
    send,
    rename,
    pin,
    remove,
    cancel
  };
}
