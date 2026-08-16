/**
 * Continuity between the drill assistant and the platform assistant
 * (docs/plan/platform-assistant.md §5, build step 5).
 *
 * THE PROBLEM THIS SOLVES: two assistants that look alike but do not share
 * history is the worst outcome, because it teaches the operator that neither
 * remembers. A question started inside a drill panel has to be the SAME
 * conversation, opened wider.
 *
 * WHY A PROVIDER AND NOT A PROP: the console is a multi-page app — soc, choke,
 * devices and fleet are separate entries with separate bundles and no shared
 * router. There is no common parent to thread props through, so the handover
 * point is the render shell every entry already goes through. Mounting it there
 * also means a drill panel on ANY page can hand over, including pages whose
 * shells were written before this existed.
 */
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { ChatSidebar } from "./ChatSidebar";
import type { UseChatsOptions } from "./useChats";

export interface AssistantHandover {
  /** The process under investigation, when the handover came from a drill. */
  execId?: string;
  /** A question to ask on open. */
  question?: string;
  /** Tenant or host this console is showing, for the header's scope chip. */
  scopeLabel?: string;
}

interface AssistantChatValue {
  open: boolean;
  /** Open the sidebar, optionally carrying a subject and a question with it. */
  openAssistant: (handover?: AssistantHandover) => void;
  closeAssistant: () => void;
  toggleAssistant: () => void;
}

const Ctx = createContext<AssistantChatValue | null>(null);

/**
 * useAssistantChat returns null when no provider is mounted.
 *
 * Null rather than a throw, deliberately. A drill panel rendered inside a test,
 * a Storybook story, or an entry that has not adopted the provider yet must
 * still render — the handover button simply does not appear. An assistant
 * convenience must never be able to blank a containment surface.
 */
export function useAssistantChat(): AssistantChatValue | null {
  return useContext(Ctx);
}

export function AssistantChatProvider({
  children,
  ...apis
}: { children: ReactNode } & Pick<UseChatsOptions, "chatApi" | "assistantApi">) {
  const [open, setOpen] = useState(false);
  const [handover, setHandover] = useState<AssistantHandover>({});

  const openAssistant = useCallback((next?: AssistantHandover) => {
    // Only replace the subject when the caller supplies one, so opening from
    // the nav does not wipe the context a drill panel just handed over.
    if (next) setHandover(next);
    setOpen(true);
  }, []);

  const closeAssistant = useCallback(() => setOpen(false), []);
  const toggleAssistant = useCallback(() => setOpen((v) => !v), []);

  const value = useMemo(
    () => ({ open, openAssistant, closeAssistant, toggleAssistant }),
    [open, openAssistant, closeAssistant, toggleAssistant]
  );

  return (
    <Ctx.Provider value={value}>
      {children}
      <ChatSidebar
        open={open}
        onClose={closeAssistant}
        execId={handover.execId}
        initialQuestion={handover.question}
        scopeLabel={handover.scopeLabel}
        {...apis}
      />
    </Ctx.Provider>
  );
}
