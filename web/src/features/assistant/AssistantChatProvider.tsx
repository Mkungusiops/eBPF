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
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { ChatSidebar } from "./ChatSidebar";
import { assistantRequest, type AssistantSurface } from "./api";
import type { UseChatsOptions } from "./useChats";

export interface AssistantHandover {
  /** The process under investigation, when the handover came from a drill. */
  execId?: string;
  /** A question to ask on open. */
  question?: string;
  /** Tenant or host this console is showing, for the header's scope chip. */
  scopeLabel?: string;
  /**
   * The panel the handover came from, so the wider view opens knowing not just
   * WHICH process is under investigation but WHAT KIND OF PANEL the analyst was
   * standing on. Without it, expanding from Devices Assurance produced a
   * sidebar that had forgotten it was ever about devices.
   */
  surface?: AssistantSurface;
}

interface AssistantChatValue {
  open: boolean;
  /** Open the sidebar, optionally carrying a subject and a question with it. */
  openAssistant: (handover?: AssistantHandover) => void;
  closeAssistant: () => void;
  toggleAssistant: () => void;
  /**
   * Whether this deployment has an assistant at all. null while unknown.
   *
   * The console needs it for one specific decision: Behaviour & Intel was taken
   * out of the side menu and is now opened FROM the assistant. The assistant is
   * opt-in and off by default, while enrichment is on by default — so on a
   * deployment with no model configured that panel would be unreachable. The
   * nav entry comes back when this is false, which is the whole reason the flag
   * is here rather than assumed.
   */
  available: boolean | null;
  /**
   * Register a way to open the Behaviour & Reputation panel.
   *
   * The provider is mounted at the app root, above the surface that owns the
   * panel's open state, so it cannot reach it directly. The owner registers a
   * callback and the sidebar shows its "view the findings" link only while one
   * is registered — so on a route with no such panel the link simply is not
   * offered, rather than being offered and doing nothing.
   */
  setFindingsOpener: (open: (() => void) | null) => void;
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
  const [available, setAvailable] = useState<boolean | null>(null);
  const [findingsOpener, setFindingsOpenerState] = useState<(() => void) | null>(null);

  // One capability probe at the root, on mount. The drill panels each ask again
  // when they open; this one exists so the NAV can decide whether Behaviour &
  // Intel needs its own entry, which has to be answered before anything is
  // opened.
  //
  // Through the shared transport rather than a bare fetch, so this probe cannot
  // be the one assistant request that skips what that transport applies (api.ts
  // — CSRF, the customer on the query string, the wait for the boot driver). It
  // reads a DEPLOYMENT fact and would survive being unscoped; being the only
  // exception is what would not survive, because the next reader has to find
  // out which of two shapes is the right one to copy.
  useEffect(() => {
    const ctl = new AbortController();
    assistantRequest("/api/assistant", { signal: ctl.signal })
      .then((r) => (r.ok ? r.json() : null))
      .then((d: { enabled?: boolean } | null) => {
        if (!ctl.signal.aborted) setAvailable(d?.enabled === true);
      })
      // Unreachable is treated as UNAVAILABLE, not unknown: the fallback nav
      // entry appearing is harmless, and a panel nobody can reach is not.
      .catch(() => {
        if (!ctl.signal.aborted) setAvailable(false);
      });
    return () => ctl.abort();
  }, []);

  // Wrapped in an updater because React invokes a bare function passed to a
  // state setter — storing a callback needs `() => fn`, and getting that wrong
  // calls the opener instead of remembering it.
  const setFindingsOpener = useCallback((fn: (() => void) | null) => {
    setFindingsOpenerState(() => fn);
  }, []);

  const openAssistant = useCallback((next?: AssistantHandover) => {
    // Only replace the subject when the caller supplies one, so opening from
    // the nav does not wipe the context a drill panel just handed over.
    if (next) setHandover(next);
    setOpen(true);
  }, []);

  const closeAssistant = useCallback(() => setOpen(false), []);
  const toggleAssistant = useCallback(() => setOpen((v) => !v), []);

  const value = useMemo(
    () => ({ open, openAssistant, closeAssistant, toggleAssistant, available, setFindingsOpener }),
    [open, openAssistant, closeAssistant, toggleAssistant, available, setFindingsOpener]
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
        surface={handover.surface}
        onOpenFindings={findingsOpener ?? undefined}
        {...apis}
      />
    </Ctx.Provider>
  );
}
