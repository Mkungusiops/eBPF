// Shell state: the transient layers an operator opens over the gateway, the
// preferences that outlive a reload, and the toast channel every action
// reports through. Nothing here talks to the engine — it is the state that
// decides what is on screen, kept out of the data hooks so a poll can never
// close a dialog and a dialog can never trigger a poll.
import { useCallback, useEffect, useState } from "react";
import type { ViewMode } from "../common/ContainmentCommand";
import { getProcess } from "./api";
import type { ConfirmRequest, ToastMessage } from "./types";
import type { DrillState, JailDetail, PopoverName } from "./constants";
import { useStoredBoolean, useStoredSet } from "./hooks";
import { readJsonStorage, writeJsonStorage } from "./utils";

export interface Toasts {
  toasts: ToastMessage[];
  pushToast: (message: string, kind?: ToastMessage["kind"]) => void;
}

// Toasts self-expire after 3.2s. pushToast is stable across renders because
// the data layer takes it as a dependency: an unstable identity here would
// churn every refresh callback and re-fire the mount effect on a loop.
export function useToasts(): Toasts {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const pushToast = useCallback((message: string, kind: ToastMessage["kind"] = "ok") => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((prev) => [...prev, { id, kind, message }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, 3200);
  }, []);
  return { toasts, pushToast };
}

// The stacked surfaces, in the order Escape unwinds them: command palette,
// help, drill, jail, confirm, popover, notifications, profile.
export function useOverlays() {
  const [confirm, setConfirm] = useState<ConfirmRequest | null>(null);
  const [popover, setPopover] = useState<PopoverName>(null);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [jailOpen, setJailOpen] = useState(false);
  const [jailDetail, setJailDetail] = useState<JailDetail>({ kind: "closed" });
  return {
    confirm,
    setConfirm,
    popover,
    setPopover,
    notificationsOpen,
    setNotificationsOpen,
    profileOpen,
    setProfileOpen,
    commandOpen,
    setCommandOpen,
    helpOpen,
    setHelpOpen,
    jailOpen,
    setJailOpen,
    jailDetail,
    setJailDetail,
  };
}

export function useDrill() {
  const [drill, setDrill] = useState<DrillState>({ kind: "closed" });

  async function openDrill(execId: string): Promise<void> {
    setDrill({ kind: "loading", execId });
    try {
      setDrill({ kind: "ready", execId, payload: await getProcess(execId) });
    } catch (error) {
      setDrill({
        kind: "error",
        execId,
        message: error instanceof Error ? error.message : "process detail failed",
      });
    }
  }

  return { drill, setDrill, openDrill };
}

export function useViewPrefs() {
  const [density, setDensity] = useState<"normal" | "compact">("normal");
  const [viewMode, setViewMode] = useState<ViewMode>(() =>
    readJsonStorage<ViewMode>("choke.viewMode", "command") === "assurance" ? "assurance" : "command"
  );
  useEffect(() => writeJsonStorage("choke.viewMode", viewMode), [viewMode]);
  return { density, setDensity, viewMode, setViewMode };
}

export function useAlertPrefs() {
  const [ackedDecisionIds, setAckedDecisionIds] = useStoredSet("choke.tape.acked");
  const [alertsActive, setAlertsActive] = useStoredBoolean("soc.notifications", true);
  const [alertBadgeEnabled, setAlertBadgeEnabled] = useStoredBoolean("choke.alerts.badge", true);
  // "Clear all" in the alerts drawer hides everything up to this instant; newer
  // severed decisions still surface afterwards. Kept in state (session-scoped).
  const [alertsClearedAt, setAlertsClearedAt] = useState(0);
  return {
    ackedDecisionIds,
    setAckedDecisionIds,
    alertsActive,
    setAlertsActive,
    alertBadgeEnabled,
    setAlertBadgeEnabled,
    alertsClearedAt,
    setAlertsClearedAt,
  };
}
