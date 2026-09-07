// Everything that floats above the page, in the two groups the DOM order puts
// them in: the anchored drawers that sit under the topbar, and the dialog layer
// that sits at the end of the document.
//
// They are separate components because a scrim and the status-pill popover
// render between them, and stacking here is DOM order — not z-index.
import {
  annotateCircuit,
  forgetCircuits,
  getProc,
  jailProcesses,
} from "./api";
import type { Decision, ToastMessage } from "./types";
import type { CommandItem } from "./commandItems";
import type { useAlertPrefs, useDrill, useOverlays, useViewPrefs } from "./useChokeShell";
import { ToastStack } from "./components";
import { NotificationsPanel } from "./notifications";
import { CommandPalette, ConfirmModal, HelpModal, ProfilePanel } from "./modals";
import { ProcessDrill } from "./ProcessDrill";
import { JailPicker } from "./JailPicker";

export function ChokeDrawers({
  overlays,
  alertPrefs,
  viewPrefs,
  drill,
  decisions,
  userLabel,
  theme,
  bootMs,
  windowMin,
  windowOptions,
  onWindow,
  onAck,
  onSnapshot,
  onThaw,
  thawBlockedReason = "",
}: {
  overlays: ReturnType<typeof useOverlays>;
  alertPrefs: ReturnType<typeof useAlertPrefs>;
  viewPrefs: ReturnType<typeof useViewPrefs>;
  drill: ReturnType<typeof useDrill>;
  decisions: Decision[];
  userLabel: string;
  theme: string;
  bootMs: number;
  windowMin: number;
  windowOptions: number[];
  onWindow: (value: number) => void;
  onAck: (ids: number[]) => void;
  onSnapshot: () => void;
  onThaw: () => void;
  /** Why "Thaw all" is withheld from this account — see ProfilePanel. */
  thawBlockedReason?: string;
}) {
  return (
    <>
      {overlays.notificationsOpen && (
        <NotificationsPanel
          decisions={decisions}
          acked={alertPrefs.ackedDecisionIds}
          clearedAt={alertPrefs.alertsClearedAt}
          alertsActive={alertPrefs.alertsActive}
          badgeEnabled={alertPrefs.alertBadgeEnabled}
          onClose={() => overlays.setNotificationsOpen(false)}
          onToggleAlerts={() => alertPrefs.setAlertsActive((value) => !value)}
          onToggleBadge={() => alertPrefs.setAlertBadgeEnabled((value) => !value)}
          onAck={onAck}
          onClear={() => alertPrefs.setAlertsClearedAt(Date.now())}
          onOpenDrill={(execId) => void drill.openDrill(execId)}
        />
      )}

      {overlays.profileOpen && (
        <ProfilePanel
          userLabel={userLabel}
          bootMs={bootMs}
          decisionsSeen={decisions.length}
          ackedCount={alertPrefs.ackedDecisionIds.size}
          theme={theme}
          density={viewPrefs.density}
          windowMin={windowMin}
          windowOptions={windowOptions}
          onDensity={() => viewPrefs.setDensity((prev) => (prev === "compact" ? "normal" : "compact"))}
          onWindow={onWindow}
          onSnapshot={onSnapshot}
          onCommand={() => { overlays.setProfileOpen(false); overlays.setCommandOpen(true); }}
          onHelp={() => { overlays.setProfileOpen(false); overlays.setHelpOpen(true); }}
          onThaw={() => { overlays.setProfileOpen(false); onThaw(); }}
          thawBlockedReason={thawBlockedReason}
          onClose={() => overlays.setProfileOpen(false)}
        />
      )}
    </>
  );
}

export function ChokeOverlays({
  overlays,
  drill,
  commandItems,
  toasts,
  pushToast,
  disabled,
  readOnly = false,
  readOnlyReason = "",
  onCopy,
  refreshAll,
  refreshCircuits,
}: {
  overlays: ReturnType<typeof useOverlays>;
  drill: ReturnType<typeof useDrill>;
  commandItems: CommandItem[];
  toasts: ToastMessage[];
  pushToast: (message: string, kind?: ToastMessage["kind"]) => void;
  disabled: boolean;
  /**
   * whoami says this account cannot respond. Separate from `disabled`, which
   * is about the gateway serving at all — the layers below have to disable the
   * same controls for two different reasons and say the right one.
   */
  readOnly?: boolean;
  readOnlyReason?: string;
  onCopy: (value: string) => void;
  refreshAll: () => Promise<void>;
  refreshCircuits: () => Promise<void>;
}) {
  return (
    <>
      <ProcessDrill
        drill={drill.drill}
        readOnly={readOnly}
        readOnlyReason={readOnlyReason}
        onClose={() => drill.setDrill({ kind: "closed" })}
        onRefresh={() => void refreshAll()}
        onForget={async (execId) => {
          await forgetCircuits([execId]);
          pushToast("forgot circuit", "ok");
          drill.setDrill({ kind: "closed" });
          await refreshAll();
        }}
        onAnnotate={async (execId, note) => {
          // "note saved" used to fire unconditionally. On the control plane the
          // endpoint returned {"ok": true} without ever reading the body, so
          // the operator was told their justification was recorded and it was
          // discarded — then the field came back empty on refresh with no
          // explanation. The server now refuses honestly, so the console has to
          // relay the refusal rather than congratulate the user on it.
          try {
            await annotateCircuit(execId, note);
            pushToast(note ? "note saved" : "note cleared", "ok");
            await refreshCircuits();
          } catch (error) {
            pushToast(error instanceof Error ? error.message : "note NOT saved", "warn");
          }
        }}
        onCopy={onCopy}
      />

      <JailPicker
        open={overlays.jailOpen}
        disabled={disabled}
        readOnly={readOnly}
        readOnlyReason={readOnlyReason}
        detail={overlays.jailDetail}
        onClose={() => overlays.setJailOpen(false)}
        onInspect={async (process) => {
          overlays.setJailDetail({ kind: "loading", process });
          try {
            overlays.setJailDetail({ kind: "ready", process, detail: await getProc(process.pid) });
          } catch (error) {
            overlays.setJailDetail({ kind: "error", process, message: error instanceof Error ? error.message : "live proc failed" });
          }
        }}
        onOpenDrill={(process) => {
          if (process.exec_id) void drill.openDrill(process.exec_id);
          else overlays.setJailDetail({ kind: "loading", process });
        }}
        onAction={async ({ pids, action, reason, descendants, revert_after_seconds }) => {
          const response = await jailProcesses({ pids, action, reason, descendants, revert_after_seconds });
          const results = response.results || [];
          const ok = results.filter((result) => result.ok).length;
          pushToast(`jail ${action}: ${ok}/${results.length || pids.length} ok`, ok === results.length ? "ok" : "warn");
          await refreshAll();
        }}
        pushToast={pushToast}
      />

      {overlays.commandOpen && <CommandPalette items={commandItems} onClose={() => overlays.setCommandOpen(false)} />}
      {overlays.confirm && <ConfirmModal request={overlays.confirm} onClose={() => overlays.setConfirm(null)} pushToast={pushToast} />}
      {overlays.helpOpen && <HelpModal onClose={() => overlays.setHelpOpen(false)} />}
      <ToastStack toasts={toasts} />
    </>
  );
}
