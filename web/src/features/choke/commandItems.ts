// The command palette's action list.
//
// Deliberately a plain builder rather than a hook with useMemo. The list is
// consumed only while the palette is open and it is ~30 object literals — the
// useMemo that used to wrap it saved nothing measurable while its [circuits]
// dependency list captured stale handlers, so opening the palette could run a
// closure over old state. Rebuilding it every render is the fix.
import type { CircuitEntry } from "./types";
import type { useChokeActions } from "./useChokeActions";
import type { useDrill, useOverlays, useViewPrefs } from "./useChokeShell";

export interface CommandItem {
  group: string;
  label: string;
  run: () => void;
}

export function buildCommandItems({
  actions,
  overlays,
  drill,
  viewPrefs,
  circuits,
  isFleetConsole,
  canRespond = null,
}: {
  actions: ReturnType<typeof useChokeActions>;
  overlays: ReturnType<typeof useOverlays>;
  drill: ReturnType<typeof useDrill>;
  viewPrefs: ReturnType<typeof useViewPrefs>;
  circuits: CircuitEntry[];
  isFleetConsole: boolean;
  /**
   * whoami's `can_respond`. `null` is "the server did not say" and leaves the
   * list whole — see canRespond.ts. An explicit `false` drops the response
   * entries, the same way an unavailable action is dropped below: the palette
   * has no disabled state, so listing a command that can only refuse would be
   * the armed control this gate exists to remove. The page's read-only banner
   * is what explains the absence.
   */
  canRespond?: boolean | null;
}): CommandItem[] {
  const respondItems: CommandItem[] =
    canRespond === false
      ? []
      : [
          { group: "preset", label: "Apply containment preset", run: () => actions.openPresetConfirm("containment") },
          { group: "preset", label: "Apply forensic preset", run: () => actions.openPresetConfirm("forensic") },
          { group: "preset", label: "Apply maintenance preset", run: () => actions.openPresetConfirm("maintenance") },
          { group: "preset", label: "Apply default preset", run: () => actions.openPresetConfirm("default") },
          { group: "action", label: "Open jail picker", run: () => overlays.setJailOpen(true) },
          { group: "action", label: "Toggle kill-switch", run: actions.openKillSwitchConfirm },
          // Named for what it releases on THIS deployment. "Thaw quarantine"
          // read as one host's tier on both, and on the control plane it is a
          // release across the fleet — the confirm states the exact hosts, but
          // the operator should not have to open it to learn the scale.
          {
            group: "action",
            label: isFleetConsole ? "Thaw containment across the fleet" : "Thaw this host's quarantine",
            run: actions.openThawConfirm,
          },
        ];
  return [
      ...respondItems,
      // Omitted on the fleet console: the endpoint is a deliberate 501 there.
      ...(isFleetConsole ? [] : [{ group: "action", label: "Download forensic snapshot", run: () => void actions.downloadSnapshot() }]),
      { group: "view", label: "Toggle density", run: () => viewPrefs.setDensity((prev) => (prev === "compact" ? "normal" : "compact")) },
      { group: "view", label: "Show help", run: () => overlays.setHelpOpen(true) },
      ...circuits.slice(0, 25).map((entry) => ({
        group: "process",
        label: `Drill in pid ${entry.pid || "-"} ${entry.binary || "(unknown)"}`,
        run: () => void drill.openDrill(entry.exec_id),
      })),
  ];
}
