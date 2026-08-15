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
}: {
  actions: ReturnType<typeof useChokeActions>;
  overlays: ReturnType<typeof useOverlays>;
  drill: ReturnType<typeof useDrill>;
  viewPrefs: ReturnType<typeof useViewPrefs>;
  circuits: CircuitEntry[];
  isFleetConsole: boolean;
}): CommandItem[] {
  return [
      { group: "preset", label: "Apply containment preset", run: () => actions.openPresetConfirm("containment") },
      { group: "preset", label: "Apply forensic preset", run: () => actions.openPresetConfirm("forensic") },
      { group: "preset", label: "Apply maintenance preset", run: () => actions.openPresetConfirm("maintenance") },
      { group: "preset", label: "Apply default preset", run: () => actions.openPresetConfirm("default") },
      { group: "action", label: "Open jail picker", run: () => overlays.setJailOpen(true) },
      { group: "action", label: "Toggle kill-switch", run: actions.openKillSwitchConfirm },
      { group: "action", label: "Thaw quarantine", run: actions.openThawConfirm },
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
