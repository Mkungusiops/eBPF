// Global keyboard routing for the gateway.
//
// The handler closes over a dozen pieces of state and can fire the fleet
// KILL-SWITCH (Shift-K) and the containment presets, so it must always see
// current state — but it must not re-register on every render of the route
// either, which is what it did with no dependency array at all. Holding the
// callback in a ref gives both: the listener is attached once, and the function
// it calls is always the latest one. The empty dependency array below is
// deliberate and load-bearing; do not add to it.
import { useEffect, useRef } from "react";
import type { useChokeActions } from "./useChokeActions";
import type { useChokeFilters } from "./useChokeFilters";
import type { useDrill, useOverlays } from "./useChokeShell";

export function useChokeHotkeys({
  overlays,
  drill,
  filters,
  actions,
}: {
  overlays: ReturnType<typeof useOverlays>;
  drill: ReturnType<typeof useDrill>;
  filters: ReturnType<typeof useChokeFilters>;
  actions: ReturnType<typeof useChokeActions>;
}): void {
  const onKeyRef = useRef<(event: KeyboardEvent) => void>(() => {});
  onKeyRef.current = (event: KeyboardEvent) => {
    {
      const active = document.activeElement;
      const typing =
        active instanceof HTMLInputElement ||
        active instanceof HTMLTextAreaElement ||
        active instanceof HTMLSelectElement ||
        active?.getAttribute("contenteditable") === "true";

      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        overlays.setCommandOpen(true);
        return;
      }
      if (event.key === "Escape") {
        if (overlays.commandOpen) return overlays.setCommandOpen(false);
        if (overlays.helpOpen) return overlays.setHelpOpen(false);
        if (drill.drill.kind !== "closed") return drill.setDrill({ kind: "closed" });
        if (overlays.jailOpen) return overlays.setJailOpen(false);
        if (overlays.confirm) return overlays.setConfirm(null);
        if (overlays.popover) return overlays.setPopover(null);
        if (overlays.notificationsOpen) return overlays.setNotificationsOpen(false);
        if (overlays.profileOpen) return overlays.setProfileOpen(false);
        if (filters.selectedExecs.size) return filters.setSelectedExecs(new Set());
      }
      if (typing) return;
      if (event.key === "?") overlays.setHelpOpen(true);
      if (event.key === "/") {
        event.preventDefault();
        document.querySelector<HTMLInputElement>("[data-choke-global-search]")?.focus();
      }
      if (event.key === "J") overlays.setJailOpen(true);
      if (event.key === "K") actions.openKillSwitchConfirm();
      if (event.key === "g") window.location.href = "/";
      if (["c", "f", "m", "d"].includes(event.key)) {
        const map: Record<string, string> = { c: "containment", f: "forensic", m: "maintenance", d: "default" };
        actions.openPresetConfirm(map[event.key]);
      }
    }
  };

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => onKeyRef.current(event);
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);
}
