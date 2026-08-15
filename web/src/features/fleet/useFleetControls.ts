/**
 * The fleet console's write path: who a write targets, what it carries, and the
 * fan-out result the operator is shown afterwards.
 *
 * Targeting and writing are one hook because they are one decision. A fleet
 * write is either "all configured peers" (`targets: null` on the wire) or an
 * explicit host list, and the difference between those is the difference
 * between choking one suspicious box and choking the estate — so the target set
 * is resolved at the moment of the write, from the same state the rail is
 * showing, rather than captured earlier and possibly gone stale.
 *
 * Every fan-out is partial-by-default: hosts fail independently, so the result
 * is summarised per host and the toast names the ones that did not take.
 */
import { useCallback, useEffect, useState } from "react";

import { writeKillSwitch, writePreset, writeThaw, writeThresholds } from "./api";
import { summarizeFanout, validateThresholds } from "./fleetLogic";
import type {
  ApplyMode,
  ConfirmState,
  FleetPeer,
  PollStatus,
  PresetName,
  Thresholds,
  ToastMessage
} from "./types";

export const DEFAULT_THRESHOLDS: Thresholds = {
  throttle_at: 10,
  tarpit_at: 30,
  quarantine_at: 60,
  sever_at: 100
};

/** `null` is the wire's "every configured peer" — not "no hosts". */
function targetsForMode(mode: ApplyMode, selected: Set<string>): string[] | null {
  return mode === "sel" ? Array.from(selected) : null;
}

export interface FleetControlsOptions {
  peers: FleetPeer[];
  /** Configured peer count — the target count when writing to all hosts. */
  totalHosts: number;
  majorityThresholds: Thresholds | null;
  pollStatus: PollStatus;
  pushToast: (kind: ToastMessage["kind"], title: string, body?: string) => void;
  refresh: () => Promise<void>;
  setConfirmState: (state: ConfirmState | null) => void;
}

export interface FleetControls {
  selected: Set<string>;
  applyMode: ApplyMode;
  setApplyMode: (mode: ApplyMode) => void;
  selectHost: (host: string, checked: boolean) => void;
  selectAll: () => void;
  clearSelection: () => void;
  targetCount: number;
  writesDisabled: boolean;
  thresholdDraft: Thresholds;
  thresholdDirty: boolean;
  setThreshold: (key: keyof Thresholds, value: string) => void;
  applyThresholds: () => Promise<void>;
  requestPreset: (name: PresetName) => void;
  requestKillSwitchOn: () => void;
  disengageKillSwitch: () => void;
  requestThaw: () => void;
}

export function useFleetControls({
  peers,
  totalHosts,
  majorityThresholds,
  pollStatus,
  pushToast,
  refresh,
  setConfirmState
}: FleetControlsOptions): FleetControls {
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [applyMode, setApplyMode] = useState<ApplyMode>("all");
  const [thresholdDraft, setThresholdDraft] = useState<Thresholds>(DEFAULT_THRESHOLDS);
  const [thresholdDirty, setThresholdDirty] = useState(false);
  const [pendingAction, setPendingAction] = useState<string | null>(null);

  // A host that drops out of the peer list must drop out of the selection with
  // it, or the next "Selected only" write names a host nobody can see.
  useEffect(() => {
    setSelected((current) => {
      const allowed = new Set(peers.map((peer) => peer.name));
      const next = new Set(Array.from(current).filter((host) => allowed.has(host)));
      if (next.size === current.size) {
        return current;
      }
      if (next.size === 0) {
        setApplyMode("all");
      }
      return next;
    });
  }, [peers]);

  useEffect(() => {
    if (!thresholdDirty && majorityThresholds) {
      setThresholdDraft(majorityThresholds);
    }
  }, [majorityThresholds, thresholdDirty]);

  const activeTargets = targetsForMode(applyMode, selected);
  const targetCount = activeTargets?.length ?? totalHosts;
  const writesDisabled = pollStatus === "disabled" || pendingAction !== null || totalHosts === 0;

  const requireTargets = useCallback((): string[] | null | undefined => {
    const targets = targetsForMode(applyMode, selected);
    if (applyMode === "sel" && (!targets || targets.length === 0)) {
      pushToast("warn", "No hosts selected", "Pick at least one host or switch to All hosts.");
      return undefined;
    }
    return targets;
  }, [applyMode, pushToast, selected]);

  const reportAndRefresh = useCallback(
    async (label: string, hosts: Array<{ ok: boolean; name: string; status?: number; error?: string }>) => {
      const summary = summarizeFanout(label, hosts);
      pushToast(summary.ok ? "ok" : "err", summary.title, summary.body);
      await refresh();
    },
    [pushToast, refresh]
  );

  const runPreset = useCallback(
    async (name: PresetName, reason: string) => {
      const targets = requireTargets();
      if (targets === undefined) return;
      setPendingAction(`preset-${name}`);
      try {
        const result = await writePreset(name, targets, reason || `fleet UI preset: ${name}`);
        await reportAndRefresh(`Preset ${name}`, result.hosts ?? []);
      } catch (error) {
        pushToast("err", "Preset failed", error instanceof Error ? error.message : "request failed");
      } finally {
        setPendingAction(null);
      }
    },
    [pushToast, reportAndRefresh, requireTargets]
  );

  const requestPreset = useCallback(
    (name: PresetName) => {
      const danger = name === "containment" || name === "maintenance";
      if (!danger) {
        void runPreset(name, `fleet UI preset: ${name}`);
        return;
      }
      setConfirmState({
        title: `Apply ${name} preset?`,
        body:
          name === "containment"
            ? "Containment lowers thresholds across targeted hosts and can immediately choke suspicious chains."
            : "Maintenance engages the kill-switch and raises thresholds across targeted hosts.",
        tone: "danger",
        confirmLabel: "Apply preset",
        reasonLabel: "Audit reason",
        reasonRequired: true,
        defaultReason: `fleet UI preset: ${name}`,
        onConfirm: (reason) => runPreset(name, reason)
      });
    },
    [runPreset, setConfirmState]
  );

  const applyThresholds = useCallback(async () => {
    const validation = validateThresholds(thresholdDraft);
    if (validation) {
      pushToast("err", "Invalid thresholds", validation);
      return;
    }
    const targets = requireTargets();
    if (targets === undefined) return;
    setPendingAction("thresholds");
    try {
      const result = await writeThresholds(thresholdDraft, targets);
      setThresholdDirty(false);
      await reportAndRefresh("Thresholds", result.hosts ?? []);
    } catch (error) {
      pushToast("err", "Threshold update failed", error instanceof Error ? error.message : "request failed");
    } finally {
      setPendingAction(null);
    }
  }, [pushToast, reportAndRefresh, requireTargets, thresholdDraft]);

  const setKillSwitch = useCallback(
    async (on: boolean) => {
      const targets = requireTargets();
      if (targets === undefined) return;
      setPendingAction(on ? "kill-on" : "kill-off");
      try {
        const result = await writeKillSwitch(on, targets);
        await reportAndRefresh(on ? "Kill-switch ON" : "Kill-switch OFF", result.hosts ?? []);
      } catch (error) {
        pushToast("err", "Kill-switch failed", error instanceof Error ? error.message : "request failed");
      } finally {
        setPendingAction(null);
      }
    },
    [pushToast, reportAndRefresh, requireTargets]
  );

  const thaw = useCallback(
    async (reason: string) => {
      const targets = requireTargets();
      if (targets === undefined) return;
      setPendingAction("thaw");
      try {
        const result = await writeThaw(reason || "fleet UI thaw", targets);
        await reportAndRefresh("Thaw", result.hosts ?? []);
      } catch (error) {
        pushToast("err", "Thaw failed", error instanceof Error ? error.message : "request failed");
      } finally {
        setPendingAction(null);
      }
    },
    [pushToast, reportAndRefresh, requireTargets]
  );

  const requestKillSwitchOn = useCallback(() => {
    setConfirmState({
      title: "Engage kill-switch?",
      body: "Kill-switch on bypasses enforcement across targeted hosts. Decisions still log.",
      tone: "danger",
      confirmLabel: "Engage",
      onConfirm: () => setKillSwitch(true)
    });
  }, [setConfirmState, setKillSwitch]);

  const disengageKillSwitch = useCallback(() => {
    void setKillSwitch(false);
  }, [setKillSwitch]);

  const requestThaw = useCallback(() => {
    setConfirmState({
      title: "Thaw quarantined cgroup?",
      body: "Releases paused processes from choke-quarantined on targeted hosts.",
      confirmLabel: "Thaw",
      reasonLabel: "Audit reason",
      reasonRequired: true,
      defaultReason: "fleet UI thaw",
      onConfirm: thaw
    });
  }, [setConfirmState, thaw]);

  const setThreshold = useCallback((key: keyof Thresholds, value: string) => {
    setThresholdDirty(true);
    setThresholdDraft((current) => ({ ...current, [key]: Number(value) }));
  }, []);

  const selectHost = useCallback((host: string, checked: boolean) => {
    setSelected((current) => {
      const next = new Set(current);
      if (checked) {
        next.add(host);
      } else {
        next.delete(host);
      }
      setApplyMode(next.size > 0 ? "sel" : "all");
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelected(new Set(peers.map((peer) => peer.name)));
    setApplyMode("sel");
  }, [peers]);

  const clearSelection = useCallback(() => {
    setSelected(new Set());
    setApplyMode("all");
  }, []);

  return {
    selected,
    applyMode,
    setApplyMode,
    selectHost,
    selectAll,
    clearSelection,
    targetCount,
    writesDisabled,
    thresholdDraft,
    thresholdDirty,
    setThreshold,
    applyThresholds,
    requestPreset,
    requestKillSwitchOn,
    disengageKillSwitch,
    requestThaw
  };
}
