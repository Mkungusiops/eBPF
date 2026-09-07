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
import { readFanout, summarizeFanout, validateThresholds } from "./fleetLogic";
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

/**
 * What the audit log records when the operator adds nothing of their own. It
 * says where the change came from rather than inventing a justification.
 */
const DEFAULT_KILL_SWITCH_REASON = {
  on: "fleet UI: kill-switch engaged",
  off: "fleet UI: kill-switch disengaged"
} as const;

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
  /**
   * whoami's `can_respond`, or `null` when the server did not publish one.
   *
   * Only `false` disables anything, and only once `identityResolved` is true.
   * `null` from an answered whoami is the single-tenant engine, which has no
   * permission model to consult — see FleetWhoami in api.ts.
   */
  canRespond?: boolean | null;
  /**
   * Whether whoami has answered at all. Required, and deliberately not
   * defaulted: `canRespond: null` cannot distinguish "the single-tenant engine
   * publishes no can_respond" from "the request has not come back yet", and
   * arming the rail on the second is how a read-only account got live
   * containment controls on first paint.
   */
  identityResolved: boolean;
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
  /**
   * Why the rail is disabled, in the operator's terms — "" when it is armed.
   *
   * Only the standing reasons are named. A write already in flight also
   * disables the rail, but it lasts a request and the button's own disabled
   * state says it; announcing that one would flicker a banner on every write.
   */
  writesDisabledReason: string;
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
  canRespond = null,
  identityResolved,
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

  // Two of these facts are about the operator and three about the estate. The
  // operator's were missing entirely, so a read-only account got a fully armed
  // write rail and found out it could not respond by pressing an emergency
  // control mid-incident and watching the server refuse it.
  const readOnlyAccount = identityResolved && canRespond === false;
  // An unanswered whoami is not permission. The rail stays closed until the
  // server has said something — otherwise, whenever /api/whoami loses the race
  // with the fleet snapshot, a read-only principal is handed an armed
  // estate-wide kill-switch for as long as the identity call is in flight.
  const writesDisabledReason = !identityResolved
    ? "Checking your response rights with the server."
    : readOnlyAccount
      ? "Your account is read-only: it can watch the fleet but not change it. Ask an operator with response rights to send this."
      : pollStatus === "disabled"
        ? "Fleet mode is not enabled on this engine, so there is nothing to write to."
        : totalHosts === 0
          ? "No peers are configured, so a write would have no target."
          : "";
  const writesDisabled = writesDisabledReason !== "" || pendingAction !== null;

  /**
   * The two questions every write answers before it leaves: may this account
   * write at all, and to which hosts. Both refusals are loud — a control that
   * silently does nothing is indistinguishable from a broken one.
   *
   * The target set is resolved HERE, at write time, rather than captured when a
   * confirm dialog opened, so what goes on the wire is what the rail is showing.
   */
  const resolveWrite = useCallback((): { targets: string[] | null } | null => {
    if (!identityResolved) {
      pushToast(
        "warn",
        "Still checking your rights",
        "The server has not yet said whether this account may respond, so this write was not sent. Try again in a moment."
      );
      return null;
    }
    if (canRespond === false) {
      pushToast(
        "warn",
        "Read-only account",
        "Your account does not carry response rights, so this write was not sent."
      );
      return null;
    }
    const targets = targetsForMode(applyMode, selected);
    if (applyMode === "sel" && (!targets || targets.length === 0)) {
      pushToast("warn", "No hosts selected", "Pick at least one host or switch to All hosts.");
      return null;
    }
    return { targets };
  }, [applyMode, canRespond, identityResolved, pushToast, selected]);

  const reportAndRefresh = useCallback(
    async (label: string, result: unknown) => {
      // The raw envelope, not `result.hosts ?? []`: the control plane reports
      // coverage as applied/total, and reading only `hosts` off it discarded
      // what it said and printed 0/0 under a green "applied".
      const summary = summarizeFanout(label, readFanout(result));
      pushToast(summary.ok ? "ok" : "err", summary.title, summary.body);
      await refresh();
    },
    [pushToast, refresh]
  );

  const runPreset = useCallback(
    async (name: PresetName, reason: string) => {
      const write = resolveWrite();
      if (!write) return;
      setPendingAction(`preset-${name}`);
      try {
        const result = await writePreset(name, write.targets, reason || `fleet UI preset: ${name}`);
        await reportAndRefresh(`Preset ${name}`, result);
      } catch (error) {
        pushToast("err", "Preset failed", error instanceof Error ? error.message : "request failed");
      } finally {
        setPendingAction(null);
      }
    },
    [pushToast, reportAndRefresh, resolveWrite]
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
    const write = resolveWrite();
    if (!write) return;
    setPendingAction("thresholds");
    try {
      const result = await writeThresholds(thresholdDraft, write.targets);
      setThresholdDirty(false);
      await reportAndRefresh("Thresholds", result);
    } catch (error) {
      pushToast("err", "Threshold update failed", error instanceof Error ? error.message : "request failed");
    } finally {
      setPendingAction(null);
    }
  }, [pushToast, reportAndRefresh, resolveWrite, thresholdDraft]);

  const setKillSwitch = useCallback(
    async (on: boolean, reason: string) => {
      const write = resolveWrite();
      if (!write) return;
      setPendingAction(on ? "kill-on" : "kill-off");
      try {
        const audit = reason.trim() || DEFAULT_KILL_SWITCH_REASON[on ? "on" : "off"];
        const result = await writeKillSwitch(on, write.targets, audit);
        await reportAndRefresh(on ? "Kill-switch ON" : "Kill-switch OFF", result);
      } catch (error) {
        pushToast("err", "Kill-switch failed", error instanceof Error ? error.message : "request failed");
      } finally {
        setPendingAction(null);
      }
    },
    [pushToast, reportAndRefresh, resolveWrite]
  );

  const thaw = useCallback(
    async (reason: string) => {
      const write = resolveWrite();
      if (!write) return;
      setPendingAction("thaw");
      try {
        const result = await writeThaw(reason || "fleet UI thaw", write.targets);
        await reportAndRefresh("Thaw", result);
      } catch (error) {
        pushToast("err", "Thaw failed", error instanceof Error ? error.message : "request failed");
      } finally {
        setPendingAction(null);
      }
    },
    [pushToast, reportAndRefresh, resolveWrite]
  );

  const requestKillSwitchOn = useCallback(() => {
    setConfirmState({
      title: "Engage kill-switch?",
      body: "Kill-switch on bypasses enforcement across targeted hosts. Decisions still log.",
      tone: "danger",
      confirmLabel: "Engage",
      // The engine audits this transition and the console used to hand it an
      // empty reason, so the audit row for the widest-blast-radius toggle on
      // the platform recorded who and when but never why. Collected and
      // required exactly as the thaw and containment confirms do it.
      reasonLabel: "Audit reason",
      reasonRequired: true,
      defaultReason: DEFAULT_KILL_SWITCH_REASON.on,
      onConfirm: (reason) => setKillSwitch(true, reason)
    });
  }, [setConfirmState, setKillSwitch]);

  // Disengaging is the way OUT of a bad state, so it is never gated behind a
  // dialog. It still carries a reason, because the engine audits this
  // transition too and an unexplained restore is as odd in the log as an
  // unexplained bypass.
  const disengageKillSwitch = useCallback(() => {
    void setKillSwitch(false, DEFAULT_KILL_SWITCH_REASON.off);
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
    writesDisabledReason,
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
