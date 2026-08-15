/**
 * The device console's write path — everything that changes the data plane.
 *
 * It is kept apart from the read path deliberately: reads are polled and
 * abortable, writes are one-shot, operator-initiated and auditable. Every write
 * here ends the same way — a toast the operator can read, then a quiet refresh
 * so the table reflects what the engine actually did rather than what the UI
 * asked for. A 2xx is an accepted command, not an applied one.
 */
import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";

import { isDisabledError, type DevicesApi } from "./api";
import type { ConfirmOptions, ConfirmResult } from "./ConfirmModal";
import type { DeviceAction, DeviceDataPlaneState } from "./types";
import type { ToastTone } from "./useDeviceToast";
import { DISABLED_MESSAGE, summarizeResults } from "./utils";
import { ACTION_FOR_RUNG, type Rung } from "../common/enforcement";

export interface DeviceActionsOptions {
  api: DevicesApi;
  state: DeviceDataPlaneState | null;
  /** Macs the bulk bar acts on. */
  selected: Set<string>;
  /** The bulk bar's chosen choke action, audit reason and auto-revert window. */
  action: DeviceAction;
  reason: string;
  revertAfter: string;
  pushToast: (message: string, tone: ToastTone) => void;
  setDisabledMessage: Dispatch<SetStateAction<string | null>>;
  requestConfirm: (options: ConfirmOptions) => Promise<ConfirmResult | null>;
  refresh: () => void;
  clearSelection: () => void;
}

export interface DeviceActions {
  toggleMode: () => Promise<void>;
  toggleKillSwitch: () => Promise<void>;
  jailSelected: () => Promise<void>;
  thawSelected: () => Promise<void>;
  applyToDevice: (mac: string, rung: Rung, why: string) => Promise<{ ok: boolean; detail: string }>;
  readDeviceState: (mac: string) => Promise<string | undefined>;
}

export function useDeviceActions({
  api,
  state,
  selected,
  action,
  reason,
  revertAfter,
  pushToast,
  setDisabledMessage,
  requestConfirm,
  refresh,
  clearSelection
}: DeviceActionsOptions): DeviceActions {
  const toggleMode = useCallback(async () => {
    if (!state || state.dry_run) return;
    const currentlyEnforcing = Boolean(state.enforcing);
    const nextEnforcing = !currentlyEnforcing;
    const result = await requestConfirm({
      title: nextEnforcing ? "Switch to enforcing" : "Switch to detect-only",
      message: nextEnforcing
        ? "Device chokes will rate-limit or drop real LAN traffic. Confirm protected MACs are correct before going live."
        : "New device decisions will be audited without touching the data plane. Existing chokes stay visible.",
      confirmLabel: nextEnforcing ? "Go live" : "Switch to detect-only",
      danger: nextEnforcing,
      requireReason: true,
      reasonPlaceholder: "Why are you changing device mode?",
      defaultReason: nextEnforcing ? "go live" : "staging policy"
    });
    if (!result) return;
    try {
      const response = await api.setMode(nextEnforcing, result.reason);
      pushToast(`mode -> ${response.mode}`, "ok");
      refresh();
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [api, pushToast, refresh, requestConfirm, setDisabledMessage, state]);

  const toggleKillSwitch = useCallback(async () => {
    if (!state) return;
    const on = !state.kill_switched;
    const result = await requestConfirm({
      title: on ? "Engage kill-switch" : "Disengage kill-switch",
      message: on
        ? "This bypasses all device enforcement immediately. Decisions will still be audited."
        : "Device enforcement will resume according to the current mode and active buckets.",
      confirmLabel: on ? "Engage kill-switch" : "Disengage",
      danger: on
    });
    if (!result) return;
    try {
      const response = await api.setKillSwitch(on);
      pushToast(response.engaged ? "kill-switch engaged" : "kill-switch disengaged", response.engaged ? "warn" : "ok");
      refresh();
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [api, pushToast, refresh, requestConfirm, setDisabledMessage, state]);

  const jailSelected = useCallback(async () => {
    const macs = [...selected];
    if (macs.length === 0) {
      pushToast("select at least one device", "error");
      return;
    }
    const trimmedReason = reason.trim();
    if (!trimmedReason) {
      pushToast("reason is required for the audit log", "error");
      return;
    }
    const revert = Number.parseInt(revertAfter, 10);
    try {
      const response = await api.jailDevices({
        macs,
        action,
        reason: trimmedReason,
        revert_after_seconds: Number.isFinite(revert) && revert > 0 ? revert : undefined
      });
      const successes = response.results.filter((result) => result.ok).length;
      pushToast(summarizeResults(response.results, "choked"), successes > 0 ? "ok" : "error");
      refresh();
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [action, api, pushToast, reason, refresh, revertAfter, selected, setDisabledMessage]);

  const thawSelected = useCallback(async () => {
    const macs = [...selected];
    if (macs.length === 0) {
      pushToast("select at least one device", "error");
      return;
    }
    try {
      const response = await api.thawDevices({
        macs,
        reason: reason.trim() || "operator thaw"
      });
      const successes = response.results.filter((result) => result.ok).length;
      pushToast(summarizeResults(response.results, "thawed"), successes > 0 ? "ok" : "error");
      clearSelection();
      refresh();
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [api, clearSelection, pushToast, reason, refresh, selected, setDisabledMessage]);

  // Per-device enforcement for the shared ladder. The bulk bar above acts on a
  // checkbox selection; this acts on the one device the operator opened. A
  // device sever is a reversible drop rule, so release works from every rung —
  // unlike a process sever, which is a SIGKILL (see DEVICE_TERMINAL).
  const applyToDevice = useCallback(
    async (mac: string, rung: Rung, why: string) => {
      try {
        if (rung === "pristine") {
          const response = await api.thawDevices({ macs: [mac], reason: why || "operator thaw" });
          const failure = response.results.find((result) => !result.ok);
          return failure
            ? { ok: false, detail: failure.error || "release rejected" }
            : { ok: true, detail: "release accepted" };
        }
        const response = await api.jailDevices({
          macs: [mac],
          action: ACTION_FOR_RUNG[rung] as DeviceAction,
          reason: why
        });
        const failure = response.results.find((result) => !result.ok);
        return failure
          ? { ok: false, detail: failure.error || `${ACTION_FOR_RUNG[rung]} rejected` }
          : { ok: true, detail: `${ACTION_FOR_RUNG[rung]} accepted` };
      } catch (caught) {
        handleActionError(caught, pushToast, setDisabledMessage);
        return { ok: false, detail: (caught as Error).message || "action failed" };
      }
    },
    [api, pushToast, setDisabledMessage]
  );

  const readDeviceState = useCallback(
    async (mac: string) => {
      const list = await api.fetchDevices();
      return list.find((device) => device.mac === mac)?.state;
    },
    [api]
  );

  return { toggleMode, toggleKillSwitch, jailSelected, thawSelected, applyToDevice, readDeviceState };
}

function handleActionError(
  error: unknown,
  pushToast: (message: string, tone: ToastTone) => void,
  setDisabledMessage: (message: string) => void
) {
  if (isDisabledError(error)) {
    setDisabledMessage(DISABLED_MESSAGE);
    pushToast("device choke disabled", "error");
    return;
  }
  pushToast(error instanceof Error ? error.message : "request failed", "error");
}
