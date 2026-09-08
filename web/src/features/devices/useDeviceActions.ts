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
import { readOnlyReason } from "../choke/canRespond";
import type { ConfirmOptions, ConfirmResult } from "./ConfirmModal";
import type { DeviceAction, DeviceDataPlaneState } from "./types";
import type { ToastTone } from "./useDeviceToast";
import { deviceRungNeedsReason, DISABLED_MESSAGE, summarizeResults } from "./utils";
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
  /**
   * whoami's `can_respond`, or `null` when the server did not publish one.
   * Only `false` refuses — see features/choke/canRespond.ts.
   */
  canRespond?: boolean | null;
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
  clearSelection,
  canRespond = null
}: DeviceActionsOptions): DeviceActions {
  /**
   * The device plane's permission gate.
   *
   * Deliberately its own, not inherited from the process plane: the two
   * gateways arm independently, and a console that let one route's grant stand
   * in for the other's would be guessing. Same grant today, separate reads —
   * so if they ever diverge the console reports what it was told rather than
   * what it assumed.
   */
  const refuseIfReadOnly = useCallback((): boolean => {
    if (canRespond !== false) return false;
    pushToast(readOnlyReason("the device plane"), "error");
    return true;
  }, [canRespond, pushToast]);

  const toggleMode = useCallback(async () => {
    if (refuseIfReadOnly()) return;
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
      // No defaultReason. The modal pre-selects whatever it is given and Enter
      // confirms, so a prefilled "go live" shipped as the audit reason for a
      // plane-wide arm that no operator justified — a fabricated justification,
      // which reads worse in the audit row than a refused write. The reason box
      // starts empty and the modal's confirm button stays disabled until one is
      // typed, so this promise cannot resolve with a blank reason.
      reasonPlaceholder: "Why are you changing device mode?"
    });
    if (!result) return;
    try {
      const response = await api.setMode(nextEnforcing, result.reason);
      pushToast(`mode -> ${response.mode}`, "ok");
      refresh();
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [api, pushToast, refresh, refuseIfReadOnly, requestConfirm, setDisabledMessage, state]);

  const toggleKillSwitch = useCallback(async () => {
    if (refuseIfReadOnly()) return;
    if (!state) return;
    // Do NOT derive a direction from an unknown state.
    //
    // The control plane cannot observe the agent's kill-switch — no heartbeat
    // field carries it — so it reports null. `!null` is true, which meant the
    // toggle always resolved to "engage": the emergency bypass could be turned
    // ON from the console and never OFF again, and an operator trying to
    // restore enforcement would bypass it a second time instead.
    //
    // Refusing is the safe failure here. On the single-tenant engine the state
    // IS observed and the toggle behaves normally; on the control plane the
    // control is disabled with the reason, until the agent reports it.
    if (state.kill_switched === null || state.kill_switched === undefined) {
      pushToast(
        "kill-switch state is not reported by this deployment — engage or disengage it on the agent's own console",
        "warn"
      );
      return;
    }
    const on = !state.kill_switched;
    const result = await requestConfirm({
      title: on ? "Engage kill-switch" : "Disengage kill-switch",
      message: on
        ? "This bypasses all device enforcement immediately. Decisions will still be audited."
        : "Device enforcement will resume according to the current mode and active buckets.",
      confirmLabel: on ? "Engage kill-switch" : "Disengage",
      danger: on,
      // An ENGAGE carries an audit reason, collected in the same confirm modal
      // the mode switch uses rather than through a second kind of prompt.
      //
      // The single-tenant engine (engine/internal/api/devchoke.go,
      // handleChokeDeviceKillSwitch) refuses an engage with an empty reason:
      // shipping that engine against a console that posts only {on} would
      // answer this button with a 400 naming a field the operator was never
      // shown. Collecting it here means the console asks for the sentence
      // instead of relaying that refusal.
      //
      // A DISENGAGE is deliberately not gated. Both servers accept it without
      // one, the engine records its own "kill-switch released (no reason
      // stated)" marker, and demanding a typed justification before enforcement
      // can be restored is friction in the one moment nobody has time for it.
      requireReason: on,
      // No defaultReason, for the reason toggleMode states above: the modal
      // pre-selects what it is given and Enter confirms, so a prefilled string
      // ships as a justification no operator wrote.
      reasonPlaceholder: "Why are you halting device enforcement?"
    });
    if (!result) return;
    try {
      const response = await api.setKillSwitch(on, result.reason);
      pushToast(response.engaged ? "kill-switch engaged" : "kill-switch disengaged", response.engaged ? "warn" : "ok");
      refresh();
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [api, pushToast, refresh, refuseIfReadOnly, requestConfirm, setDisabledMessage, state]);

  const jailSelected = useCallback(async () => {
    if (refuseIfReadOnly()) return;
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
  }, [action, api, pushToast, reason, refresh, refuseIfReadOnly, revertAfter, selected, setDisabledMessage]);

  const thawSelected = useCallback(async () => {
    if (refuseIfReadOnly()) return;
    const macs = [...selected];
    if (macs.length === 0) {
      pushToast("select at least one device", "error");
      return;
    }
    try {
      // Send nothing when the operator typed nothing.
      //
      // Neither server blocks a release for want of a reason, so the only
      // question is what an empty box puts on the wire. The old fallback posted
      // the literal "operator thaw", which lands in the audit row looking
      // exactly like a sentence an operator wrote — a fabricated justification,
      // and the one outcome no deployment can correct after the fact.
      //
      // The two deployments record an ABSENT reason differently, and the
      // console cannot tell which it is talking to. The single-tenant engine
      // (engine/internal/api/devchoke.go, handleChokeDeviceThaw) substitutes
      // its own "operator thaw (no reason stated)" marker, which is the only
      // thing in that row telling a later reader nobody spoke. The multi-tenant
      // control plane (engine/internal/controlplane/choke.go, handleDeviceThaw)
      // decodes the field and then discards it — the Thaw command on the wire
      // carries no reason at all — so the row simply has none. Absent is honest
      // on both; invented is a lie on both.
      const trimmed = reason.trim();
      const response = await api.thawDevices({
        macs,
        ...(trimmed ? { reason: trimmed } : {})
      });
      const successes = response.results.filter((result) => result.ok).length;
      pushToast(summarizeResults(response.results, "thawed"), successes > 0 ? "ok" : "error");
      clearSelection();
      refresh();
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [api, clearSelection, pushToast, reason, refresh, refuseIfReadOnly, selected, setDisabledMessage]);

  // Per-device enforcement for the shared ladder. The bulk bar above acts on a
  // checkbox selection; this acts on the one device the operator opened. A
  // device sever is a reversible drop rule, so release works from every rung —
  // unlike a process sever, which is a SIGKILL (see DEVICE_TERMINAL).
  const applyToDevice = useCallback(
    async (mac: string, rung: Rung, why: string) => {
      if (canRespond === false) {
        // The ladder renders this string to the operator, so it must read as a
        // permission refusal and not as a rejected command.
        return { ok: false, detail: readOnlyReason("the device plane") };
      }
      const stated = why.trim();
      // The plane's reason rule, read from the one place that states it —
      // deviceRungNeedsReason in ./utils, whose comment carries the reasoning
      // and which DEVICE_REASON_NOTE puts on screen beside the ladder. Every
      // jail rung is refused without a reason, throttle and tarpit included.
      // Refusing here rather than posting an empty one keeps the console from
      // inventing a stand-in for the server that demands one, and names the box
      // the operator has to type in instead of returning that server's bare 400
      // for a field they cannot see.
      if (deviceRungNeedsReason(rung) && !stated) {
        return { ok: false, detail: "a reason is required — type one in the reason box before applying" };
      }
      try {
        if (rung === "pristine") {
          // Empty means empty. Both release endpoints treat the reason as
          // optional and neither is helped by a console literal: the
          // single-tenant engine would have its "operator thaw (no reason
          // stated)" marker overwritten by it, and the control plane discards
          // the field either way, so the only thing an invented string can
          // change is whether the one row that keeps it reads as a lie. See
          // thawSelected above for both servers.
          const response = await api.thawDevices({ macs: [mac], ...(stated ? { reason: stated } : {}) });
          const failure = response.results.find((result) => !result.ok);
          return failure
            ? { ok: false, detail: failure.error || "release rejected" }
            : { ok: true, detail: "release accepted" };
        }
        const response = await api.jailDevices({
          macs: [mac],
          action: ACTION_FOR_RUNG[rung] as DeviceAction,
          reason: stated
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
    [api, canRespond, pushToast, setDisabledMessage]
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
