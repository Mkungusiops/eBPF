import {
  AlertTriangle,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Network,
  Power,
  RefreshCcw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  X
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useOSTheme } from "../../lib/theme";

import {
  createDevicesApi,
  isAbortError,
  isDisabledError,
  type DevicesApi
} from "./api";
import { EnforcementLadder } from "../common/EnforcementLadder";
import { ACTION_FOR_RUNG, DEVICE_TERMINAL, type Rung } from "../common/enforcement";
import "./devices.css";
import type {
  DeviceAction,
  DeviceDataPlaneState,
  DeviceEntry,
  DeviceFlow
} from "./types";
import {
  DEVICE_ACTIONS,
  DEVICE_STATE_ORDER,
  formatAgo,
  formatBucket,
  formatBytes,
  isBridgeMasterWarning,
  isDeviceStateName,
  macSlug,
  normalizeCounts,
  sortFlows,
  summarizeResults
} from "./utils";

type ToastTone = "ok" | "error" | "warn";

interface ToastState {
  message: string;
  tone: ToastTone;
}

interface FlowLoadState {
  loading: boolean;
  error?: string;
  flows?: DeviceFlow[];
}

interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  requireReason?: boolean;
  reasonPlaceholder?: string;
  defaultReason?: string;
}

interface ConfirmResult {
  reason: string;
}

export interface DevicesRouteProps {
  api?: DevicesApi;
  pollMs?: number;
  now?: () => number;
}

const DISABLED_MESSAGE = "device choke disabled (start with -devchoke-iface)";

export function DevicesRoute({
  api: providedApi,
  pollMs = 4000,
  now = () => Date.now()
}: DevicesRouteProps) {
  const api = useMemo(() => providedApi ?? createDevicesApi(), [providedApi]);
  // Theme comes from the OS for every console page — see src/lib/theme.ts.
  const theme = useOSTheme();
  const [state, setState] = useState<DeviceDataPlaneState | null>(null);
  const [devices, setDevices] = useState<DeviceEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [disabledMessage, setDisabledMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [flows, setFlows] = useState<Record<string, FlowLoadState>>({});
  const [action, setAction] = useState<DeviceAction>("throttle");
  const [reason, setReason] = useState("");
  const [revertAfter, setRevertAfter] = useState("");
  const [toast, setToast] = useState<ToastState | null>(null);
  const [confirm, setConfirm] = useState<ConfirmOptions | null>(null);
  const expandedRef = useRef(expanded);
  const confirmResolverRef = useRef<((result: ConfirmResult | null) => void) | null>(null);
  const toastTimerRef = useRef<number | null>(null);

  useEffect(() => {
    expandedRef.current = expanded;
  }, [expanded]);

  const pushToast = useCallback((message: string, tone: ToastTone) => {
    setToast({ message, tone });
    if (toastTimerRef.current !== null) {
      window.clearTimeout(toastTimerRef.current);
    }
    toastTimerRef.current = window.setTimeout(() => setToast(null), 4500);
  }, []);

  useEffect(() => {
    return () => {
      if (toastTimerRef.current !== null) window.clearTimeout(toastTimerRef.current);
    };
  }, []);

  const requestConfirm = useCallback((options: ConfirmOptions) => {
    return new Promise<ConfirmResult | null>((resolve) => {
      confirmResolverRef.current = resolve;
      setConfirm(options);
    });
  }, []);

  const closeConfirm = useCallback((result: ConfirmResult | null) => {
    confirmResolverRef.current?.(result);
    confirmResolverRef.current = null;
    setConfirm(null);
  }, []);

  const refreshFlows = useCallback(
    async (mac: string, signal?: AbortSignal) => {
      // Only show the loading state on first fetch; background re-polls update
      // silently (keep showing existing flows) so expanded rows don't flash.
      setFlows((previous) => ({
        ...previous,
        [mac]: { ...previous[mac], loading: !previous[mac]?.flows, error: undefined }
      }));
      try {
        const response = await api.fetchFlows(mac, { signal });
        setFlows((previous) => ({
          ...previous,
          [mac]: { loading: false, flows: sortFlows(response.flows ?? []) }
        }));
      } catch (caught) {
        if (isAbortError(caught)) return;
        if (isDisabledError(caught)) {
          setDisabledMessage(DISABLED_MESSAGE);
          return;
        }
        setFlows((previous) => ({
          ...previous,
          [mac]: {
            loading: false,
            error: caught instanceof Error ? caught.message : "connections unavailable"
          }
        }));
      }
    },
    [api]
  );

  const loadDevices = useCallback(
    async (options: { quiet?: boolean; signal?: AbortSignal } = {}) => {
      if (options.quiet) setRefreshing(true);
      else setLoading(true);
      setError(null);
      try {
        const nextState = await api.fetchState({ signal: options.signal });
        const nextDevices = await api.fetchDevices({ signal: options.signal });
        if (options.signal?.aborted) return;
        const knownMacs = new Set(nextDevices.map((device) => device.mac));
        setState(nextState);
        setDevices(nextDevices);
        setDisabledMessage(null);
        setLastUpdatedAt(Date.now());
        setSelected((previous) => new Set([...previous].filter((mac) => knownMacs.has(mac))));
        for (const mac of expandedRef.current) {
          if (knownMacs.has(mac)) void refreshFlows(mac, options.signal);
        }
      } catch (caught) {
        if (isAbortError(caught)) return;
        if (isDisabledError(caught)) {
          setDisabledMessage(DISABLED_MESSAGE);
          setState(null);
          setDevices([]);
          setSelected(new Set());
          return;
        }
        setError(caught instanceof Error ? caught.message : "Unable to load device state");
      } finally {
        if (!options.signal?.aborted) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [api, refreshFlows]
  );

  useEffect(() => {
    const controller = new AbortController();
    void loadDevices({ signal: controller.signal });
    const interval = window.setInterval(() => {
      void loadDevices({ quiet: true, signal: controller.signal });
    }, pollMs);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [loadDevices, pollMs]);

  const toggleSelected = useCallback((mac: string, checked: boolean) => {
    setSelected((previous) => {
      const next = new Set(previous);
      if (checked) next.add(mac);
      else next.delete(mac);
      return next;
    });
  }, []);

  const setAllSelected = useCallback(
    (checked: boolean) => {
      setSelected(checked ? new Set(devices.map((device) => device.mac)) : new Set());
    },
    [devices]
  );

  const toggleFlows = useCallback(
    (mac: string) => {
      let shouldOpen = false;
      setExpanded((previous) => {
        const next = new Set(previous);
        if (next.has(mac)) {
          next.delete(mac);
        } else {
          next.add(mac);
          shouldOpen = true;
        }
        return next;
      });
      if (shouldOpen) void refreshFlows(mac);
    },
    [refreshFlows]
  );

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
      void loadDevices({ quiet: true });
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [api, loadDevices, pushToast, requestConfirm, state]);

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
      void loadDevices({ quiet: true });
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [api, loadDevices, pushToast, requestConfirm, state]);

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
      void loadDevices({ quiet: true });
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [action, api, loadDevices, pushToast, reason, revertAfter, selected]);

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
      setSelected(new Set());
      void loadDevices({ quiet: true });
    } catch (caught) {
      handleActionError(caught, pushToast, setDisabledMessage);
    }
  }, [api, loadDevices, pushToast, reason, selected]);

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
    [api, pushToast]
  );

  const readDeviceState = useCallback(
    async (mac: string) => {
      const list = await api.fetchDevices();
      return list.find((device) => device.mac === mac)?.state;
    },
    [api]
  );

  const counts = normalizeCounts(state?.counts);
  const allSelected = devices.length > 0 && devices.every((device) => selected.has(device.mac));
  const modeDisabled = Boolean(disabledMessage || state?.dry_run);
  const bridgeWarning = isBridgeMasterWarning(state);

  return (
    <main className={`devices-route${theme === "light" ? " theme-light" : ""}`}>
      {/* Uniform platform header: full-width sticky bar — back-to-SOC · brand · mode,
         then status + theme. Mirrors the Choke gateway header standard. */}
      <header className="devices-topbar">
        <div className="devices-topbar-row" data-panel="topbar-row-1">
          <a className="devices-back" href="/" title="Back to SOC dashboard">
            <ArrowLeft size={15} aria-hidden="true" />
            <span>SOC</span>
          </a>
          <span className="devices-brand-divider" aria-hidden="true" />
          <h1 className="devices-brand-mark">Network Choke - Devices</h1>
          <ModeBadge state={state} compact />
          <div className="devices-topbar-spacer" />
          <PlaneStateStrip state={state} disabledMessage={disabledMessage} updatedAt={lastUpdatedAt} />
        </div>
      </header>
      <div className="devices-layout">

        {disabledMessage ? (
          <section className="devices-grid" aria-live="polite">
            <div className="devices-banner">
              <ShieldAlert size={19} aria-hidden="true" />
              <div>
                <strong>{disabledMessage}</strong>
                <div className="devices-panel-copy">
                  Start the engine with a device choke interface to enable the data plane.
                </div>
              </div>
            </div>
          </section>
        ) : null}

        {bridgeWarning ? (
          <section className="devices-grid" aria-live="polite">
            <div className="devices-banner devices-banner--warn">
              <AlertTriangle size={19} aria-hidden="true" />
              <div>
                <strong>Links are attached, but no forwarded frames have been seen.</strong>
                <div className="devices-panel-copy">
                  This usually means the program is attached to a bridge master instead of a bridge slave interface.
                </div>
              </div>
            </div>
          </section>
        ) : null}

        {error ? (
          <section className="devices-grid" aria-live="polite">
            <div className="devices-banner devices-banner--warn">
              <AlertTriangle size={19} aria-hidden="true" />
              <div>
                <strong>Device state could not be refreshed.</strong>
                <div className="devices-panel-copy">{error}</div>
              </div>
            </div>
          </section>
        ) : null}

        <section className="devices-grid devices-counts" aria-label="Device state counts">
          {DEVICE_STATE_ORDER.map((key) => (
            <div key={key} className={`devices-count devices-count--${key}`}>
              <div className="devices-count-value">{counts[key]}</div>
              <div className="devices-count-label">{key}</div>
            </div>
          ))}
        </section>

        <section className="devices-grid">
          <div className="devices-panel devices-panel--padded">
            <div className="devices-panel-header">
              <div>
                <h2 className="devices-panel-title">Enforcement mode</h2>
                <p className="devices-panel-copy">
                  Detect-only audits would-be chokes. Kill-switch bypasses device enforcement globally.
                </p>
              </div>
              <ModeBadge state={state} />
            </div>
            <div className="devices-mode-actions">
              <button
                type="button"
                className="devices-button devices-button--primary"
                disabled={modeDisabled}
                onClick={toggleMode}
              >
                <ShieldCheck size={15} aria-hidden="true" />
                {state?.enforcing ? "Switch to detect-only" : "Switch to enforcing"}
              </button>
              <button
                type="button"
                className="devices-button devices-button--danger"
                disabled={Boolean(disabledMessage || !state)}
                onClick={toggleKillSwitch}
              >
                <Power size={15} aria-hidden="true" />
                {state?.kill_switched ? "Disengage kill-switch" : "Engage kill-switch"}
              </button>
              {state?.dry_run ? (
                <span className="devices-pill devices-pill--warn">dry-run boot flag</span>
              ) : null}
            </div>
          </div>
        </section>

        <section className="devices-grid">
          <div className="devices-panel devices-panel--padded">
            <div className="devices-panel-header">
              <div>
                <h2 className="devices-panel-title">Bulk actions</h2>
                <p className="devices-panel-copy">
                  Select devices, choose a choke action, add an audit reason, and optionally schedule an auto-revert.
                </p>
              </div>
              <button
                type="button"
                className={`devices-button${refreshing ? " is-refreshing" : ""}`}
                disabled={refreshing || loading}
                onClick={() => void loadDevices({ quiet: true })}
              >
                <RefreshCcw size={15} aria-hidden="true" />
                {refreshing ? "Refreshing" : "Refresh"}
              </button>
            </div>
            <div className="devices-bulk-row">
              <span className="devices-selected">{selected.size} selected</span>
              <select
                className="devices-select"
                value={action}
                disabled={Boolean(disabledMessage)}
                onChange={(event) => setAction(event.target.value as DeviceAction)}
                aria-label="Device choke action"
              >
                {DEVICE_ACTIONS.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label} ({item.detail})
                  </option>
                ))}
              </select>
              <input
                className="devices-input devices-reason-input"
                value={reason}
                disabled={Boolean(disabledMessage)}
                onChange={(event) => setReason(event.target.value)}
                placeholder="reason (required for audit)"
              />
              <input
                className="devices-input devices-revert-input"
                type="number"
                min="0"
                inputMode="numeric"
                value={revertAfter}
                disabled={Boolean(disabledMessage)}
                onChange={(event) => setRevertAfter(event.target.value)}
                placeholder="revert after (s)"
              />
              <button
                type="button"
                className="devices-button devices-button--danger"
                disabled={Boolean(disabledMessage)}
                onClick={jailSelected}
              >
                Choke
              </button>
              <button
                type="button"
                className="devices-button devices-button--good"
                disabled={Boolean(disabledMessage)}
                onClick={thawSelected}
              >
                Thaw
              </button>
            </div>
            <div
              className={`devices-toast${toast ? ` devices-toast--${toast.tone}` : ""}`}
              aria-live="polite"
            >
              {toast?.message ?? ""}
            </div>
          </div>
        </section>

        <section className="devices-grid">
          <div className="devices-panel">
            <div className="devices-table-wrap">
              <table className="devices-table">
                <thead>
                  <tr>
                    <th>
                      <input
                        className="devices-checkbox"
                        type="checkbox"
                        checked={allSelected}
                        disabled={devices.length === 0 || Boolean(disabledMessage)}
                        onChange={(event) => setAllSelected(event.currentTarget.checked)}
                        aria-label="Select all devices"
                      />
                    </th>
                    <th>Device</th>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>State</th>
                    <th>Bucket</th>
                    <th>Seen</th>
                    <th>Src</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device) => {
                    const open = expanded.has(device.mac);
                    return (
                      <DeviceRow
                        key={device.mac}
                        device={device}
                        open={open}
                        selected={selected.has(device.mac)}
                        flowState={flows[device.mac]}
                        now={now}
                        disabled={Boolean(disabledMessage)}
                        onSelect={toggleSelected}
                        onToggleFlows={toggleFlows}
                        onApply={applyToDevice}
                        onReadState={readDeviceState}
                        onSettled={() => void loadDevices({ quiet: true })}
                      />
                    );
                  })}
                </tbody>
              </table>
            </div>
            {devices.length === 0 ? (
              <div className="devices-empty">
                {loading ? "Loading device state..." : "No devices observed yet. Generate LAN traffic to populate the table."}
              </div>
            ) : null}
          </div>
        </section>

        <p className="devices-footnote">
          Identity is the MAC, stable across DHCP and IP changes. Quarantine still allows DHCP/DNS so a device can recover. Protected MACs refuse quarantine and sever actions.
          {lastUpdatedAt ? ` Last refreshed ${formatAgo(new Date(lastUpdatedAt), now())} ago.` : ""}
        </p>
      </div>

      <ConfirmModal options={confirm} onClose={closeConfirm} />
    </main>
  );
}

function PlaneStateStrip({
  state,
  disabledMessage,
  updatedAt
}: {
  state: DeviceDataPlaneState | null;
  disabledMessage: string | null;
  updatedAt: number | null;
}) {
  if (disabledMessage) {
    return (
      <div className="devices-plane-strip">
        <span className="devices-pill devices-pill--danger">disabled</span>
      </div>
    );
  }

  return (
    <div className="devices-plane-strip" aria-label="Device data-plane state">
      {/* Quiet secondary telemetry; hover/focus reveals what each term means. */}
      <div className="devices-diag">
        <span
          tabIndex={0}
          data-tip="Data-plane actuator: ‘noop’ = audit only, no kernel enforcement; ‘tc’ = live TC/eBPF dropping or rate-limiting by MAC."
        >
          plane <strong>{state?.data_plane ?? "-"}</strong>
        </span>
        <span
          tabIndex={0}
          data-tip="Network interfaces the device-choke BPF program is attached to. 0 = not attached (single-NIC box / no inline bridge)."
        >
          links <strong>{state?.links_attached ?? 0}</strong>
        </span>
        <span
          tabIndex={0}
          className={isBridgeMasterWarning(state) ? "is-warn" : undefined}
          data-tip="Forwarded Ethernet frames the data plane has actually seen. Turns amber if links are up but frames stay 0 — a sign it’s attached to a bridge master instead of a slave."
        >
          frames <strong>{state?.frames_seen ?? 0}</strong>
        </span>
      </div>
      <LiveBeacon updatedAt={updatedAt} />
    </div>
  );
}

// A calm "live" beacon: a steady dot that emits a single radar-style ping ripple
// each time a poll lands fresh data (keyed on updatedAt so the ring re-animates).
// Replaces the old jarring "polling" text flash.
function LiveBeacon({ updatedAt }: { updatedAt: number | null }) {
  return (
    <span className="devices-beacon" title="Live · auto-refreshing" aria-label="Live, auto-refreshing">
      <span className="devices-beacon-core" />
      {updatedAt ? <span className="devices-beacon-ping" key={updatedAt} /> : null}
      <span className="devices-beacon-label">live</span>
    </span>
  );
}

function ModeBadge({
  state,
  compact = false
}: {
  state: DeviceDataPlaneState | null;
  compact?: boolean;
}) {
  const mode = state?.mode ?? "unknown";
  const tone =
    mode === "enforcing" ? "good" :
    mode === "detect-only" ? "info" :
    mode === "dry-run" ? "warn" :
    mode === "kill-switched" ? "danger" :
    "muted";
  return (
    <span className={`devices-pill devices-pill--${tone}`}>
      {compact ? mode : `Mode: ${mode}`}
    </span>
  );
}

function DeviceRow({
  device,
  open,
  selected,
  flowState,
  now,
  disabled,
  onSelect,
  onToggleFlows,
  onApply,
  onReadState,
  onSettled
}: {
  device: DeviceEntry;
  open: boolean;
  selected: boolean;
  flowState?: FlowLoadState;
  now: () => number;
  disabled: boolean;
  onSelect: (mac: string, checked: boolean) => void;
  onToggleFlows: (mac: string) => void;
  onApply: (mac: string, rung: Rung, reason: string) => Promise<{ ok: boolean; detail: string }>;
  onReadState: (mac: string) => Promise<string | undefined>;
  onSettled: () => void;
}) {
  const stateClass = isDeviceStateName(device.state)
    ? device.state
    : "unknown";
  return (
    <>
      <tr>
        <td>
          <input
            className="devices-checkbox"
            type="checkbox"
            checked={selected}
            disabled={disabled}
            onChange={(event) => onSelect(device.mac, event.currentTarget.checked)}
            aria-label={`Select ${device.mac}`}
          />
        </td>
        <td className="devices-device-cell devices-mono">
          <div className="devices-row-main">
            <button
              type="button"
              className="devices-icon-button"
              onClick={() => onToggleFlows(device.mac)}
              aria-expanded={open}
              aria-controls={`flows-${macSlug(device.mac)}`}
              title={open ? "Collapse device flows" : "Expand device flows"}
            >
              {open ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
            </button>
            <span>{device.mac}</span>
            {device.protected ? <span className="devices-pill devices-pill--muted">protected</span> : null}
            {device.flows ? <span className="devices-pill devices-pill--plain">{device.flows} dst</span> : null}
          </div>
          <div className="devices-device-id">{device.device_id ?? "-"}</div>
        </td>
        <td className="devices-mono">{device.last_ip || "-"}</td>
        <td>{device.hostname || "-"}</td>
        <td>
          <span className={`devices-state devices-state--${stateClass}`}>{device.state || "unknown"}</span>
          {device.revert_pending ? (
            <RotateCcw className="devices-revert" size={14} aria-label="Auto-revert pending" />
          ) : null}
        </td>
        <td className="devices-mono">{formatBucket(device.bucket)}</td>
        <td>{formatAgo(device.last_seen, now())}</td>
        <td>{device.source || "-"}</td>
      </tr>
      {open ? (
        <tr className="devices-flow-row" id={`flows-${macSlug(device.mac)}`}>
          <td colSpan={8}>
            <FlowList state={flowState} />
            {/* Evidence and control in one place: the flows say what this
                device is doing, the ladder does something about it. Same
                component as the correlation graph and Choke Gateway. */}
            <EnforcementLadder
              target={{
                id: device.mac,
                label: device.hostname || device.mac,
                host: device.last_ip || undefined
              }}
              state={device.state || "pristine"}
              policy={DEVICE_TERMINAL}
              apply={(rung, why) => onApply(device.mac, rung, why)}
              readState={() => onReadState(device.mac)}
              onSettled={onSettled}
            />
          </td>
        </tr>
      ) : null}
    </>
  );
}

function FlowList({ state }: { state?: FlowLoadState }) {
  if (!state || state.loading) {
    return <div className="devices-flow-panel">Loading connections...</div>;
  }
  if (state.error) {
    return <div className="devices-flow-panel">{state.error}</div>;
  }
  if (!state.flows?.length) {
    return <div className="devices-flow-panel">No outbound connections observed yet.</div>;
  }
  return (
    <div className="devices-flow-panel">
      <div className="devices-flow-title">Connecting to (device -&gt; destination)</div>
      {state.flows.map((flow) => (
        <div
          className="devices-flow-line devices-mono"
          key={`${flow.dest_ip}:${flow.dest_port ?? 0}:${flow.proto ?? ""}`}
        >
          <Network size={14} aria-hidden="true" />
          <span>
            {flow.dest_ip}:{flow.dest_port || "-"}
          </span>
          <span className="devices-flow-proto">{flow.proto || "unknown"}</span>
          <span>
            {flow.packets ?? 0} pkts / {formatBytes(flow.bytes)}
          </span>
        </div>
      ))}
    </div>
  );
}

function ConfirmModal({
  options,
  onClose
}: {
  options: ConfirmOptions | null;
  onClose: (result: ConfirmResult | null) => void;
}) {
  const [reason, setReason] = useState("");
  const [showReasonError, setShowReasonError] = useState(false);
  const dialogRef = useRef<HTMLElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const confirmRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!options) return;
    setReason(options.defaultReason ?? "");
    setShowReasonError(false);
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose(null);
      if (event.key === "Tab") trapFocus(event, dialogRef.current);
      if (event.key === "Enter" && document.activeElement === inputRef.current) {
        event.preventDefault();
        confirmRef.current?.click();
      }
    };
    document.addEventListener("keydown", handleKey);
    window.setTimeout(() => {
      if (options.requireReason) {
        inputRef.current?.focus();
        inputRef.current?.select();
      } else {
        confirmRef.current?.focus();
      }
    }, 0);
    return () => document.removeEventListener("keydown", handleKey);
  }, [onClose, options]);

  if (!options) return null;

  const confirm = () => {
    if (options.requireReason && reason.trim() === "") {
      setShowReasonError(true);
      inputRef.current?.focus();
      return;
    }
    onClose({ reason: options.requireReason ? reason.trim() : "" });
  };

  return (
    <div
      className="devices-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.currentTarget === event.target) onClose(null);
      }}
    >
      <section
        ref={dialogRef}
        className="devices-modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="devices-confirm-title"
      >
        <div className="devices-modal-head">
          <div className={`devices-modal-icon${options.danger ? " devices-modal-icon--danger" : ""}`}>
            <AlertTriangle size={18} aria-hidden="true" />
          </div>
          <div>
            <h2 className="devices-modal-title" id="devices-confirm-title">{options.title}</h2>
            <p className="devices-modal-message">{options.message}</p>
          </div>
        </div>
        {options.requireReason ? (
          <div className="devices-modal-body">
            <label className="devices-label">
              Reason
              <input
                ref={inputRef}
                className="devices-input"
                value={reason}
                placeholder={options.reasonPlaceholder ?? "reason"}
                onChange={(event) => {
                  setReason(event.target.value);
                  setShowReasonError(false);
                }}
              />
            </label>
            {showReasonError ? (
              <div className="devices-field-error">A reason is required for the audit log.</div>
            ) : null}
          </div>
        ) : null}
        <div className="devices-modal-actions">
          <button type="button" className="devices-button" onClick={() => onClose(null)}>
            <X size={15} aria-hidden="true" />
            Cancel
          </button>
          <button
            ref={confirmRef}
            type="button"
            className={`devices-button${options.danger ? " devices-button--danger" : " devices-button--primary"}`}
            onClick={confirm}
          >
            {options.confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}

function trapFocus(event: KeyboardEvent, root: HTMLElement | null): void {
  if (!root) return;
  const focusable = root.querySelectorAll<HTMLElement>(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  if (focusable.length === 0) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
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
