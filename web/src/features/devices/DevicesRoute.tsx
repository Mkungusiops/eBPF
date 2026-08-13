import {
  AlertTriangle,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Network,
  RefreshCcw,
  RotateCcw,
  Search,
  ShieldAlert,
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
import { ACTION_FOR_RUNG, DEVICE_TERMINAL, LADDER, type Rung } from "../common/enforcement";
import {
  ContainmentCommandHeader,
  ContainmentLadder,
  computePosture,
  type CommandMetrics,
  type ViewMode
} from "../common/ContainmentCommand";
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

/**
 * Can this data plane actually drop a packet?
 *
 * "noop" means no tc program is attached — the ladder still moves and the
 * device table still reads back "severed", but nothing touches traffic. That is
 * the correct configuration for a host with no bridge to sit inline on, so it
 * is not an error; claiming otherwise is.
 *
 * This existed twice with two different answers. One version excluded "noop"
 * and drove a single status dot; the other treated "noop" as healthy and drove
 * the header's integrity readout, `auditOk`, AND the exported evidence bundle —
 * which recorded `data_plane: "active"` for a plane that cannot enforce. An
 * unknown value is treated as inactive for the same reason: on an artefact
 * someone may hand to an auditor, "I could not tell" must never render as "yes".
 */
export function planeIsActive(dataPlane: string | undefined | null): boolean {
  return Boolean(dataPlane) && dataPlane !== "noop" && dataPlane !== "disabled";
}

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
  const [viewMode, setViewMode] = useState<ViewMode>(() =>
    (typeof localStorage !== "undefined" && localStorage.getItem("devices.viewMode")) === "assurance"
      ? "assurance"
      : "command"
  );
  useEffect(() => {
    try {
      localStorage.setItem("devices.viewMode", viewMode);
    } catch {
      /* storage may be unavailable */
    }
  }, [viewMode]);
  const [rungFilter, setRungFilter] = useState<string | null>(null);
  const [deviceSearch, setDeviceSearch] = useState("");
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

  // ── Containment Command metrics (shared hero + ladder) ──────────────────
  const countsByRung = counts as unknown as Record<string, number>;
  const containedDevices = LADDER.filter((r) => r !== "pristine").reduce((sum, r) => sum + (countsByRung[r] || 0), 0);
  const protectedCount = devices.filter((d) => d.protected).length;
  const deviceMode: "detect-only" | "enforcing" = state?.enforcing ? "enforcing" : "detect-only";
  const planeHealthy = !disabledMessage && planeIsActive(state?.data_plane);
  const deviceMetrics: CommandMetrics = {
    subject: "devices",
    mode: deviceMode,
    activeThreats: 0,
    contained: containedDevices,
    tracked: state?.tracked ?? state?.devices_known ?? devices.length,
    auditOk: planeHealthy,
    auditRows: 0,
    integrityLabel: "Data plane",
    integrityValue: planeHealthy ? "active" : "offline",
    integritySub: `${state?.links_attached ?? 0} links · ${state?.frames_seen ?? 0} frames`,
    killSwitched: Boolean(state?.kill_switched),
    headline: `${protectedCount}`,
    headlineLabel: "Protected assets",
    posture: computePosture({
      mode: deviceMode,
      activeThreats: 0,
      contained: containedDevices,
      auditOk: planeHealthy,
      killSwitched: Boolean(state?.kill_switched)
    })
  };
  const deviceQuery = deviceSearch.trim().toLowerCase();
  const visibleDevices = devices.filter((d) => {
    if (rungFilter && (d.state || "pristine") !== rungFilter) return false;
    if (!deviceQuery) return true;
    return [d.mac, d.last_ip, d.hostname, d.vendor, d.source, d.state]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(deviceQuery);
  });
  const toggleRungFilter = (rung: Rung) => setRungFilter((prev) => (prev === rung ? null : rung));

  const exportDeviceAssurance = (kind: "report" | "bundle") => {
    const when = new Date();
    const stamp = when.toISOString().replace(/[:.]/g, "-");
    if (kind === "bundle") {
      const bundle = {
        generated_at: when.toISOString(),
        subject: "devices",
        posture: deviceMetrics.posture,
        mode: deviceMetrics.mode,
        kill_switch: deviceMetrics.killSwitched ? "engaged" : "standby",
        // Both: the verdict AND what it was derived from. An evidence bundle
        // that flattens "noop" to "offline" is honest but lossy — a reader
        // cannot tell an unattached plane from a broken one.
        data_plane: planeHealthy ? "active" : "offline",
        data_plane_reported: state?.data_plane ?? "unknown",
        links_attached: state?.links_attached ?? 0,
        frames_seen: state?.frames_seen ?? 0,
        contained: deviceMetrics.contained,
        tracked: deviceMetrics.tracked,
        protected_assets: protectedCount,
        containment_ladder: LADDER.reduce<Record<string, number>>((acc, r) => ({ ...acc, [r]: countsByRung[r] || 0 }), {}),
        devices: devices.map((d) => ({
          mac: d.mac,
          ip: d.last_ip || null,
          hostname: d.hostname || null,
          vendor: d.vendor || null,
          state: d.state,
          protected: Boolean(d.protected)
        }))
      };
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `device-containment-evidence-${stamp}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setToast({ message: "evidence bundle downloaded", tone: "ok" });
      return;
    }
    const html = buildDeviceAssuranceHtml({
      metrics: deviceMetrics,
      counts: countsByRung,
      links: state?.links_attached ?? 0,
      frames: state?.frames_seen ?? 0,
      protectedCount,
      devices,
      when
    });
    const win = window.open("", "_blank");
    if (!win) {
      setToast({ message: "popup blocked — allow popups to print the report", tone: "error" });
      return;
    }
    win.document.write(html);
    win.document.close();
    setToast({ message: "board report opened — Print → Save as PDF", tone: "ok" });
  };
  const allSelected = devices.length > 0 && devices.every((device) => selected.has(device.mac));
  const modeDisabled = Boolean(disabledMessage || state?.dry_run);
  const bridgeWarning = isBridgeMasterWarning(state);

  return (
    <main className={`devices-route${theme === "light" ? " theme-light" : ""}`}>
      {/* Uniform platform header: full-width sticky bar — back-to-SOC · brand · mode,
         then status + theme. Mirrors the Choke gateway header standard. */}
      <header className="devices-topbar">
        {/* Same header standard as the Choke Gateway: brand cluster · search ·
            status pills — so the two containment surfaces read as one product. */}
        <div className="devices-topbar-row devices-topbar-primary" data-panel="topbar-row-1">
          <div className="devices-brand">
            <a className="devices-back" href="/" title="Back to SOC dashboard">
              <ArrowLeft size={15} aria-hidden="true" />
              <span>SOC</span>
            </a>
            <span className="devices-brand-divider" aria-hidden="true" />
            <h1 className="devices-brand-mark">Device Choke</h1>
          </div>
          <label className="devices-search">
            <Search size={16} aria-hidden="true" />
            <input
              value={deviceSearch}
              onChange={(event) => setDeviceSearch(event.target.value)}
              placeholder="Search devices — MAC, IP, hostname, vendor…"
              aria-label="Search devices"
            />
          </label>
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

        {/* Containment Command — identical hero + ladder to the Choke Gateway,
            so the network plane and the process plane read as one product. */}
        <section className="devices-grid">
          <ContainmentCommandHeader
            metrics={deviceMetrics}
            viewMode={viewMode}
            onViewMode={setViewMode}
            onToggleMode={modeDisabled ? undefined : toggleMode}
            onKillSwitch={disabledMessage || !state ? undefined : toggleKillSwitch}
            disabled={Boolean(disabledMessage)}
          />
        </section>
        <section className="devices-grid">
          <ContainmentLadder counts={countsByRung} activeRung={rungFilter} onRungClick={toggleRungFilter} subject="devices" />
        </section>

        {viewMode === "assurance" ? (
          <DevicesAssuranceView metrics={deviceMetrics} counts={countsByRung} state={state} protectedCount={protectedCount} onExport={exportDeviceAssurance} />
        ) : (
        <>
        {/* Enforcement mode + kill-switch now live in the Containment Command
            header's control cluster — the single home for the plane controls. */}
        {state?.dry_run ? (
          <section className="devices-grid">
            <div className="devices-banner devices-banner--warn">
              <AlertTriangle size={19} aria-hidden="true" />
              <div>
                <strong>Dry-run boot flag is set.</strong>
                <div className="devices-panel-copy">
                  Enforcement is forced off at boot regardless of mode; chokes are audited but never applied.
                </div>
              </div>
            </div>
          </section>
        ) : null}

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
                  {visibleDevices.map((device) => {
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
            {visibleDevices.length === 0 ? (
              <div className="devices-empty">
                {loading
                  ? "Loading device state..."
                  : deviceQuery
                    ? `No devices match "${deviceSearch.trim()}". Clear the search to see all.`
                    : rungFilter
                      ? `No ${rungFilter} devices. Clear the ladder filter to see all.`
                      : "No devices observed yet. Generate LAN traffic to populate the table."}
              </div>
            ) : null}
          </div>
        </section>

        <p className="devices-footnote">
          Identity is the MAC, stable across DHCP and IP changes. Quarantine still allows DHCP/DNS so a device can recover. Protected MACs refuse quarantine and sever actions.
          {lastUpdatedAt ? ` Last refreshed ${formatAgo(new Date(lastUpdatedAt), now())} ago.` : ""}
        </p>
        </>
        )}
      </div>

      <ConfirmModal options={confirm} onClose={closeConfirm} />
    </main>
  );
}

// Assurance lens for the network plane — the device equivalent of the Choke
// Gateway's, read for a CISO/board: posture with a transparent breakdown,
// network reach, reversible data-plane integrity, and board-ready evidence.
function DevicesAssuranceView({
  metrics,
  counts,
  state,
  protectedCount,
  onExport
}: {
  metrics: CommandMetrics;
  counts: Record<string, number>;
  state: DeviceDataPlaneState | null;
  protectedCount: number;
  onExport: (kind: "report" | "bundle") => void;
}) {
  const needing = metrics.activeThreats + metrics.contained;
  const coverage = needing === 0 ? 100 : Math.round((metrics.contained / needing) * 100);
  const postureTone = metrics.posture >= 80 ? "good" : metrics.posture >= 55 ? "warn" : "bad";
  const enforcing = metrics.mode === "enforcing";
  const planeOk = metrics.auditOk;
  return (
    <section className="devices-grid">
      <div className="cc-assur-grid">
        <article className={`cc-assur-card span2 tone-${postureTone}`}>
          <header>
            <h3>Network posture</h3>
            <span className="cc-assur-score">
              {metrics.posture}
              <small>/100</small>
            </span>
          </header>
          <div className="cc-assur-drivers">
            <div className={`cc-assur-driver ${coverage >= 80 ? "good" : "warn"}`}>
              <span>Containment coverage</span>
              <strong>{coverage}%</strong>
            </div>
            <div className={`cc-assur-driver ${enforcing ? "good" : "warn"}`}>
              <span>Enforcement</span>
              <strong>{enforcing ? "Enforcing" : "Detect-only"}</strong>
            </div>
            <div className={`cc-assur-driver ${planeOk ? "good" : "warn"}`}>
              <span>Data plane</span>
              <strong>{planeOk ? "Active" : "Offline"}</strong>
            </div>
            <div className={`cc-assur-driver ${metrics.killSwitched ? "warn" : "good"}`}>
              <span>Kill-switch</span>
              <strong>{metrics.killSwitched ? "Engaged" : "Standby"}</strong>
            </div>
          </div>
          <p className="cc-assur-note">
            Network-plane posture reflects how much of the tracked device population is contained, adjusted for
            enforcement mode and data-plane health.
            {enforcing ? "" : " Switch to Enforcing to apply drop/throttle rules at the link layer."}
          </p>
        </article>

        <article className="cc-assur-card">
          <header>
            <h3>Network reach</h3>
          </header>
          <div className="cc-assur-kv wide">
            <span>Devices tracked</span>
            <strong>{metrics.tracked.toLocaleString()}</strong>
            <span>Links attached</span>
            <strong>{state?.links_attached ?? 0}</strong>
            <span>Frames seen</span>
            <strong>{(state?.frames_seen ?? 0).toLocaleString()}</strong>
            <span>Protected assets</span>
            <strong>{protectedCount}</strong>
          </div>
        </article>

        <article className="cc-assur-card">
          <header>
            <h3>Data-plane integrity</h3>
          </header>
          <div className={`cc-assur-audit ${planeOk ? "ok" : "bad"}`}>{planeOk ? "Plane active" : "PLANE OFFLINE"}</div>
          <p className="cc-assur-note">
            Every device choke is a reversible drop/throttle rule — sever cuts a device off the network, thaw restores
            it. Quarantine still permits DHCP/DNS so a device can always recover.
          </p>
        </article>

        <article className="cc-assur-card">
          <header>
            <h3>Containment ladder</h3>
          </header>
          <ul className="cc-assur-top">
            {LADDER.map((r) => (
              <li key={r}>
                <span>{r}</span>
                <strong>{counts[r] || 0}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cc-assur-card span2 cc-assur-export">
          <header>
            <h3>Board-ready evidence</h3>
          </header>
          <p>
            Export a point-in-time network-containment summary — device inventory, ladder state and data-plane
            health — for leadership, audit, or cyber-insurance.
          </p>
          <div className="cc-assur-actions">
            <button type="button" className="devices-button devices-button--primary" onClick={() => onExport("report")}>
              Board report
            </button>
            <button type="button" className="devices-button" onClick={() => onExport("bundle")}>
              Evidence bundle (JSON)
            </button>
          </div>
        </article>
      </div>
    </section>
  );
}

function buildDeviceAssuranceHtml(args: {
  metrics: CommandMetrics;
  counts: Record<string, number>;
  links: number;
  frames: number;
  protectedCount: number;
  devices: DeviceEntry[];
  when: Date;
}): string {
  const { metrics: m, counts, links, frames, protectedCount, devices, when } = args;
  const esc = (s: string) =>
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
  const needing = m.activeThreats + m.contained;
  const coverage = needing === 0 ? 100 : Math.round((m.contained / needing) * 100);
  const tone = m.posture >= 80 ? "#2f9e5e" : m.posture >= 55 ? "#c9871f" : "#d23a4f";
  const rung = (r: string) => counts[r] || 0;
  const deviceRows =
    devices.length === 0
      ? `<tr><td colspan="4" style="color:#888">no devices observed</td></tr>`
      : devices
          .map(
            (d) =>
              `<tr><td class="mono">${esc(d.mac)}</td><td>${esc(d.last_ip || "—")}</td><td>${esc(d.hostname || d.vendor || "—")}</td><td style="text-align:right">${esc(String(d.state))}${d.protected ? " · protected" : ""}</td></tr>`
          )
          .join("");
  return `<!doctype html><html><head><meta charset="utf-8">
<title>Network Containment Assurance Report</title>
<style>
  * { box-sizing: border-box; }
  body { font: 13px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; color: #1a2230; margin: 0; padding: 40px; background: #fff; }
  .head { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #1a2230; padding-bottom: 14px; }
  .head h1 { margin: 0; font-size: 22px; }
  .head .sub { color: #667085; font-size: 12px; margin-top: 4px; }
  .posture { text-align: center; }
  .posture .num { font-size: 44px; font-weight: 800; color: ${tone}; line-height: 1; }
  .posture .lbl { font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; color: #667085; }
  .tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 22px 0; }
  .tile { border: 1px solid #e3e7ee; border-radius: 8px; padding: 14px; }
  .tile .v { font-size: 24px; font-weight: 700; }
  .tile .l { font-size: 10px; letter-spacing: 0.09em; text-transform: uppercase; color: #667085; margin-top: 4px; }
  h2 { font-size: 13px; letter-spacing: 0.08em; text-transform: uppercase; color: #667085; border-bottom: 1px solid #e3e7ee; padding-bottom: 6px; margin: 26px 0 12px; }
  table { width: 100%; border-collapse: collapse; }
  td, th { padding: 7px 8px; border-bottom: 1px solid #eef1f5; text-align: left; }
  .ladder { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
  .ladder .cell { border: 1px solid #e3e7ee; border-radius: 8px; padding: 12px; text-align: center; }
  .ladder .cell .c { font-size: 22px; font-weight: 700; }
  .ladder .cell .n { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #667085; }
  .mono { font-family: ui-monospace, Menlo, monospace; font-size: 11px; }
  .foot { margin-top: 30px; padding-top: 12px; border-top: 1px solid #e3e7ee; color: #98a2b3; font-size: 11px; }
  @media print { body { padding: 0; } }
</style></head><body>
<div class="head">
  <div>
    <h1>Network Containment Assurance Report</h1>
    <div class="sub">Device enforcement plane · generated ${esc(when.toLocaleString())}</div>
  </div>
  <div class="posture"><div class="num">${m.posture}</div><div class="lbl">Posture / 100</div></div>
</div>
<div class="tiles">
  <div class="tile"><div class="v">${m.tracked.toLocaleString()}</div><div class="l">Devices tracked</div></div>
  <div class="tile"><div class="v">${m.contained}</div><div class="l">Contained</div></div>
  <div class="tile"><div class="v">${coverage}%</div><div class="l">Coverage</div></div>
  <div class="tile"><div class="v">${protectedCount}</div><div class="l">Protected assets</div></div>
</div>
<h2>Containment ladder</h2>
<div class="ladder">
  <div class="cell"><div class="c">${rung("pristine")}</div><div class="n">Pristine</div></div>
  <div class="cell"><div class="c">${rung("throttled")}</div><div class="n">Throttled</div></div>
  <div class="cell"><div class="c">${rung("tarpit")}</div><div class="n">Tarpit</div></div>
  <div class="cell"><div class="c">${rung("quarantined")}</div><div class="n">Quarantined</div></div>
  <div class="cell"><div class="c">${rung("severed")}</div><div class="n">Severed</div></div>
</div>
<h2>Data plane</h2>
<table>
  <tr><td>Mode</td><td style="text-align:right">${m.mode === "enforcing" ? "Enforcing" : "Detect-only"}</td></tr>
  <tr><td>Kill-switch</td><td style="text-align:right">${m.killSwitched ? "Engaged" : "Standby"}</td></tr>
  <tr><td>Links attached</td><td style="text-align:right">${links}</td></tr>
  <tr><td>Frames forwarded</td><td style="text-align:right">${frames.toLocaleString()}</td></tr>
</table>
<h2>Device inventory</h2>
<table><tr><th>MAC</th><th>IP</th><th>Host / vendor</th><th style="text-align:right">State</th></tr>${deviceRows}</table>
<div class="foot">This report is a point-in-time summary of live network-enforcement state. Device identity is the MAC address, stable across DHCP and IP changes. Every choke is a reversible, audited drop/throttle rule.</div>
<script>window.onload=function(){setTimeout(function(){window.print();},250);};</script>
</body></html>`;
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
      <div className="devices-status-cluster">
        <span className="devices-status-pill">
          <span className="devices-status-dot down" />
          plane <strong>disabled</strong>
        </span>
      </div>
    );
  }

  const planeActive = planeIsActive(state?.data_plane);
  const mode = state?.mode ?? "unknown";
  return (
    <div className="devices-status-cluster" aria-label="Device data-plane state">
      {/* Choke-style dot+label status pills — quiet at rest, boxed on hover.
          Enforcement mode leads (amber = detect-only, green = enforcing); the
          header's ENFORCEMENT control remains the actionable toggle. */}
      <span className={`devices-status-pill mode-${mode}`} title={`enforcement mode: ${mode}`}>
        <span className="devices-status-dot" />
        mode <strong>{mode}</strong>
      </span>
      <span
        className="devices-status-pill"
        title="Data-plane actuator: 'noop' = audit only, no kernel enforcement; 'tc' = live TC/eBPF dropping or rate-limiting by MAC."
      >
        <span className={`devices-status-dot${planeActive ? "" : " idle"}`} />
        plane <strong>{state?.data_plane ?? "-"}</strong>
      </span>
      <span
        className="devices-status-pill"
        title="Network interfaces the device-choke BPF program is attached to. 0 = not attached (single-NIC box / no inline bridge)."
      >
        links <strong>{state?.links_attached ?? 0}</strong>
      </span>
      <span
        className={`devices-status-pill${isBridgeMasterWarning(state) ? " is-warn" : ""}`}
        title="Forwarded Ethernet frames the data plane has actually seen. Turns amber if links are up but frames stay 0 — a sign it is attached to a bridge master instead of a slave."
      >
        frames <strong>{state?.frames_seen ?? 0}</strong>
      </span>
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
