import {
  Activity,
  AlertTriangle,
  Check,
  ChevronRight,
  Power,
  RefreshCw,
  Server,
  ShieldCheck,
  Unlock,
  X
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useOSTheme } from "../../lib/theme";
import {
  fleetErrorMessage,
  isFleetDisabled,
  readFleetSnapshot,
  readWhoami,
  writeKillSwitch,
  writePreset,
  writeThaw,
  writeThresholds
} from "./api";
import "./fleet.css";
import {
  actionClass,
  deriveFleet,
  formatTime,
  mergeHostPayloads,
  severityTone,
  summarizeFanout,
  thresholdKey,
  validateThresholds
} from "./fleetLogic";
import type {
  ApplyMode,
  ChokeState,
  ConfirmState,
  CgroupSnapshot,
  FleetStateSnapshot,
  PollStatus,
  PresetName,
  Thresholds,
  ToastMessage
} from "./types";

const POLL_MS = 5000;
const DEFAULT_THRESHOLDS: Thresholds = {
  throttle_at: 10,
  tarpit_at: 30,
  quarantine_at: 60,
  sever_at: 100
};

const PRESETS: Array<{
  name: PresetName;
  label: string;
  eyebrow: string;
  description: string;
  tone: "good" | "danger" | "warn" | "muted";
}> = [
  {
    name: "default",
    label: "Default",
    eyebrow: "Everyday",
    description: "10/30/60/100, kill-switch off",
    tone: "good"
  },
  {
    name: "containment",
    label: "Containment",
    eyebrow: "Severe",
    description: "1/3/8/60, aggressive choke",
    tone: "danger"
  },
  {
    name: "forensic",
    label: "Forensic",
    eyebrow: "Observe",
    description: "Preserve evidence, enforce lightly",
    tone: "warn"
  },
  {
    name: "maintenance",
    label: "Maintenance",
    eyebrow: "Pause",
    description: "Kill-switch on, thresholds raised",
    tone: "muted"
  }
];

function emptySnapshot(): FleetStateSnapshot {
  return {
    peers: [],
    states: [],
    cgroups: [],
    decisions: [],
    alerts: [],
    devices: []
  };
}

function cgroupCount(snapshot: CgroupSnapshot | undefined, key: string): number {
  const value = snapshot?.[key];
  return Array.isArray(value) ? value.length : 0;
}

function targetsForMode(mode: ApplyMode, selected: Set<string>): string[] | null {
  return mode === "sel" ? Array.from(selected) : null;
}

export default function FleetRoute() {
  // Applies the OS theme + keeps it live; Fleet renders no theme-dependent markup.
  useOSTheme();
  const [who, setWho] = useState("...");
  const [snapshot, setSnapshot] = useState<FleetStateSnapshot>(() => emptySnapshot());
  const [pollStatus, setPollStatus] = useState<PollStatus>("idle");
  const [disabledMessage, setDisabledMessage] = useState("");
  const [pollError, setPollError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [applyMode, setApplyMode] = useState<ApplyMode>("all");
  const [thresholdDraft, setThresholdDraft] = useState<Thresholds>(DEFAULT_THRESHOLDS);
  const [thresholdDirty, setThresholdDirty] = useState(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const toastId = useRef(0);

  useEffect(() => {
    readWhoami()
      .then((identity) => setWho(identity.user ?? "operator"))
      .catch(() => setWho("operator"));
  }, []);

  const pushToast = useCallback((kind: ToastMessage["kind"], title: string, body?: string) => {
    const id = ++toastId.current;
    setToasts((current) => [...current, { id, kind, title, body }]);
    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 6500);
  }, []);

  const refresh = useCallback(async () => {
    setPollStatus((current) => (current === "idle" ? "loading" : current));
    try {
      const next = await readFleetSnapshot();
      setSnapshot({
        peers: next.peers,
        states: next.states.hosts ?? [],
        cgroups: next.cgroups.hosts ?? [],
        decisions: next.decisions.hosts ?? [],
        alerts: next.alerts.hosts ?? [],
        devices: next.devices.hosts ?? []
      });
      setDisabledMessage("");
      setPollError("");
      setPollStatus(next.peers.length === 0 ? "degraded" : "connected");
      setLastUpdated(new Date());
    } catch (error) {
      if (isFleetDisabled(error)) {
        setSnapshot(emptySnapshot());
        setDisabledMessage(fleetErrorMessage(error));
        setPollStatus("disabled");
        setPollError("");
        return;
      }
      setPollStatus("degraded");
      setPollError(fleetErrorMessage(error));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(interval);
  }, [refresh]);

  const derived = useMemo(
    () => deriveFleet(snapshot.peers, snapshot.states, snapshot.devices),
    [snapshot.devices, snapshot.peers, snapshot.states]
  );
  const decisions = useMemo(
    () => mergeHostPayloads(snapshot.decisions, 60),
    [snapshot.decisions]
  );
  const alerts = useMemo(() => mergeHostPayloads(snapshot.alerts, 50), [snapshot.alerts]);
  const cgroupByHost = useMemo(
    () => new Map(snapshot.cgroups.map((result) => [result.name, result])),
    [snapshot.cgroups]
  );

  useEffect(() => {
    setSelected((current) => {
      const allowed = new Set(snapshot.peers.map((peer) => peer.name));
      const next = new Set(Array.from(current).filter((host) => allowed.has(host)));
      if (next.size === current.size) {
        return current;
      }
      if (next.size === 0) {
        setApplyMode("all");
      }
      return next;
    });
  }, [snapshot.peers]);

  useEffect(() => {
    if (!thresholdDirty && derived.majorityThresholds) {
      setThresholdDraft(derived.majorityThresholds);
    }
  }, [derived.majorityThresholds, thresholdDirty]);

  const activeTargets = targetsForMode(applyMode, selected);
  const targetCount = activeTargets?.length ?? derived.kpis.total;
  const writesDisabled =
    pollStatus === "disabled" || pendingAction !== null || derived.kpis.total === 0;

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
    [runPreset]
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

  const setThreshold = (key: keyof Thresholds, value: string) => {
    setThresholdDirty(true);
    setThresholdDraft((current) => ({ ...current, [key]: Number(value) }));
  };

  const selectHost = (host: string, checked: boolean) => {
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
  };

  const statusLabel =
    pollStatus === "connected"
      ? "connected"
      : pollStatus === "disabled"
        ? "disabled"
        : pollStatus === "loading" || pollStatus === "idle"
          ? "connecting"
          : "degraded";

  return (
    <div className="fleet-app">
      <header className="fleet-topbar">
        <div className="fleet-brand">
          <div className="fleet-brand__mark" aria-hidden="true">
            <ShieldCheck size={22} />
          </div>
          <div>
            <div className="fleet-brand__title">Choke Fleet Console</div>
            <div className="fleet-brand__sub">eBPF Threat Gateway · Tier 1</div>
          </div>
        </div>

        <div className="fleet-status" aria-live="polite">
          <span className={`fleet-dot fleet-dot--${pollStatus === "connected" ? "ok" : pollStatus === "disabled" ? "warn" : "err"} ${pollStatus === "connected" ? "fleet-dot--live" : ""}`} />
          <span>{statusLabel}</span>
          <span className="fleet-status__divider" />
          <span>auto-refresh {POLL_MS / 1000}s</span>
          {lastUpdated ? (
            <>
              <span className="fleet-status__divider" />
              <span>{lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
            </>
          ) : null}
        </div>

        <nav className="fleet-nav" aria-label="Console navigation">
          <a className="fleet-btn fleet-btn--sm" href="/">
            Single Host
          </a>
          <a className="fleet-btn fleet-btn--sm" href="/choke">
            Choke
          </a>
          <a className="fleet-btn fleet-btn--sm" href="/devices">
            Devices
          </a>
          <span className="fleet-btn fleet-btn--sm fleet-btn--active">Fleet</span>
        </nav>

        <div className="fleet-user">
          <span>signed in as</span>
          <strong>{who}</strong>
          <a className="fleet-btn fleet-btn--sm" href="/api/logout">
            Sign out
          </a>
        </div>
      </header>

      {disabledMessage ? (
        <section className="fleet-disabled" aria-live="polite">
          <AlertTriangle size={18} />
          <div>
            <strong>Fleet mode is not enabled on this engine</strong>
            <p>
              {disabledMessage}. Start the engine with <code>--fleet-hosts=/path/to/chokectl.hosts</code>
              to enable cross-host control.
            </p>
          </div>
        </section>
      ) : null}

      {pollError ? (
        <section className="fleet-error" aria-live="polite">
          <AlertTriangle size={18} />
          <span>{pollError}</span>
        </section>
      ) : null}

      <section className="fleet-kpis" aria-label="Fleet KPI strip">
        <KpiTile label="Fleet size" value={derived.kpis.total} sub={`${derived.kpis.devices} fleet devices`} icon={<Server size={17} />} />
        {/* "Reachable", because that is what is counted — a host answers or it
            does not. It was labelled "Healthy", which claims something about
            the host's condition that this number does not measure: a reachable
            host can be kill-switched, drifted, or sitting on a broken chain. */}
        <KpiTile label="Reachable" value={derived.kpis.healthy} sub={`of ${derived.kpis.total} configured`} tone="good" />
        <KpiTile label="Enforcing" value={derived.kpis.enforcing} sub={`${derived.kpis.tracked} tracked processes`} />
        <KpiTile label="Kill-switched" value={derived.kpis.killed} sub="enforcement bypass" tone="danger" />
        <KpiTile
          label="Drift"
          value={derived.kpis.drift}
          sub={derived.kpis.drift === 0 ? "fleet aligned" : "investigate highlighted rows"}
          tone="warn"
        />
        {/* The denominator is hosts that actually MAINTAIN a chain, not every
            reachable host. Dividing by reachable counted a host that does not
            chain centrally as a missing chain, and the caption then read
            "broken chain on a host" — a false alarm about tamper-evidence on a
            fleet where nothing was wrong. */}
        <KpiTile
          label="Audit chain"
          value={
            derived.kpis.auditOk + derived.kpis.auditBroken === 0
              ? "—"
              : `${derived.kpis.auditOk}/${derived.kpis.auditOk + derived.kpis.auditBroken}`
          }
          sub={
            derived.kpis.auditBroken > 0
              ? `broken on ${derived.kpis.auditBroken} host${derived.kpis.auditBroken === 1 ? "" : "s"}`
              : derived.kpis.auditOk + derived.kpis.auditBroken === 0
                ? derived.kpis.auditUnsupported > 0
                  ? "not maintained on these hosts"
                  : "no data"
                : derived.kpis.auditUnsupported > 0
                  ? `all intact · ${derived.kpis.auditUnsupported} not maintained here`
                  : "all chains intact"
          }
        />
      </section>

      <main className="fleet-grid">
        <aside className="fleet-rail">
          <section className="fleet-panel">
            <PanelTitle title="Apply Changes To" />
            <div className="fleet-segment">
              <button
                className={applyMode === "all" ? "is-active" : ""}
                type="button"
                onClick={() => setApplyMode("all")}
              >
                All hosts
              </button>
              <button
                className={applyMode === "sel" ? "is-active" : ""}
                type="button"
                onClick={() => setApplyMode("sel")}
              >
                Selected only
              </button>
            </div>
            <p className="fleet-muted">
              {applyMode === "all"
                ? "Writes target every configured peer."
                : `Writes target ${selected.size} selected host${selected.size === 1 ? "" : "s"}.`}
            </p>
          </section>

          <section className="fleet-panel">
            <PanelTitle title="Posture Preset" />
            <div className="fleet-postures">
              {PRESETS.map((preset) => (
                <button
                  className={`fleet-posture fleet-posture--${preset.tone}`}
                  disabled={writesDisabled}
                  key={preset.name}
                  type="button"
                  onClick={() => requestPreset(preset.name)}
                >
                  <span>{preset.eyebrow}</span>
                  <strong>{preset.label}</strong>
                  <small>{preset.description}</small>
                </button>
              ))}
            </div>
          </section>

          <section className="fleet-panel">
            <PanelTitle title="Thresholds" />
            <div className="fleet-thresholds">
              <ThresholdInput label="Throttle" value={thresholdDraft.throttle_at} onChange={(value) => setThreshold("throttle_at", value)} />
              <ThresholdInput label="Tarpit" value={thresholdDraft.tarpit_at} onChange={(value) => setThreshold("tarpit_at", value)} />
              <ThresholdInput label="Quarantine" value={thresholdDraft.quarantine_at} onChange={(value) => setThreshold("quarantine_at", value)} />
              <ThresholdInput label="Sever" value={thresholdDraft.sever_at} onChange={(value) => setThreshold("sever_at", value)} />
            </div>
            <div className="fleet-panel__row">
              <span className={thresholdDirty ? "fleet-dirty" : "fleet-muted"}>{thresholdDirty ? "Unsaved changes" : `Majority ${thresholdKey(derived.majorityThresholds)}`}</span>
              <button
                className="fleet-btn fleet-btn--primary"
                disabled={writesDisabled || !thresholdDirty}
                type="button"
                onClick={() => void applyThresholds()}
              >
                <Check size={15} />
                Apply
              </button>
            </div>
          </section>

          <section className="fleet-panel">
            <PanelTitle title="Emergency Controls" />
            <div className="fleet-actions">
              <button
                className="fleet-btn fleet-btn--danger"
                disabled={writesDisabled}
                type="button"
                onClick={() =>
                  setConfirmState({
                    title: "Engage kill-switch?",
                    body: "Kill-switch on bypasses enforcement across targeted hosts. Decisions still log.",
                    tone: "danger",
                    confirmLabel: "Engage",
                    onConfirm: () => setKillSwitch(true)
                  })
                }
              >
                <Power size={15} />
                Kill-switch on
              </button>
              <button className="fleet-btn" disabled={writesDisabled} type="button" onClick={() => void setKillSwitch(false)}>
                <Activity size={15} />
                Kill-switch off
              </button>
              <button
                className="fleet-btn"
                disabled={writesDisabled}
                type="button"
                onClick={() =>
                  setConfirmState({
                    title: "Thaw quarantined cgroup?",
                    body: "Releases paused processes from choke-quarantined on targeted hosts.",
                    confirmLabel: "Thaw",
                    reasonLabel: "Audit reason",
                    reasonRequired: true,
                    defaultReason: "fleet UI thaw",
                    onConfirm: thaw
                  })
                }
              >
                <Unlock size={15} />
                Thaw quarantine
              </button>
            </div>
            <p className="fleet-muted">Current target set: {targetCount} host{targetCount === 1 ? "" : "s"}.</p>
          </section>
        </aside>

        <section className="fleet-main">
          <section className="fleet-panel fleet-panel--table">
            <div className="fleet-panel__head">
              <div>
                <PanelTitle title="Fleet" />
                <p className="fleet-muted">
                  {derived.kpis.healthy}/{derived.kpis.total} reachable · {derived.kpis.enforcing} enforcing · {derived.kpis.killed} kill-switched · {derived.kpis.drift} drift
                </p>
              </div>
              <div className="fleet-toolbar">
                <button
                  className="fleet-btn fleet-btn--sm"
                  type="button"
                  onClick={() => {
                    setSelected(new Set(snapshot.peers.map((peer) => peer.name)));
                    setApplyMode("sel");
                  }}
                >
                  Select all
                </button>
                <button
                  className="fleet-btn fleet-btn--sm"
                  type="button"
                  onClick={() => {
                    setSelected(new Set());
                    setApplyMode("all");
                  }}
                >
                  Clear
                </button>
                <button className="fleet-btn fleet-btn--sm" type="button" onClick={() => void refresh()}>
                  <RefreshCw size={14} />
                  Refresh
                </button>
              </div>
            </div>
            <FleetTable
              rows={derived.rows}
              selected={selected}
              onSelect={selectHost}
              loading={pollStatus === "loading" || pollStatus === "idle"}
            />
          </section>

          <section className="fleet-panel">
            <div className="fleet-panel__head">
              <PanelTitle title="Cgroup Tier Inhabitants" />
              <span className="fleet-muted">live PID counts</span>
            </div>
            <CgroupBars peers={snapshot.peers} cgroupByHost={cgroupByHost} />
          </section>
        </section>

        <aside className="fleet-feedrail">
          <section className="fleet-panel fleet-feed-panel">
            <div className="fleet-panel__head fleet-panel__head--tight">
              <div>
                <PanelTitle title="Live Decisions" />
                <p className="fleet-muted">merged across the fleet</p>
              </div>
              <span className="fleet-live-label"><span className="fleet-dot fleet-dot--ok fleet-dot--live" /> live</span>
            </div>
            <DecisionFeed decisions={decisions} />
          </section>

          <section className="fleet-panel fleet-alert-panel">
            <div className="fleet-panel__head fleet-panel__head--tight">
              <PanelTitle title="Alerts" />
              <span className="fleet-muted">latest 50</span>
            </div>
            <AlertFeed alerts={alerts} />
          </section>
        </aside>
      </main>

      <ToastContainer toasts={toasts} onDismiss={(id) => setToasts((current) => current.filter((toast) => toast.id !== id))} />
      {confirmState ? <ConfirmModal state={confirmState} onClose={() => setConfirmState(null)} /> : null}
    </div>
  );
}

function KpiTile({
  label,
  value,
  sub,
  tone = "default",
  icon
}: {
  label: string;
  value: string | number;
  sub: string;
  tone?: "default" | "good" | "warn" | "danger";
  icon?: React.ReactNode;
}) {
  return (
    <article className={`fleet-kpi fleet-kpi--${tone}`}>
      <div className="fleet-kpi__label">
        {icon}
        {label}
      </div>
      <div className="fleet-kpi__value">{value}</div>
      <div className="fleet-kpi__sub">{sub}</div>
    </article>
  );
}

function PanelTitle({ title }: { title: string }) {
  return <h2 className="fleet-panel__title">{title}</h2>;
}

function ThresholdInput({
  label,
  value,
  onChange
}: {
  label: string;
  value: number;
  onChange: (value: string) => void;
}) {
  return (
    <label>
      <span>{label}</span>
      <input min={1} type="number" value={Number.isFinite(value) ? value : ""} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

function FleetTable({
  rows,
  selected,
  onSelect,
  loading
}: {
  rows: ReturnType<typeof deriveFleet>["rows"];
  selected: Set<string>;
  onSelect: (host: string, checked: boolean) => void;
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="fleet-table-empty">
        <div className="fleet-skeleton" />
        <div className="fleet-skeleton fleet-skeleton--short" />
      </div>
    );
  }
  if (rows.length === 0) {
    return <div className="fleet-table-empty">No fleet peers configured.</div>;
  }

  return (
    <div className="fleet-table-wrap">
      <table className="fleet-table">
        <thead>
          <tr>
            <th aria-label="Selected" />
            <th>Host</th>
            <th>State</th>
            <th>Mode</th>
            <th>Kill</th>
            <th>Thresholds</th>
            <th>Tracked</th>
            <th>Quarantined</th>
            <th>Tarpit</th>
            <th>Throttled</th>
            <th>Audit</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const data = row.result?.data;
            if (!row.reachable || !data) {
              return (
                <tr className="is-unreachable" key={row.peer.name}>
                  <td>
                    <input
                      aria-label={`Select ${row.peer.name}`}
                      checked={selected.has(row.peer.name)}
                      type="checkbox"
                      onChange={(event) => onSelect(row.peer.name, event.target.checked)}
                    />
                  </td>
                  <td>
                    <strong>{row.peer.name}</strong>
                    <small>{row.peer.url}</small>
                  </td>
                  <td colSpan={9}>
                    <span className="fleet-pill fleet-pill--danger">unreachable</span>
                    <span className="fleet-row-error">{row.result?.error ?? "no response"}</span>
                  </td>
                </tr>
              );
            }
            const counts = data.counts ?? {};
            const audit = data.audit;
            return (
              <tr className={row.driftMode || row.driftKill || row.driftThresholds ? "has-drift" : ""} key={row.peer.name}>
                <td>
                  <input
                    aria-label={`Select ${row.peer.name}`}
                    checked={selected.has(row.peer.name)}
                    type="checkbox"
                    onChange={(event) => onSelect(row.peer.name, event.target.checked)}
                  />
                </td>
                <td>
                  <strong>{row.peer.name}</strong>
                  <small>{row.peer.url}</small>
                </td>
                <td>
                  <span className={`fleet-pill ${data.kill_switched ? "fleet-pill--danger" : "fleet-pill--good"}`}>
                    {data.kill_switched ? "bypass" : "live"}
                  </span>
                </td>
                <td>
                  {row.driftMode ? <DriftMark /> : null}
                  <span className={`fleet-pill ${data.mode === "enforcing" ? "fleet-pill--info" : "fleet-pill--muted"}`}>{data.mode ?? "?"}</span>
                </td>
                <td>
                  {row.driftKill ? <DriftMark /> : null}
                  {data.kill_switched ? "on" : "off"}
                </td>
                <td>
                  {row.driftThresholds ? <DriftMark /> : null}
                  {thresholdKey(data.thresholds)}
                </td>
                <td>{data.tracked ?? 0}</td>
                <td>{counts.quarantined ?? 0}</td>
                <td>{counts.tarpit ?? 0}</td>
                <td>{counts.throttled ?? 0}</td>
                <td>
                  {audit?.ok ? (
                    <span className="fleet-pill fleet-pill--good">ok · {audit.total ?? 0}</span>
                  ) : audit?.bad_at != null ? (
                    <span className="fleet-pill fleet-pill--danger">broken @{audit.bad_at}</span>
                  ) : (
                    <span className="fleet-pill fleet-pill--muted">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DriftMark() {
  return (
    <span className="fleet-drift" title="Differs from fleet majority">
      !
    </span>
  );
}

function CgroupBars({
  peers,
  cgroupByHost
}: {
  peers: Array<{ name: string }>;
  cgroupByHost: Map<string, { ok: boolean; data?: CgroupSnapshot; error?: string }>;
}) {
  const rows = peers.map((peer) => {
    const result = cgroupByHost.get(peer.name);
    return {
      name: peer.name,
      ok: Boolean(result?.ok && result.data),
      throttled: cgroupCount(result?.data, "choke-throttled"),
      tarpit: cgroupCount(result?.data, "choke-tarpit"),
      quarantined: cgroupCount(result?.data, "choke-quarantined"),
      error: result?.error
    };
  });
  const max = Math.max(1, ...rows.flatMap((row) => [row.throttled, row.tarpit, row.quarantined]));

  if (rows.length === 0) {
    return <div className="fleet-empty">No cgroup data.</div>;
  }

  return (
    <div className="fleet-cgroups">
      {rows.map((row) =>
        row.ok ? (
          <div className="fleet-cgroup-row" key={row.name}>
            <strong>{row.name}</strong>
            <TierBar label="throttle" value={row.throttled} max={max} tone="warn" />
            <TierBar label="tarpit" value={row.tarpit} max={max} tone="danger" />
            <TierBar label="quarantine" value={row.quarantined} max={max} tone="purple" />
          </div>
        ) : (
          <div className="fleet-cgroup-row fleet-cgroup-row--down" key={row.name}>
            <strong>{row.name}</strong>
            <span>{row.error ?? "unreachable"}</span>
          </div>
        )
      )}
    </div>
  );
}

function TierBar({ label, value, max, tone }: { label: string; value: number; max: number; tone: "warn" | "danger" | "purple" }) {
  return (
    <div className="fleet-tier">
      <span>{label}</span>
      <div className="fleet-tier__track">
        <div className={`fleet-tier__bar fleet-tier__bar--${tone}`} style={{ width: `${Math.max(0, (value / max) * 100)}%` }} />
      </div>
      <em>{value}</em>
    </div>
  );
}

function DecisionFeed({ decisions }: { decisions: Array<{ _host: string; timestamp?: string; action?: string; binary?: string; reason?: string }> }) {
  if (decisions.length === 0) {
    return <div className="fleet-empty">No decisions yet.</div>;
  }
  return (
    <div className="fleet-decision-feed">
      {decisions.map((decision, index) => (
        <div className="fleet-decision-row" key={`${decision._host}-${decision.timestamp ?? index}-${index}`}>
          <span>{formatTime(decision.timestamp)}</span>
          <strong>{decision._host}</strong>
          <em className={`fleet-action ${actionClass(decision.action)}`}>{(decision.action ?? "?").toUpperCase()}</em>
          <p title={`${decision.binary ?? ""} ${decision.reason ?? ""}`}>
            {decision.binary ?? "?"}
            <small>{decision.reason ? ` · ${decision.reason}` : ""}</small>
          </p>
        </div>
      ))}
    </div>
  );
}

function AlertFeed({ alerts }: { alerts: Array<{ _host: string; timestamp?: string; severity?: string; title?: string; summary?: string; score?: number }> }) {
  if (alerts.length === 0) {
    return <div className="fleet-empty">No recent alerts.</div>;
  }
  return (
    <div className="fleet-alerts">
      {alerts.map((alert, index) => (
        <article className="fleet-alert" key={`${alert._host}-${alert.timestamp ?? index}-${index}`}>
          <div>
            <span className={`fleet-pill fleet-pill--${severityTone(alert.severity)}`}>{(alert.severity ?? "info").toUpperCase()}</span>
            <span>{formatTime(alert.timestamp)}</span>
            <strong>{alert._host}</strong>
            {alert.score != null ? <em>score {alert.score}</em> : null}
          </div>
          <p>{alert.title || alert.summary || "(no title)"}</p>
        </article>
      ))}
    </div>
  );
}

function ToastContainer({
  toasts,
  onDismiss
}: {
  toasts: ToastMessage[];
  onDismiss: (id: number) => void;
}) {
  return (
    <div className="fleet-toasts" aria-live="polite">
      {toasts.map((toast) => (
        <div className={`fleet-toast fleet-toast--${toast.kind}`} key={toast.id}>
          <span className={`fleet-dot fleet-dot--${toast.kind === "ok" ? "ok" : toast.kind === "err" ? "err" : "warn"}`} />
          <div>
            <strong>{toast.title}</strong>
            {toast.body ? <p>{toast.body}</p> : null}
          </div>
          <button aria-label="Dismiss toast" type="button" onClick={() => onDismiss(toast.id)}>
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}

function ConfirmModal({ state, onClose }: { state: ConfirmState; onClose: () => void }) {
  const [reason, setReason] = useState(state.defaultReason ?? "");
  const [error, setError] = useState("");
  const confirmRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    confirmRef.current?.focus();
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const confirm = async () => {
    if (state.reasonRequired && reason.trim() === "") {
      setError("A reason is required for the audit log.");
      return;
    }
    await state.onConfirm(reason.trim());
    onClose();
  };

  return (
    <div
      className="fleet-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <section className="fleet-modal" role="dialog" aria-modal="true" aria-labelledby="fleet-confirm-title">
        <div className={`fleet-modal__icon fleet-modal__icon--${state.tone === "danger" ? "danger" : "default"}`}>
          {state.tone === "danger" ? <AlertTriangle size={20} /> : <ChevronRight size={20} />}
        </div>
        <div className="fleet-modal__body">
          <h2 id="fleet-confirm-title">{state.title}</h2>
          <p>{state.body}</p>
          {state.reasonLabel ? (
            <label className="fleet-modal__reason">
              <span>{state.reasonLabel}</span>
              <input value={reason} onChange={(event) => setReason(event.target.value)} />
            </label>
          ) : null}
          {error ? <div className="fleet-modal__error">{error}</div> : null}
          <div className="fleet-modal__actions">
            <button className="fleet-btn" type="button" onClick={onClose}>
              Cancel
            </button>
            <button
              className={`fleet-btn ${state.tone === "danger" ? "fleet-btn--danger" : "fleet-btn--primary"}`}
              ref={confirmRef}
              type="button"
              onClick={() => void confirm()}
            >
              {state.confirmLabel ?? "Confirm"}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
