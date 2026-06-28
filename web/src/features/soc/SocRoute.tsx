import {
  Activity,
  AlertTriangle,
  Bell,
  BookOpen,
  Clock,
  Command,
  Cpu,
  Database,
  Download,
  Eye,
  FileText,
  Filter,
  Flame,
  Gauge,
  GitBranch,
  HelpCircle,
  ListChecks,
  Maximize2,
  Menu,
  Minimize2,
  Moon,
  Network,
  Radio,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Terminal,
  UserCircle,
  Wifi,
  X,
  Zap
} from "lucide-react";
import { Command as CommandPrimitive } from "cmdk";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent, MouseEvent } from "react";
import type * as React from "react";
import type { Selection as D3Selection, SimulationLinkDatum, SimulationNodeDatum } from "d3";
import { EventReplay } from "../../components/EventReplay";
import { VirtualList } from "../../components/VirtualList";
import {
  EMPTY_SOC_SNAPSHOT,
  fetchProcessDetail,
  fetchSocSnapshot,
  jailSocAlert,
  normalizeAlert,
  normalizeEvent,
  runSocAttack
} from "./api";
import { useStream } from "../../lib/stream";
import type { StreamFrame } from "../../lib/types";
import {
  EmptyState,
  IconButton,
  InlineNotice,
  MetricTile,
  ModalShell,
  PanelFrame,
  PopoverCard,
  SeverityBadge,
  SlideOver,
  Sparkline,
  StatusPill,
  ToggleChip,
  cx,
  relTime
} from "./components";
import {
  AccountBody,
  FleetBody,
  HoneypotsBody,
  KprobeBody,
  MitreNavigatorBody,
  NotificationsBody,
  PoliciesBody,
  RiskGauge,
  SearchField
} from "./panels";
import { SOC_PANEL_INVENTORY, SOC_STORAGE_KEYS } from "./panelInventory";
import type {
  AlertClassification,
  Severity,
  SocAlert,
  SocDecision,
  SocEvent,
  SocPanelInventoryItem,
  SocProcessDetail,
  SocSnapshot,
  StreamState
} from "./types";
import "./soc.css";

type AckState = "new" | "ack" | "resolved";
type SortField = "time" | "severity" | "score";
type OpenSurface =
  | "policies"
  | "attacks"
  | "graph"
  | "simulator"
  | "mitre"
  | "fleet"
  | "watchlist"
  | "honeypots"
  | "kprobes"
  | "time-machine"
  | "command"
  | "notifications"
  | "profile"
  | "kpi"
  | "help"
  | "export";
type PillSurface = "live" | "host" | "risk";

const PANELS = Object.fromEntries(SOC_PANEL_INVENTORY.map((item) => [item.id, item])) as Record<
  string,
  SocPanelInventoryItem
>;

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const DEFAULT_WATCHLIST = { paths: [] as string[], ips: [] as string[], binaries: [] as string[] };

interface StreamTelemetry {
  state: StreamState;
  lastMessageAt?: number;
  lastEventAt?: number;
  frames: number;
  error?: string;
}

interface AlertGroup extends SocAlert {
  groupCount: number;
  members: SocAlert[];
}

interface TimelineBucket {
  label: string;
  total: number;
  anomaly: boolean;
  counts: Record<Severity, number>;
}

interface KpiDrill {
  kind: "critical" | "high" | "medium" | "eps" | "procs";
  title: string;
}

interface ContextMenuState {
  alert: SocAlert;
  x: number;
  y: number;
}

interface HoverPreviewState {
  alert: SocAlert;
  x: number;
  y: number;
}

export function SocRoute() {
  const { snapshot, setSnapshot, loading, errors, statuses, refresh } = useSocData();
  const sharedStream = useStream();
  const stream = useMemo<StreamTelemetry>(
    () => ({
      state: sharedStream.state,
      lastMessageAt: sharedStream.lastMessageAt,
      lastEventAt: sharedStream.lastEventAt,
      frames: sharedStream.messageCount,
      error: sharedStream.error
    }),
    [sharedStream.error, sharedStream.lastEventAt, sharedStream.lastMessageAt, sharedStream.messageCount, sharedStream.state]
  );
  const now = useNow(1000);

  const [theme, setTheme] = useLocalJsonState<"dark" | "light">("soc.theme", "dark");
  // Default open on desktop, collapsed on phones — a 234px drawer over a
  // ~390px screen would otherwise bury the content on first load.
  const [sidebarOpen, setSidebarOpen] = useLocalJsonState<boolean>(
    "soc.sidebarOpen",
    typeof window === "undefined" ? true : window.innerWidth >= 760
  );
  const [rangeMin, setRangeMin] = useLocalJsonState<number>("soc.prefDefaultRange", 30);
  const [execBandOpen, setExecBandOpen] = useLocalJsonState<boolean>("soc.execBand", true);
  const [briefingOpen, setBriefingOpen] = useLocalJsonState<boolean>("soc.briefingMode", false);
  const [query, setQuery] = useState("");
  const [hideBaseline, setHideBaseline] = useLocalJsonState<boolean>("soc.hideBaseline", true);
  const [filterUnack, setFilterUnack] = useState(false);
  const [groupAlerts, setGroupAlerts] = useLocalJsonState<boolean>("soc.groupAlerts", true);
  const [sortField, setSortField] = useState<SortField>("time");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [ackStates, setAckStates] = useLocalJsonState<Record<string, AckState>>("soc.alertStates", {});
  const [pinnedAlerts, setPinnedAlerts] = useLocalJsonState<string[]>("soc.pinnedAlerts", []);
  const [alertNotes, setAlertNotes] = useLocalJsonState<Record<string, string>>("soc.alertNotes", {});
  const [timelineHidden, setTimelineHidden] = useLocalJsonState<Severity[]>("soc.timelineSevHidden", []);
  const [streamFilter, setStreamFilter] = useState("");
  const [streamPaused, setStreamPaused] = useState(false);
  const [streamHideNoise, setStreamHideNoise] = useState(true);
  const [openSurface, setOpenSurface] = useState<OpenSurface | null>(null);
  const [openPill, setOpenPill] = useState<PillSurface | null>(null);
  const [kpiDrill, setKpiDrill] = useState<KpiDrill | null>(null);
  const [drillAlert, setDrillAlert] = useState<SocAlert | null>(null);
  const [processDetail, setProcessDetail] = useState<SocProcessDetail | null>(null);
  const [processDetailError, setProcessDetailError] = useState("");
  const [hoverPreview, setHoverPreview] = useState<HoverPreviewState | null>(null);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [commandQuery, setCommandQuery] = useState("");
  const [watchlist, setWatchlist] = useLocalJsonState("soc.watchlist", DEFAULT_WATCHLIST);
  const [fleetHosts, setFleetHosts] = useLocalJsonState<Array<{ name: string; url: string }>>("soc.fleet.hosts", []);
  const [notifyHistory, setNotifyHistory] = useLocalJsonState<
    Array<{ title?: string; body?: string; ts?: string; read?: boolean; severity?: Severity }>
  >("soc.notifyHistory", []);
  const [notificationsActive, setNotificationsActive] = useLocalJsonState<boolean>("soc.notifications", true);
  const [notifyChannels, setNotifyChannels] = useLocalJsonState<{ inApp: boolean; desktop: boolean; audio: boolean }>(
    "soc.notifyChannels",
    { inApp: true, desktop: true, audio: false }
  );
  const searchRef = useRef<HTMLInputElement | null>(null);
  const processedStreamBatchRef = useRef(0);
  const previousStreamStateRef = useRef(sharedStream.state);

  useEffect(() => {
    if (sharedStream.batchId === 0 || processedStreamBatchRef.current === sharedStream.batchId) return;
    processedStreamBatchRef.current = sharedStream.batchId;
    applySocStreamBatch(setSnapshot, sharedStream.latestBatch);
  }, [setSnapshot, sharedStream.batchId, sharedStream.latestBatch]);

  useEffect(() => {
    const previous = previousStreamStateRef.current;
    if (sharedStream.state === "live" && (previous === "reconnect" || previous === "down")) {
      refresh();
    }
    previousStreamStateRef.current = sharedStream.state;
  }, [refresh, sharedStream.state]);

  useEffect(() => {
    const body = document.body;
    body.classList.toggle("theme-light", theme === "light");
    body.classList.toggle("theme-dark", theme === "dark");
    const favicon = document.getElementById("appFavicon") as HTMLLinkElement | null;
    if (favicon) favicon.href = theme === "light" ? "/favicon-light.svg" : "/favicon.svg";
  }, [theme]);

  useEffect(() => {
    const controller = new AbortController();
    if (!drillAlert?.execId) {
      setProcessDetail(null);
      setProcessDetailError("");
      return () => controller.abort();
    }

    setProcessDetail(null);
    setProcessDetailError("");
    void fetchProcessDetail(drillAlert.execId, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (result.ok) {
        setProcessDetail(result.data);
      } else {
        setProcessDetailError(result.error || "process detail unavailable");
      }
    });

    return () => controller.abort();
  }, [drillAlert?.execId]);

  useEffect(() => {
    function onKeyDown(event: globalThis.KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const inTextInput =
        target?.tagName === "INPUT" || target?.tagName === "TEXTAREA" || target?.getAttribute("contenteditable") === "true";
      if (event.key === "Escape") {
        setOpenSurface(null);
        setOpenPill(null);
        setContextMenu(null);
        setHoverPreview(null);
        if (drillAlert) setDrillAlert(null);
        return;
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpenSurface("command");
        return;
      }
      if (inTextInput) return;
      if (event.key === "/") {
        event.preventDefault();
        searchRef.current?.focus();
      } else if (event.key === "?") {
        setOpenSurface("help");
      } else if (event.key.toLowerCase() === "a" && drillAlert) {
        setAckState(drillAlert.id, "ack");
      } else if (event.key.toLowerCase() === "r" && drillAlert) {
        setAckState(drillAlert.id, "resolved");
      }
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [drillAlert, setAckStates]);

  const rangeAlerts = useMemo(() => {
    const cutoff = now - rangeMin * 60_000;
    return snapshot.alerts.filter((alert) => Date.parse(alert.timestamp) >= cutoff);
  }, [now, rangeMin, snapshot.alerts]);

  const previousRangeAlerts = useMemo(() => {
    const windowMs = rangeMin * 60_000;
    const start = now - windowMs * 2;
    const end = now - windowMs;
    return snapshot.alerts.filter((alert) => {
      const ts = Date.parse(alert.timestamp);
      return ts >= start && ts < end;
    });
  }, [now, rangeMin, snapshot.alerts]);

  const rangeEvents = useMemo(() => {
    const cutoff = now - rangeMin * 60_000;
    return snapshot.events.filter((event) => Date.parse(event.timestamp) >= cutoff);
  }, [now, rangeMin, snapshot.events]);

  const counts = useMemo(() => countSeverities(rangeAlerts), [rangeAlerts]);
  const previousCounts = useMemo(() => countSeverities(previousRangeAlerts), [previousRangeAlerts]);
  const hiddenTimelineSet = useMemo(() => new Set(timelineHidden), [timelineHidden]);
  const filteredAlerts = useMemo(() => {
    const pinned = new Set(pinnedAlerts);
    const filtered = rangeAlerts
      .filter((alert) => !hideBaseline || classifyAlert(alert) !== "baseline")
      .filter((alert) => !filterUnack || (ackStates[alert.id] || "new") === "new")
      .filter((alert) => matchesQuery(alert, query))
      .sort((a, b) => compareAlerts(a, b, sortField, pinned));
    return groupAlerts ? groupAlertList(filtered) : filtered.map((alert) => ({ ...alert, groupCount: 1, members: [alert] }));
  }, [ackStates, filterUnack, groupAlerts, hideBaseline, pinnedAlerts, query, rangeAlerts, sortField]);

  const riskScore = useMemo(() => Math.min(100, counts.critical * 8 + counts.high * 3 + counts.medium), [counts]);
  const riskLabel = riskScore >= 80 ? "critical" : riskScore >= 45 ? "high" : riskScore >= 18 ? "elevated" : "low";
  const previousRiskScore = useMemo(
    () => Math.min(100, previousCounts.critical * 8 + previousCounts.high * 3 + previousCounts.medium),
    [previousCounts]
  );
  const openContainment = useMemo(() => {
    let critical = 0;
    let high = 0;
    for (const alert of rangeAlerts) {
      if ((ackStates[alert.id] || "new") !== "new") continue;
      if (alert.severity === "critical") critical += 1;
      else if (alert.severity === "high") high += 1;
    }
    return { critical, high };
  }, [ackStates, rangeAlerts]);
  const eps = useMemo(() => eventsPerSecond(snapshot.events, now), [now, snapshot.events]);
  const activeProcesses = useMemo(() => processSummary(rangeAlerts, rangeEvents), [rangeAlerts, rangeEvents]);
  const timeline = useMemo(() => buildTimeline(rangeAlerts, rangeMin, now, hiddenTimelineSet), [
    hiddenTimelineSet,
    now,
    rangeAlerts,
    rangeMin
  ]);
  const severitySparks = useMemo(() => {
    const buckets = buildTimeline(rangeAlerts, rangeMin, now, new Set(), 12);
    return Object.fromEntries(SEVERITIES.map((severity) => [severity, buckets.map((bucket) => bucket.counts[severity])])) as Record<
      Severity,
      number[]
    >;
  }, [now, rangeAlerts, rangeMin]);
  const eventSparkValues = useMemo(() => eventSpark(snapshot.events, now), [now, snapshot.events]);
  const mitreRows = useMemo(
    () => mitreCoverage(rangeEvents, snapshot.policies, snapshot.policyStats),
    [rangeEvents, snapshot.policies, snapshot.policyStats]
  );
  const topProcesses = useMemo(() => topProcessRows(rangeAlerts), [rangeAlerts]);
  const iocs = useMemo(() => extractIocs(rangeAlerts, rangeEvents), [rangeAlerts, rangeEvents]);
  const networkRows = useMemo(() => aggregateNetwork(rangeEvents), [rangeEvents]);
  const visibleEvents = useMemo(
    () => filterEvents(snapshot.events, streamFilter, streamHideNoise).slice(0, 200),
    [snapshot.events, streamFilter, streamHideNoise]
  );
  const staleSeconds = stream.lastMessageAt ? Math.max(0, Math.floor((now - stream.lastMessageAt) / 1000)) : undefined;
  const streamStale = staleSeconds === undefined || staleSeconds > 30;
  const selectedAlertCount = selectedIds.size;
  const activeEndpointErrors = Object.entries(errors).filter(([, error]) => error);
  const disabledEndpoints = Object.entries(statuses)
    .filter(([, status]) => status === 503)
    .map(([key]) => key);

  const [knownVersionSha, setKnownVersionSha] = useState("");
  const [versionToastDismissed, setVersionToastDismissed] = useState(false);
  const versionChanged = Boolean(knownVersionSha && snapshot.version.sha && snapshot.version.sha !== knownVersionSha);
  useEffect(() => {
    if (!snapshot.version.sha) return;
    if (!knownVersionSha) {
      setKnownVersionSha(snapshot.version.sha);
    }
  }, [knownVersionSha, snapshot.version.sha]);

  function setAckState(id: string, value: AckState) {
    setAckStates((current) => ({ ...current, [id]: value }));
  }

  function toggleSelected(id: string) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function applyBulkAck(value: AckState) {
    setAckStates((current) => {
      const next = { ...current };
      for (const id of selectedIds) next[id] = value;
      return next;
    });
    setSelectedIds(new Set());
  }

  function togglePin(id: string) {
    setPinnedAlerts((current) => (current.includes(id) ? current.filter((item) => item !== id) : [id, ...current]));
  }

  function openKpi(kind: KpiDrill["kind"], title: string) {
    setKpiDrill({ kind, title });
    setOpenSurface("kpi");
  }

  function openDrill(alert: SocAlert) {
    setDrillAlert(alert);
    setContextMenu(null);
  }

  function closeModal() {
    setOpenSurface(null);
    setCommandQuery("");
  }

  function openSurfaceByName(surface: OpenSurface) {
    setOpenSurface(surface);
    setCommandQuery("");
    // On phones the sidebar is an overlay drawer; close it so the surface
    // it opened isn't hidden behind it.
    if (typeof window !== "undefined" && window.innerWidth < 760) setSidebarOpen(false);
  }

  function toggleTimelineSeverity(severity: Severity) {
    setTimelineHidden((current) =>
      current.includes(severity) ? current.filter((item) => item !== severity) : [...current, severity]
    );
  }

  function onAlertContext(event: MouseEvent, alert: SocAlert) {
    event.preventDefault();
    const width = typeof window === "undefined" ? 280 : window.innerWidth;
    const height = typeof window === "undefined" ? 220 : window.innerHeight;
    setContextMenu({
      alert,
      x: Math.min(event.clientX, width - 290),
      y: Math.min(event.clientY, height - 230)
    });
  }

  function onAlertHover(event: MouseEvent, alert: SocAlert) {
    const width = typeof window === "undefined" ? 320 : window.innerWidth;
    setHoverPreview({
      alert,
      x: Math.min(event.clientX + 18, width - 330),
      y: event.clientY + 18
    });
  }

  return (
    <div className={cx("soc-route", theme === "light" && "theme-light", sidebarOpen && "sidebar-open")}>
      <aside className="soc-sidebar" data-panel={PANELS["left-sidebar"].id}>
        <button
          type="button"
          className="soc-sidebar-toggle"
          onClick={() => setSidebarOpen((value) => !value)}
          aria-label="Toggle sidebar"
          title="Toggle sidebar"
        >
          <Menu size={18} />
        </button>
        <SidebarSection title="Tools">
          <SidebarButton icon={FileText} label="Policies" onClick={() => openSurfaceByName("policies")} />
          <SidebarButton icon={Zap} label="Attacks" onClick={() => openSurfaceByName("attacks")} />
          <SidebarButton icon={Gauge} label="MITRE Navigator" onClick={() => openSurfaceByName("mitre")} />
          <SidebarButton icon={GitBranch} label="Correlation Graph" onClick={() => openSurfaceByName("graph")} />
          <SidebarButton icon={Settings} label="Rule Simulator" onClick={() => openSurfaceByName("simulator")} />
          <SidebarButton icon={Database} label="Honeypots" onClick={() => openSurfaceByName("honeypots")} />
          <SidebarButton icon={Cpu} label="Kprobe Perf" onClick={() => openSurfaceByName("kprobes")} />
          <SidebarLink icon={ShieldAlert} label="Choke Gateway" href="/choke" />
          <SidebarLink icon={Wifi} label="Devices" href="/devices" />
          <SidebarButton icon={Network} label="Fleet" onClick={() => openSurfaceByName("fleet")} />
        </SidebarSection>
        <SidebarSection title="Workflow">
          <SidebarButton icon={Command} label="Command Palette" onClick={() => openSurfaceByName("command")} />
          <SidebarButton icon={Eye} label="Watchlist" onClick={() => openSurfaceByName("watchlist")} badge={watchCount(watchlist)} />
          <SidebarButton icon={Clock} label="Time Machine" onClick={() => openSurfaceByName("time-machine")} />
          <SidebarButton icon={Download} label="Export view" onClick={() => openSurfaceByName("export")} />
        </SidebarSection>
        <SidebarSection title="Settings">
          <SidebarButton
            icon={Bell}
            label="Notifications"
            onClick={() => openSurfaceByName("notifications")}
            badge={notificationsActive && notifyChannels.inApp ? notifyHistory.filter((item) => !item.read).length : undefined}
          />
          <SidebarButton icon={HelpCircle} label="Help" onClick={() => openSurfaceByName("help")} />
        </SidebarSection>
        <div className="soc-sidebar-spacer" />
        <SidebarSection title="Account">
          <SidebarButton icon={UserCircle} label={snapshot.whoami.user} onClick={() => openSurfaceByName("profile")} />
          <SidebarLink icon={X} label="Sign out" href="/api/logout" />
        </SidebarSection>
        <div className="soc-sidebar-foot">{SOC_PANEL_INVENTORY.length}/31 SOC panels</div>
      </aside>

      {/* Phone-only dismiss scrim for the overlay sidebar drawer. */}
      <button
        type="button"
        className="soc-sidebar-scrim"
        aria-label="Close menu"
        tabIndex={sidebarOpen ? 0 : -1}
        onClick={() => setSidebarOpen(false)}
      />

      <div className="soc-main-shell">
        <header className="soc-topbar" data-panel={PANELS["top-bar"].id}>
          <div className="soc-brand">
            <ShieldCheck size={28} />
            <div>
              <strong>eBPF SOC</strong>
              <span>Threat Intelligence</span>
            </div>
          </div>
          <label className="soc-search">
            <Search size={16} />
            <input
              ref={searchRef}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search alerts, processes, policies…"
            />
            <kbd>/</kbd>
          </label>
          {/* Grouped by function: time range · system status (host/stream) · utilities.
             Posture is no longer duplicated here — the executive band below owns it. */}
          <div className="soc-top-actions">
            <div className="soc-range" role="group" aria-label="Time range">
              {[5, 30, 60, 1440].map((value) => (
                <button
                  key={value}
                  type="button"
                  className={value === rangeMin ? "is-active" : ""}
                  onClick={() => setRangeMin(value)}
                >
                  {value === 1440 ? "24h" : `${value}m`}
                </button>
              ))}
            </div>
            <span className="soc-topbar-sep" aria-hidden="true" />
            <button type="button" className="soc-host-pill" onClick={() => setOpenPill(openPill === "host" ? null : "host")}>
              <Server size={14} />
              <span>{snapshot.whoami.host}</span>
            </button>
            <button type="button" className={cx("soc-live-pill", stream.state)} onClick={() => setOpenPill(openPill === "live" ? null : "live")}>
              <Radio size={14} />
              <span>{stream.state}</span>
            </button>
            <span className="soc-topbar-sep" aria-hidden="true" />
            <IconButton icon={RefreshCw} label="Refresh snapshots" onClick={refresh} active={loading} />
            <IconButton
              icon={theme === "light" ? Moon : Sun}
              label="Toggle theme"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
            />
          </div>
        </header>

        <main className="soc-content">
          <div className={cx("soc-stale-banner", streamStale && "is-visible")} data-panel={PANELS["stale-data-banner"].id} role="status">
            <AlertTriangle size={16} />
            <span>
              Stream silent{staleSeconds !== undefined ? ` for ${staleSeconds}s` : ""}. Dashboard snapshots remain available.
            </span>
            <button type="button" onClick={sharedStream.reconnect}>
              Force reconnect
            </button>
          </div>

          <div
            className={cx("soc-version-toast", versionChanged && !versionToastDismissed && "is-visible")}
            data-panel={PANELS["version-update-toast"].id}
            role="status"
          >
            <RefreshCw size={16} />
            <span>New frontend version detected.</span>
            <button type="button" onClick={() => window.location.reload()}>
              Reload
            </button>
            <button type="button" onClick={() => setVersionToastDismissed(true)} aria-label="Dismiss">
              x
            </button>
          </div>

          {activeEndpointErrors.length ? (
            <InlineNotice tone="warn" title="Some read-only SOC endpoints are unavailable.">
              {activeEndpointErrors.map(([key, error]) => `${key}: ${error}`).join("; ")}
            </InlineNotice>
          ) : null}
          {disabledEndpoints.length ? (
            <InlineNotice tone="info" title="Disabled endpoint state detected.">
              {disabledEndpoints.join(", ")}
            </InlineNotice>
          ) : null}

          <ExecutiveBand
            open={execBandOpen}
            onToggle={() => setExecBandOpen((value) => !value)}
            briefingOpen={briefingOpen}
            onToggleBriefing={() => setBriefingOpen((value) => !value)}
            riskScore={riskScore}
            riskLabel={riskLabel}
            riskDelta={riskScore - previousRiskScore}
            windowLabel={rangeMin === 1440 ? "24h" : `${rangeMin}m`}
            totalAlerts={rangeAlerts.length}
            openCritical={openContainment.critical}
            openHigh={openContainment.high}
            containmentActions={snapshot.decisions.length}
            topTechnique={mitreRows[0]}
            eps={eps}
            activeProcesses={activeProcesses.count}
            topProcess={activeProcesses.top}
            hostName={snapshot.whoami.host}
            hostOk={!activeEndpointErrors.length}
            streamState={stream.state}
            onReviewCriticals={() => openKpi("critical", "Critical alerts")}
            onOpenRisk={() => setOpenPill("risk")}
          />

          <section className="soc-kpi-grid" data-panel={PANELS["kpi-row"].id}>
            <ExecutiveMetricTile
              label="Critical"
              value={counts.critical}
              sub="Containment priority"
              meta={`${rangeMin}m window`}
              delta={counts.critical - previousCounts.critical}
              badge="P1"
              tone="critical"
              onClick={() => openKpi("critical", "Critical alerts")}
            >
              <Sparkline values={severitySparks.critical} tone="critical" />
            </ExecutiveMetricTile>
            <ExecutiveMetricTile
              label="High"
              value={counts.high}
              sub="Escalation watch"
              meta={`${rangeMin}m window`}
              delta={counts.high - previousCounts.high}
              badge="P2"
              tone="high"
              onClick={() => openKpi("high", "High alerts")}
            >
              <Sparkline values={severitySparks.high} tone="high" />
            </ExecutiveMetricTile>
            <ExecutiveMetricTile
              label="Medium"
              value={counts.medium}
              sub="Analyst triage"
              meta={`${rangeMin}m window`}
              delta={counts.medium - previousCounts.medium}
              badge="P3"
              tone="medium"
              onClick={() => openKpi("medium", "Medium alerts")}
            >
              <Sparkline values={severitySparks.medium} tone="medium" />
            </ExecutiveMetricTile>
            <ExecutiveMetricTile
              label="Events / sec"
              value={eps.toFixed(1)}
              sub="60s ingestion rate"
              meta={`${eventSparkValues.reduce((sum, value) => sum + value, 0)} events / 60s`}
              badge="LIVE"
              tone="accent"
              onClick={() => openKpi("eps", "Events per second")}
            >
              <Sparkline values={eventSparkValues} tone="accent" />
            </ExecutiveMetricTile>
            <ExecutiveMetricTile
              label="Active processes"
              value={activeProcesses.count}
              sub={activeProcesses.top || "No dominant process"}
              meta={`${topProcesses.length} scored processes`}
              badge="LAST 10M"
              tone="good"
              onClick={() => openKpi("procs", "Active processes")}
            />
          </section>

          <PanelFrame
            panel={PANELS["severity-timeline"]}
            status={<StatusPill label={`${timeline.reduce((sum, bucket) => sum + bucket.total, 0)} alerts`} tone="info" />}
            actions={
              <div className="soc-severity-toggle-row">
                {SEVERITIES.map((severity) => (
                  <button
                    key={severity}
                    type="button"
                    className={cx("soc-severity-toggle", hiddenTimelineSet.has(severity) && "is-muted")}
                    onClick={() => toggleTimelineSeverity(severity)}
                  >
                    <SeverityBadge severity={severity} />
                  </button>
                ))}
              </div>
            }
          >
            <TimelinePanel buckets={timeline} rangeMin={rangeMin} />
          </PanelFrame>

          <section className="soc-primary-grid">
            <PanelFrame
              panel={PANELS["alert-triage-queue"]}
              className="soc-alert-panel"
              status={<StatusPill label={`${filteredAlerts.length} shown`} tone="info" />}
              actions={
                <div className="soc-control-row">
                  <ToggleChip label="Hide baseline" active={hideBaseline} onChange={setHideBaseline} />
                  <ToggleChip label="Unacked only" active={filterUnack} onChange={setFilterUnack} tone="warn" />
                  <ToggleChip label="Group" active={groupAlerts} onChange={setGroupAlerts} />
                </div>
              }
            >
              <div className="soc-sort-row">
                <span>sort by</span>
                {(["time", "severity", "score"] as SortField[]).map((field) => (
                  <button key={field} type="button" className={sortField === field ? "is-active" : ""} onClick={() => setSortField(field)}>
                    {field}
                  </button>
                ))}
              </div>
              {selectedAlertCount ? (
                <div className="soc-bulk-bar">
                  <strong>{selectedAlertCount} selected</strong>
                  <button type="button" onClick={() => applyBulkAck("ack")}>
                    Acknowledge
                  </button>
                  <button type="button" onClick={() => applyBulkAck("resolved")}>
                    Resolve
                  </button>
                  <button type="button" onClick={() => setSelectedIds(new Set())}>
                    Clear
                  </button>
                </div>
              ) : null}
              <div className="soc-alert-list">
                {filteredAlerts.length ? (
                  filteredAlerts.map((alert) => (
                    <AlertRow
                      key={alert.id}
                      alert={alert}
                      ack={ackStates[alert.id] || "new"}
                      selected={selectedIds.has(alert.id)}
                      pinned={pinnedAlerts.includes(alert.id)}
                      onSelect={() => toggleSelected(alert.id)}
                      onOpen={() => openDrill(alert)}
                      onAck={(value) => setAckState(alert.id, value)}
                      onPin={() => togglePin(alert.id)}
                      onContext={(event) => onAlertContext(event, alert)}
                      onHover={(event) => onAlertHover(event, alert)}
                      onLeave={() => setHoverPreview(null)}
                    />
                  ))
                ) : (
                  <EmptyState title="No alerts match current filters" detail="Snapshots and SSE updates will fill this queue when the engine emits alerts." />
                )}
              </div>
            </PanelFrame>

            <div className="soc-right-rail">
              <PanelFrame panel={PANELS["mitre-coverage"]}>
                <MiniBarList rows={mitreRows} empty="No MITRE techniques observed in this range." />
              </PanelFrame>
              <PanelFrame panel={PANELS["top-processes"]}>
                <MiniBarList
                  rows={topProcesses.map((row) => ({
                    label: row.process,
                    value: row.score,
                    meta: `${row.pid ? `pid ${row.pid} · ` : ""}${row.count} alert${row.count === 1 ? "" : "s"}`,
                    id: row.execId
                  }))}
                  empty="No scored processes yet."
                  onClick={(id) => {
                    const alert = rangeAlerts.find((item) => item.execId === id);
                    if (alert) openDrill(alert);
                  }}
                />
              </PanelFrame>
              <PanelFrame panel={PANELS["iocs-observed"]}>
                <IocList files={iocs.files} peers={iocs.peers} />
              </PanelFrame>
              <PanelFrame panel={PANELS["network-connections"]}>
                <NetworkList rows={networkRows} />
              </PanelFrame>
            </div>
          </section>

          <PanelFrame
            panel={PANELS["live-event-stream"]}
            status={<StatusPill label={`${visibleEvents.length} events`} tone={streamPaused ? "warn" : "ok"} />}
            actions={
              <div className="soc-control-row">
                <ToggleChip label="Hide self-noise" active={streamHideNoise} onChange={setStreamHideNoise} />
                <ToggleChip label={streamPaused ? "Paused" : "Pause"} active={streamPaused} onChange={setStreamPaused} tone="warn" />
                <input className="soc-stream-filter" value={streamFilter} onChange={(event) => setStreamFilter(event.target.value)} placeholder="filter /regex/" />
              </div>
            }
          >
            <VirtualList
              className={cx("soc-event-list", streamPaused && "is-paused")}
              items={visibleEvents}
              estimateSize={68}
              getKey={(event) => event.id}
              renderItem={(event) => <EventRow event={event} onOpen={openDrillByEvent} />}
              empty={
                <EmptyState
                  title="No events yet"
                  detail="The list is capped at 200 rows and updates from /api/stream when available."
                />
              }
            />
          </PanelFrame>
        </main>
      </div>

      <SlideOver panel={PANELS["drill-down-slide-over"]} open={Boolean(drillAlert)} title={drillAlert?.title || "Alert drill-down"} onClose={() => setDrillAlert(null)}>
        {drillAlert ? (
          <DrillPanel
            alert={drillAlert}
            ack={ackStates[drillAlert.id] || "new"}
            note={alertNotes[drillAlert.id] || ""}
            processDetail={processDetail}
            processDetailError={processDetailError}
            onAck={(value) => setAckState(drillAlert.id, value)}
            onNote={(note) => setAlertNotes((current) => ({ ...current, [drillAlert.id]: note }))}
            onActionComplete={refresh}
          />
        ) : null}
      </SlideOver>

      <PopoverCard panel={PANELS["pill-popovers"]} open={openPill === "live"} title="Live data stream" onClose={() => setOpenPill(null)}>
        <PillLiveContent stream={stream} staleSeconds={staleSeconds} onReconnect={sharedStream.reconnect} />
      </PopoverCard>
      <PopoverCard panel={PANELS["pill-popovers"]} open={openPill === "host"} title="Host reachability" onClose={() => setOpenPill(null)}>
        <PillHostContent whoami={snapshot.whoami} errors={errors} statuses={statuses} onRefresh={refresh} />
      </PopoverCard>
      <PopoverCard panel={PANELS["pill-popovers"]} open={openPill === "risk"} title="Risk breakdown" onClose={() => setOpenPill(null)}>
        <PillRiskContent counts={counts} riskScore={riskScore} alerts={rangeAlerts} windowLabel={`last ${rangeMin}m`} />
      </PopoverCard>

      <SocModals
        openSurface={openSurface}
        closeModal={closeModal}
        openSurfaceByName={openSurfaceByName}
        snapshot={snapshot}
        filteredAlerts={filteredAlerts}
        rangeAlerts={rangeAlerts}
        rangeEvents={rangeEvents}
        mitreRows={mitreRows}
        topProcesses={topProcesses}
        watchlist={watchlist}
        setWatchlist={setWatchlist}
        fleetHosts={fleetHosts}
        setFleetHosts={setFleetHosts}
        trackedCount={activeProcesses.count}
        now={now}
        notifyHistory={notifyHistory}
        setNotifyHistory={setNotifyHistory}
        notificationsActive={notificationsActive}
        notifyChannels={notifyChannels}
        setNotificationsActive={setNotificationsActive}
        setNotifyChannels={setNotifyChannels}
        kpiDrill={kpiDrill}
        ackStates={ackStates}
        commandQuery={commandQuery}
        setCommandQuery={setCommandQuery}
        theme={theme}
        setTheme={setTheme}
        stream={stream}
        onActionComplete={refresh}
      />

      <AlertPreview preview={hoverPreview} />
      <AlertContextMenu
        state={contextMenu}
        onClose={() => setContextMenu(null)}
        onOpen={(alert) => openDrill(alert)}
        onAck={(alert) => setAckState(alert.id, "ack")}
        onResolve={(alert) => setAckState(alert.id, "resolved")}
        onPin={(alert) => togglePin(alert.id)}
      />
    </div>
  );

  function openDrillByEvent(event: SocEvent) {
    const alert = rangeAlerts.find((item) => item.execId && item.execId === event.execId);
    if (alert) openDrill(alert);
  }
}

function useSocData() {
  const [snapshot, setSnapshot] = useState<SocSnapshot>(EMPTY_SOC_SNAPSHOT);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [statuses, setStatuses] = useState<Record<string, number | undefined>>({});

  const load = useCallback(async (signal?: AbortSignal, quiet = false) => {
    if (!quiet) setLoading(true);
    const read = await fetchSocSnapshot(signal);
    if (signal?.aborted) return;
    setSnapshot(read.snapshot);
    setErrors(read.errors);
    setStatuses(read.statuses);
    setLoading(false);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    const interval = window.setInterval(() => void load(undefined, true), 30_000);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [load]);

  // Manual refresh: refetch every snapshot endpoint and keep the spinner up for
  // a floor of 500ms so the action always reads as "did something" even when the
  // live stream already has the data warm.
  const refresh = useCallback(() => {
    setLoading(true);
    const started = Date.now();
    void load(undefined, true).finally(() => {
      const wait = Math.max(0, 500 - (Date.now() - started));
      window.setTimeout(() => setLoading(false), wait);
    });
  }, [load]);

  return {
    snapshot,
    setSnapshot,
    loading,
    errors,
    statuses,
    refresh
  };
}

function applySocStreamBatch(
  setSnapshot: React.Dispatch<React.SetStateAction<SocSnapshot>>,
  batch: StreamFrame[]
) {
  setSnapshot((current) => {
    let next = current;
    for (const frame of batch) {
      if (frame.type === "alert") {
        const alert = normalizeAlert(frame.payload);
        next = {
          ...next,
          alerts: [alert, ...next.alerts.filter((item) => item.id !== alert.id)].slice(0, 200)
        };
      } else if (frame.type === "event" || frame.type === "process_exit") {
        const socEvent = normalizeEvent(frame.payload);
        next = {
          ...next,
          events: [socEvent, ...next.events.filter((item) => item.id !== socEvent.id)].slice(0, 500)
        };
      } else if (frame.type === "decision") {
        next = {
          ...next,
          decisions: [normalizeDecisionFrame(frame.payload), ...next.decisions].slice(0, 20)
        };
      }
    }
    return next;
  });
}

function useNow(intervalMs: number) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(interval);
  }, [intervalMs]);
  return now;
}

function useLocalJsonState<T>(key: string, fallback: T): [T, React.Dispatch<React.SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => readLocalJson(key, fallback));
  useEffect(() => {
    writeLocalJson(key, value);
  }, [key, value]);
  return [value, setValue];
}

function SidebarSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="soc-sidebar-section">
      <div className="soc-sidebar-label">{title}</div>
      {children}
    </div>
  );
}

function SidebarButton({
  icon: Icon,
  label,
  onClick,
  badge
}: {
  icon: typeof Activity;
  label: string;
  onClick: () => void;
  badge?: number;
}) {
  return (
    <button type="button" className="soc-sidebar-item" onClick={onClick} title={label}>
      <Icon size={18} />
      <span>{label}</span>
      {badge ? <em>{badge}</em> : null}
    </button>
  );
}

function SidebarLink({ icon: Icon, label, href }: { icon: typeof Activity; label: string; href: string }) {
  return (
    <a className="soc-sidebar-item" href={href} title={label}>
      <Icon size={18} />
      <span>{label}</span>
    </a>
  );
}

// Stacked alert-volume-over-time chart. Each bar is a time bucket; segments are
// severity-coloured; red dots mark statistical spikes. Hover any bar for a full
// breakdown so an analyst can see exactly what happened in that window.
function TimelinePanel({ buckets, rangeMin }: { buckets: TimelineBucket[]; rangeMin: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...buckets.map((bucket) => bucket.total));
  const total = buckets.reduce((sum, bucket) => sum + bucket.total, 0);
  const avg = total / Math.max(1, buckets.length);
  const bucketMinutes = Math.max(1, Math.round(rangeMin / Math.max(1, buckets.length)));

  return (
    <div className="soc-timeline-wrap">
      <div
        className="soc-timeline"
        onMouseLeave={() => setHover(null)}
        role="img"
        aria-label={`Alert volume over the last ${rangeMin >= 1440 ? "24 hours" : `${rangeMin} minutes`}: ${total} alerts, peak ${max} per bar. Hover a bar for the severity breakdown.`}
      >
        {buckets.map((bucket, index) => (
          <div
            key={`${bucket.label}-${index}`}
            className={cx("soc-timeline-bucket", hover === index && "is-hover", bucket.anomaly && "is-anomaly")}
            onMouseEnter={() => setHover(index)}
          >
            {bucket.anomaly ? <span className="soc-anomaly" /> : null}
            <div className="soc-timeline-stack" style={{ height: `${Math.max(bucket.total ? 6 : 2, (bucket.total / max) * 100)}%` }}>
              {SEVERITIES.map((severity) => {
                const value = bucket.counts[severity];
                if (!value) return null;
                return <span key={severity} className={`severity-${severity}`} style={{ flex: value }} />;
              })}
            </div>
            <small>{index % 5 === 0 ? bucket.label : ""}</small>
          </div>
        ))}
        {hover != null && buckets[hover] ? (
          <TimelineTooltip
            bucket={buckets[hover]}
            leftPct={((hover + 0.5) / Math.max(1, buckets.length)) * 100}
            avg={avg}
            bucketMinutes={bucketMinutes}
          />
        ) : null}
      </div>
      <div className="soc-timeline-legend">
        <span>{buckets[0]?.label}</span>
        <span className="soc-timeline-legend-mid">
          each bar ≈ {bucketMinutes}m · avg {avg.toFixed(1)} · peak {max} alerts
        </span>
        <span>
          {buckets.at(-1)?.label} <em>· now</em>
        </span>
      </div>
    </div>
  );
}

function TimelineTooltip({
  bucket,
  leftPct,
  avg,
  bucketMinutes
}: {
  bucket: TimelineBucket;
  leftPct: number;
  avg: number;
  bucketMinutes: number;
}) {
  // Absolutely positioned inside the chart; the column index drives a pure-CSS
  // clamp so the card tracks the hovered bar yet never spills past either edge.
  return (
    <div className="soc-timeline-tip" style={{ left: `clamp(8px, ${leftPct.toFixed(2)}%, calc(100% - 218px))` }} role="tooltip">
      <div className="soc-timeline-tip-head">
        <strong>{bucket.label}</strong>
        <span>{bucketMinutes}m window</span>
      </div>
      {bucket.total === 0 ? (
        <p className="soc-timeline-tip-empty">No alerts in this window.</p>
      ) : (
        <>
          <div className="soc-timeline-tip-total">
            {bucket.total} alert{bucket.total === 1 ? "" : "s"}
          </div>
          <div className="soc-timeline-tip-rows">
            {SEVERITIES.map((severity) =>
              bucket.counts[severity] ? (
                <div key={severity} className="soc-timeline-tip-row">
                  <span className={cx("soc-timeline-tip-dot", `sev-${severity}`)} />
                  <span>{severity}</span>
                  <strong>{bucket.counts[severity]}</strong>
                </div>
              ) : null
            )}
          </div>
        </>
      )}
      {bucket.anomaly ? (
        <div className="soc-timeline-tip-anomaly">⚠ Anomalous spike — far above the {avg.toFixed(1)}/bar baseline</div>
      ) : null}
    </div>
  );
}

function ExecutiveMetricTile({
  label,
  value,
  sub,
  meta,
  delta,
  badge,
  tone,
  onClick,
  children
}: {
  label: string;
  value: string | number;
  sub: string;
  meta: string;
  delta?: number;
  badge: string;
  tone: Severity | "accent" | "good";
  onClick: () => void;
  children?: React.ReactNode;
}) {
  const trend = delta === undefined ? null : delta > 0 ? "up" : delta < 0 ? "down" : "flat";
  const deltaText = delta === undefined ? "" : delta === 0 ? "0" : `${delta > 0 ? "+" : ""}${delta}`;
  return (
    <button className={cx("soc-exec-metric", `tone-${tone}`)} type="button" onClick={onClick}>
      <span className="soc-exec-metric-glow" aria-hidden="true" />
      <div className="soc-exec-metric-head">
        <span>{label}</span>
        <em>{badge}</em>
      </div>
      <div className="soc-exec-metric-value">
        <strong>{value}</strong>
        {trend ? (
          <span className={cx("soc-exec-trend", `is-${trend}`)}>
            {deltaText} vs prior
          </span>
        ) : null}
      </div>
      <div className="soc-exec-metric-sub">{sub}</div>
      <div className="soc-exec-metric-foot">
        <span>{meta}</span>
        {children}
      </div>
    </button>
  );
}

function postureSeverityClass(label: string) {
  if (label === "critical") return "severity-critical";
  if (label === "high") return "severity-high";
  if (label === "elevated") return "severity-medium";
  return "severity-low";
}

function techniqueId(label: string) {
  return /T\d{4}(?:\.\d+)?/.exec(label)?.[0] || label.split(" ")[0] || "—";
}

function techniqueName(label: string) {
  return label.replace(/^T\d{4}(?:\.\d+)?\s*/, "").trim() || "technique";
}

function ExecPostureGauge({ score, label }: { score: number; label: string }) {
  const radius = 56;
  const centerX = 66;
  const centerY = 66;
  const circumference = Math.PI * radius;
  const filled = (score / 100) * circumference;
  const arc = `M ${centerX - radius} ${centerY} A ${radius} ${radius} 0 0 1 ${centerX + radius} ${centerY}`;
  return (
    <div className={cx("soc-exec-gauge", postureSeverityClass(label))}>
      <svg viewBox="0 0 132 76" role="img" aria-label={`Security posture ${label} score ${score} of 100`}>
        <path className="soc-exec-gauge-track" d={arc} strokeWidth={11} fill="none" strokeLinecap="round" />
        <path
          className="soc-exec-gauge-fill"
          d={arc}
          strokeWidth={11}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
        />
      </svg>
      <div className="soc-exec-gauge-readout">
        <strong>{score}</strong>
        <small>/100</small>
      </div>
    </div>
  );
}

// Executive summary band: a 5-second posture read for the Head of SOC / CTO / CEO,
// built entirely from signals already computed on the dashboard. Collapsible for
// analysts who live in the queue below.
function ExecutiveBand({
  open,
  onToggle,
  briefingOpen,
  onToggleBriefing,
  riskScore,
  riskLabel,
  riskDelta,
  windowLabel,
  totalAlerts,
  openCritical,
  openHigh,
  containmentActions,
  topTechnique,
  eps,
  activeProcesses,
  topProcess,
  hostName,
  hostOk,
  streamState,
  onReviewCriticals,
  onOpenRisk
}: {
  open: boolean;
  onToggle: () => void;
  briefingOpen: boolean;
  onToggleBriefing: () => void;
  riskScore: number;
  riskLabel: string;
  riskDelta: number;
  windowLabel: string;
  totalAlerts: number;
  openCritical: number;
  openHigh: number;
  containmentActions: number;
  topTechnique?: { label: string; value: number };
  eps: number;
  activeProcesses: number;
  topProcess?: string;
  hostName?: string;
  hostOk: boolean;
  streamState: string;
  onReviewCriticals: () => void;
  onOpenRisk: () => void;
}) {
  const trend = riskDelta > 0 ? "up" : riskDelta < 0 ? "down" : "flat";
  const trendText = riskDelta === 0 ? `no change vs prior ${windowLabel}` : `${riskDelta > 0 ? "+" : ""}${riskDelta} vs prior ${windowLabel}`;
  const postureClass = postureSeverityClass(riskLabel);
  const healthy = hostOk && streamState === "live";
  const priorityCount = openCritical + openHigh;
  const responseGap = Math.max(0, priorityCount - containmentActions);
  const topTechniqueName = topTechnique ? `${techniqueId(topTechnique.label)} ${techniqueName(topTechnique.label)}` : "";
  const readableTopProcess = topProcess ? shortGraphLabel(topProcess, 32) : undefined;
  const leadSignal = topTechniqueName || readableTopProcess || "No dominant technique or process yet";
  const incidentLabel = openCritical
    ? "Critical active incident queue"
    : riskScore >= 45
      ? "High-risk security posture"
      : riskScore >= 18
        ? "Elevated security posture"
        : "No priority incident in the current window";
  const briefingSummary = openCritical
    ? `${openCritical} critical alert${openCritical === 1 ? "" : "s"} need containment review. Telemetry is ${healthy ? "healthy" : "degraded"}, so the dashboard can still support triage.`
    : totalAlerts
      ? `${totalAlerts} alert${totalAlerts === 1 ? "" : "s"} are visible in this window. The next step is to confirm whether any create business or service impact.`
      : "No alerts are visible in this window. Keep monitoring stream health and host reachability.";
  const responseLine = priorityCount
    ? responseGap
      ? `${responseGap} priority item${responseGap === 1 ? "" : "s"} still need containment ownership.`
      : "Response decisions are logged; confirm they map to the open priority items."
    : "No critical or high containment queue is open.";
  const briefingItems = [
    {
      label: "What is happening",
      value: incidentLabel,
      detail: briefingSummary
    },
    {
      label: "Why it matters",
      value: leadSignal,
      detail: topTechnique
        ? `${topTechnique.value} technique hit${topTechnique.value === 1 ? "" : "s"} point to the current threat pattern.`
        : "Technique attribution is not available yet; use the alert queue and process view to confirm the pattern."
    },
    {
      label: "What is affected",
      value: hostName || "Current SOC host",
      detail: `${activeProcesses} active process${activeProcesses === 1 ? "" : "es"} observed${readableTopProcess ? `; top signal is ${readableTopProcess}.` : "."}`
    },
    {
      label: "What has been done",
      value: `${containmentActions} response action${containmentActions === 1 ? "" : "s"}`,
      detail: `${responseLine} Host is ${hostOk ? "reachable" : "showing errors"} and stream state is ${streamState}.`
    },
    {
      label: "Next action",
      value: openCritical ? "Contain criticals first" : priorityCount ? "Clear high-priority queue" : "Keep watch",
      detail: openCritical
        ? "Validate true positives, group duplicates, identify asset owner, and execute the safest containment path."
        : priorityCount
          ? "Review high-severity items, confirm scope, and decide whether containment needs approval."
          : "Maintain monitoring and investigate any new spike, asset owner change, or stream degradation."
    }
  ];

  if (!open) {
    return (
      <section className="soc-exec-band is-collapsed" data-panel="exec-summary" aria-label="Executive summary">
        <span className="soc-exec-eyebrow">Executive summary</span>
        <button type="button" className={cx("soc-exec-mini-score", postureClass)} onClick={onOpenRisk} title="View risk breakdown">
          {riskScore}
          <em>{riskLabel} · {trendText}</em>
        </button>
        <span className="soc-exec-mini-stat">
          <strong className={openCritical ? "severity-critical" : ""}>{openCritical}</strong> open critical · {openHigh} high
        </span>
        <span className={cx("soc-exec-mini-health", healthy ? "is-ok" : "is-warn")}>
          host {hostOk ? "ok" : "degraded"} · stream {streamState}
        </span>
        <button
          type="button"
          className={cx("soc-exec-toggle", "soc-exec-briefing-toggle", briefingOpen && "is-active")}
          onClick={() => {
            if (!briefingOpen) onToggleBriefing();
            onToggle();
          }}
          aria-pressed={briefingOpen}
        >
          <BookOpen size={13} aria-hidden="true" />
          Briefing
        </button>
        <button type="button" className="soc-exec-toggle" onClick={onToggle} aria-expanded={false}>
          Expand
        </button>
      </section>
    );
  }

  return (
    <section className="soc-exec-band" data-panel="exec-summary" aria-label="Executive summary">
      <div className="soc-exec-band-head">
        <span className="soc-exec-eyebrow">Executive summary · live security posture</span>
        <div className="soc-exec-head-actions">
          <button
            type="button"
            className={cx("soc-exec-toggle", "soc-exec-briefing-toggle", briefingOpen && "is-active")}
            onClick={onToggleBriefing}
            aria-pressed={briefingOpen}
          >
            <BookOpen size={13} aria-hidden="true" />
            Briefing
          </button>
          <button type="button" className="soc-exec-toggle" onClick={onToggle} aria-expanded>
            Collapse
          </button>
        </div>
      </div>
      <div className="soc-exec-band-body">
        <button type="button" className="soc-exec-posture" onClick={onOpenRisk} title="View risk breakdown">
          <ExecPostureGauge score={riskScore} label={riskLabel} />
          <div className="soc-exec-posture-meta">
            <span className="soc-exec-cell-label">Security posture</span>
            <strong className={cx("soc-exec-posture-label", postureClass)}>{riskLabel}</strong>
            <span className={cx("soc-exec-trend", `is-${trend}`)}>{trendText}</span>
          </div>
        </button>
        <div className="soc-exec-cells">
          <button type="button" className="soc-exec-cell is-action" onClick={onReviewCriticals}>
            <span className="soc-exec-cell-label">Needs containment</span>
            <strong className={openCritical ? "severity-critical" : ""}>{openCritical}</strong>
            <span className="soc-exec-cell-sub">{openHigh} high-sev also open · review →</span>
          </button>
          <div className="soc-exec-cell">
            <span className="soc-exec-cell-label">Response actions</span>
            <strong>{containmentActions}</strong>
            <span className="soc-exec-cell-sub">containment decisions logged</span>
          </div>
          <div className="soc-exec-cell">
            <span className="soc-exec-cell-label">Top technique</span>
            <strong className="soc-exec-cell-tech">{topTechnique ? techniqueId(topTechnique.label) : "—"}</strong>
            <span className="soc-exec-cell-sub">
              {topTechnique ? `${topTechnique.value} hit${topTechnique.value === 1 ? "" : "s"} · ${techniqueName(topTechnique.label)}` : "no techniques in window"}
            </span>
          </div>
          <div className="soc-exec-cell">
            <span className="soc-exec-cell-label">Throughput</span>
            <strong>
              {eps.toFixed(1)}
              <small>/s</small>
            </strong>
            <span className="soc-exec-cell-sub">{activeProcesses} active processes</span>
          </div>
          <div className="soc-exec-cell">
            <span className="soc-exec-cell-label">Operations</span>
            <strong className={cx("soc-exec-health", healthy ? "is-ok" : "is-warn")}>{healthy ? "Healthy" : hostOk ? "Degraded" : "Check"}</strong>
            <span className="soc-exec-cell-sub">host {hostOk ? "reachable" : "errors"} · stream {streamState}</span>
          </div>
        </div>
      </div>
      {briefingOpen ? (
        <div className="soc-briefing" aria-label="Briefing mode">
          <div className="soc-briefing-summary">
            <div>
              <span className="soc-exec-cell-label">Briefing mode</span>
              <strong>{incidentLabel}</strong>
            </div>
            <p>{briefingSummary}</p>
          </div>
          <div className="soc-briefing-grid">
            {briefingItems.map((item) => (
              <section key={item.label} className="soc-briefing-item">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
                <p>{item.detail}</p>
              </section>
            ))}
          </div>
          <div className="soc-briefing-lenses" aria-label="Briefing decision lenses">
            <div>
              <span>Business impact</span>
              <p>Confirm affected services, data exposure, customer impact, and whether executive escalation is required.</p>
            </div>
            <div>
              <span>Technical scope</span>
              <p>Map hosts, accounts, processes, and recent changes before isolation, credential rotation, or rollback.</p>
            </div>
            <div>
              <span>Response execution</span>
              <p>Validate true positives, group duplicate alerts, assign owners, and remove blockers from containment.</p>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function AlertRow({
  alert,
  ack,
  selected,
  pinned,
  onSelect,
  onOpen,
  onAck,
  onPin,
  onContext,
  onHover,
  onLeave
}: {
  alert: AlertGroup;
  ack: AckState;
  selected: boolean;
  pinned: boolean;
  onSelect: () => void;
  onOpen: () => void;
  onAck: (value: AckState) => void;
  onPin: () => void;
  onContext: (event: MouseEvent) => void;
  onHover: (event: MouseEvent) => void;
  onLeave: () => void;
}) {
  const classification = classifyAlert(alert);
  const classLabel = classificationLabel(classification);
  const chain = processChainFromAlert(alert);
  const processLabel = chain.at(-1) || alert.process || "unknown process";
  const technique = alert.mitreId ? /T\d{4}/.exec(alert.mitreId)?.[0] : undefined;
  return (
    <article
      className={cx(
        "soc-alert-row",
        selected && "is-selected",
        pinned && "is-pinned",
        ack !== "new" && "is-acked",
        `severity-rail-${alert.severity}`,
        `class-${classification}`
      )}
      onContextMenu={onContext}
      onMouseMove={onHover}
      onMouseLeave={onLeave}
    >
      <input
        className="soc-alert-check"
        type="checkbox"
        checked={selected}
        onChange={onSelect}
        aria-label={`Select ${alert.title}`}
      />
      <button type="button" className="soc-alert-main" onClick={onOpen}>
        <div className="soc-alert-head">
          <SeverityBadge severity={alert.severity} />
          <strong title={alert.title}>{alert.title}</strong>
          {alert.groupCount > 1 ? <span className="soc-group-count">×{alert.groupCount}</span> : null}
          <time className="soc-alert-time" title={new Date(alert.timestamp).toLocaleString()}>
            {relTime(alert.timestamp)}
          </time>
        </div>
        <p className="soc-alert-desc">{alert.description}</p>
        <div className="soc-alert-chips">
          <span className={cx("soc-entity-chip", `cls-${classification}`)}>{classLabel}</span>
          <span className="soc-entity-chip is-score">score {alert.score}</span>
          {technique ? <span className="soc-entity-chip is-mitre">{technique}</span> : null}
          <span className="soc-entity-chip is-proc" title={processLabel}>
            {processLabel}
          </span>
          {alert.pid ? <span className="soc-entity-chip">pid {alert.pid}</span> : null}
          {alert.policyName ? <span className="soc-entity-chip is-policy">{alert.policyName}</span> : null}
        </div>
      </button>
      <div className="soc-alert-actions">
        <button type="button" className={cx("soc-pin", pinned && "is-active")} onClick={onPin} title={pinned ? "Unpin" : "Pin to top"}>
          {pinned ? "Pinned" : "Pin"}
        </button>
        <span className={cx("soc-ack", `ack-${ack}`)}>{ack === "new" ? "New" : ack === "ack" ? "Ack'd" : "Resolved"}</span>
        {ack === "new" ? (
          <button type="button" onClick={() => onAck("ack")}>
            Ack
          </button>
        ) : null}
        {ack !== "resolved" ? (
          <button type="button" onClick={() => onAck("resolved")}>
            Resolve
          </button>
        ) : (
          <button type="button" onClick={() => onAck("new")}>
            Reopen
          </button>
        )}
      </div>
    </article>
  );
}

// Group raw event types into a few human-meaningful kinds so the stream reads
// at a glance (and colours consistently) instead of showing opaque API strings.
function eventKind(eventType: string): { key: string; label: string } {
  const t = eventType.toLowerCase();
  if (t.includes("exit")) return { key: "exit", label: "exit" };
  if (t.includes("kprobe")) return { key: "kprobe", label: "syscall" };
  if (t.includes("exec") || t.includes("bprm")) return { key: "exec", label: "exec" };
  if (t.includes("connect") || t.includes("tcp") || t.includes("net")) return { key: "net", label: "network" };
  return { key: "event", label: "event" };
}

function EventRow({ event, onOpen }: { event: SocEvent; onOpen: (event: SocEvent) => void }) {
  const kind = eventKind(event.eventType);
  const detail =
    event.args ||
    event.path ||
    (event.destIp ? `${event.destIp}${event.destPort ? `:${event.destPort}` : ""}` : "") ||
    event.policyName ||
    "—";
  return (
    <button
      type="button"
      className={cx("soc-event-row", `kind-${kind.key}`)}
      aria-label={`${event.eventType} ${event.process || "process"} ${detail}`}
      onClick={() => onOpen(event)}
    >
      <time title={new Date(event.timestamp).toLocaleString()}>{relTime(event.timestamp)}</time>
      <span className={cx("soc-event-kind", `kind-${kind.key}`)}>{kind.label}</span>
      <code className="soc-event-proc" title={event.process || ""}>
        {event.process || "process"}
      </code>
      <span className="soc-event-detail" title={detail}>
        {detail}
      </span>
    </button>
  );
}

function MiniBarList({
  rows,
  empty,
  onClick
}: {
  rows: Array<{ label: string; value: number; meta?: string; id?: string }>;
  empty: string;
  onClick?: (id: string) => void;
}) {
  const max = Math.max(1, ...rows.map((row) => row.value));
  if (!rows.length) return <EmptyState title={empty} />;
  return (
    <div className="soc-mini-bars">
      {rows.slice(0, 8).map((row) => {
        const body = (
          <>
            <span>{row.label}</span>
            <em>{row.meta || row.value}</em>
            <i style={{ width: `${Math.max(4, (row.value / max) * 100)}%` }} />
          </>
        );
        return onClick && row.id ? (
          <button key={row.label} type="button" onClick={() => onClick(row.id || "")}>
            {body}
          </button>
        ) : (
          <div key={row.label}>{body}</div>
        );
      })}
    </div>
  );
}

function IocList({ files, peers }: { files: Array<[string, number]>; peers: Array<[string, number]> }) {
  if (!files.length && !peers.length) {
    return <EmptyState title="No IOCs yet" detail="File and network indicators appear here after matching alerts or events." />;
  }
  return (
    <div className="soc-ioc-list">
      <strong>files</strong>
      {files.slice(0, 5).map(([file, count]) => (
        <span key={file}>
          <code>{file}</code>
          <em>x{count}</em>
        </span>
      ))}
      <strong>network</strong>
      {peers.slice(0, 5).map(([peer, count]) => (
        <span key={peer}>
          <code>{peer}</code>
          <em>x{count}</em>
        </span>
      ))}
    </div>
  );
}

function NetworkList({ rows }: { rows: Array<{ peer: string; count: number; procs: string[] }> }) {
  if (!rows.length) return <EmptyState title="No outbound peers" detail="Network activity from shell events and LOLBins will aggregate here." />;
  return (
    <div className="soc-network-list">
      {rows.slice(0, 8).map((row) => (
        <div key={row.peer}>
          <code>{row.peer}</code>
          <span>{row.procs.slice(0, 3).join(", ") || "unknown"} x{row.count}</span>
        </div>
      ))}
    </div>
  );
}

function DrillPanel({
  alert,
  ack,
  note,
  processDetail,
  processDetailError,
  onAck,
  onNote,
  onActionComplete
}: {
  alert: SocAlert;
  ack: AckState;
  note: string;
  processDetail: SocProcessDetail | null;
  processDetailError: string;
  onAck: (value: AckState) => void;
  onNote: (note: string) => void;
  onActionComplete: () => void;
}) {
  const [action, setAction] = useState<"throttle" | "tarpit" | "quarantine" | "sever">("quarantine");
  const [reason, setReason] = useState("");
  const [descendants, setDescendants] = useState(true);
  const [revertAfterSeconds, setRevertAfterSeconds] = useState(0);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ tone: "ok" | "warn"; message: string } | null>(null);
  const iocs = extractIocs([alert], processDetail?.events || []);
  const chain = processDetail?.chain || [];
  const events = processDetail?.events || [];
  const firstProcess = chain[0]?.binary || alert.process || "process";
  const lastProcess = chain[chain.length - 1]?.binary || alert.process || "process";
  const eventCount = events.length || "multiple";
  const narrative = `${chain.length || 1}-process chain starting from ${firstProcess} descended into ${lastProcess} and triggered ${eventCount} kernel event${events.length === 1 ? "" : "s"}. ${
    alert.mitreId ? `Mapped to MITRE ${alert.mitreId}${alert.tactic ? ` ${alert.tactic}` : ""}. ` : ""
  }Aggregate suspicion score: ${alert.score}.`;
  const canTarget = Boolean(alert.pid || alert.process);
  const canSubmit = canTarget && reason.trim().length > 2 && !busy;

  async function submitChokeAction() {
    if (!canSubmit) return;
    setBusy(true);
    setResult(null);
    try {
      await jailSocAlert({
        alert,
        action,
        reason: reason.trim(),
        descendants,
        revertAfterSeconds
      });
      setResult({ tone: "ok", message: `${action} requested for ${alert.process || alert.pid || alert.id}.` });
      onActionComplete();
    } catch (error) {
      setResult({
        tone: "warn",
        message: error instanceof Error ? error.message : String(error)
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="soc-drill">
      <header className="soc-drill-hero">
        <SeverityBadge severity={alert.severity} />
        <strong>{alert.title}</strong>
        <span>
          {formatTime(alert.timestamp)} · {alert.policyName || "policy"}{alert.mitreId ? ` · ${alert.mitreId}` : ""}
        </span>
      </header>
      <div className="soc-drill-grid">
        <MetricTile label="Score" value={alert.score} tone={alert.severity} />
        <MetricTile label="Events" value={events.length || "-"} />
        <MetricTile label="Chain depth" value={chain.length || "-"} />
      </div>
      <div className="soc-drill-actions">
        <button type="button" onClick={() => onAck("ack")}>Acknowledge</button>
        <button type="button" onClick={() => onAck("resolved")}>Resolve</button>
        <StatusPill label={ack} tone={ack === "resolved" ? "ok" : ack === "ack" ? "info" : "warn"} />
      </div>
      {!canTarget ? <InlineNotice tone="warn" title="No process target">This alert has no pid or process name for /api/choke/jail.</InlineNotice> : null}
      {result ? <InlineNotice tone={result.tone} title="Choke action result">{result.message}</InlineNotice> : null}
      {processDetailError ? <InlineNotice tone="warn" title="Process detail unavailable">{processDetailError}</InlineNotice> : null}
      <section className="soc-drill-section">
        <h3>Narrative</h3>
        <div className="soc-drill-narrative">{narrative}</div>
      </section>
      <section className="soc-drill-section">
        <h3>Choke response</h3>
        <div className="soc-choke-action-grid">
          <label>
            <span>Action</span>
            <select value={action} onChange={(event) => setAction(event.target.value as typeof action)}>
              <option value="throttle">throttle</option>
              <option value="tarpit">tarpit</option>
              <option value="quarantine">quarantine</option>
              <option value="sever">sever</option>
            </select>
          </label>
          <label>
            <span>Revert after</span>
            <select value={revertAfterSeconds} onChange={(event) => setRevertAfterSeconds(Number(event.target.value))}>
              <option value={0}>manual</option>
              <option value={300}>5 minutes</option>
              <option value={900}>15 minutes</option>
              <option value={3600}>1 hour</option>
            </select>
          </label>
          <label className="soc-checkbox-row">
            <input type="checkbox" checked={descendants} onChange={(event) => setDescendants(event.target.checked)} />
            <span>Include descendants</span>
          </label>
          <label className="soc-choke-reason">
            <span>Audit reason</span>
            <input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="required for /api/choke/jail" />
          </label>
          <button type="button" className="soc-danger-button" disabled={!canSubmit} onClick={() => void submitChokeAction()}>
            {busy ? "Sending" : `Send ${action}`}
          </button>
        </div>
      </section>
      <label className="soc-notes">
        <span>Investigator notes</span>
        <textarea value={note} onChange={(event) => onNote(event.target.value)} placeholder="Saved locally as soc.alertNotes" />
      </label>
      <div className="soc-drill-section">
        <h3>Process lineage</h3>
        {chain.length ? (
          chain.map((node, index) => (
            <div key={`${node.execId || node.pid || index}`} className="soc-lineage-row">
              <span>{index + 1}</span>
              <code>{node.binary || node.execId || "process"}</code>
              <em>{node.pid ? `pid ${node.pid}` : ""}</em>
            </div>
          ))
        ) : (
          <EmptyState title="No lineage loaded" detail={alert.execId ? "Waiting on /api/process/{exec_id}." : "This alert has no exec_id."} />
        )}
      </div>
      <div className="soc-drill-section">
        <h3>Indicators</h3>
        <IocList files={iocs.files} peers={iocs.peers} />
      </div>
      <div className="soc-drill-section">
        <h3>Event timeline</h3>
        <EventReplay
          events={events.map((event) => ({
            id: event.id,
            time: event.timestamp,
            kind: event.eventType,
            detail:
              event.path ||
              event.args ||
              (event.destIp ? `${event.destIp}${event.destPort ? `:${event.destPort}` : ""}` : "")
          }))}
        />
      </div>
    </div>
  );
}

function SocModals({
  openSurface,
  closeModal,
  openSurfaceByName,
  snapshot,
  filteredAlerts,
  rangeAlerts,
  rangeEvents,
  mitreRows,
  topProcesses,
  watchlist,
  setWatchlist,
  fleetHosts,
  setFleetHosts,
  trackedCount,
  now,
  notifyHistory,
  setNotifyHistory,
  notificationsActive,
  notifyChannels,
  setNotificationsActive,
  setNotifyChannels,
  kpiDrill,
  ackStates,
  commandQuery,
  setCommandQuery,
  theme,
  setTheme,
  stream,
  onActionComplete
}: {
  openSurface: OpenSurface | null;
  closeModal: () => void;
  openSurfaceByName: (surface: OpenSurface) => void;
  snapshot: SocSnapshot;
  filteredAlerts: AlertGroup[];
  rangeAlerts: SocAlert[];
  rangeEvents: SocEvent[];
  mitreRows: Array<{ label: string; value: number; meta?: string; id?: string }>;
  topProcesses: Array<{ process: string; score: number; count: number; execId?: string }>;
  watchlist: typeof DEFAULT_WATCHLIST;
  setWatchlist: React.Dispatch<React.SetStateAction<typeof DEFAULT_WATCHLIST>>;
  fleetHosts: Array<{ name: string; url: string }>;
  setFleetHosts: React.Dispatch<React.SetStateAction<Array<{ name: string; url: string }>>>;
  trackedCount: number;
  now: number;
  notifyHistory: Array<{ title?: string; body?: string; ts?: string; read?: boolean; severity?: Severity }>;
  setNotifyHistory: React.Dispatch<
    React.SetStateAction<Array<{ title?: string; body?: string; ts?: string; read?: boolean; severity?: Severity }>>
  >;
  notificationsActive: boolean;
  notifyChannels: { inApp: boolean; desktop: boolean; audio: boolean };
  setNotificationsActive: React.Dispatch<React.SetStateAction<boolean>>;
  setNotifyChannels: React.Dispatch<React.SetStateAction<{ inApp: boolean; desktop: boolean; audio: boolean }>>;
  kpiDrill: KpiDrill | null;
  ackStates: Record<string, AckState>;
  commandQuery: string;
  setCommandQuery: React.Dispatch<React.SetStateAction<string>>;
  theme: "dark" | "light";
  setTheme: React.Dispatch<React.SetStateAction<"dark" | "light">>;
  stream: StreamTelemetry;
  onActionComplete: () => void;
}) {
  return (
    <>
      <ModalShell panel={PANELS["policy-viewer-modal"]} open={openSurface === "policies"} onClose={closeModal} wide>
        <PoliciesBody
          policies={snapshot.policies}
          alerts={rangeAlerts}
          events={rangeEvents}
          policyStats={snapshot.policyStats}
          now={now}
        />
      </ModalShell>

      <ModalShell panel={PANELS["quick-fire-attacks-modal"]} open={openSurface === "attacks"} onClose={closeModal}>
        <AttackRunnerList attacks={snapshot.attacks} onActionComplete={onActionComplete} />
      </ModalShell>

      <ModalShell panel={PANELS["process-correlation-graph-modal"]} open={openSurface === "graph"} onClose={closeModal} fullScreen>
        <CorrelationGraph active={openSurface === "graph"} alerts={rangeAlerts} events={rangeEvents} topProcesses={topProcesses} />
      </ModalShell>

      <ModalShell panel={PANELS["rule-simulator-modal"]} open={openSurface === "simulator"} onClose={closeModal}>
        <SimulatorBody alerts={rangeAlerts} />
      </ModalShell>

      <ModalShell panel={PANELS["mitre-navigator-modal"]} open={openSurface === "mitre"} onClose={closeModal} wide>
        <MitreNavigatorBody mitreRows={mitreRows} alerts={rangeAlerts} onExport={() => void downloadMitrePdf(mitreRows)} />
      </ModalShell>

      <ModalShell panel={PANELS["fleet-modal"]} open={openSurface === "fleet"} onClose={closeModal} wide>
        <FleetBody hosts={fleetHosts} setHosts={setFleetHosts} whoami={snapshot.whoami} currentTracked={trackedCount} />
      </ModalShell>

      <ModalShell panel={PANELS["watchlist-modal"]} open={openSurface === "watchlist"} onClose={closeModal}>
        <WatchlistBody watchlist={watchlist} setWatchlist={setWatchlist} />
      </ModalShell>

      <ModalShell panel={PANELS["honeypots-modal"]} open={openSurface === "honeypots"} onClose={closeModal} wide>
        <HoneypotsBody honeypots={snapshot.honeypots} now={now} />
      </ModalShell>

      <ModalShell panel={PANELS["kprobe-performance-modal"]} open={openSurface === "kprobes"} onClose={closeModal} wide>
        <KprobeBody policyStats={snapshot.policyStats} />
      </ModalShell>

      <ModalShell panel={PANELS["time-machine-modal"]} open={openSurface === "time-machine"} onClose={closeModal}>
        <InlineNotice tone="info" title="Snapshot shell">
          The live buffer currently holds {rangeAlerts.length} alerts and {rangeEvents.length} events.
        </InlineNotice>
        <EmptyState title="No bookmarks loaded" detail="Expected localStorage key: soc.tmBookmarks." />
      </ModalShell>

      <ModalShell panel={PANELS["command-palette"]} open={openSurface === "command"} onClose={closeModal}>
        <CommandPrimitive label="SOC command palette" value={commandQuery} onValueChange={setCommandQuery}>
          <label className="soc-command-input">
            <Search size={16} />
            <CommandPrimitive.Input placeholder="Type a command" autoFocus />
          </label>
          <CommandPrimitive.List className="soc-command-list">
            <CommandPrimitive.Empty>No matching commands.</CommandPrimitive.Empty>
            {commandItems.map((item) => (
              <CommandPrimitive.Item
                key={item.label}
                value={`${item.kind} ${item.label}`}
                onSelect={() => openSurfaceByName(item.surface)}
              >
                <span>{item.kind}</span>
                <strong>{item.label}</strong>
              </CommandPrimitive.Item>
            ))}
          </CommandPrimitive.List>
        </CommandPrimitive>
      </ModalShell>

      <ModalShell panel={PANELS["notifications-center-modal"]} open={openSurface === "notifications"} onClose={closeModal} wide>
        <NotificationsBody
          history={notifyHistory}
          active={notificationsActive}
          channels={notifyChannels}
          onActiveChange={setNotificationsActive}
          onChannelsChange={setNotifyChannels}
          onMarkAllRead={() => setNotifyHistory((items) => items.map((item) => ({ ...item, read: true })))}
          onClearAll={() => setNotifyHistory([])}
        />
      </ModalShell>

      <ModalShell panel={PANELS["account-profile-modal"]} open={openSurface === "profile"} onClose={closeModal}>
        <AccountBody
          user={snapshot.whoami.user}
          host={snapshot.whoami.host}
          role={snapshot.whoami.role}
          theme={theme}
          onToggleTheme={() => setTheme(theme === "light" ? "dark" : "light")}
          streamState={stream.state}
          versionSha={snapshot.version.sha}
          storageKeyCount={SOC_STORAGE_KEYS.length}
        />
      </ModalShell>

      <ModalShell panel={PANELS["kpi-drill-modal"]} open={openSurface === "kpi"} title={kpiDrill?.title || "KPI drill"} onClose={closeModal}>
        <KpiDrillBody drill={kpiDrill} alerts={rangeAlerts} events={rangeEvents} ackStates={ackStates} now={now} />
      </ModalShell>

      <ModalShell panel={PANELS["help-modal"]} open={openSurface === "help"} onClose={closeModal}>
        <div className="soc-help-grid">
          <span>/</span>
          <strong>Focus search</strong>
          <span>Ctrl+K</span>
          <strong>Command palette</strong>
          <span>Esc</span>
          <strong>Close modal or drill panel</strong>
          <span>a/r</span>
          <strong>Ack or resolve selected drill alert</strong>
        </div>
      </ModalShell>

      <ModalShell panel={PANELS["export-confirm-modal"]} open={openSurface === "export"} onClose={closeModal}>
        <InlineNotice tone="info" title="Export confirmation">
          The current snapshot includes {filteredAlerts.length} visible alerts and {rangeEvents.length} events.
        </InlineNotice>
        <div className="soc-drill-actions">
          <button type="button" onClick={() => downloadCsv(filteredAlerts)}>
            Download alert CSV
          </button>
          <button type="button" onClick={() => void downloadAlertPdf(filteredAlerts, rangeEvents, snapshot)}>
            Download PDF
          </button>
        </div>
      </ModalShell>
    </>
  );
}

const commandItems: Array<{ label: string; kind: string; surface: OpenSurface }> = [
  { label: "Show policies", kind: "panel", surface: "policies" },
  { label: "Open attacks", kind: "panel", surface: "attacks" },
  { label: "Open correlation graph", kind: "panel", surface: "graph" },
  { label: "Open watchlist", kind: "panel", surface: "watchlist" },
  { label: "Show honeypots", kind: "panel", surface: "honeypots" },
  { label: "Show kprobe perf", kind: "panel", surface: "kprobes" },
  { label: "Open export", kind: "action", surface: "export" },
  { label: "Show help", kind: "panel", surface: "help" }
];

function AttackRunnerList({
  attacks,
  onActionComplete
}: {
  attacks: SocSnapshot["attacks"];
  onActionComplete: () => void;
}) {
  const [runningId, setRunningId] = useState("");
  const [result, setResult] = useState<{ tone: "ok" | "warn"; message: string } | null>(null);

  async function runAttack(id: string) {
    setRunningId(id);
    setResult(null);
    try {
      await runSocAttack(id);
      setResult({ tone: "ok", message: `${id} launched. The engine will stream resulting events when they arrive.` });
      onActionComplete();
    } catch (error) {
      setResult({ tone: "warn", message: error instanceof Error ? error.message : String(error) });
    } finally {
      setRunningId("");
    }
  }

  return (
    <>
      <InlineNotice tone="warn" title="Runs on the engine host">
        Attack scripts are allowlisted by the backend and require the same CSRF-protected POST path as the legacy UI.
      </InlineNotice>
      {result ? <InlineNotice tone={result.tone} title="Attack result">{result.message}</InlineNotice> : null}
      <div className="soc-modal-list">
        {attacks.length ? (
          attacks.map((attack) => (
            <article key={attack.id}>
              <strong>{attack.name}</strong>
              <span>{attack.description || attack.id}</span>
              <button type="button" disabled={Boolean(runningId)} onClick={() => void runAttack(attack.id)}>
                {runningId === attack.id ? "Launching" : "Run"}
              </button>
            </article>
          ))
        ) : (
          <EmptyState title="No attack catalog returned" />
        )}
      </div>
    </>
  );
}

type GraphClass = "attack" | "threat" | "baseline";

interface GraphNode extends SimulationNodeDatum {
  id: string;
  label: string;
  fullLabel?: string;
  group: "process" | "policy" | "peer" | "file";
  weight: number;
  // Max alert score touching this process — drives node colour (attack/threat/
  // baseline). Only meaningful for process nodes; context nodes inherit neutral.
  score?: number;
  cls?: GraphClass;
}

function classifyGraphScore(score: number): GraphClass {
  if (score >= 25) return "attack";
  if (score >= 10) return "threat";
  return "baseline";
}

interface GraphLink extends SimulationLinkDatum<GraphNode> {
  source: string | GraphNode;
  target: string | GraphNode;
  weight: number;
}

interface CorrelationGraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

interface GraphControls {
  zoomIn: () => void;
  zoomOut: () => void;
  reset: () => void;
  fit: () => void;
}

type GraphLayout = "force" | "radial" | "decay";

interface GraphHandle {
  destroy: () => void;
  controls: GraphControls;
  resize: () => void;
  // Incrementally fold the latest correlation data into the running graph,
  // preserving existing node positions and animating in newly-seen processes.
  // Returns the number of brand-new process nodes folded in (drives "LIVE +N").
  update: (data: CorrelationGraphData) => number;
  setLayout: (layout: GraphLayout) => void;
  setSearch: (query: string) => void;
  setSelected: (id: string | null) => void;
}

type GraphLinkSel = D3Selection<SVGLineElement, GraphLink, SVGGElement, unknown>;
type GraphNodeSel = D3Selection<SVGGElement, GraphNode, SVGGElement, unknown>;

function graphLinkKey(link: GraphLink): string {
  const source = typeof link.source === "object" ? link.source.id : link.source;
  const target = typeof link.target === "object" ? link.target.id : link.target;
  return `${source}->${target}`;
}

// Imperatively render a live D3 force graph into the svg shell: a running
// simulation (so nodes can be dragged), wheel zoom + canvas pan, and a
// fit-to-view so the whole graph is legible at once. React owns the svg element
// but D3 owns its contents, which keeps the simulation off the React render path:
// live data arrives through update(), which diffs by id so existing nodes keep
// their positions (no re-mount/blink) while new processes animate in.
function renderForceGraph(
  svgEl: SVGSVGElement,
  d3: typeof import("d3"),
  data: CorrelationGraphData,
  onSelect: (node: GraphNode | null) => void
): GraphHandle {
  const rect = svgEl.getBoundingClientRect();
  let width = Math.max(320, Math.round(rect.width) || 920);
  let height = Math.max(280, Math.round(rect.height) || 460);

  const svg = d3.select(svgEl);
  svg.selectAll("*").remove();
  svg.attr("viewBox", `0 0 ${width} ${height}`);

  const root = svg.append("g").attr("class", "soc-graph-zoomable");
  const linkLayer = root.append("g").attr("class", "soc-graph-link-layer");
  const nodeLayer = root.append("g").attr("class", "soc-graph-node-layer");

  // Smaller discs + more spacing keep dense graphs (40+ nodes) legible — the
  // old r≤14 made big nodes collide and labels overlap.
  const nodeRadius = (node: GraphNode) => Math.max(4, Math.min(9, 3.5 + node.weight * 0.45));

  let nodes = data.nodes;
  let links = data.links;
  let layout: GraphLayout = "force";
  let selectedId: string | null = null;
  let searchQuery = "";

  const searchableNodeText = (node: GraphNode) => `${node.label} ${node.fullLabel || ""}`.toLowerCase();

  // Adjacency, rebuilt on each structural change, powers neighbourhood highlight
  // when a node is selected and the radial grouping order.
  let adjacency = new Map<string, Set<string>>();
  const rebuildAdjacency = () => {
    adjacency = new Map();
    for (const lnk of links) {
      const s = typeof lnk.source === "object" ? lnk.source.id : String(lnk.source);
      const t = typeof lnk.target === "object" ? lnk.target.id : String(lnk.target);
      if (!adjacency.has(s)) adjacency.set(s, new Set());
      if (!adjacency.has(t)) adjacency.set(t, new Set());
      adjacency.get(s)!.add(t);
      adjacency.get(t)!.add(s);
    }
  };

  const linkForce = d3
    .forceLink<GraphNode, GraphLink>(links)
    .id((node) => node.id)
    .distance(92)
    .strength(0.32);
  const simulation = d3
    .forceSimulation<GraphNode>(nodes)
    .force("link", linkForce)
    .force("charge", d3.forceManyBody<GraphNode>().strength(-340))
    // A generous collision pad (≈ a label's width) keeps node labels from
    // stacking on top of each other.
    .force("collide", d3.forceCollide<GraphNode>().radius((node) => nodeRadius(node) + 26))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("x", d3.forceX<GraphNode>(width / 2).strength(0.045))
    .force("y", d3.forceY<GraphNode>(height / 2).strength(0.045))
    .stop();

  // Switch the active force configuration. Force = organic spread; Radial =
  // concentric rings keyed by node group; Decay = tight, fast-settling cluster
  // (high velocity decay) that reads as a "cooling" snapshot.
  const GROUP_RING: Record<GraphNode["group"], number> = { process: 0.34, policy: 0.6, file: 0.82, peer: 0.95 };
  const applyLayout = (next: GraphLayout) => {
    layout = next;
    const minDim = Math.min(width, height);
    if (next === "radial") {
      simulation
        .force("charge", d3.forceManyBody<GraphNode>().strength(-120))
        .force("x", null)
        .force("y", null)
        .force(
          "radial",
          d3
            .forceRadial<GraphNode>((node) => GROUP_RING[node.group] * (minDim / 2 - 24), width / 2, height / 2)
            .strength(0.85)
        );
      linkForce.distance(48).strength(0.25);
      simulation.velocityDecay(0.4);
    } else if (next === "decay") {
      simulation
        .force("charge", d3.forceManyBody<GraphNode>().strength(-160))
        .force("radial", null)
        .force("x", d3.forceX<GraphNode>(width / 2).strength(0.11))
        .force("y", d3.forceY<GraphNode>(height / 2).strength(0.11));
      linkForce.distance(58).strength(0.6);
      simulation.velocityDecay(0.75);
    } else {
      simulation
        .force("charge", d3.forceManyBody<GraphNode>().strength(-340))
        .force("radial", null)
        .force("x", d3.forceX<GraphNode>(width / 2).strength(0.045))
        .force("y", d3.forceY<GraphNode>(height / 2).strength(0.045));
      linkForce.distance(92).strength(0.32);
      simulation.velocityDecay(0.4);
    }
    simulation.alpha(0.6).restart();
  };

  const drag = d3
    .drag<SVGGElement, GraphNode>()
    // Use the (zoom-transformed) node layer as the pointer reference so drag
    // coordinates stay aligned with node positions at any zoom level.
    .container(function () {
      return this.parentNode as SVGGElement;
    })
    .on("start", (event, d) => {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    })
    .on("drag", (event, d) => {
      d.fx = event.x;
      d.fy = event.y;
    })
    .on("end", (event, d) => {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    });

  let link: GraphLinkSel = linkLayer.selectAll<SVGLineElement, GraphLink>("line");
  let node: GraphNodeSel = nodeLayer.selectAll<SVGGElement, GraphNode>("g.soc-graph-node");
  let firstRender = true;
  let pulseIds = new Set<string>();

  // A ring that expands and fades behind a node — flags a process that just
  // joined or just produced fresh events, so the live graph reads as alive.
  const pulse = (selection: GraphNodeSel) => {
    selection
      .insert("circle", ":first-child")
      .attr("class", "soc-graph-pulse")
      .attr("r", (d) => nodeRadius(d))
      .style("opacity", 0.5)
      .call((sel) => sel.transition().duration(900).attr("r", (d) => nodeRadius(d) + 16).style("opacity", 0).remove());
  };

  const baseNodeClass = (d: GraphNode) =>
    `soc-graph-node node-${d.group}${d.group === "process" && d.cls ? ` score-${d.cls}` : ""}`;

  const applyJoin = () => {
    link = link
      .data(links, graphLinkKey)
      .join((enter) => enter.append("line"))
      .attr("stroke-width", (d) => Math.max(0.75, Math.min(3, d.weight)));

    node = node.data(nodes, (d) => d.id).join(
      (enter) => {
        const group = enter
          .append("g")
          .attr("class", baseNodeClass)
          .attr("aria-label", (d) => d.fullLabel || d.label)
          .style("cursor", "pointer")
          .on("click", (event: PointerEvent, d) => {
            event.stopPropagation();
            select(selectedId === d.id ? null : d.id);
          });
        const disc = group.append("circle").attr("class", "soc-graph-disc");
        if (firstRender) disc.attr("r", nodeRadius);
        else disc.attr("r", 0).transition().duration(450).attr("r", nodeRadius);
        group
          .append("text")
          .attr("x", (d) => nodeRadius(d) + 4)
          .attr("y", 3)
          .text((d) => d.label);
        // A process appearing after the first paint visibly "joins" the graph.
        if (!firstRender) pulse(group);
        return group;
      },
      (existing) => {
        existing.attr("class", baseNodeClass).attr("aria-label", (d) => d.fullLabel || d.label);
        existing.select<SVGCircleElement>("circle.soc-graph-disc").attr("r", nodeRadius);
        existing
          .select<SVGTextElement>("text")
          .attr("x", (d) => nodeRadius(d) + 4)
          .text((d) => d.label);
        // Already-present processes with fresh activity pulse in place.
        existing.filter((d) => pulseIds.has(d.id)).call(pulse);
        return existing;
      },
      (exit) => exit.call((sel) => sel.transition().duration(300).style("opacity", 0).remove())
    );
    node.call(drag);
    firstRender = false;
    restyle();
  };

  // Apply selection-highlight and search-dim classes without touching the
  // simulation. A selected node lights its neighbourhood; everything else dims.
  const restyle = () => {
    const neighbours = selectedId ? new Set<string>([selectedId, ...(adjacency.get(selectedId) ?? [])]) : null;
    const q = searchQuery.trim().toLowerCase();
    node
      .classed("is-selected", (d) => d.id === selectedId)
      .classed("is-neighbour", (d) => Boolean(neighbours && neighbours.has(d.id) && d.id !== selectedId))
      .classed("is-match", (d) => Boolean(q) && searchableNodeText(d).includes(q))
      .classed("is-dim", (d) => {
        if (neighbours && !neighbours.has(d.id)) return true;
        if (q && !searchableNodeText(d).includes(q)) return true;
        return false;
      });
    link.classed("is-active", (d) => {
      if (!neighbours) return false;
      const s = (d.source as GraphNode).id ?? String(d.source);
      const t = (d.target as GraphNode).id ?? String(d.target);
      return neighbours.has(s) && neighbours.has(t);
    });
  };

  const select = (id: string | null) => {
    selectedId = id;
    restyle();
    onSelect(id ? nodes.find((entry) => entry.id === id) ?? null : null);
  };

  // Clicking empty canvas clears the current selection.
  svg.on("click", () => select(null));

  const ticked = () => {
    link
      .attr("x1", (d) => (d.source as GraphNode).x ?? 0)
      .attr("y1", (d) => (d.source as GraphNode).y ?? 0)
      .attr("x2", (d) => (d.target as GraphNode).x ?? 0)
      .attr("y2", (d) => (d.target as GraphNode).y ?? 0);
    node.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
  };

  applyJoin();
  rebuildAdjacency();
  simulation.on("tick", ticked);
  simulation.tick(260); // settle once for a stable, non-jumpy initial layout
  ticked();

  const zoom = d3
    .zoom<SVGSVGElement, unknown>()
    .scaleExtent([0.25, 4])
    .on("zoom", (event) => {
      root.attr("transform", event.transform.toString());
    });
  svg.call(zoom).style("cursor", "grab");

  const fit = () => {
    if (!nodes.length) return;
    const xs = nodes.map((entry) => entry.x ?? width / 2);
    const ys = nodes.map((entry) => entry.y ?? height / 2);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const minY = Math.min(...ys);
    const maxY = Math.max(...ys);
    const graphWidth = Math.max(1, maxX - minX);
    const graphHeight = Math.max(1, maxY - minY);
    const padding = 70;
    const scale = Math.max(0.25, Math.min(2, Math.min((width - padding) / graphWidth, (height - padding) / graphHeight)));
    const tx = width / 2 - scale * (minX + maxX) / 2;
    const ty = height / 2 - scale * (minY + maxY) / 2;
    svg.transition().duration(350).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  };
  fit();

  const resize = () => {
    const nextRect = svgEl.getBoundingClientRect();
    const nextWidth = Math.max(320, Math.round(nextRect.width) || width);
    const nextHeight = Math.max(280, Math.round(nextRect.height) || height);
    if (nextWidth === width && nextHeight === height) {
      fit();
      return;
    }
    width = nextWidth;
    height = nextHeight;
    svg.attr("viewBox", `0 0 ${width} ${height}`);
    simulation.force("center", d3.forceCenter(width / 2, height / 2));
    applyLayout(layout);
    fit();
  };

  const update = (next: CorrelationGraphData): number => {
    const byId = new Map(nodes.map((entry) => [entry.id, entry] as const));
    const prevNodeIds = new Set(byId.keys());
    const prevLinkKeys = new Set(links.map(graphLinkKey));
    pulseIds = new Set();
    let added = 0;

    // Reuse existing node objects so positions/velocities (and any active drag
    // pins) survive; seed brand-new processes near the centre so they fly in.
    nodes = next.nodes.map((entry) => {
      const existing = byId.get(entry.id);
      if (existing) {
        // A heavier weight means new alerts/events landed on this process.
        if (entry.weight > existing.weight + 0.05) pulseIds.add(entry.id);
        existing.weight = entry.weight;
        existing.label = entry.label;
        existing.fullLabel = entry.fullLabel;
        existing.group = entry.group;
        existing.score = entry.score;
        existing.cls = entry.cls;
        return existing;
      }
      if (entry.group === "process") added += 1;
      entry.x = width / 2 + (Math.random() - 0.5) * 60;
      entry.y = height / 2 + (Math.random() - 0.5) * 60;
      return entry;
    });
    links = next.links.map((entry) => ({
      source: typeof entry.source === "object" ? entry.source.id : entry.source,
      target: typeof entry.target === "object" ? entry.target.id : entry.target,
      weight: entry.weight
    }));

    const nodesChanged = nodes.length !== prevNodeIds.size || nodes.some((entry) => !prevNodeIds.has(entry.id));
    const linksChanged = links.length !== prevLinkKeys.size || links.some((entry) => !prevLinkKeys.has(graphLinkKey(entry)));

    // A selected process that aged out of the graph clears the selection panel.
    if (selectedId && !nodes.some((entry) => entry.id === selectedId)) select(null);

    applyJoin();
    rebuildAdjacency();
    simulation.nodes(nodes);
    linkForce.links(links);
    // Re-heat only on structural change, and gently — keep the operator's
    // current pan/zoom and avoid a full re-layout jitter on every tick.
    if (nodesChanged || linksChanged) simulation.alpha(0.3).restart();
    return added;
  };

  return {
    destroy: () => {
      simulation.on("tick", null);
      simulation.stop();
      svg.on(".zoom", null);
      svg.on("click", null);
      svg.selectAll("*").remove();
    },
    resize,
    update,
    setLayout: (next: GraphLayout) => {
      if (next !== layout) applyLayout(next);
    },
    setSearch: (query: string) => {
      searchQuery = query;
      restyle();
    },
    setSelected: (id: string | null) => select(id),
    controls: {
      zoomIn: () => void svg.transition().duration(200).call(zoom.scaleBy, 1.3),
      zoomOut: () => void svg.transition().duration(200).call(zoom.scaleBy, 1 / 1.3),
      reset: () => void svg.transition().duration(250).call(zoom.transform, d3.zoomIdentity),
      fit
    }
  };
}

// Drop process nodes whose classification is hidden, plus any context node
// (policy/file/peer) that no longer attaches to a visible process.
function filterGraph(data: CorrelationGraphData, show: Set<GraphClass>): CorrelationGraphData {
  if (show.size >= 3) return data;
  const linkEnds = (link: GraphLink) => {
    const s = typeof link.source === "object" ? link.source.id : String(link.source);
    const t = typeof link.target === "object" ? link.target.id : String(link.target);
    return [s, t] as const;
  };
  const keep = new Set<string>();
  for (const node of data.nodes) {
    if (node.group === "process" && node.cls && show.has(node.cls)) keep.add(node.id);
  }
  for (const link of data.links) {
    const [s, t] = linkEnds(link);
    if (keep.has(s)) keep.add(t);
    if (keep.has(t)) keep.add(s);
  }
  return {
    nodes: data.nodes.filter((node) => keep.has(node.id)),
    links: data.links.filter((link) => {
      const [s, t] = linkEnds(link);
      return keep.has(s) && keep.has(t);
    })
  };
}

function graphMeta(data: CorrelationGraphData) {
  return { processes: data.nodes.filter((node) => node.group === "process").length, edges: data.links.length };
}

const GRAPH_CLASSES: Array<{ key: GraphClass; label: string }> = [
  { key: "attack", label: "ATTACK" },
  { key: "threat", label: "THREAT" },
  { key: "baseline", label: "BASELINE" }
];

function CorrelationGraph({
  active,
  alerts,
  events,
  topProcesses
}: {
  active: boolean;
  alerts: SocAlert[];
  events: SocEvent[];
  topProcesses: Array<{ process: string; score: number; count: number; execId?: string }>;
}) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dataRef = useRef<{ alerts: SocAlert[]; events: SocEvent[] }>({ alerts, events });
  dataRef.current = { alerts, events };
  const lastDataRef = useRef<CorrelationGraphData>({ nodes: [], links: [] });
  const controlsRef = useRef<GraphControls | null>(null);
  const handleRef = useRef<GraphHandle | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "empty" | "error">("loading");
  const [errorMsg, setErrorMsg] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [live, setLive] = useState(true);
  const [layout, setLayout] = useState<GraphLayout>("force");
  const [show, setShow] = useState<Set<GraphClass>>(() => new Set<GraphClass>(["attack", "threat", "baseline"]));
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [liveAdded, setLiveAdded] = useState(0);
  const [meta, setMeta] = useState({ processes: 0, edges: 0 });
  const [maximized, setMaximized] = useState(false);

  // Refs so the build closure always reads the latest filter without forcing a
  // teardown/rebuild (which blinks) whenever a chip toggles.
  const showRef = useRef(show);
  showRef.current = show;
  const queryRef = useRef(query);
  queryRef.current = query;
  const layoutRef = useRef(layout);
  layoutRef.current = layout;

  const buildFiltered = useCallback(() => {
    const data = filterGraph(
      buildCorrelationGraph(dataRef.current.alerts, dataRef.current.events),
      showRef.current
    );
    lastDataRef.current = data;
    return data;
  }, []);

  // Build the simulation once when the surface opens or the user forces a
  // rebuild — never on every live buffer tick, which is what used to blink.
  useEffect(() => {
    if (!active) return undefined;
    let cancelled = false;
    let raf = 0;
    setPhase("loading");
    setErrorMsg("");
    setSelected(null);
    setLiveAdded(0);
    controlsRef.current = null;
    handleRef.current = null;
    void import("d3")
      .then((d3) => {
        if (cancelled) return;
        const data = buildFiltered();
        if (!data.nodes.length) {
          setPhase("empty");
          return;
        }
        raf = requestAnimationFrame(() => {
          if (cancelled || !svgRef.current) return;
          const handle = renderForceGraph(svgRef.current, d3, data, (node) => setSelected(node));
          handleRef.current = handle;
          controlsRef.current = handle.controls;
          if (layoutRef.current !== "force") handle.setLayout(layoutRef.current);
          if (queryRef.current) handle.setSearch(queryRef.current);
          setMeta(graphMeta(data));
          setPhase("ready");
        });
      })
      .catch((error) => {
        if (!cancelled) {
          setErrorMsg(error instanceof Error ? error.message : String(error));
          setPhase("error");
        }
      });

    return () => {
      cancelled = true;
      if (raf) cancelAnimationFrame(raf);
      handleRef.current?.destroy();
      handleRef.current = null;
    };
  }, [active, refreshKey, buildFiltered]);

  // Live updates: fold the latest data into the running graph (debounced) so new
  // processes animate in. Pausing freezes the current view.
  const liveSignature = `${alerts.length}:${events.length}:${alerts[0]?.id ?? ""}:${events[0]?.id ?? ""}`;
  useEffect(() => {
    if (!active || !live || phase !== "ready") return undefined;
    const timer = window.setTimeout(() => {
      const data = buildFiltered();
      const added = handleRef.current?.update(data) ?? 0;
      if (added > 0) setLiveAdded((value) => value + added);
      setMeta(graphMeta(data));
    }, 700);
    return () => window.clearTimeout(timer);
  }, [active, live, phase, liveSignature, buildFiltered]);

  // Filter / layout / search push to the running handle without a rebuild.
  useEffect(() => {
    if (phase !== "ready") return;
    const data = buildFiltered();
    handleRef.current?.update(data);
    setMeta(graphMeta(data));
  }, [show, phase, buildFiltered]);
  useEffect(() => {
    if (phase === "ready") handleRef.current?.setLayout(layout);
  }, [layout, phase]);
  useEffect(() => {
    if (phase === "ready") handleRef.current?.setSearch(query);
  }, [query, phase]);
  useEffect(() => {
    if (phase !== "ready") return undefined;
    let secondFrame = 0;
    const firstFrame = requestAnimationFrame(() => {
      secondFrame = requestAnimationFrame(() => handleRef.current?.resize());
    });
    return () => {
      cancelAnimationFrame(firstFrame);
      if (secondFrame) cancelAnimationFrame(secondFrame);
    };
  }, [maximized, phase]);

  const toggleClass = (key: GraphClass) =>
    setShow((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      // Never let every class be hidden — keep at least one visible.
      return next.size ? next : prev;
    });

  const neighbours = useMemo(() => {
    if (!selected) return [];
    const ids = new Set<string>();
    for (const link of lastDataRef.current.links) {
      const s = typeof link.source === "object" ? link.source.id : String(link.source);
      const t = typeof link.target === "object" ? link.target.id : String(link.target);
      if (s === selected.id) ids.add(t);
      if (t === selected.id) ids.add(s);
    }
    return lastDataRef.current.nodes.filter((node) => ids.has(node.id));
  }, [selected]);
  const graphCounts = useMemo(() => countSeverities(alerts), [alerts]);
  const policyCount = useMemo(() => new Set(events.map((event) => event.policyName).filter(Boolean)).size, [events]);
  const policyEventCount = useMemo(() => events.filter((event) => event.policyName).length, [events]);
  const indicatorCount = useMemo(
    () => new Set(events.map((event) => event.path || event.destIp || event.remoteIp).filter(Boolean)).size,
    [events]
  );
  const criticalPathCount = graphCounts.critical + graphCounts.high;
  const criticalShare = alerts.length ? Math.round((criticalPathCount / alerts.length) * 100) : 0;
  const fabricDensity = meta.processes ? Math.min(100, Math.round((meta.edges / Math.max(1, meta.processes * 1.6)) * 100)) : 0;
  const policyCoverage = events.length ? Math.round((policyEventCount / events.length) * 100) : 0;
  const dominant = topProcesses[0];
  const dominantProcess = dominant?.process || "No dominant process";
  const dominantDisplay = dominant ? shortGraphLabel(dominant.process, 18) : "No source";
  const graphBriefCards = [
    {
      key: "critical",
      tone: "tone-critical",
      icon: ShieldAlert,
      label: "Critical paths",
      badge: criticalPathCount ? "Escalated" : "Clear",
      value: String(criticalPathCount),
      title: String(criticalPathCount),
      meta: "high-confidence chains",
      detail: `${graphCounts.critical} critical · ${graphCounts.high} high`,
      fill: criticalShare
    },
    {
      key: "fabric",
      tone: "tone-accent",
      icon: GitBranch,
      label: "Signal fabric",
      badge: live ? "Live" : "Paused",
      value: `${meta.processes}/${meta.edges}`,
      title: `${meta.processes} processes / ${meta.edges} edges`,
      meta: "processes / edges",
      detail: `${indicatorCount} indicators observed`,
      fill: fabricDensity
    },
    {
      key: "policies",
      tone: "tone-medium",
      icon: FileText,
      label: "Policies",
      badge: policyCount ? "Mapped" : "Idle",
      value: String(policyCount),
      title: String(policyCount),
      meta: "mapped controls",
      detail: `${policyEventCount} policy events`,
      fill: policyCoverage
    },
    {
      key: "origin",
      tone: "tone-good",
      icon: Server,
      label: "Primary origin",
      badge: dominant ? "Top source" : "Waiting",
      value: dominantDisplay,
      title: dominantProcess,
      meta: dominant ? `${dominant.count} alert${dominant.count === 1 ? "" : "s"} · score ${Math.round(dominant.score)}` : "no source process yet",
      detail: `${indicatorCount} observed indicators`,
      fill: dominant ? Math.max(8, Math.min(100, Math.round(dominant.score))) : 0
    }
  ];

  if (!active) {
    return <EmptyState title="Graph paused" detail="Open the correlation graph to load the D3 graph engine." />;
  }

  return (
    <div className={cx("soc-graph-shell", maximized && "is-maximized")}>
      <div className="soc-graph-main">
        <div className="soc-graph-brief">
          {graphBriefCards.map((card) => {
            const Icon = card.icon;
            return (
              <div key={card.key} className={cx("soc-graph-brief-card", card.tone)}>
                <div className="soc-graph-card-head">
                  <span className="soc-graph-card-icon"><Icon size={14} aria-hidden="true" /></span>
                  <span>{card.label}</span>
                  <em className="soc-graph-card-badge">{card.badge}</em>
                </div>
                <strong title={card.title}>{card.value}</strong>
                <div className="soc-graph-card-meter" aria-hidden="true">
                  <span style={{ width: `${card.fill}%` }} />
                </div>
                <div className="soc-graph-card-detail">
                  <span>{card.meta}</span>
                  <em>{card.detail}</em>
                </div>
              </div>
            );
          })}
        </div>
        <div className="soc-graph-controlbar">
          <div className="soc-graph-counts">
            <strong>{meta.processes}</strong> processes · <strong>{meta.edges}</strong> edges
          </div>
          <SearchField value={query} onChange={setQuery} placeholder="Search binary or exec_id…" />
          <div className="soc-graph-segment" role="group" aria-label="show">
            <span>show</span>
            {GRAPH_CLASSES.map((entry) => (
              <button
                key={entry.key}
                type="button"
                className={cx("soc-graph-show", `cls-${entry.key}`, show.has(entry.key) && "is-active")}
                onClick={() => toggleClass(entry.key)}
              >
                {entry.label}
              </button>
            ))}
          </div>
          <div className="soc-graph-segment" role="group" aria-label="layout">
            <span>layout</span>
            {(["force", "radial", "decay"] as GraphLayout[]).map((entry) => (
              <button
                key={entry}
                type="button"
                className={cx("soc-graph-layout", layout === entry && "is-active")}
                onClick={() => setLayout(entry)}
              >
                {entry}
              </button>
            ))}
          </div>
          <button
            type="button"
            className={cx("soc-graph-live", live && "is-live")}
            onClick={() => {
              setLive((value) => !value);
              setLiveAdded(0);
            }}
            title={live ? "Live — new processes stream in. Click to pause." : "Paused. Click to resume."}
          >
            <span className="soc-graph-live-dot" />
            {live ? "LIVE" : "PAUSED"}
            {live && liveAdded > 0 ? <em>+{liveAdded}</em> : null}
          </button>
          <button
            type="button"
            className="soc-graph-icon"
            onClick={() => setMaximized((value) => !value)}
            title={maximized ? "Minimize graph" : "Maximize graph"}
            aria-label={maximized ? "Minimize graph" : "Maximize graph"}
          >
            {maximized ? <Minimize2 size={14} aria-hidden="true" /> : <Maximize2 size={14} aria-hidden="true" />}
          </button>
          <button type="button" className="soc-graph-icon" onClick={() => setRefreshKey((key) => key + 1)} title="Rebuild" aria-label="Rebuild">
            <RefreshCw size={14} aria-hidden="true" />
          </button>
        </div>

        <div className="soc-graph-canvas">
          <svg ref={svgRef} className="soc-correlation-graph" role="img" aria-label="Process correlation graph" />
          <div className="soc-graph-zoomdock">
            <button type="button" onClick={() => controlsRef.current?.zoomOut()} aria-label="Zoom out">−</button>
            <button type="button" onClick={() => controlsRef.current?.zoomIn()} aria-label="Zoom in">+</button>
            <button type="button" onClick={() => controlsRef.current?.fit()} title="Fit to view">Fit</button>
            <button type="button" onClick={() => controlsRef.current?.reset()} title="Reset zoom">Reset</button>
          </div>
          {phase === "loading" ? <div className="soc-graph-overlay">Loading graph engine…</div> : null}
          {phase === "empty" ? (
            <div className="soc-graph-overlay">
              <MiniBarList
                rows={topProcesses.map((row) => ({ label: row.process, value: row.score, meta: `${row.count} alerts`, id: row.execId }))}
                empty="No correlated processes in the selected range."
              />
            </div>
          ) : null}
          {phase === "error" ? (
            <div className="soc-graph-overlay">
              <InlineNotice tone="warn" title="Graph engine unavailable">
                {errorMsg}
              </InlineNotice>
            </div>
          ) : null}
        </div>

        <div className="soc-graph-legend">
          <span className="cls-attack"><i />attack</span>
          <span className="cls-threat"><i />threat</span>
          <span className="cls-baseline"><i />baseline</span>
          <span className="node-policy"><i />policy</span>
          <span className="node-file"><i />file</span>
          <span className="node-peer"><i />peer</span>
        </div>
      </div>

      <aside className="soc-graph-selection">
        <span className="soc-stat-label">Selection</span>
        {selected ? (
          <div className="soc-graph-detail">
            <strong className={selected.group === "process" && selected.cls ? `cls-${selected.cls}` : undefined}>
              {selected.fullLabel || selected.label}
            </strong>
            <dl>
              <div>
                <dt>kind</dt>
                <dd>{selected.group}</dd>
              </div>
              {selected.group === "process" ? (
                <>
                  <div>
                    <dt>classification</dt>
                    <dd className={selected.cls ? `cls-${selected.cls}` : undefined}>{selected.cls ?? "—"}</dd>
                  </div>
                  <div>
                    <dt>max score</dt>
                    <dd>{Math.round(selected.score ?? 0)}</dd>
                  </div>
                </>
              ) : null}
              <div>
                <dt>connections</dt>
                <dd>{neighbours.length}</dd>
              </div>
            </dl>
            {neighbours.length ? (
              <div className="soc-graph-neighbours">
                <span className="soc-stat-label">Connected</span>
                {neighbours.slice(0, 14).map((node) => (
                  <button
                    key={node.id}
                    type="button"
                    className={cx("soc-graph-neighbour", `node-${node.group}`)}
                    onClick={() => handleRef.current?.setSelected(node.id)}
                    title={node.fullLabel || node.label}
                  >
                    <i />
                    {node.label}
                  </button>
                ))}
              </div>
            ) : null}
          </div>
        ) : (
          <p className="soc-graph-selection-empty">Click a node to inspect its lineage, classification, and correlations.</p>
        )}
      </aside>
    </div>
  );
}

function WatchlistBody({
  watchlist,
  setWatchlist
}: {
  watchlist: typeof DEFAULT_WATCHLIST;
  setWatchlist: React.Dispatch<React.SetStateAction<typeof DEFAULT_WATCHLIST>>;
}) {
  const [kind, setKind] = useState<keyof typeof DEFAULT_WATCHLIST>("paths");
  const [value, setValue] = useState("");
  return (
    <div className="soc-watchlist">
      <div className="soc-control-row">
        <select value={kind} onChange={(event) => setKind(event.target.value as keyof typeof DEFAULT_WATCHLIST)}>
          <option value="paths">paths</option>
          <option value="ips">ips</option>
          <option value="binaries">binaries</option>
        </select>
        <input value={value} onChange={(event) => setValue(event.target.value)} placeholder="Add watch term" />
        <button
          type="button"
          onClick={() => {
            const trimmed = value.trim();
            if (!trimmed) return;
            setWatchlist((current) => ({ ...current, [kind]: [...current[kind], trimmed] }));
            setValue("");
          }}
        >
          Add
        </button>
      </div>
      {(["paths", "ips", "binaries"] as const).map((group) => (
        <div key={group}>
          <strong>{group}</strong>
          {watchlist[group].length ? (
            watchlist[group].map((item) => <code key={`${group}-${item}`}>{item}</code>)
          ) : (
            <span>none</span>
          )}
        </div>
      ))}
    </div>
  );
}

function SimulatorBody({ alerts }: { alerts: SocAlert[] }) {
  const [low, setLow] = useState(5);
  const [medium, setMedium] = useState(10);
  const [high, setHigh] = useState(20);
  const [critical, setCritical] = useState(40);
  const simulated = alerts.reduce(
    (acc, alert) => {
      const severity = classifyScore(alert.score, low, medium, high, critical);
      acc[severity] += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>
  );
  return (
    <div className="soc-simulator">
      {[
        ["low", low, setLow],
        ["medium", medium, setMedium],
        ["high", high, setHigh],
        ["critical", critical, setCritical]
      ].map(([label, value, setter]) => (
        <label key={label as string}>
          <span>{label as string}</span>
          <input type="number" value={value as number} onChange={(event) => (setter as (value: number) => void)(Number(event.target.value))} />
        </label>
      ))}
      <div className="soc-profile-grid">
        {SEVERITIES.map((severity) => (
          <MetricTile key={severity} label={severity} value={simulated[severity]} tone={severity} />
        ))}
      </div>
    </div>
  );
}

function KpiDrillBody({
  drill,
  alerts,
  events,
  ackStates,
  now
}: {
  drill: KpiDrill | null;
  alerts: SocAlert[];
  events: SocEvent[];
  ackStates: Record<string, AckState>;
  now: number;
}) {
  if (!drill) return <EmptyState title="No KPI selected" />;
  if (drill.kind === "eps") {
    const spark = eventSpark(events, now);
    const total60 = spark.reduce((sum, value) => sum + value, 0);
    const byProcess = aggregateEventProcesses(events).slice(0, 5);
    const byType = aggregateEventTypes(events);
    return (
      <div className="soc-kpi-drill">
        <div className="soc-kpi-stat-grid">
          <KpiStat label="Current" value={eventsPerSecond(events, now).toFixed(1)} meta="events/sec" />
          <KpiStat label="Last 60s" value={total60} meta="events ingested" />
          <KpiStat label="Peak" value={Math.max(0, ...spark)} meta="events / 5s bucket" />
          <KpiStat label="Live buffer" value={events.length} meta="events in view" />
        </div>
        <section className="soc-kpi-panel">
          <h3>Last 60 seconds</h3>
          <Sparkline values={spark} tone="accent" />
        </section>
        <section className="soc-kpi-panel">
          <h3>Top emitting binaries</h3>
          <MiniBarList rows={byProcess.map((row) => ({ label: row.label, value: row.value, meta: `${row.value} events` }))} empty="No emitting binaries in this window." />
        </section>
        <section className="soc-kpi-breakdown">
          {byType.map((row) => (
            <div key={row.label}>
              <strong>{row.value}</strong>
              <span>{row.label}</span>
            </div>
          ))}
        </section>
      </div>
    );
  }
  if (drill.kind === "procs") {
    const rows = topProcessRows(alerts);
    const uniqueBinaries = new Set(rows.map((row) => row.process)).size;
    const flagged = rows.filter((row) => row.count > 0).length;
    const avgEvents = rows.length ? (events.length / rows.length).toFixed(1) : "0";
    return (
      <div className="soc-kpi-drill">
        <div className="soc-kpi-stat-grid">
          <KpiStat label="Unique exec_ids" value={new Set(alerts.map((alert) => alert.execId || alert.id)).size} meta="with alert signal" />
          <KpiStat label="Distinct binaries" value={uniqueBinaries} meta="unique paths" />
          <KpiStat label="Flagged" value={flagged} meta="with at least 1 alert" />
          <KpiStat label="Avg events" value={avgEvents} meta="per process" />
        </div>
        <section className="soc-kpi-panel">
          <h3>Top processes</h3>
          <div className="soc-kpi-table">
            <div><span>Binary</span><span>Events</span><span>Alerts</span><span>Max score</span><span>Exec ID</span></div>
            {rows.slice(0, 25).map((row) => (
              <div key={row.execId || row.process}>
                <strong>{row.process}</strong>
                <span>{events.filter((event) => (event.execId && event.execId === row.execId) || event.process === row.process).length}</span>
                <span>{row.count}</span>
                <span>{row.score}</span>
                <code>{shortId(row.execId || row.process)}</code>
              </div>
            ))}
          </div>
        </section>
      </div>
    );
  }
  const scopedAlerts = alerts.filter((alert) => alert.severity === drill.kind);
  const ackCounts = scopedAlerts.reduce(
    (acc, alert) => {
      const state = ackStates[alert.id] || "new";
      acc[state] += 1;
      return acc;
    },
    { new: 0, ack: 0, resolved: 0 }
  );
  const topRows = topProcessRows(scopedAlerts);
  return (
    <div className="soc-kpi-drill">
      <div className="soc-kpi-stat-grid">
        <KpiStat label="Total" value={scopedAlerts.length} meta="in current view" tone={drill.kind} />
        <KpiStat label="Unack" value={ackCounts.new} meta="needs triage" />
        <KpiStat label="Acked" value={ackCounts.ack} meta="acknowledged" />
        <KpiStat label="Resolved" value={ackCounts.resolved} meta="closed" />
      </div>
      <section className="soc-kpi-panel">
        <h3>Top originating processes</h3>
        <MiniBarList rows={topRows.map((row) => ({ label: row.process, value: row.score, meta: `${row.count} alerts` }))} empty="No originating processes in this bucket." />
      </section>
      <section className="soc-kpi-panel">
        <h3>Top 10 by score</h3>
        <div className="soc-kpi-table">
          <div><span>Time</span><span>Score</span><span>Title</span><span>State</span></div>
          {scopedAlerts.slice(0, 10).map((alert) => (
            <div key={alert.id}>
              <span>{formatTime(alert.timestamp)}</span>
              <strong className={`severity-${alert.severity}`}>{alert.score}</strong>
              <span>{alert.title}</span>
              <span>{ackStates[alert.id] || "new"}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function KpiStat({
  label,
  value,
  meta,
  tone
}: {
  label: string;
  value: string | number;
  meta: string;
  tone?: Severity | "accent" | "good";
}) {
  return (
    <div className={cx("soc-kpi-stat", tone && `tone-${tone}`)}>
      <span>{label}</span>
      <strong>{value}</strong>
      <em>{meta}</em>
    </div>
  );
}

function PillLiveContent({
  stream,
  staleSeconds,
  onReconnect
}: {
  stream: StreamTelemetry;
  staleSeconds?: number;
  onReconnect: () => void;
}) {
  return (
    <div className="soc-popover-body">
      <MetricTile label="State" value={stream.state} />
      <MetricTile label="Frames" value={stream.frames} />
      <MetricTile label="Last message" value={staleSeconds === undefined ? "never" : `${staleSeconds}s ago`} />
      {stream.error ? <InlineNotice tone="warn" title="Stream note">{stream.error}</InlineNotice> : null}
      <button type="button" onClick={onReconnect}>
        Reconnect
      </button>
    </div>
  );
}

function PillHostContent({
  whoami,
  errors,
  statuses,
  onRefresh
}: {
  whoami: SocSnapshot["whoami"];
  errors: Record<string, string>;
  statuses: Record<string, number | undefined>;
  onRefresh: () => void;
}) {
  return (
    <div className="soc-popover-body">
      <div className="soc-popover-kv">
        <div>
          <span>User</span>
          <strong>{whoami.user}</strong>
        </div>
        <div>
          <span>Host</span>
          <strong>{whoami.host}</strong>
        </div>
      </div>
      <div className="soc-endpoint-list">
        {Object.entries(statuses).map(([key, status]) => (
          <span key={key}>
            <code>{key}</code>
            <em>{status || "n/a"}</em>
          </span>
        ))}
      </div>
      {Object.keys(errors).length ? <InlineNotice tone="warn" title="Endpoint errors">{Object.keys(errors).join(", ")}</InlineNotice> : null}
      <button type="button" onClick={onRefresh}>
        Probe now
      </button>
    </div>
  );
}

function PillRiskContent({
  counts,
  riskScore,
  alerts,
  windowLabel
}: {
  counts: Record<Severity, number>;
  riskScore: number;
  alerts: SocAlert[];
  windowLabel: string;
}) {
  const contributors = useMemo(
    () =>
      [...alerts]
        .filter((alert) => alert.severity === "critical" || alert.severity === "high")
        .sort((a, b) => b.score - a.score)
        .slice(0, 5)
        .map((alert) => ({ title: alert.title, score: alert.score, severity: alert.severity })),
    [alerts]
  );
  return (
    <div className="soc-popover-body soc-popover-risk">
      <RiskGauge score={riskScore} counts={counts} contributors={contributors} window={windowLabel} />
    </div>
  );
}

function AlertPreview({ preview }: { preview: HoverPreviewState | null }) {
  return (
    <div
      className={cx("soc-alert-preview", preview && "is-open")}
      data-panel={PANELS["alert-hover-preview-context-menu"].id}
      style={preview ? { left: preview.x, top: preview.y } : undefined}
      aria-hidden={!preview}
    >
      {preview ? (
        <>
          <SeverityBadge severity={preview.alert.severity} />
          <strong>{preview.alert.title}</strong>
          <span>{preview.alert.description}</span>
          <code>{preview.alert.execId || preview.alert.process || preview.alert.id}</code>
        </>
      ) : null}
    </div>
  );
}

function AlertContextMenu({
  state,
  onClose,
  onOpen,
  onAck,
  onResolve,
  onPin
}: {
  state: ContextMenuState | null;
  onClose: () => void;
  onOpen: (alert: SocAlert) => void;
  onAck: (alert: SocAlert) => void;
  onResolve: (alert: SocAlert) => void;
  onPin: (alert: SocAlert) => void;
}) {
  return (
    <div
      className={cx("soc-context-menu", state && "is-open")}
      data-panel={PANELS["alert-hover-preview-context-menu"].id}
      style={state ? { left: state.x, top: state.y } : undefined}
      aria-hidden={!state}
      onMouseLeave={onClose}
    >
      {state ? (
        <>
          <button type="button" onClick={() => onOpen(state.alert)}>
            Open drill
          </button>
          <button type="button" onClick={() => onAck(state.alert)}>
            Acknowledge
          </button>
          <button type="button" onClick={() => onResolve(state.alert)}>
            Resolve
          </button>
          <button type="button" onClick={() => onPin(state.alert)}>
            Toggle pin
          </button>
        </>
      ) : null}
    </div>
  );
}

function countSeverities(alerts: SocAlert[]): Record<Severity, number> {
  return alerts.reduce(
    (acc, alert) => {
      acc[alert.severity] += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );
}

function buildTimeline(alerts: SocAlert[], rangeMin: number, now: number, hidden: Set<Severity>, bucketCount = 30): TimelineBucket[] {
  const rangeMs = rangeMin * 60_000;
  const bucketMs = Math.max(1, rangeMs / bucketCount);
  const buckets = Array.from({ length: bucketCount }, (_, index) => {
    const bucketTime = new Date(now - rangeMs + bucketMs * index);
    return {
      label: `${String(bucketTime.getHours()).padStart(2, "0")}:${String(bucketTime.getMinutes()).padStart(2, "0")}`,
      total: 0,
      anomaly: false,
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>
    };
  });

  for (const alert of alerts) {
    if (hidden.has(alert.severity)) continue;
    const offset = Date.parse(alert.timestamp) - (now - rangeMs);
    const index = Math.max(0, Math.min(bucketCount - 1, Math.floor(offset / bucketMs)));
    buckets[index].counts[alert.severity] += 1;
    buckets[index].total += 1;
  }

  const totals = buckets.map((bucket) => bucket.total);
  const avg = totals.reduce((sum, value) => sum + value, 0) / Math.max(1, totals.length);
  const variance = totals.reduce((sum, value) => sum + (value - avg) ** 2, 0) / Math.max(1, totals.length);
  const std = Math.sqrt(variance);
  return buckets.map((bucket) => ({ ...bucket, anomaly: bucket.total > avg + std * 2 && bucket.total > 2 }));
}

function groupAlertList(alerts: SocAlert[]): AlertGroup[] {
  const groups = new Map<string, SocAlert[]>();
  for (const alert of alerts) {
    const key = `${alert.severity}:${alert.policyName || ""}:${alert.process || ""}:${alert.title}`;
    groups.set(key, [...(groups.get(key) || []), alert]);
  }
  return [...groups.values()].map((members) => ({ ...members[0], groupCount: members.length, members }));
}

function compareAlerts(a: SocAlert, b: SocAlert, sortField: SortField, pinned: Set<string>) {
  const ap = pinned.has(a.id) ? 1 : 0;
  const bp = pinned.has(b.id) ? 1 : 0;
  if (ap !== bp) return bp - ap;
  if (sortField === "severity") return SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
  if (sortField === "score") return b.score - a.score;
  return Date.parse(b.timestamp) - Date.parse(a.timestamp);
}

function matchesQuery(alert: SocAlert, query: string): boolean {
  const raw = query.trim();
  if (!raw) return true;
  const haystack = [alert.title, alert.description, alert.policyName, alert.process, alert.execId, alert.pid, alert.severity, alert.score]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return raw
    .split(/\s+/)
    .filter(Boolean)
    .every((token) => {
      const lower = token.toLowerCase();
      if (lower.startsWith("severity:")) return alert.severity === lower.slice("severity:".length);
      if (lower.startsWith("policy:")) return (alert.policyName || "").toLowerCase().includes(lower.slice("policy:".length));
      if (lower.startsWith("process:")) return (alert.process || "").toLowerCase().includes(lower.slice("process:".length));
      if (lower.startsWith("exec:")) return (alert.execId || "").toLowerCase().includes(lower.slice("exec:".length));
      if (lower.startsWith("pid:")) return String(alert.pid || "").includes(lower.slice("pid:".length));
      if (lower.startsWith("score:>")) return alert.score > Number(lower.slice("score:>".length));
      if (lower.startsWith("score:<")) return alert.score < Number(lower.slice("score:<".length));
      if (lower.startsWith("/") && lower.endsWith("/") && lower.length > 2) {
        try {
          return new RegExp(lower.slice(1, -1), "i").test(haystack);
        } catch {
          return false;
        }
      }
      return haystack.includes(lower);
    });
}

function classifyAlert(alert: SocAlert): AlertClassification {
  const text = `${alert.title} ${alert.description} ${alert.process || ""} ${alert.policyName || ""}`.toLowerCase();
  if (/attack|credential|reverse|shell|exfil|privilege|t1003|t1059|t1105/.test(text) || alert.score >= 70) return "attack";
  if (/cron|systemd|motd|apt|snapd|journald|dbus/.test(text) && alert.score < 35) return "baseline";
  if (alert.score >= 20 || alert.severity === "critical" || alert.severity === "high") return "threat";
  return "unknown";
}

function classificationLabel(classification: AlertClassification): string {
  if (classification === "attack") return "attack path";
  if (classification === "threat") return "threat";
  if (classification === "baseline") return "baseline";
  return "unknown origin";
}

function classifyScore(score: number, low: number, medium: number, high: number, critical: number): Severity {
  if (score >= critical) return "critical";
  if (score >= high) return "high";
  if (score >= medium) return "medium";
  if (score >= low) return "low";
  return "info";
}

function eventsPerSecond(events: SocEvent[], now: number): number {
  const cutoff = now - 60_000;
  return events.filter((event) => Date.parse(event.timestamp) >= cutoff).length / 60;
}

function eventSpark(events: SocEvent[], now: number): number[] {
  const buckets = Array.from({ length: 12 }, () => 0);
  const bucketMs = 5_000;
  for (const event of events) {
    const age = now - Date.parse(event.timestamp);
    if (age < 0 || age >= bucketMs * buckets.length) continue;
    const index = buckets.length - 1 - Math.floor(age / bucketMs);
    buckets[index] += 1;
  }
  return buckets;
}

function aggregateEventProcesses(events: SocEvent[]) {
  const rows = new Map<string, number>();
  for (const event of events) {
    const label = event.process || event.policyName || "unknown";
    rows.set(label, (rows.get(label) || 0) + 1);
  }
  return [...rows.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
}

function aggregateEventTypes(events: SocEvent[]) {
  const wanted = ["process_exec", "process_kprobe", "process_exit"];
  const rows = wanted.map((label) => ({ label: label.replace("process_", ""), value: events.filter((event) => event.eventType === label).length }));
  const known = rows.reduce((sum, row) => sum + row.value, 0);
  return [...rows, { label: "other", value: Math.max(0, events.length - known) }];
}

function processSummary(alerts: SocAlert[], events: SocEvent[]) {
  const ids = new Set<string>();
  const scores = new Map<string, number>();
  for (const alert of alerts) {
    const id = alert.execId || alert.process || alert.id;
    const label = readableProcessLabel(alert);
    ids.add(id);
    scores.set(label, (scores.get(label) || 0) + alert.score);
  }
  for (const event of events) {
    if (event.execId || event.process) ids.add(event.execId || event.process || event.id);
  }
  const top = [...scores.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  return { count: ids.size, top };
}

function topProcessRows(alerts: SocAlert[]) {
  const rows = new Map<string, { process: string; score: number; count: number; execId?: string; pid?: number }>();
  for (const alert of alerts) {
    // Prefer a readable binary (the leaf of the alert's chain title) over the
    // opaque base64 exec_id, then fall back to the PID — so rows are always
    // human-legible instead of "ZDJlMjUwYjE…".
    const label = readableProcessLabel(alert);
    const key = alert.execId || label;
    const row = rows.get(key) || { process: label, score: 0, count: 0, execId: alert.execId, pid: alert.pid };
    row.score += alert.score;
    row.count += 1;
    if (row.pid === undefined) row.pid = alert.pid;
    rows.set(key, row);
  }
  return [...rows.values()].sort((a, b) => b.score - a.score).slice(0, 10);
}

function readableProcessLabel(alert: SocAlert) {
  const chain = processChainFromAlert(alert);
  return (
    chain.at(-1) ||
    (alert.process && alert.process.startsWith("/") ? alert.process : undefined) ||
    (alert.pid ? `pid ${alert.pid}` : alert.process || alert.execId || "unknown")
  );
}

// mitreCoverage builds the ATT&CK technique breakdown. Alerts don't carry a
// technique, but each event carries its triggering `policy_name`, and each
// policy maps to a MITRE technique — so we join event → policy → technique.
// Range-aware (counts techniques observed in the current event window). If no
// technique-bearing events are in range, we fall back to the cumulative
// per-policy post counts so the table still shows the full coverage map.
function mitreCoverage(
  events: SocEvent[],
  policies: SocSnapshot["policies"],
  policyStats: SocSnapshot["policyStats"]
) {
  const mitreByPolicy = new Map<string, string>();
  for (const policy of policies) {
    if (policy.mitre) mitreByPolicy.set(policy.name, policy.mitre);
  }

  type Row = { label: string; value: number; meta?: string; id?: string };
  const rows = new Map<string, Row>();

  for (const event of events) {
    const mitre = event.policyName ? mitreByPolicy.get(event.policyName) : undefined;
    if (!mitre) continue;
    const row = rows.get(mitre) || { label: mitre, value: 0, meta: event.policyName, id: mitre };
    row.value += 1;
    rows.set(mitre, row);
  }

  if (rows.size === 0) {
    const postsByPolicy = new Map<string, number>();
    for (const stat of policyStats) postsByPolicy.set(stat.name, stat.posts);
    for (const policy of policies) {
      if (!policy.mitre) continue;
      const posts = postsByPolicy.get(policy.name) ?? 0;
      const existing = rows.get(policy.mitre);
      if (existing) existing.value += posts;
      else rows.set(policy.mitre, { label: policy.mitre, value: posts, meta: policy.name, id: policy.mitre });
    }
  }

  return [...rows.values()].sort((a, b) => b.value - a.value).slice(0, 12);
}

function extractIocs(alerts: SocAlert[], events: SocEvent[]) {
  const files = new Map<string, number>();
  const peers = new Map<string, number>();
  const add = (map: Map<string, number>, key?: string) => {
    if (!key) return;
    map.set(key, (map.get(key) || 0) + 1);
  };
  for (const event of events) {
    add(files, event.path);
    add(peers, event.destIp);
    add(peers, event.remoteIp);
  }
  for (const alert of alerts) {
    for (const match of `${alert.description} ${alert.args || ""}`.matchAll(/(\/(?:[\w.-]+\/?){2,})/g)) add(files, match[1]);
    for (const match of `${alert.description} ${alert.args || ""}`.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) add(peers, match[0]);
  }
  return {
    files: [...files.entries()].sort((a, b) => b[1] - a[1]),
    peers: [...peers.entries()].sort((a, b) => b[1] - a[1])
  };
}

function aggregateNetwork(events: SocEvent[]) {
  const rows = new Map<string, { peer: string; count: number; procs: Set<string> }>();
  for (const event of events) {
    const peer = event.destIp ? `${event.destIp}${event.destPort ? `:${event.destPort}` : ""}` : event.remoteIp;
    if (!peer) continue;
    const row = rows.get(peer) || { peer, count: 0, procs: new Set<string>() };
    row.count += 1;
    if (event.process) row.procs.add(event.process);
    rows.set(peer, row);
  }
  return [...rows.values()]
    .map((row) => ({ peer: row.peer, count: row.count, procs: [...row.procs] }))
    .sort((a, b) => b.count - a.count);
}

function buildCorrelationGraph(alerts: SocAlert[], events: SocEvent[]): CorrelationGraphData {
  // On this engine alerts carry only an opaque exec_id (the command lives in the
  // title chain) while the binary, policy, and accessed-file context live on the
  // correlated events. Resolve a readable binary label per exec_id from events,
  // then key every process node by that label so alert + event signal merges into
  // one node instead of drifting into disconnected base64 dots.
  const binaryByExec = new Map<string, string>();
  for (const event of events) {
    if (!event.execId || !event.process) continue;
    const current = binaryByExec.get(event.execId);
    // Prefer an absolute binary path, but a bare comm name still beats a base64 exec_id.
    if (!current || (!current.startsWith("/") && event.process.startsWith("/"))) {
      binaryByExec.set(event.execId, event.process);
    }
  }
  const labelFor = (execId: string | undefined, fallback: string | undefined) =>
    (execId ? binaryByExec.get(execId) : undefined) || fallback || execId || "process";

  type ProcAgg = {
    key: string;
    label: string;
    weight: number;
    score: number;
    policies: Set<string>;
    files: Set<string>;
    peers: Set<string>;
  };
  const procs = new Map<string, ProcAgg>();
  const ensureProc = (label: string, weight: number, score = 0) => {
    const key = `process:${label}`;
    let agg = procs.get(key);
    if (!agg) {
      agg = { key, label, weight, score, policies: new Set(), files: new Set(), peers: new Set() };
      procs.set(key, agg);
    } else {
      agg.weight += weight;
      if (score > agg.score) agg.score = score;
    }
    return agg;
  };

  // Process lineage edges (runc → sh → pg_isready) parsed from the alert title.
  const chainLinks = new Set<string>();

  for (const alert of alerts) {
    const chain = processChainFromAlert(alert);
    const leafLabel = labelFor(alert.execId, chain.at(-1) || alert.process);
    ensureProc(leafLabel, Math.max(1, alert.score / 18), alert.score);
    let prev: string | undefined;
    chain.forEach((token, index) => {
      const label = index === chain.length - 1 ? leafLabel : token;
      ensureProc(label, 0.4, index === chain.length - 1 ? alert.score : 0);
      if (prev && prev !== label) chainLinks.add(`process:${prev}||process:${label}`);
      prev = label;
    });
  }

  for (const event of events) {
    const agg = ensureProc(labelFor(event.execId, event.process), 0.3);
    if (event.policyName) agg.policies.add(event.policyName);
    const file = event.path || (event.policyName ? extractFilePath(event.args) : undefined);
    if (file) agg.files.add(file);
    const peer = event.destIp || event.remoteIp;
    if (peer) agg.peers.add(event.destPort ? `${peer}:${event.destPort}` : peer);
  }

  // Keep the heaviest processes so the graph stays legible, then attach each
  // one's correlated policy / file / peer nodes and the edges between them.
  const topProcs = [...procs.values()].sort((a, b) => b.weight - a.weight).slice(0, 26);
  const keptProcKeys = new Set(topProcs.map((proc) => proc.key));

  const nodes = new Map<string, GraphNode>();
  const links = new Map<string, GraphLink>();
  const addNode = (id: string, label: string, group: GraphNode["group"], weight: number, score?: number) => {
    const existing = nodes.get(id);
    if (existing) {
      existing.weight += weight;
      if (score !== undefined && score > (existing.score ?? 0)) {
        existing.score = score;
        existing.cls = classifyGraphScore(score);
      }
      return;
    }
    nodes.set(id, {
      id,
      label: shortGraphLabel(label),
      fullLabel: label,
      group,
      weight,
      score,
      cls: group === "process" ? classifyGraphScore(score ?? 0) : undefined
    });
  };
  const addLink = (source: string, target: string, weight: number) => {
    if (source === target) return;
    const key = `${source}->${target}`;
    const existing = links.get(key);
    if (existing) existing.weight += weight;
    else links.set(key, { source, target, weight });
  };

  for (const proc of topProcs) {
    addNode(proc.key, proc.label, "process", Math.max(2, proc.weight), proc.score);
    for (const policy of proc.policies) {
      const id = `policy:${policy}`;
      addNode(id, policy, "policy", 1.5);
      addLink(proc.key, id, 2);
    }
    for (const file of [...proc.files].slice(0, 4)) {
      const id = `file:${file}`;
      addNode(id, file, "file", 1);
      addLink(proc.key, id, 1);
    }
    for (const peer of [...proc.peers].slice(0, 4)) {
      const id = `peer:${peer}`;
      addNode(id, peer, "peer", 1);
      addLink(proc.key, id, 1);
    }
  }
  for (const pair of chainLinks) {
    const [source, target] = pair.split("||");
    if (keptProcKeys.has(source) && keptProcKeys.has(target)) addLink(source, target, 1.5);
  }

  const graphNodes = [...nodes.values()];
  const nodeIds = new Set(graphNodes.map((node) => node.id));
  const graphLinks = [...links.values()].filter(
    (link) => nodeIds.has(String(link.source)) && nodeIds.has(String(link.target))
  );

  return { nodes: graphNodes, links: graphLinks };
}

// Pull the ordered binary chain out of an alert title such as
// "Suspicious chain: /usr/sbin/runc → /bin/sh → /usr/local/bin/pg_isready (score 17)".
function processChainFromAlert(alert: SocAlert): string[] {
  if (alert.process && alert.process.startsWith("/")) return [alert.process];
  return alert.title.match(/\/[^\s→()]+/g) ?? [];
}

// File-access events keep the accessed path in args ("/etc/passwd 4"); pull the
// first absolute-path token so it can become a shared "file" node.
function extractFilePath(args: string | undefined): string | undefined {
  if (!args) return undefined;
  const match = args.match(/\/[^\s"']+/);
  return match ? match[0] : undefined;
}

function shortGraphLabel(value: string, max = 24) {
  const clean = value.replace(/\s+/g, " ").trim();
  if (!clean) return "unknown";
  if (clean.length <= max) return clean;
  const leaf = clean.split("/").filter(Boolean).at(-1);
  const candidate = leaf && leaf.length <= Math.max(10, max) ? leaf : clean;
  if (candidate.length <= max) return candidate;
  const side = Math.max(5, Math.floor((max - 3) / 2));
  return `${candidate.slice(0, side)}...${candidate.slice(-side)}`;
}

function filterEvents(events: SocEvent[], query: string, hideNoise: boolean) {
  const regex = query.trim() ? safeRegex(query.trim()) : null;
  return events.filter((event) => {
    const text = `${event.eventType} ${event.process || ""} ${event.args || ""} ${event.policyName || ""}`;
    if (hideNoise && /vite|node|chrome|browser|npm/.test(text.toLowerCase())) return false;
    return regex ? regex.test(text) : true;
  });
}

function safeRegex(source: string): RegExp | null {
  try {
    return new RegExp(source, "i");
  } catch {
    return null;
  }
}

function normalizeDecisionFrame(value: unknown): SocDecision {
  const record = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const timestamp = stringValue(record.timestamp || record.Timestamp) || new Date().toISOString();
  return {
    id: stringValue(record.id || record.ID || record.decision_id) || `decision-${timestamp}`,
    action: stringValue(record.action || record.Action) || "observe",
    state: stringValue(record.state || record.State),
    target: stringValue(record.target || record.Target || record.exec_id || record.ExecID),
    reason: stringValue(record.reason || record.Reason),
    timestamp
  };
}

function watchCount(watchlist: typeof DEFAULT_WATCHLIST) {
  return watchlist.paths.length + watchlist.ips.length + watchlist.binaries.length;
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "n/a";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function shortId(value: string) {
  return value.length > 18 ? `${value.slice(0, 8)}...${value.slice(-6)}` : value;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function readLocalJson<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const value = window.localStorage.getItem(key);
    return value == null ? fallback : (JSON.parse(value) as T);
  } catch {
    return fallback;
  }
}

function writeLocalJson<T>(key: string, value: T) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Local persistence is operator convenience. Decode/write failures must not break the SOC route.
  }
}

function downloadCsv(alerts: AlertGroup[]) {
  const rows = [
    ["id", "severity", "score", "title", "process", "policy", "timestamp"],
    ...alerts.map((alert) => [
      alert.id,
      alert.severity,
      String(alert.score),
      alert.title,
      alert.process || "",
      alert.policyName || "",
      alert.timestamp
    ])
  ];
  const csv = rows.map((row) => row.map((cell) => `"${cell.replaceAll('"', '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "soc-alerts.csv";
  link.click();
  URL.revokeObjectURL(url);
}

async function loadPdfTools() {
  const [{ default: jsPDF }, { default: autoTable }] = await Promise.all([
    import("jspdf"),
    import("jspdf-autotable")
  ]);
  return { jsPDF, autoTable };
}

async function downloadAlertPdf(alerts: AlertGroup[], events: SocEvent[], snapshot: SocSnapshot) {
  const { jsPDF, autoTable } = await loadPdfTools();
  const doc = new jsPDF({ orientation: "landscape", unit: "pt" });
  doc.setFontSize(15);
  doc.text("eBPF SOC Alert Export", 40, 38);
  doc.setFontSize(9);
  doc.text(`Host: ${snapshot.whoami.host}  User: ${snapshot.whoami.user}  SHA: ${snapshot.version.sha || "n/a"}`, 40, 55);
  doc.text(`Generated: ${new Date().toISOString()}  Alerts: ${alerts.length}  Events buffered: ${events.length}`, 40, 70);
  autoTable(doc, {
    startY: 92,
    head: [["Severity", "Score", "Title", "Process", "Policy", "Time"]],
    body: alerts.slice(0, 120).map((alert) => [
      alert.severity,
      String(alert.score),
      alert.title,
      alert.process || "",
      alert.policyName || "",
      alert.timestamp
    ]),
    styles: { fontSize: 8, cellPadding: 4 },
    headStyles: { fillColor: [20, 31, 48] }
  });
  doc.save("soc-alert-export.pdf");
}

async function downloadMitrePdf(rows: Array<{ label: string; value: number; meta?: string; id?: string }>) {
  const { jsPDF, autoTable } = await loadPdfTools();
  const doc = new jsPDF({ orientation: "portrait", unit: "pt" });
  doc.setFontSize(15);
  doc.text("MITRE Coverage", 40, 40);
  doc.setFontSize(9);
  doc.text(`Generated: ${new Date().toISOString()}`, 40, 56);
  autoTable(doc, {
    startY: 82,
    head: [["Technique", "Count", "Tactic / Metadata"]],
    body: rows.map((row) => [row.label, String(row.value), row.meta || "observed"]),
    styles: { fontSize: 9, cellPadding: 5 },
    headStyles: { fillColor: [20, 31, 48] }
  });
  doc.save("mitre-coverage.pdf");
}
