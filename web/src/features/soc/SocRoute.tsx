// The SOC dashboard route.
//
// This file is the composition root — it owns the operator's session state
// (filters, selection, which surface is open) and wires the data hooks to the
// panels. The panels themselves, the derivations behind them, and the modal
// bodies live in sibling modules.
//
// Two things stay here rather than moving out, because they are inseparable
// from the surfaces the route hosts:
//
//   • the D3 correlation-graph bridge — React owns the <svg>, D3 owns its
//     contents, and the handle between them is this file's contract;
//   • the export studio's report model — what a downloadable report is allowed
//     to CLAIM is a product decision that has been wrong in production twice
//     (see buildExportModel and coverageLabel), so it sits next to the route
//     that gathers the evidence rather than in a serialisation helper.
import {
  AlertTriangle,
  Braces,
  Check,
  Copy,
  Download,
  FileText,
  Maximize2,
  Minimize2,
  Radio,
  RefreshCw,
  Search,
  Server,
  ShieldCheck
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { MouseEvent } from "react";
import type * as React from "react";
import {
  fetchProcessDetail,
  applyChokeAction,
  decisionOutcome,
  fetchChokeCircuits,
  type ChokeAction,
  type ChokeCircuit
} from "./api";
import { useStream } from "../../lib/stream";
import { ACTION_FOR_RUNG, ladderIndex, type Rung } from "../common/enforcement";
import { useOSTheme } from "../../lib/theme";
import {
  EmptyState,
  IconButton,
  InlineNotice,
  PanelFrame,
  PopoverCard,
  SeverityBadge,
  SlideOver,
  Sparkline,
  StatusPill,
  cx
} from "./components";
import { MITRE_MATRIX, SearchField, buildMitreCoverageModel } from "./panels";
import { AlertQueue } from "./AlertQueue";
import { DrillPanel } from "./DrillPanel";
import { EventStream } from "./EventStream";
import { ExecutiveBand } from "./ExecutiveBand";
import { GraphBrief } from "./GraphBrief";
import { GraphSelectionRail } from "./GraphSelectionRail";
import { PillHostContent, PillLiveContent, PillRiskContent } from "./pills";
import { ProcessActionModal } from "./ProcessActionModal";
import { RightRail } from "./RightRail";
import { SocModals } from "./SocModals";
import { SocNotices } from "./SocNotices";
import { SocSidebar } from "./Sidebar";
import { TimelinePanel } from "./TimelinePanel";
import { AlertContextMenu, AlertPreview, MiniBarList } from "./rows";
import { ExecutiveMetricTile } from "./tiles";
import { watchCount } from "./WatchlistBody";
import { extractIocs, peerFromEvent } from "./telemetry";
import { applySocStreamBatch, useLocalJsonState, useNow, useSocData } from "./hooks";
import { useSocWindowModel } from "./useSocWindowModel";
import { rangeLabel } from "./format";
import {
  GRAPH_CLASSES,
  buildCorrelationGraph,
  filterGraph,
  graphLinkKey,
  graphMeta,
  type CorrelationGraphData,
  type GraphClass,
  type GraphControls,
  type GraphLayout,
  type GraphLink,
  type GraphLinkSel,
  type GraphNode,
  type GraphNodeSel,
  type ProcessInstance
} from "./graphModel";
import { RISK_HALF_SCALE_PER_HOUR, riskScoreFromRate } from "./risk";
import {
  EXPORT_PRESETS,
  csvBlock,
  exportJson,
  triggerDownload,
  type ExportFormat,
  type ExportModel,
  type ExportSection
} from "./report";
import { loadPdfTools } from "./pdf";
import {
  DEFAULT_WATCHLIST,
  PANELS,
  SEVERITIES,
  type AckState,
  type AlertGroup,
  type HoverPreviewState,
  type ContextMenuState,
  type KpiDrill,
  type OpenSurface,
  type PillSurface,
  type SortField,
  type StreamTelemetry
} from "./dashboard";
import type {
  Severity,
  SocAlert,
  SocDecision,
  SocEvent,
  SocPolicy,
  SocProcessDetail,
  SocSnapshot,
  SocWhoami
} from "./types";
import "./soc.css";

// The posture curve and the graph builder are re-exported from the route so
// consumers (and the tests that pin their behaviour) keep one entry point for
// the SOC feature.
export { RISK_HALF_SCALE_PER_HOUR, riskScoreFromRate, buildCorrelationGraph };
export type { ProcessInstance };

export function SocRoute() {
  const { snapshot, setSnapshot, loading, errors, statuses, truncated, refresh } = useSocData();
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

  // Theme follows the OS for every console page — see src/lib/theme.ts.
  const theme = useOSTheme();
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
  // useCallback because the global keydown effect depends on it; as a plain
  // function declaration it was a new value every render, re-registering a
  // document-level listener on each one.
  const setAckState = useCallback(
    (id: string, value: AckState) => {
      setAckStates((current) => ({ ...current, [id]: value }));
    },
    [setAckStates]
  );
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
  }, [drillAlert, setAckState]);

  const model = useSocWindowModel({
    snapshot,
    rangeMin,
    now,
    truncated,
    errors,
    statuses,
    query,
    hideBaseline,
    filterUnack,
    groupAlerts,
    sortField,
    ackStates,
    pinnedAlerts,
    timelineHidden,
    streamFilter,
    streamHideNoise
  });

  const staleSeconds = stream.lastMessageAt ? Math.max(0, Math.floor((now - stream.lastMessageAt) / 1000)) : undefined;
  const streamStale = staleSeconds === undefined || staleSeconds > 30;

  const [knownVersionSha, setKnownVersionSha] = useState("");
  const [versionToastDismissed, setVersionToastDismissed] = useState(false);
  const versionChanged = Boolean(knownVersionSha && snapshot.version.sha && snapshot.version.sha !== knownVersionSha);
  useEffect(() => {
    if (!snapshot.version.sha) return;
    if (!knownVersionSha) {
      setKnownVersionSha(snapshot.version.sha);
    }
  }, [knownVersionSha, snapshot.version.sha]);

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

  function openDrillByEvent(event: SocEvent) {
    const alert = model.rangeAlerts.find((item) => item.execId && item.execId === event.execId);
    if (alert) openDrill(alert);
  }

  function openDrillByExecId(execId: string) {
    const alert = model.rangeAlerts.find((item) => item.execId === execId);
    if (alert) openDrill(alert);
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
      <SocSidebar
        sidebarOpen={sidebarOpen}
        openSurface={openSurface}
        onToggleSidebar={() => setSidebarOpen((value) => !value)}
        onCloseSidebar={() => setSidebarOpen(false)}
        onOpenSurface={openSurfaceByName}
        watchlistCount={watchCount(watchlist)}
        notificationBadge={notificationsActive && notifyChannels.inApp ? notifyHistory.filter((item) => !item.read).length : undefined}
        userName={snapshot.whoami.user}
      />

      <div className="soc-main-shell">
        <SocTopBar
          searchRef={searchRef}
          query={query}
          onQuery={setQuery}
          rangeMin={rangeMin}
          onRangeMin={setRangeMin}
          host={snapshot.whoami.host}
          streamState={stream.state}
          openPill={openPill}
          onOpenPill={setOpenPill}
          loading={loading}
          onRefresh={refresh}
        />

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

          <SocNotices model={model} rangeMin={rangeMin} />

          <ExecutiveBand
            open={execBandOpen}
            onToggle={() => setExecBandOpen((value) => !value)}
            briefingOpen={briefingOpen}
            onToggleBriefing={() => setBriefingOpen((value) => !value)}
            riskScore={model.riskScore}
            riskLabel={model.riskLabel}
            riskDelta={Math.round(model.riskPerHour - model.previousRiskPerHour)}
            riskSaturated={model.riskSaturated}
            countsUnfounded={model.countsUnfounded}
            windowLabel={rangeLabel(rangeMin)}
            totalAlerts={model.rangeAlerts.length}
            openCritical={model.openContainment.critical}
            openHigh={model.openContainment.high}
            containmentActions={model.rangeDecisions.length}
            topTechnique={model.mitreRows[0]}
            techniqueMapped={model.techniqueMapped}
            eps={model.eps}
            activeProcesses={model.activeProcesses.count}
            topProcess={model.activeProcesses.top}
            hostName={snapshot.whoami.host}
            hostOk={!model.activeEndpointErrors.length}
            streamState={stream.state}
            onReviewCriticals={() => openKpi("critical", "Critical alerts")}
            onOpenRisk={() => setOpenPill("risk")}
          />

          <SocKpiRow model={model} rangeMin={rangeMin} onOpenKpi={openKpi} />

          <PanelFrame
            panel={PANELS["severity-timeline"]}
            status={<StatusPill label={`${model.timeline.reduce((sum, bucket) => sum + bucket.total, 0)} alerts`} tone="info" />}
            actions={
              <div className="soc-severity-toggle-row">
                {SEVERITIES.map((severity) => (
                  <button
                    key={severity}
                    type="button"
                    className={cx("soc-severity-toggle", model.hiddenTimelineSet.has(severity) && "is-muted")}
                    onClick={() => toggleTimelineSeverity(severity)}
                  >
                    <SeverityBadge severity={severity} />
                  </button>
                ))}
              </div>
            }
          >
            <TimelinePanel buckets={model.timeline} rangeMin={rangeMin} />
          </PanelFrame>

          <section className="soc-primary-grid">
            <AlertQueue
              alerts={model.filteredAlerts}
              coverage={model.windowCoverage.alerts}
              hideBaseline={hideBaseline}
              onHideBaseline={setHideBaseline}
              filterUnack={filterUnack}
              onFilterUnack={setFilterUnack}
              grouped={groupAlerts}
              onGrouped={setGroupAlerts}
              sortField={sortField}
              onSortField={setSortField}
              selectedIds={selectedIds}
              onToggleSelected={toggleSelected}
              onClearSelection={() => setSelectedIds(new Set())}
              onBulkAck={applyBulkAck}
              ackStates={ackStates}
              pinnedAlerts={pinnedAlerts}
              onOpen={openDrill}
              onAck={setAckState}
              onPin={togglePin}
              onContext={onAlertContext}
              onHover={onAlertHover}
              onLeave={() => setHoverPreview(null)}
            />

            <RightRail model={model} onOpenProcess={openDrillByExecId} />
          </section>

          <EventStream
            events={model.visibleEvents}
            paused={streamPaused}
            onPaused={setStreamPaused}
            hideNoise={streamHideNoise}
            onHideNoise={setStreamHideNoise}
            filter={streamFilter}
            onFilter={setStreamFilter}
            onOpenEvent={openDrillByEvent}
          />
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
        <PillRiskContent
          counts={model.counts}
          riskScore={model.riskScore}
          riskPerHour={model.riskPerHour}
          alerts={model.rangeAlerts}
          windowLabel={`last ${rangeLabel(rangeMin)}`}
        />
      </PopoverCard>

      <SocModals
        openSurface={openSurface}
        closeModal={closeModal}
        openSurfaceByName={openSurfaceByName}
        snapshot={snapshot}
        model={model}
        watchlist={watchlist}
        setWatchlist={setWatchlist}
        fleetHosts={fleetHosts}
        setFleetHosts={setFleetHosts}
        now={now}
        notifications={{
          history: notifyHistory,
          setHistory: setNotifyHistory,
          active: notificationsActive,
          setActive: setNotificationsActive,
          channels: notifyChannels,
          setChannels: setNotifyChannels
        }}
        kpiDrill={kpiDrill}
        ackStates={ackStates}
        commandQuery={commandQuery}
        setCommandQuery={setCommandQuery}
        theme={theme}
        stream={stream}
        onActionComplete={refresh}
        graphBody={
          <CorrelationGraph
            active={openSurface === "graph"}
            alerts={model.rangeAlerts}
            events={model.rangeEvents}
            topProcesses={model.topProcesses}
          />
        }
        exportBody={
          <ExportStudioBody
            filteredAlerts={model.filteredAlerts}
            rangeAlerts={model.rangeAlerts}
            events={model.rangeEvents}
            decisions={model.rangeDecisions}
            policies={snapshot.policies}
            mitreRows={model.mitreRows}
            whoami={snapshot.whoami}
            version={snapshot.version}
          />
        }
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
}

// Grouped by function: time range · system status (host/stream) · utilities.
// Posture is no longer duplicated here — the executive band below owns it.
function SocTopBar({
  searchRef,
  query,
  onQuery,
  rangeMin,
  onRangeMin,
  host,
  streamState,
  openPill,
  onOpenPill,
  loading,
  onRefresh
}: {
  searchRef: React.MutableRefObject<HTMLInputElement | null>;
  query: string;
  onQuery: (value: string) => void;
  rangeMin: number;
  onRangeMin: (value: number) => void;
  host?: string;
  streamState: string;
  openPill: PillSurface | null;
  onOpenPill: (pill: PillSurface | null) => void;
  loading: boolean;
  onRefresh: () => void;
}) {
  return (
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
          onChange={(event) => onQuery(event.target.value)}
          placeholder="Search alerts, processes, policies…"
        />
        <kbd>/</kbd>
      </label>
      <div className="soc-top-actions">
        <div className="soc-range" role="group" aria-label="Time range">
          {[5, 30, 60, 1440, 10080].map((value) => (
            <button
              key={value}
              type="button"
              className={value === rangeMin ? "is-active" : ""}
              onClick={() => onRangeMin(value)}
            >
              {/* rangeLabel, not a second inline formatter. This button had
                  its own `${value}m` rule, so adding a 7-day range rendered
                  it as "10080m" here while every notice on the page called
                  the same window "7d". One formatter, no drift. */}
              {rangeLabel(value)}
            </button>
          ))}
        </div>
        <span className="soc-topbar-sep" aria-hidden="true" />
        <button type="button" className="soc-host-pill" onClick={() => onOpenPill(openPill === "host" ? null : "host")}>
          <Server size={14} />
          <span>{host}</span>
        </button>
        <button type="button" className={cx("soc-live-pill", streamState)} onClick={() => onOpenPill(openPill === "live" ? null : "live")}>
          <Radio size={14} />
          <span>{streamState}</span>
        </button>
        <span className="soc-topbar-sep" aria-hidden="true" />
        <IconButton icon={RefreshCw} label="Refresh snapshots" onClick={onRefresh} active={loading} />
      </div>
    </header>
  );
}

// The five headline metrics. Each tile's `meta` names the window it covers
// through rangeLabel — three of them used to carry their own `${rangeMin}m`
// rule, so a 7-day view read "10080m window" under Critical, High and Medium
// while the selector directly above said "7d".
function SocKpiRow({
  model,
  rangeMin,
  onOpenKpi
}: {
  model: ReturnType<typeof useSocWindowModel>;
  rangeMin: number;
  onOpenKpi: (kind: KpiDrill["kind"], title: string) => void;
}) {
  const { counts, previousCounts, countsUnfounded, severitySparks, eps, eventSparkValues, activeProcesses, topProcesses } = model;
  return (
    <section className="soc-kpi-grid" data-panel={PANELS["kpi-row"].id}>
      <ExecutiveMetricTile
        label="Critical"
        value={counts.critical}
        sub="Containment priority"
        meta={`${rangeLabel(rangeMin)} window`}
        delta={countsUnfounded ? undefined : counts.critical - previousCounts.critical}
        badge="P1"
        tone="critical"
        onClick={() => onOpenKpi("critical", "Critical alerts")}
      >
        <Sparkline values={severitySparks.critical} tone="critical" />
      </ExecutiveMetricTile>
      <ExecutiveMetricTile
        label="High"
        value={counts.high}
        sub="Escalation watch"
        meta={`${rangeLabel(rangeMin)} window`}
        delta={countsUnfounded ? undefined : counts.high - previousCounts.high}
        badge="P2"
        tone="high"
        onClick={() => onOpenKpi("high", "High alerts")}
      >
        <Sparkline values={severitySparks.high} tone="high" />
      </ExecutiveMetricTile>
      <ExecutiveMetricTile
        label="Medium"
        value={counts.medium}
        sub="Analyst triage"
        meta={`${rangeLabel(rangeMin)} window`}
        delta={countsUnfounded ? undefined : counts.medium - previousCounts.medium}
        badge="P3"
        tone="medium"
        onClick={() => onOpenKpi("medium", "Medium alerts")}
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
        onClick={() => onOpenKpi("eps", "Events per second")}
      >
        <Sparkline values={eventSparkValues} tone="accent" />
      </ExecutiveMetricTile>
      {/* Not "active": these are distinct processes OBSERVED in the window,
          most of which have already exited. The badge used to read a
          hardcoded "LAST 10M" regardless of the selected range. */}
      <ExecutiveMetricTile
        label="Processes seen"
        value={activeProcesses.count}
        sub={activeProcesses.top || "No dominant process"}
        meta={`${topProcesses.length} scored · ${rangeLabel(rangeMin)} window`}
        badge={rangeLabel(rangeMin).toUpperCase()}
        tone="good"
        onClick={() => onOpenKpi("procs", "Processes seen")}
      />
    </section>
  );
}

/* ─────────────────────────────────────────────────────────── Export studio */

/**
 * ATT&CK coverage as text. "n/a" when no policy carries a mapping.
 *
 * Coverage is derived from policies tagged with a technique. A fleet can run
 * policies this build has never heard of — the control plane maps by name and
 * returns empty rather than guessing — and then nothing maps and the percentage
 * computes to 0. Printing "0%" asserts the estate detects nothing; the truth is
 * that coverage cannot be computed. In a document handed to a customer that is
 * the difference between "we cannot tell you" and "you are completely exposed".
 */
function coverageLabel(m: { coveragePct: number; coverageMeasurable: boolean }): string {
  return m.coverageMeasurable ? `${m.coveragePct}%` : "n/a";
}

function buildExportModel(
  scopeLabel: string,
  scopeAlerts: SocAlert[],
  events: SocEvent[],
  decisions: SocDecision[],
  policies: SocPolicy[],
  mitreRows: Array<{ label: string; value: number; meta?: string; id?: string }>,
  whoami: SocWhoami,
  version: SocSnapshot["version"]
): ExportModel {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const a of scopeAlerts) counts[a.severity] += 1;
  const risk = Math.min(100, counts.critical * 8 + counts.high * 3 + counts.medium);

  const iocsRaw = extractIocs(scopeAlerts, events);
  const bins = new Map<string, number>();
  for (const e of events) { if (e.process) bins.set(e.process, (bins.get(e.process) || 0) + 1); }
  const ips = iocsRaw.peers.filter(([v]) => /\d+\.\d+\.\d+\.\d+/.test(v));
  const files = iocsRaw.files;
  const binaries = [...bins.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40);

  const model = buildMitreCoverageModel(mitreRows, scopeAlerts, policies);
  const nameOf = (id: string) => {
    for (const t of MITRE_MATRIX) { const h = t.techniques.find((x) => x.id === id); if (h) return h.name; }
    return "";
  };
  const observed = [...model.observed.entries()].filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([id, hits]) => ({
    id, name: nameOf(id), hits, policy: (model.policiesByTech.get(id) ?? []).map((p) => p.name).join(", ") || "—"
  }));
  const gaps = model.gapIds.map((id) => ({ id, name: nameOf(id), tactic: MITRE_MATRIX.find((t) => t.techniques.some((x) => x.id === id))?.name ?? "" }));
  const tactics = MITRE_MATRIX.map((t) => ({
    name: t.name,
    covered: t.techniques.filter((x) => model.stateOf(x.id) !== "gap").length,
    observed: t.techniques.filter((x) => model.stateOf(x.id) === "observed").length,
    total: t.techniques.length
  }));

  const times = scopeAlerts.map((a) => Date.parse(a.timestamp)).filter((n) => !Number.isNaN(n));
  const rangeFrom = times.length ? new Date(Math.min(...times)).toLocaleString() : "—";
  const rangeTo = times.length ? new Date(Math.max(...times)).toLocaleString() : "—";

  return {
    meta: { generated: new Date().toLocaleString(), host: whoami.host || "—", user: whoami.user || "—", sha: version.sha || "n/a", scope: scopeLabel, rangeFrom, rangeTo },
    summary: { risk, total: scopeAlerts.length, counts, events: events.length, decisions: decisions.length, iocs: ips.length + files.length + binaries.length, coveragePct: model.coveragePct, coverageMeasurable: model.mappingAvailable },
    alerts: scopeAlerts.map((a) => ({ severity: a.severity, score: a.score, title: a.title, process: a.process || "", policy: a.policyName || "", timestamp: a.timestamp })),
    events: events.slice(0, 500).map((e) => ({ type: e.eventType, process: e.process || "", policy: e.policyName || "", detail: e.path || e.args || peerFromEvent(e) || "", timestamp: e.timestamp })),
    // `ok: d.ok !== false` exported EVERY decision as successful, because no
    // backend sends a boolean `ok` — they send `outcome`. Rows whose outcome
    // read "skipped: system-critical chain" were exported as ok:true. Carry the
    // engine's own words instead of manufacturing a verdict.
    decisions: decisions.map((d) => ({ action: d.action, state: d.state || "", target: d.target || "", reason: d.reason || "", outcome: decisionOutcome(d), timestamp: d.timestamp })),
    iocs: { ips, files, binaries },
    mitre: { coveragePct: model.coveragePct, coverageMeasurable: model.mappingAvailable, coveredCount: model.coveredCount, total: model.total, observedCount: model.observedCount, gapCount: model.gapCount, observed, gaps, tactics }
  };
}

function exportCsv(model: ExportModel, sections: Set<ExportSection>) {
  const blocks: string[] = [];
  if (sections.has("summary")) {
    const c = model.summary.counts;
    blocks.push(csvBlock("SUMMARY", ["metric", "value"], [
      ["generated", model.meta.generated], ["host", model.meta.host], ["scope", model.meta.scope],
      ["risk", model.summary.risk], ["alerts", model.summary.total],
      ["critical", c.critical], ["high", c.high], ["medium", c.medium], ["low", c.low], ["info", c.info],
      ["mitre_coverage_pct", coverageLabel(model.summary)]
    ]));
  }
  if (sections.has("alerts")) blocks.push(csvBlock("ALERTS", ["severity", "score", "title", "process", "policy", "timestamp"], model.alerts.map((a) => [a.severity, a.score, a.title, a.process, a.policy, a.timestamp])));
  if (sections.has("events")) blocks.push(csvBlock("EVENTS", ["type", "process", "policy", "detail", "timestamp"], model.events.map((e) => [e.type, e.process, e.policy, e.detail, e.timestamp])));
  if (sections.has("decisions")) blocks.push(csvBlock("DECISIONS", ["action", "state", "target", "reason", "outcome", "timestamp"], model.decisions.map((d) => [d.action, d.state, d.target, d.reason, d.outcome, d.timestamp])));
  if (sections.has("iocs")) blocks.push(csvBlock("IOCS", ["type", "value", "count"], [
    ...model.iocs.ips.map(([v, n]) => ["ip", v, n] as Array<string | number>),
    ...model.iocs.files.map(([v, n]) => ["file", v, n] as Array<string | number>),
    ...model.iocs.binaries.map(([v, n]) => ["binary", v, n] as Array<string | number>)
  ]));
  if (sections.has("mitre")) blocks.push(csvBlock("MITRE_OBSERVED", ["technique", "name", "hits", "detected_by"], model.mitre.observed.map((m) => [m.id, m.name, m.hits, m.policy])));
  triggerDownload(new Blob([blocks.join("\n")], { type: "text/csv;charset=utf-8" }), "soc-export.csv");
}

async function exportPdf(model: ExportModel, sections: Set<ExportSection>) {
  const { jsPDF, autoTable } = await loadPdfTools();
  const doc = new jsPDF({ orientation: "portrait", unit: "pt" });
  const W = doc.internal.pageSize.getWidth();
  const M = 40;
  const NAVY: [number, number, number] = [20, 31, 48];
  const RED: [number, number, number] = [240, 85, 107];
  const BLUE: [number, number, number] = [47, 129, 247];
  const AMBER: [number, number, number] = [225, 181, 62];
  const GREY: [number, number, number] = [140, 148, 158];

  doc.setFillColor(...NAVY);
  doc.rect(0, 0, W, 76, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("eBPF SOC — Incident Report", M, 34);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(`${model.meta.host} · ${model.meta.user}   ·   ${model.meta.scope}   ·   Generated ${model.meta.generated}`, M, 52);
  doc.text(`Window: ${model.meta.rangeFrom} → ${model.meta.rangeTo}   ·   build ${model.meta.sha}`, M, 65);

  let y = 96;
  if (sections.has("summary")) {
    const tiles: Array<[string, string, [number, number, number]]> = [
      [`${model.summary.risk}`, "Risk score / 100", model.summary.risk >= 45 ? RED : BLUE],
      [`${model.summary.total}`, `Alerts · ${model.summary.counts.critical} crit`, RED],
      [coverageLabel(model.summary), "ATT&CK coverage", BLUE],
      [`${model.summary.iocs}`, "IOCs extracted", AMBER]
    ];
    const tileW = (W - M * 2 - 30) / 4;
    tiles.forEach(([big, small, color], i) => {
      const x = M + i * (tileW + 10);
      doc.setDrawColor(225); doc.setFillColor(248, 249, 251);
      doc.roundedRect(x, y, tileW, 50, 5, 5, "FD");
      doc.setTextColor(...color); doc.setFont("helvetica", "bold"); doc.setFontSize(20);
      doc.text(big, x + 10, y + 26);
      doc.setTextColor(90, 98, 110); doc.setFont("helvetica", "normal"); doc.setFontSize(7.5);
      doc.text(small, x + 10, y + 40);
    });
    y += 74;
  }

  const finalY = () => {
    // @ts-expect-error autoTable augments doc at runtime
    return (doc.lastAutoTable?.finalY ?? y) as number;
  };
  const heading = (text: string, color: [number, number, number] = NAVY) => {
    if (finalY() > doc.internal.pageSize.getHeight() - 90) doc.addPage();
    const at = Math.max(y, finalY() + 22);
    doc.setTextColor(...color); doc.setFont("helvetica", "bold"); doc.setFontSize(12);
    doc.text(text, M, at);
    return at + 8;
  };

  if (sections.has("mitre")) {
    let ty = heading("Coverage by tactic");
    doc.setFontSize(8); doc.setFont("helvetica", "normal");
    for (const t of model.mitre.tactics) {
      const frac = t.covered / t.total;
      doc.setTextColor(60, 68, 80); doc.text(t.name, M, ty + 8);
      const barX = M + 150, barW = W - M - barX - 46;
      doc.setFillColor(235, 237, 240); doc.roundedRect(barX, ty, barW, 9, 2, 2, "F");
      if (frac > 0) { doc.setFillColor(...(t.observed > 0 ? RED : BLUE)); doc.roundedRect(barX, ty, Math.max(3, barW * frac), 9, 2, 2, "F"); }
      doc.setTextColor(...GREY); doc.text(`${t.covered}/${t.total}`, barX + barW + 8, ty + 8);
      ty += 16;
    }
    y = ty + 4;
  }

  if (sections.has("alerts")) {
    autoTable(doc, {
      startY: heading("Alerts"),
      head: [["Sev", "Score", "Title", "Process", "Policy", "Time"]],
      body: (model.alerts.length ? model.alerts.slice(0, 200) : [{ severity: "—", score: 0, title: "No alerts in scope", process: "", policy: "", timestamp: "" }]).map((a) => [a.severity, String(a.score), a.title, a.process, a.policy, a.timestamp]),
      styles: { fontSize: 7.5, cellPadding: 4, textColor: [40, 48, 60] }, headStyles: { fillColor: NAVY, textColor: [255, 255, 255] },
      columnStyles: { 1: { halign: "right", cellWidth: 34 } }, margin: { left: M, right: M }
    });
  }
  if (sections.has("iocs")) {
    const rows = [
      ...model.iocs.ips.map(([v, n]) => ["ip", v, String(n)]),
      ...model.iocs.files.slice(0, 20).map(([v, n]) => ["file", v, String(n)]),
      ...model.iocs.binaries.slice(0, 20).map(([v, n]) => ["binary", v, String(n)])
    ];
    autoTable(doc, {
      startY: heading("Indicators of compromise", AMBER),
      head: [["Type", "Indicator", "Hits"]],
      body: rows.length ? rows : [["—", "none observed", "0"]],
      styles: { fontSize: 8, cellPadding: 4 }, headStyles: { fillColor: AMBER, textColor: NAVY },
      columnStyles: { 2: { halign: "right", cellWidth: 40 } }, margin: { left: M, right: M }
    });
  }
  if (sections.has("decisions")) {
    autoTable(doc, {
      startY: heading("Enforcement decisions"),
      head: [["Action", "State", "Target", "Reason", "Time"]],
      body: (model.decisions.length ? model.decisions.slice(0, 120) : [{ action: "—", state: "", target: "no decisions logged", reason: "", ok: true, timestamp: "" }]).map((d) => [d.action, d.state, d.target, d.reason, d.timestamp]),
      styles: { fontSize: 7.5, cellPadding: 4 }, headStyles: { fillColor: NAVY, textColor: [255, 255, 255] }, margin: { left: M, right: M }
    });
  }
  if (sections.has("events")) {
    autoTable(doc, {
      startY: heading("Events"),
      head: [["Type", "Process", "Policy", "Detail", "Time"]],
      body: model.events.slice(0, 150).map((e) => [e.type, e.process, e.policy, e.detail, e.timestamp]),
      styles: { fontSize: 7, cellPadding: 3 }, headStyles: { fillColor: NAVY, textColor: [255, 255, 255] }, margin: { left: M, right: M }
    });
  }

  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setTextColor(...GREY); doc.setFontSize(8);
    doc.text("eBPF SOC · incident report", M, doc.internal.pageSize.getHeight() - 20);
    doc.text(`Page ${p} of ${pages}`, W - M - 60, doc.internal.pageSize.getHeight() - 20);
  }
  doc.save("soc-incident-report.pdf");
}

/**
 * Export studio — assemble a report instead of blindly downloading a flat alert
 * dump. The operator picks the SECTIONS (summary, alerts, events, decisions,
 * IOCs, ATT&CK coverage), the FORMAT (a board-ready PDF, a per-section CSV, or a
 * machine-readable JSON bundle), and a SCOPE (what's on screen vs the whole
 * window), sees a live preview of exactly what the file will contain, and can
 * copy the IOCs or a Markdown summary straight into a ticket. Presets snap it to
 * an incident report, a shift handoff, a threat-intel bundle, or raw telemetry.
 */
function ExportStudioBody({
  filteredAlerts,
  rangeAlerts,
  events,
  decisions,
  policies,
  mitreRows,
  whoami,
  version
}: {
  filteredAlerts: AlertGroup[];
  rangeAlerts: SocAlert[];
  events: SocEvent[];
  decisions: SocDecision[];
  policies: SocPolicy[];
  mitreRows: Array<{ label: string; value: number; meta?: string; id?: string }>;
  whoami: SocWhoami;
  version: SocSnapshot["version"];
}) {
  const [format, setFormat] = useState<ExportFormat>("pdf");
  const [scope, setScope] = useState<"filtered" | "range">("filtered");
  const [sections, setSections] = useState<Set<ExportSection>>(() => new Set<ExportSection>(["summary", "alerts", "iocs", "mitre"]));
  const [copied, setCopied] = useState<string | null>(null);

  const scopeAlerts = scope === "filtered" ? filteredAlerts : rangeAlerts;
  const model = useMemo(
    () => buildExportModel(scope === "filtered" ? "filtered (on screen)" : "full range", scopeAlerts, events, decisions, policies, mitreRows, whoami, version),
    [scope, scopeAlerts, events, decisions, policies, mitreRows, whoami, version]
  );

  const sectionMeta: Array<{ key: ExportSection; label: string; count: number; note: string }> = [
    { key: "summary", label: "Executive summary", count: 1, note: `risk ${model.summary.risk} · ${coverageLabel(model.summary)} coverage` },
    { key: "alerts", label: "Alerts", count: model.summary.total, note: `${model.summary.counts.critical} critical` },
    { key: "events", label: "Events", count: model.events.length, note: "raw telemetry" },
    { key: "decisions", label: "Enforcement decisions", count: model.decisions.length, note: "audit trail" },
    { key: "iocs", label: "Indicators (IOCs)", count: model.summary.iocs, note: `${model.iocs.ips.length} ip · ${model.iocs.files.length} file · ${model.iocs.binaries.length} bin` },
    { key: "mitre", label: "ATT&CK coverage", count: model.mitre.observedCount, note: `${model.mitre.gapCount} blind spots` }
  ];

  const toggle = (s: ExportSection) => setSections((prev) => { const next = new Set(prev); if (next.has(s)) next.delete(s); else next.add(s); return next; });
  const activePreset = EXPORT_PRESETS.find((p) => p.format === format && p.sections.length === sections.size && p.sections.every((s) => sections.has(s)));

  const runExport = () => {
    if (!sections.size) return;
    if (format === "json") exportJson(model, sections);
    else if (format === "csv") exportCsv(model, sections);
    else void exportPdf(model, sections);
  };

  const copy = async (kind: "iocs" | "summary") => {
    let text = "";
    if (kind === "iocs") {
      text = [
        ...model.iocs.ips.map(([v]) => v),
        ...model.iocs.files.map(([v]) => v),
        ...model.iocs.binaries.map(([v]) => v)
      ].join("\n");
    } else {
      const c = model.summary.counts;
      text = [
        `## eBPF SOC summary — ${model.meta.generated}`,
        `- Host: ${model.meta.host} · Scope: ${model.meta.scope}`,
        `- Risk: **${model.summary.risk}/100**`,
        `- Alerts: ${model.summary.total} (${c.critical} critical, ${c.high} high, ${c.medium} medium)`,
        `- ATT&CK coverage: ${coverageLabel(model.summary)} · ${model.mitre.gapCount} blind spots`,
        `- IOCs: ${model.iocs.ips.length} IP, ${model.iocs.files.length} file, ${model.iocs.binaries.length} binary`,
        model.mitre.observed.length ? `- Top technique: ${model.mitre.observed[0].id} ${model.mitre.observed[0].name} (${model.mitre.observed[0].hits} hits)` : ""
      ].filter(Boolean).join("\n");
    }
    try { await navigator.clipboard.writeText(text); setCopied(kind); window.setTimeout(() => setCopied(null), 1500); } catch { /* clipboard unavailable */ }
  };

  return (
    <div className="soc-export">
      <div className="soc-export-presets">
        <span className="soc-stat-label">Template</span>
        {EXPORT_PRESETS.map((p) => (
          <button
            key={p.key}
            type="button"
            className={cx("soc-export-preset", activePreset?.key === p.key && "is-active")}
            onClick={() => { setFormat(p.format); setSections(new Set(p.sections)); }}
            title={p.hint}
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className="soc-export-cols">
        <div className="soc-export-build">
          <div className="soc-export-row">
            <span className="soc-stat-label">Format</span>
            <div className="soc-export-format">
              {([["pdf", "PDF report", FileText], ["csv", "CSV", Download], ["json", "JSON", Braces]] as const).map(([f, label, Icon]) => (
                <button key={f} type="button" className={cx("soc-export-fmt", format === f && "is-active")} onClick={() => setFormat(f)}>
                  <Icon size={13} aria-hidden="true" /> {label}
                </button>
              ))}
            </div>
          </div>

          <div className="soc-export-row">
            <span className="soc-stat-label">Scope</span>
            <div className="soc-export-format">
              <button type="button" className={cx("soc-export-fmt", scope === "filtered" && "is-active")} onClick={() => setScope("filtered")}>On screen ({filteredAlerts.length})</button>
              <button type="button" className={cx("soc-export-fmt", scope === "range" && "is-active")} onClick={() => setScope("range")}>Full range ({rangeAlerts.length})</button>
            </div>
          </div>

          <div className="soc-export-sections">
            <span className="soc-stat-label">Include</span>
            {sectionMeta.map((s) => (
              <button key={s.key} type="button" className={cx("soc-export-section", sections.has(s.key) && "is-on")} onClick={() => toggle(s.key)}>
                <span className="soc-export-check">{sections.has(s.key) ? <Check size={12} /> : null}</span>
                <span className="soc-export-section-label">{s.label}</span>
                <span className="soc-export-section-count">{s.count}<em>{s.note}</em></span>
              </button>
            ))}
          </div>
        </div>

        <div className="soc-export-preview">
          <span className="soc-stat-label">Preview</span>
          <div className="soc-export-preview-file">
            <FileText size={26} aria-hidden="true" />
            <div>
              <strong>soc-{format === "pdf" ? "incident-report.pdf" : format === "csv" ? "export.csv" : "export.json"}</strong>
              <em>{sections.size} section{sections.size === 1 ? "" : "s"} · {model.meta.scope}</em>
            </div>
          </div>
          <ul className="soc-export-preview-list">
            {sectionMeta.filter((s) => sections.has(s.key)).map((s) => (
              <li key={s.key}><b>{s.count}</b> {s.label.toLowerCase()}</li>
            ))}
            {!sections.size ? <li className="soc-export-preview-empty">Select at least one section</li> : null}
          </ul>
          <div className="soc-export-preview-meta">
            {model.meta.host} · {model.meta.user}<br />
            {model.meta.rangeFrom} → {model.meta.rangeTo}
          </div>
        </div>
      </div>

      <div className="soc-export-actions">
        <button type="button" className="soc-export-run" disabled={!sections.size} onClick={runExport}>
          <Download size={14} aria-hidden="true" /> Export {format.toUpperCase()}
        </button>
        <button type="button" className="soc-export-copy" onClick={() => void copy("iocs")}>
          {copied === "iocs" ? <><Check size={13} /> Copied</> : <><Copy size={13} /> Copy IOCs</>}
        </button>
        <button type="button" className="soc-export-copy" onClick={() => void copy("summary")}>
          {copied === "summary" ? <><Check size={13} /> Copied</> : <><Copy size={13} /> Copy summary</>}
        </button>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────── D3 correlation graph */

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
  // Mark nodes whose processes are already held on the ladder. Keyed by node id,
  // valued by the HIGHEST rung among that node's processes. Applied through the
  // same restyle pass as selection, so a 5s containment refresh never disturbs
  // the running simulation.
  setContained: (byNode: Map<string, Rung>) => void;
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
  let containedByNode = new Map<string, Rung>();

  const searchableNodeText = (node: GraphNode) => `${node.label} ${node.fullLabel || ""}`.toLowerCase();

  // Adjacency, rebuilt on each structural change, powers neighbourhood highlight
  // when a node is selected and the radial grouping order.
  let adjacency = new Map<string, Set<string>>();
  const rebuildAdjacency = () => {
    adjacency = new Map();
    for (const lnk of links) {
      const s = typeof lnk.source === "object" ? lnk.source.id : String(lnk.source);
      const t = typeof lnk.target === "object" ? lnk.target.id : String(lnk.target);
      // get-or-create, so the set is a value the compiler can see rather than a
      // `Map.get(...)!` asserted non-null on the render path.
      const sourceEdges = adjacency.get(s) ?? new Set<string>();
      const targetEdges = adjacency.get(t) ?? new Set<string>();
      adjacency.set(s, sourceEdges);
      adjacency.set(t, targetEdges);
      sourceEdges.add(t);
      targetEdges.add(s);
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
  const GROUP_RING: Record<GraphNode["group"], number> = { process: 0.34, policy: 0.6, file: 0.82, device: 0.9, peer: 0.95 };
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
      // Containment was previously legible only after clicking a node and
      // reading its process list, so on a graph of any size an operator could
      // not see WHICH processes were already held — the question they ask first
      // during triage. The rung rides on the node as a data attribute so the
      // marker is styled in CSS per rung, in both themes.
      .classed("is-contained", (d) => containedByNode.has(d.id))
      .attr("data-rung", (d) => containedByNode.get(d.id) ?? null)
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
    setContained: (byNode: Map<string, Rung>) => {
      containedByNode = byNode;
      restyle();
    },
    controls: {
      zoomIn: () => void svg.transition().duration(200).call(zoom.scaleBy, 1.3),
      zoomOut: () => void svg.transition().duration(200).call(zoom.scaleBy, 1 / 1.3),
      reset: () => void svg.transition().duration(250).call(zoom.transform, d3.zoomIdentity),
      fit
    }
  };
}

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

  // Recover from a premature "empty" verdict.
  //
  // The graph is built once, and the live updater above only runs once it is
  // "ready". So if the surface is opened before the alert buffer has landed,
  // the build finds nothing, latches "empty", and stays empty forever — no
  // amount of incoming data brings it back, because nothing re-triggers the
  // build. Opening the graph a few seconds later showed 61 nodes; opening it
  // immediately showed none, permanently. Watch for data arriving and rebuild.
  useEffect(() => {
    if (!active || phase !== "empty") return undefined;
    const timer = window.setTimeout(() => {
      if (buildFiltered().nodes.length > 0) setRefreshKey((key) => key + 1);
    }, 700);
    return () => window.clearTimeout(timer);
  }, [active, phase, liveSignature, buildFiltered]);

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

  // The drilled-into process (level 2 of the panel). Cleared whenever the
  // selected node changes so you never act on a process from a previous node.
  const [drill, setDrill] = useState<ProcessInstance | null>(null);
  useEffect(() => {
    setDrill(null);
  }, [selected?.id]);

  // Live ladder state, keyed by exec_id. Refreshed while the panel is open so a
  // rung that was just applied (or applied autonomously by the scorer) is
  // reflected rather than the operator acting on a stale picture.
  const [circuits, setCircuits] = useState<Map<string, ChokeCircuit>>(new Map());
  // Q1: a binary node can stand for 50+ processes, most of them identical at a
  // glance. Rather than an arbitrary cap that hides work, the list scrolls and
  // is filterable, and "contained only" answers the question an operator
  // actually has during triage: what is already held, and what is not?
  const [procFilter, setProcFilter] = useState("");
  const [containedOnly, setContainedOnly] = useState(false);

  const refreshCircuits = useCallback(async () => {
    const list = await fetchChokeCircuits();
    setCircuits(new Map(list.map((c) => [c.execId, c])));
  }, []);

  useEffect(() => {
    if (!active) return;
    void refreshCircuits();
    const timer = window.setInterval(() => void refreshCircuits(), 5000);
    return () => window.clearInterval(timer);
  }, [active, refreshCircuits]);

  // Put containment on the CANVAS, not only in the drill-in.
  //
  // The rung was already fetched above and every node already carries its
  // processes, so this is a join rather than another request. Without it the
  // only way to learn which processes are held is to click each node in turn
  // and read its list — on a graph of any size that is the first question an
  // operator has and the slowest one to answer. Pushed through the handle's
  // restyle path (like selection and search) so a 5s refresh re-marks nodes
  // without restarting the force simulation and scattering the layout.
  useEffect(() => {
    if (phase !== "ready") return;
    const byNode = new Map<string, Rung>();
    for (const graphNode of lastDataRef.current.nodes) {
      for (const proc of graphNode.processes ?? []) {
        const state = circuits.get(proc.execId)?.state;
        if (!state || state === "pristine") continue;
        // A binary node stands for many processes; the node reports the most
        // severe rung among them, so a single severed child is never hidden
        // behind a dozen merely-throttled siblings.
        const current = byNode.get(graphNode.id);
        if (!current || ladderIndex(state) > ladderIndex(current)) byNode.set(graphNode.id, state as Rung);
      }
    }
    handleRef.current?.setContained(byNode);
  }, [circuits, phase]);

  useEffect(() => {
    setProcFilter("");
    setContainedOnly(false);
  }, [selected?.id]);

  const drillState = drill ? circuits.get(drill.execId)?.state ?? "pristine" : "pristine";

  // Transport for the shared ladder. The component owns the interaction (reason,
  // confirm, dispatch-vs-confirmed polling); the page owns how a process is
  // addressed and read back.
  const applyToProcess = useCallback(
    async (rung: Rung, why: string) => {
      if (!drill) return { ok: false, detail: "no process selected" };
      return applyChokeAction(
        ACTION_FOR_RUNG[rung] as ChokeAction,
        { execId: drill.execId, pid: drill.pid, binary: drill.binary },
        why
      );
    },
    [drill]
  );

  const readProcessState = useCallback(async () => {
    if (!drill) return undefined;
    const list = await fetchChokeCircuits();
    setCircuits(new Map(list.map((c) => [c.execId, c])));
    // Undefined (rather than "pristine") when the circuit is gone — the ladder
    // reads absence as "released", which is exactly what it means here.
    return list.find((c) => c.execId === drill.execId)?.state;
  }, [drill]);

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

  // Every node answers the same question: "which processes are behind this?"
  // A process node answers with its own instances; a policy/file/peer node is
  // evidence, so it answers with the processes it is wired to. Resolving via
  // edges (rather than copying instances onto context nodes) keeps one source
  // of truth and stops the same process appearing with stale data on five dots.
  const nodeProcesses = useMemo<ProcessInstance[]>(() => {
    if (!selected) return [];
    const source = selected.group === "process" ? [selected] : neighbours.filter((n) => n.group === "process");
    const byExec = new Map<string, ProcessInstance>();
    for (const node of source) {
      for (const proc of node.processes ?? []) {
        const existing = byExec.get(proc.execId);
        if (!existing || proc.score > existing.score) byExec.set(proc.execId, proc);
      }
    }
    return [...byExec.values()].sort((a, b) => b.score - a.score);
  }, [selected, neighbours]);

  const visibleProcesses = useMemo(() => {
    const q = procFilter.trim().toLowerCase();
    return nodeProcesses.filter((proc) => {
      if (containedOnly) {
        const state = circuits.get(proc.execId)?.state;
        if (!state || state === "pristine") return false;
      }
      if (!q) return true;
      return String(proc.pid ?? "").includes(q) || proc.execId.toLowerCase().includes(q);
    });
  }, [nodeProcesses, procFilter, containedOnly, circuits]);

  if (!active) {
    return <EmptyState title="Graph paused" detail="Open the correlation graph to load the D3 graph engine." />;
  }

  return (
    <div className={cx("soc-graph-shell", maximized && "is-maximized")}>
      <div className="soc-graph-main">
        <GraphBrief alerts={alerts} events={events} topProcesses={topProcesses} meta={meta} live={live} />
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
          <span className="node-device"><i />device</span>
          <span className="node-peer"><i />peer</span>
          {/* The ring is a different kind of fact from the fills above — those
              say how suspicious a node looks, this says what has been DONE to
              it. Named "contained" rather than by rung because one swatch
              stands for the whole ladder; the exact rung is on the node and in
              the detail panel. */}
          <span className="node-contained"><i />contained</span>
        </div>
      </div>

      <GraphSelectionRail
        selected={selected}
        neighbours={neighbours}
        nodeProcesses={nodeProcesses}
        visibleProcesses={visibleProcesses}
        procFilter={procFilter}
        onProcFilterChange={setProcFilter}
        containedOnly={containedOnly}
        onToggleContainedOnly={() => setContainedOnly((v) => !v)}
        circuits={circuits}
        drillExecId={drill?.execId}
        onPickProcess={setDrill}
        onSelectNode={(id) => handleRef.current?.setSelected(id)}
      />

      {/* Click node → list → click a process → this modal. Rendered last so it
          layers over the whole shell; the rail list stays visible underneath. */}
      {drill ? (
        <ProcessActionModal
          drill={drill}
          state={drillState}
          nodeLabel={selected?.fullLabel || selected?.label || drill.binary}
          apply={applyToProcess}
          readState={readProcessState}
          onClose={() => setDrill(null)}
        />
      ) : null}
    </div>
  );
}
