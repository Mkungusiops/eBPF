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
import { AlertTriangle, Radio, RefreshCw, Search, Server, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { MouseEvent } from "react";
import type * as React from "react";
import { fetchProcessDetail } from "./api";
import { useStream } from "../../lib/stream";
import { useOSTheme } from "../../lib/theme";
import { IconButton, PanelFrame, PopoverCard, SeverityBadge, SlideOver, Sparkline, StatusPill, cx } from "./components";
import { AlertQueue } from "./AlertQueue";
import { DrillPanel } from "./DrillPanel";
import { EventStream } from "./EventStream";
import { ExecutiveBand } from "./ExecutiveBand";
import { PillHostContent, PillLiveContent, PillRiskContent } from "./pills";
import { RightRail } from "./RightRail";
import { SocModals } from "./SocModals";
import { SocNotices } from "./SocNotices";
import { SocSidebar } from "./Sidebar";
import { TimelinePanel } from "./TimelinePanel";
import { AlertContextMenu, AlertPreview } from "./rows";
import { ExecutiveMetricTile } from "./tiles";
import { watchCount } from "./WatchlistBody";
import { applySocStreamBatch, useLocalJsonState, useNow, useSocData } from "./hooks";
import { useSocWindowModel } from "./useSocWindowModel";
import { rangeLabel } from "./format";
import { buildCorrelationGraph, type ProcessInstance } from "./graphModel";
import { RISK_HALF_SCALE_PER_HOUR, riskScoreFromRate } from "./risk";
import { DEFAULT_WATCHLIST, PANELS, SEVERITIES, type AckState, type HoverPreviewState, type ContextMenuState, type KpiDrill, type OpenSurface, type PillSurface, type SortField, type StreamTelemetry } from "./dashboard";
import type { Severity, SocAlert, SocEvent, SocProcessDetail } from "./types";
import "./soc.css";
import { CorrelationGraph } from "./CorrelationGraph";
import { ExportStudioBody } from "./exportStudio";

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
