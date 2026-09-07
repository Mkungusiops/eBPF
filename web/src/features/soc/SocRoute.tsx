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
import { MAX_BUFFERED_DECISIONS, fetchProcessDetail, socIdentityOf } from "./api";
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
import { useAssistantChat } from "../assistant/AssistantChatProvider";
import { TimelinePanel } from "./TimelinePanel";
import { AlertContextMenu, AlertPreview } from "./rows";
import { ExecutiveMetricTile } from "./tiles";
import { watchCount } from "./WatchlistBody";
import { alertGroupFor, groupAckState, groupMemberIds, queueExclusions } from "./analytics";
import { applySocStreamBatch, useLocalJsonState, useNow, useSocData } from "./hooks";
import { useSocWindowModel } from "./useSocWindowModel";
import { rangeLabel } from "./format";
import { buildCorrelationGraph, type ProcessInstance } from "./graphModel";
import { RISK_HALF_SCALE_PER_HOUR, riskScoreFromRate } from "./risk";
import { DEFAULT_WATCHLIST, PANELS, SEVERITIES, type AckState, type AlertGroup, type HoverPreviewState, type ContextMenuState, type KpiDrill, type OpenSurface, type PillSurface, type SortField, type StreamTelemetry } from "./dashboard";
import type { Severity, SocEvent, SocProcessDetail } from "./types";
import "./soc.css";
import { CorrelationGraph } from "./CorrelationGraph";
import { ExportStudioBody } from "./exportStudio";
import { estateSubjectOf } from "./pdf";

// The posture curve and the graph builder are re-exported from the route so
// consumers (and the tests that pin their behaviour) keep one entry point for
// the SOC feature.
export { RISK_HALF_SCALE_PER_HOUR, riskScoreFromRate, buildCorrelationGraph };
export type { ProcessInstance };

const NOTHING_EXCLUDED = { query: 0, baseline: 0, unacked: 0 };

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
  // Null when no provider is mounted (tests, or an entry that has not adopted
  // it). Every use is optional-chained so the console renders either way.
  const assistantChat = useAssistantChat();
  const [hideBaseline, setHideBaseline] = useLocalJsonState<boolean>("soc.hideBaseline", true);
  const [filterUnack, setFilterUnack] = useState(false);
  const [groupAlerts, setGroupAlerts] = useLocalJsonState<boolean>("soc.groupAlerts", true);
  const [sortField, setSortField] = useState<SortField>("time");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [ackStates, setAckStates] = useLocalJsonState<Record<string, AckState>>("soc.alertStates", {});
  // useCallback because the global keydown effect depends on it; as a plain
  // function declaration it was a new value every render, re-registering a
  // document-level listener on each one.
  //
  // It takes ONE id or MANY, because a queue row is not always one alert.
  // The queue groups by default, so a row can stand for N alerts while carrying
  // only members[0]'s id. Writing a single ack for it left the siblings
  // outstanding: the row said "Ack'd" and the same alerts came straight back
  // under "Unacked only", which is the view an analyst uses to decide the shift
  // is done. Every ack call site now passes the ids the surface it was clicked
  // on actually claims to cover.
  const setAckState = useCallback(
    (ids: string | string[], value: AckState) => {
      const list = typeof ids === "string" ? [ids] : ids;
      if (!list.length) return;
      setAckStates((current) => {
        const next = { ...current };
        for (const id of list) next[id] = value;
        return next;
      });
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

  // Hand the assistant a way to open Behaviour & Reputation.
  //
  // The chat provider is mounted at the app root, above this component, so it
  // cannot reach this state directly — the route that OWNS the panel registers
  // the opener, and the sidebar shows its link only while one is registered. On
  // a route without the panel the link is never offered, rather than offered and
  // doing nothing.
  useEffect(() => {
    assistantChat?.setFindingsOpener(() => setOpenSurface("behaviour"));
    return () => assistantChat?.setFindingsOpener(null);
  }, [assistantChat]);
  const [openPill, setOpenPill] = useState<PillSurface | null>(null);
  const [kpiDrill, setKpiDrill] = useState<KpiDrill | null>(null);
  // The WHOLE ROW, not its representative alert. The queue hands this state an
  // AlertGroup at runtime and always did; typing it `SocAlert` only hid that,
  // and every triage action taken from the drill panel or the keyboard then
  // wrote members[0] alone while the row behind it — whose state is the
  // least-progressed member — kept reading "New".
  const [drillAlert, setDrillAlert] = useState<AlertGroup | null>(null);
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
        setAckState(groupMemberIds(drillAlert), "ack");
      } else if (event.key.toLowerCase() === "r" && drillAlert) {
        setAckState(groupMemberIds(drillAlert), "resolved");
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
    streamHideNoise,
    streamPaused
  });

  // Which of this panel's filters actually excluded something, for the empty
  // state's copy. Only computed when the queue IS empty — the answer is unused
  // otherwise, and this walks the whole window on a route that re-renders once
  // a second off the clock.
  const queueExcluded = useMemo(
    () =>
      model.filteredAlerts.length
        ? NOTHING_EXCLUDED
        : queueExclusions(model.rangeAlerts, { query, hideBaseline, filterUnack, ackStates }),
    [ackStates, filterUnack, hideBaseline, model.filteredAlerts.length, model.rangeAlerts, query]
  );

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

  // The bulk bar counts SELECTED ROWS, and a selected row can be a group. Ack
  // every member it stands for, for the same reason the per-row button does —
  // "4 selected" acknowledging four of nine alerts is work reported done that
  // is not.
  function applyBulkAck(value: AckState) {
    const resolved = new Set<string>();
    const ids: string[] = [];
    for (const group of model.filteredAlerts) {
      if (!selectedIds.has(group.id)) continue;
      resolved.add(group.id);
      ids.push(...groupMemberIds(group));
    }
    // A selected row the filters have since dropped from the list is still a
    // row the operator selected. Ack its own id rather than silently skipping
    // it — a bulk action that quietly covers fewer rows than the bar counts is
    // the same class of lie as the single-member group ack.
    for (const id of selectedIds) if (!resolved.has(id)) ids.push(id);
    setAckState(ids, value);
    setSelectedIds(new Set());
  }

  // Pinning a grouped row pins every member: the queue sorts BEFORE it groups,
  // so a pin that reached only the representative would leave the row's other
  // alerts sitting wherever the sort put them, and the group would visibly
  // shed members the moment the pin took effect.
  function togglePin(ids: string | string[]) {
    const list = typeof ids === "string" ? [ids] : ids;
    if (!list.length) return;
    setPinnedAlerts((current) => {
      const pinned = list.every((id) => current.includes(id));
      if (pinned) return current.filter((item) => !list.includes(item));
      return [...list.filter((id) => !current.includes(id)), ...current];
    });
  }

  function openKpi(kind: KpiDrill["kind"], title: string) {
    setKpiDrill({ kind, title });
    setOpenSurface("kpi");
  }

  function openDrill(alert: AlertGroup) {
    setDrillAlert(alert);
    setContextMenu(null);
  }

  // Opened from somewhere that holds a bare alert (an event row, the graph).
  // Resolve it back to the queue row it belongs to first, so triaging from here
  // covers the same alerts the row's own buttons do.
  function openDrillByEvent(event: SocEvent) {
    const alert = model.rangeAlerts.find((item) => item.execId && item.execId === event.execId);
    if (alert) openDrill(alertGroupFor(alert, model.filteredAlerts));
  }

  function openDrillByExecId(execId: string) {
    const alert = model.rangeAlerts.find((item) => item.execId === execId);
    if (alert) openDrill(alertGroupFor(alert, model.filteredAlerts));
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

  function onAlertContext(event: MouseEvent, alert: AlertGroup) {
    event.preventDefault();
    const width = typeof window === "undefined" ? 280 : window.innerWidth;
    const height = typeof window === "undefined" ? 220 : window.innerHeight;
    setContextMenu({
      alert,
      x: Math.min(event.clientX, width - 290),
      y: Math.min(event.clientY, height - 230)
    });
  }

  function onAlertHover(event: MouseEvent, alert: AlertGroup) {
    const width = typeof window === "undefined" ? 320 : window.innerWidth;
    setHoverPreview({
      alert,
      x: Math.min(event.clientX + 18, width - 330),
      y: event.clientY + 18
    });
  }

  // WHO IS LOOKING, AND AT WHOSE ESTATE — two facts, and the console used to
  // publish one answer for both. See socIdentityOf and the scope banner below.
  const identity = socIdentityOf(snapshot.whoami);
  // The same two facts for every surface that names a SUBJECT rather than an
  // identity: the executive band's "What is affected", the assistant's scope
  // chip, and the exports. They kept reading `whoami.host`, which for a
  // provider account now says "all tenants" over one customer's rows — the
  // scope banner cannot travel with an exported file, and a chip is read as a
  // caption on the answer beside it. See estateSubjectOf.
  const estate = estateSubjectOf(snapshot.whoami);

  return (
    <div className={cx("soc-route", theme === "light" && "theme-light", sidebarOpen && "sidebar-open")}>
      <SocSidebar
        labMode={snapshot.version.labMode}
        sidebarOpen={sidebarOpen}
        openSurface={openSurface}
        onToggleSidebar={() => setSidebarOpen((value) => !value)}
        onCloseSidebar={() => setSidebarOpen(false)}
        onOpenSurface={openSurfaceByName}
        onOpenAssistant={() => assistantChat?.openAssistant({ scopeLabel: estate.subject })}
        assistantOpen={assistantChat?.open ?? false}
        // null (still probing) counts as AVAILABLE so the nav does not flicker
        // an entry in and straight back out on every load.
        assistantAvailable={assistantChat?.available !== false}
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
          crossTenant={identity.crossTenant}
          viewingTenant={identity.viewingTenant}
          streamState={stream.state}
          openPill={openPill}
          onOpenPill={setOpenPill}
          loading={loading}
          onRefresh={refresh}
        />

        <main className="soc-content">
          {/* THE PROVIDER'S CAPTION.
              A cross-tenant operator holds no tenant of their own, so every
              panel below is resolved by the server to ONE customer — and until
              this banner existed, nothing on the screen said which. The
              provider read one customer's alert count, posture and containment
              history as the state of their whole book of business, and the
              persona probes measured the sharper version: a cross-tenant
              RESPONDER firing containment aimed by a console that had silently
              chosen the tenant for them.
              It is rendered only when the server says cross_tenant, and it
              names viewing_tenant — the tenant the server itself resolves
              these reads to — rather than a tenant the console picked. */}
          {identity.crossTenant ? (
            <div className="soc-scope-banner" role="status">
              <Server size={16} />
              <span>
                <b>Provider view.</b>{" "}
                {identity.viewingTenant
                  ? <>Your account reaches customers by name, not by belonging to one. Every panel below is <b>{identity.viewingTenant}</b>&rsquo;s data only — not the whole estate — and any containment fired from this console lands there.</>
                  : <>Your account reaches customers by name, not by belonging to one. This server has not said which customer these panels resolve to, so treat every reading below as a single tenant&rsquo;s until it does.</>}
              </span>
            </div>
          ) : null}

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
            riskDelta={Math.round(model.riskScore - model.previousRiskScore)}
            riskSaturated={model.riskSaturated}
            riskBaselineRate={model.riskBaselineRate}
            riskPerHour={model.riskPerHour}
            countsUnfounded={model.countsUnfounded}
            // Every count in this band now comes from the same server-side
            // window aggregation the dial and the KPI tiles use, so the cells
            // no longer contradict each other. The floor disclosure remains for
            // the fallback path: a server without /api/alert-stats still leaves
            // the band counting a capped browser buffer.
            countsAreFloor={!model.statsSupported && model.windowCoverage.alerts.short}
            windowLabel={rangeLabel(rangeMin)}
            totalAlerts={model.serverStats ? model.serverStats.total : model.rangeAlerts.length}
            openCritical={model.openContainment.critical}
            openHigh={model.openContainment.high}
            containmentActions={model.decisionStats ? model.decisionStats.total : model.rangeDecisions.length}
            containmentActionsAreFloor={!model.decisionStats ? model.rangeDecisions.length >= MAX_BUFFERED_DECISIONS : model.decisionStats.truncated}
            topTechnique={model.mitreRows[0]}
            techniqueMapped={model.techniqueMapped}
            eps={model.eps}
            activeProcesses={model.activeProcesses.count}
            topProcess={model.activeProcesses.top}
            affectedScope={estate.subject}
            providerView={estate.providerView}
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
              query={query}
              windowAlertCount={model.rangeAlerts.length}
              excluded={queueExcluded}
              beyondWindow={model.beyondWindow.alerts}
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
            heldCount={model.heldEventCount}
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
            ack={groupAckState(drillAlert.members, ackStates)}
            note={alertNotes[drillAlert.id] || ""}
            processDetail={processDetail}
            processDetailError={processDetailError}
            onAck={(value) => setAckState(groupMemberIds(drillAlert), value)}
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
        onAck={(alert) => setAckState(groupMemberIds(alert), "ack")}
        onResolve={(alert) => setAckState(groupMemberIds(alert), "resolved")}
        onPin={(alert) => togglePin(groupMemberIds(alert))}
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
  crossTenant,
  viewingTenant,
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
  crossTenant: boolean;
  viewingTenant?: string;
  streamState: string;
  openPill: PillSurface | null;
  onOpenPill: (pill: PillSurface | null) => void;
  loading: boolean;
  onRefresh: () => void;
}) {
  // The estate identity for a principal that belongs to no tenant. The control
  // plane publishes this in `host`, but the console must not DEPEND on it: the
  // build that shipped the defect published scope[0] there, so a deployment
  // that has not been updated still hands a cross-tenant operator a customer's
  // name to display as their estate. When the label we were given is the very
  // tenant we are captioning underneath it, it is not an estate identity and is
  // not shown as one.
  const estateLabel = crossTenant && (!host || host === viewingTenant) ? "all tenants" : host;

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
        {/* THE ESTATE IDENTITY, WHICH IS NOT ALWAYS A HOST NAME.
            For a tenant-bound operator this pill reads their own tenant, which
            is true. For a cross-tenant one the server publishes an estate label
            here instead of a customer name — it used to publish the first entry
            of a tenant list built out of grants that authorized nothing, which
            put ONE customer's name in the provider's top bar, identical to what
            that customer's own analyst sees.
            The estate label alone would be its own falsehood: the panels
            underneath are one customer's, so a pill reading "all tenants" over
            them claims a breadth the data does not have. Both facts go in the
            pill — reach, then the tenant actually on screen — and the banner at
            the top of the content says it in a sentence. */}
        <button
          type="button"
          className={cx("soc-host-pill", crossTenant && "is-cross-tenant")}
          title={
            crossTenant && viewingTenant
              ? `Provider account: no tenant of its own. These panels show ${viewingTenant} only.`
              : undefined
          }
          onClick={() => onOpenPill(openPill === "host" ? null : "host")}
        >
          <Server size={14} />
          <span>{estateLabel}</span>
          {crossTenant && viewingTenant ? (
            <em className="soc-host-pill-scope">showing {viewingTenant} only</em>
          ) : null}
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
