// Choke Gateway — the surface an operator uses to throttle, tarpit, quarantine
// and SEVER (SIGKILL) a process, and to engage the fleet kill-switch.
//
// This file is the composition root. State lives in the hooks it calls
// (useChokeData · useChokeFilters · useChokePosture · useChokeActions ·
// useChokeShell · useChokeHotkeys), rendering lives in the components it
// mounts, and what stays here is the wiring plus the audit-verdict pair:
// the status-pill popover and the exported board report, kept side by side so
// the three-state chain verdict cannot drift between them. Both must consult
// `supported` before rendering a verdict — src/test/auditHonesty.test.ts reads
// this file's source and fails if either stops doing so.
import React, { useRef } from "react";
import { copyToClipboard, updateThresholds } from "./api";
import { useStream } from "../../lib/stream";
import type { ChokeState, HostPingResult, Thresholds, ToastMessage } from "./types";
import { LADDER } from "../common/enforcement";
import {
  ContainmentCommandHeader,
  ContainmentLadder,
  type CommandMetrics,
} from "../common/ContainmentCommand";
import { PRESET_DESCRIPTIONS, formatWindow, type PopoverName, type StreamInfo } from "./constants";
import { formatRelative } from "./utils";
import { useChokeTheme } from "./hooks";
import { useAlertPrefs, useDrill, useOverlays, useToasts, useViewPrefs } from "./useChokeShell";
import { useChokeData } from "./useChokeData";
import { useChokeFilters } from "./useChokeFilters";
import { useChokePosture } from "./useChokePosture";
import { useChokeActions } from "./useChokeActions";
import { useChokeHotkeys } from "./useChokeHotkeys";
import { usePolicyWorkbench } from "./usePolicyWorkbench";
import { buildCommandItems } from "./commandItems";
import { PopoverHeader } from "./components";
import {
  ActiveFilterStrip,
  ApprovalsQueue,
  ChokeBanners,
  ChokeStatusBar,
  ChokeTopBar,
  KernelPostureBanner,
} from "./sections";
import { AssuranceView } from "./AssuranceView";
import { CommandView } from "./CommandView";
import { ChokeDrawers, ChokeOverlays } from "./overlays";
import "./ChokeRoute.css";

const WINDOW_OPTIONS = [5, 30, 60, 1440, 10080];

export function ChokeRoute(): React.ReactElement {
  const theme = useChokeTheme();
  const sharedStream = useStream();
  const bootMs = useRef(Date.now());

  const { toasts, pushToast } = useToasts();
  const overlays = useOverlays();
  const viewPrefs = useViewPrefs();
  const alertPrefs = useAlertPrefs();
  const drill = useDrill();

  const data = useChokeData({ pushToast, sharedStream });
  const filters = useChokeFilters({
    windowOptions: WINDOW_OPTIONS,
    circuits: data.circuits,
    decisions: data.decisions,
    alerts: data.alerts,
    now: data.now,
    ackedDecisionIds: alertPrefs.ackedDecisionIds,
  });
  const posture = useChokePosture({
    chokeState: data.chokeState,
    circuits: data.circuits,
    approvals: data.approvals,
    whoami: data.whoami,
    hostPings: data.hostPings,
    streamInfo: data.streamInfo,
    loadState: data.loadState,
    now: data.now,
    windowMin: filters.windowMin,
    currentWindowDecisions: filters.currentWindowDecisions,
  });
  const workbench = usePolicyWorkbench(data.circuits);
  const actions = useChokeActions({
    chokeState: data.chokeState,
    setChokeState: data.setChokeState,
    selectedEntries: filters.selectedEntries,
    selectedExecs: filters.selectedExecs,
    setSelectedExecs: filters.setSelectedExecs,
    setConfirm: overlays.setConfirm,
    pushToast,
    refreshAll: data.refreshAll,
    refreshState: data.refreshState,
    refreshApprovals: data.refreshApprovals,
  });
  useChokeHotkeys({ overlays, drill, filters, actions });

  const copyValue = async (value: string) =>
    pushToast((await copyToClipboard(value)) ? "copied" : "copy failed", "ok");
  const ackDecisions = (ids: number[]) => {
    const next = new Set(alertPrefs.ackedDecisionIds);
    ids.forEach((id) => next.add(id));
    alertPrefs.setAckedDecisionIds(next);
  };
  const unackDecisions = (ids: number[]) => {
    const next = new Set(alertPrefs.ackedDecisionIds);
    ids.forEach((id) => next.delete(id));
    alertPrefs.setAckedDecisionIds(next);
  };
  const toggleDensity = () =>
    viewPrefs.setDensity((prev) => (prev === "compact" ? "normal" : "compact"));

  return (
    <div className="choke-route" data-theme={theme}>
      <ChokeTopBar
        isFleetConsole={posture.isFleetConsole}
        globalSearch={filters.globalSearch}
        onGlobalSearch={filters.setGlobalSearch}
        mode={posture.mode}
        popover={overlays.popover}
        onPopover={overlays.setPopover}
        hostState={posture.hostState}
        chokeState={data.chokeState}
        streamInfo={data.streamInfo}
        alertsActive={alertPrefs.alertsActive}
        alertBadgeEnabled={alertPrefs.alertBadgeEnabled}
        decisions={data.decisions}
        ackedDecisionIds={alertPrefs.ackedDecisionIds}
        alertsClearedAt={alertPrefs.alertsClearedAt}
        onToggleNotifications={() => overlays.setNotificationsOpen((open) => !open)}
        onToggleProfile={() => overlays.setProfileOpen((open) => !open)}
        userLabel={posture.userLabel}
        windowOptions={WINDOW_OPTIONS}
        windowMin={filters.windowMin}
        onWindowMin={filters.setWindowMin}
        disabled={posture.disabled}
        onPreset={actions.openPresetConfirm}
        trackedCount={data.chokeState?.tracked || data.circuits.length}
        refreshing={data.refreshing}
        onRefreshAll={() => void data.refreshAll()}
        onJail={() => overlays.setJailOpen(true)}
      />

      {(overlays.popover || overlays.notificationsOpen || overlays.profileOpen) ? (
        <button
          type="button"
          className="choke-floating-scrim"
          aria-label="Close floating panel"
          onClick={() => {
            overlays.setPopover(null);
            overlays.setNotificationsOpen(false);
            overlays.setProfileOpen(false);
          }}
        />
      ) : null}

      <LayeredPanels
        popover={overlays.popover}
        hostPings={data.hostPings}
        streamInfo={data.streamInfo}
        chokeState={data.chokeState}
        mode={posture.mode}
        onPing={() => void data.pingHost()}
        onSnapshot={() => void data.refreshAll()}
        onReconnect={sharedStream.reconnect}
        onAuditVerify={() => void actions.handleAuditVerify()}
        onAuditCopy={() => void actions.copyAuditHead()}
        onModeToggle={actions.openModeConfirm}
        onKillSwitch={actions.openKillSwitchConfirm}
        onPreset={actions.openPresetConfirm}
        onClose={() => overlays.setPopover(null)}
      />

      <ChokeDrawers
        overlays={overlays}
        alertPrefs={alertPrefs}
        viewPrefs={viewPrefs}
        drill={drill}
        decisions={data.decisions}
        userLabel={posture.userLabel}
        theme={theme}
        bootMs={bootMs.current}
        windowMin={filters.windowMin}
        windowOptions={WINDOW_OPTIONS}
        onWindow={filters.setWindowMin}
        onAck={ackDecisions}
        onSnapshot={() => void actions.downloadSnapshot()}
        onThaw={actions.openThawConfirm}
      />

      <ChokeBanners
        loadState={data.loadState}
        staleSeconds={posture.staleSeconds}
        onReconnect={sharedStream.reconnect}
        kernel={posture.kernel}
        mode={posture.mode}
        divergedAgents={posture.divergedAgents}
        kernelFired={posture.kernelFired}
      />

      <ApprovalsQueue pendingApprovals={posture.pendingApprovals} onDecide={(req, approve) => void actions.decideOnApproval(req, approve)} />

      <KernelPostureBanner kernel={posture.kernel} agentsSilent={posture.agentsSilent} agentsTotal={posture.agentsTotal} />

      <ActiveFilterStrip
        globalSearch={filters.globalSearch}
        procFilter={filters.procFilter}
        tapeFilterExec={filters.tapeFilterExec}
        onGlobalSearch={filters.setGlobalSearch}
        onProcFilter={filters.setProcFilter}
        onTapeFilterExec={filters.setTapeFilterExec}
      />

      {/* Containment Command — the shared hero. The UVP made visual: graduated,
          reversible, audited containment, with the Command⇄Assurance lens. */}
      <ContainmentCommandHeader
        metrics={posture.commandMetrics}
        viewMode={viewPrefs.viewMode}
        onViewMode={viewPrefs.setViewMode}
        onToggleMode={() => actions.openModeConfirm(posture.enforceMode !== "enforcing")}
        onKillSwitch={actions.openKillSwitchConfirm}
        disabled={posture.disabled}
      />
      <ContainmentLadder counts={posture.stateCounts} activeRung={filters.activeRung} onRungClick={filters.toggleRungFilter} subject="processes" />

      {viewPrefs.viewMode === "assurance" ? (
        <AssuranceView
          metrics={posture.commandMetrics}
          thresholds={posture.thresholds}
          decisions={filters.currentWindowDecisions}
          windowMin={filters.windowMin}
          topBinaries={filters.topBinaries}
          velocityBuckets={filters.velocityBuckets}
          auditHash={data.chokeState?.audit?.head_hash}
          onVerifyAudit={() => void actions.handleAuditVerify()}
          onCopyAudit={() => void actions.copyAuditHead()}
          onExport={(kind) =>
            exportAssuranceReport(kind, {
              metrics: posture.commandMetrics,
              stateCounts: posture.stateCounts,
              thresholds: posture.thresholds,
              windowMin: filters.windowMin,
              decisionsInWindow: filters.currentWindowDecisions.length,
              topBinaries: filters.topBinaries,
              audit: data.chokeState?.audit,
              user: posture.userLabel,
              pushToast,
            })
          }
        />
      ) : (
        <CommandView
          data={data}
          filters={filters}
          posture={posture}
          workbench={workbench}
          density={viewPrefs.density}
          acked={alertPrefs.ackedDecisionIds}
          onDensity={toggleDensity}
          onCopy={copyValue}
          onAck={ackDecisions}
          onUnack={unackDecisions}
          onManualAction={actions.openManualConfirm}
          onBulkAction={actions.openBulkConfirm}
          onBulkForget={actions.openBulkForgetConfirm}
          onDrill={(execId) => void drill.openDrill(execId)}
          onCommitThresholds={async (next) => {
            await updateThresholds(next);
            pushToast("thresholds committed", "ok");
            await data.refreshState();
          }}
        />
      )}

      <ChokeOverlays
        overlays={overlays}
        drill={drill}
        commandItems={buildCommandItems({
          actions,
          overlays,
          drill,
          viewPrefs,
          circuits: data.circuits,
          isFleetConsole: posture.isFleetConsole,
        })}
        toasts={toasts}
        pushToast={pushToast}
        disabled={posture.disabled}
        onCopy={copyValue}
        refreshAll={data.refreshAll}
        refreshCircuits={data.refreshCircuits}
      />

      <ChokeStatusBar
        streamInfo={data.streamInfo}
        chokeState={data.chokeState}
        mode={posture.mode}
        trackedCount={data.chokeState?.tracked || data.circuits.length}
        decisions={data.decisions}
        userLabel={posture.userLabel}
        uptimeMs={data.now - bootMs.current}
        onCopyAuditHead={() => void actions.copyAuditHead()}
      />
    </div>
  );
}

// The four status-pill popovers. They share one shell and one `popover` state
// so only ever one is open, and so Escape has a single thing to close.
function LayeredPanels({
  popover,
  hostPings,
  streamInfo,
  chokeState,
  mode,
  onPing,
  onSnapshot,
  onReconnect,
  onAuditVerify,
  onAuditCopy,
  onModeToggle,
  onKillSwitch,
  onPreset,
  onClose,
}: {
  popover: PopoverName;
  hostPings: HostPingResult[];
  streamInfo: StreamInfo;
  chokeState: ChokeState | null;
  mode: string;
  onPing: () => void;
  onSnapshot: () => void;
  onReconnect: () => void;
  onAuditVerify: () => void;
  onAuditCopy: () => void;
  onModeToggle: (enforcing: boolean) => void;
  onKillSwitch: () => void;
  onPreset: (name: string) => void;
  onClose: () => void;
}) {
  if (!popover) return null;
  return (
    <div className="choke-popover" data-panel={`pill-popover-${popover}`} role="dialog" aria-modal="false">
      {popover === "host" ? (
        <>
          <PopoverHeader title="Host reachability" onClose={onClose} />
          <div className="choke-kv-list">
            {hostPings.map((ping) => (
              <div key={ping.path}><span>{ping.path}</span><strong>{ping.ok ? "ok" : `down ${ping.status || ""}`} · {ping.rtt_ms}ms</strong></div>
            ))}
          </div>
          <div className="choke-popover-actions">
            <button type="button" onClick={onPing}>Ping all</button>
          </div>
        </>
      ) : null}
      {popover === "live" ? (
        <>
          <PopoverHeader title="Live data stream" onClose={onClose} />
          <div className="choke-kv-list">
            <div><span>state</span><strong>{streamInfo.state}</strong></div>
            <div><span>last message</span><strong>{formatRelative(streamInfo.lastMessageAt)}</strong></div>
            <div><span>retries</span><strong>{streamInfo.retries}</strong></div>
            <div><span>total messages</span><strong>{streamInfo.totalMessages}</strong></div>
            <div><span>msg/sec</span><strong>{(streamInfo.messagesByMinute.length / 60).toFixed(2)}</strong></div>
          </div>
          <div className="choke-popover-actions">
            <button type="button" onClick={onSnapshot}>Snapshot now</button>
            <button type="button" onClick={onReconnect}>Force reconnect</button>
          </div>
        </>
      ) : null}
      {popover === "audit" ? (
        <>
          <PopoverHeader title="Audit chain" onClose={onClose} />
          <div className="choke-kv-list">
            {/* "verified" for a check that never ran is the worst of the three
                answers, and "broken" for a capability this deployment does not
                have is the second worst. Both were reachable here. */}
            <div>
              <span>status</span>
              <strong>
                {chokeState?.audit?.supported === false
                  ? "not maintained here"
                  : chokeState?.audit?.ok === false
                    ? "broken"
                    : "verified"}
              </strong>
            </div>
            <div><span>decisions</span><strong>{chokeState?.audit?.total || 0}</strong></div>
            <div><span>head</span><strong>{String(chokeState?.audit?.head_hash || chokeState?.audit?.head || chokeState?.audit?.tip || "-").slice(0, 32)}</strong></div>
            {chokeState?.audit?.ok === false ? <div><span>bad at</span><strong>{chokeState.audit.bad_at}</strong></div> : null}
          </div>
          <div className="choke-popover-actions">
            <button type="button" onClick={onAuditCopy}>Copy head</button>
            <button type="button" onClick={onAuditVerify}>Re-verify now</button>
          </div>
        </>
      ) : null}
      {popover === "mode" ? (
        <>
          <PopoverHeader title="Enforcement mode" onClose={onClose} />
          <div className="choke-kv-list">
            <div><span>mode</span><strong>{mode}</strong></div>
            <div><span>dry-run</span><strong>{chokeState?.dry_run ? "on" : "off"}</strong></div>
            <div><span>kill-switch</span><strong>{chokeState?.kill_switched ? "engaged" : "standby"}</strong></div>
            <div><span>tracked</span><strong>{chokeState?.tracked || 0}</strong></div>
          </div>
          <div className="choke-popover-actions">
            <button type="button" onClick={() => onModeToggle(mode !== "enforcing")}>{mode === "enforcing" ? "Switch to detect-only" : "Switch to enforcing"}</button>
            <button type="button" onClick={onKillSwitch}>Kill-switch</button>
          </div>
          <div className="choke-chip-row">{Object.keys(PRESET_DESCRIPTIONS).map((name) => <button key={name} type="button" className="choke-chip" onClick={() => onPreset(name)}>{name}</button>)}</div>
        </>
      ) : null}
    </div>
  );
}

// Assurance-lens export: a board-ready printable report, or a machine-readable
// evidence bundle (the audit head hash + posture + containment ladder) for
// audit / cyber-insurance. Both are built from the same live data as the view.
function exportAssuranceReport(
  kind: "report" | "bundle",
  args: {
    metrics: CommandMetrics;
    stateCounts: Record<string, number>;
    thresholds: Thresholds;
    windowMin: number;
    decisionsInWindow: number;
    topBinaries: Array<{ key: string; count: number }>;
    audit: ChokeState["audit"];
    user: string;
    pushToast: (message: string, kind?: ToastMessage["kind"]) => void;
  },
): void {
  const { metrics: commandMetrics, stateCounts, thresholds, windowMin, decisionsInWindow, topBinaries, audit, user: userLabel, pushToast } = args;
  const when = new Date();
  const stamp = when.toISOString().replace(/[:.]/g, "-");
  const headHash = String(audit?.head_hash || audit?.head || "");
  if (kind === "bundle") {
    const bundle = {
      generated_at: when.toISOString(),
      generated_by: userLabel,
      subject: "processes",
      posture: commandMetrics.posture,
      mode: commandMetrics.mode,
      kill_switch: commandMetrics.killSwitched ? "engaged" : "standby",
      active_threats: commandMetrics.activeThreats,
      contained: commandMetrics.contained,
      tracked: commandMetrics.tracked,
      audit: { intact: commandMetrics.auditOk, records: commandMetrics.auditRows, head_hash: headHash || null },
      containment_ladder: LADDER.reduce<Record<string, number>>((acc, r) => ({ ...acc, [r]: stateCounts[r] || 0 }), {}),
      thresholds,
      window_minutes: windowMin,
      decisions_in_window: decisionsInWindow,
      top_binaries: topBinaries.map((b) => ({ binary: b.key, decisions: b.count }))
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `containment-evidence-${stamp}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    pushToast("evidence bundle downloaded", "ok");
    return;
  }
  const html = buildAssuranceReportHtml({
    metrics: commandMetrics,
    stateCounts,
    thresholds,
    decisionsInWindow,
    windowLabel: formatWindow(windowMin),
    topBinaries,
    headHash,
    user: userLabel,
    when
  });
  const win = window.open("", "_blank");
  if (!win) {
    pushToast("popup blocked — allow popups to print the report", "err");
    return;
  }
  win.document.write(html);
  win.document.close();
  pushToast("board report opened — Print → Save as PDF", "ok");
}

function buildAssuranceReportHtml(args: {
  metrics: CommandMetrics;
  thresholds: Thresholds;
  decisionsInWindow: number;
  windowLabel: string;
  stateCounts: Record<string, number>;
  topBinaries: Array<{ key: string; count: number }>;
  headHash: string;
  user: string;
  when: Date;
}): string {
  const { metrics: m, stateCounts, thresholds, decisionsInWindow, windowLabel, topBinaries, headHash, user, when } = args;
  const esc = (s: string) =>
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
  const needing = m.activeThreats + m.contained;
  const coverage = needing === 0 ? 100 : Math.round((m.contained / needing) * 100);
  const tone = m.posture >= 80 ? "#2f9e5e" : m.posture >= 55 ? "#c9871f" : "#d23a4f";
  const rung = (r: string) => stateCounts[r] || 0;
  const topRows =
    topBinaries.length === 0
      ? `<tr><td colspan="2" style="color:#888">no decisions in window</td></tr>`
      : topBinaries.map((b) => `<tr><td>${esc(b.key)}</td><td style="text-align:right">${b.count}</td></tr>`).join("");
  return `<!doctype html><html><head><meta charset="utf-8">
<title>Containment Assurance Report</title>
<style>
  * { box-sizing: border-box; }
  body { font: 13px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; color: #1a2230; margin: 0; padding: 40px; background: #fff; }
  .head { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #1a2230; padding-bottom: 14px; }
  .head h1 { margin: 0; font-size: 22px; letter-spacing: -0.01em; }
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
  .mono { font-family: ui-monospace, Menlo, monospace; font-size: 11px; word-break: break-all; color: #344054; }
  .foot { margin-top: 30px; padding-top: 12px; border-top: 1px solid #e3e7ee; color: #98a2b3; font-size: 11px; }
  @media print { body { padding: 0; } }
</style></head><body>
<div class="head">
  <div>
    <h1>Containment Assurance Report</h1>
    <div class="sub">Process enforcement · generated ${esc(when.toLocaleString())} · by ${esc(user)}</div>
  </div>
  <div class="posture"><div class="num">${m.posture}</div><div class="lbl">Posture / 100</div></div>
</div>
<div class="tiles">
  <div class="tile"><div class="v" style="color:${m.activeThreats ? "#d23a4f" : "#2f9e5e"}">${m.activeThreats}</div><div class="l">Active threats</div></div>
  <div class="tile"><div class="v">${m.contained}</div><div class="l">Contained</div></div>
  <div class="tile"><div class="v">${coverage}%</div><div class="l">Threats contained</div></div>
  <div class="tile"><div class="v" style="color:${m.auditSupported === false ? "#6b7a8c" : m.auditOk ? "#2f9e5e" : "#d23a4f"}">${m.auditSupported === false ? "Not verified here" : m.auditOk ? "Intact" : "BROKEN"}</div><div class="l">Audit chain</div></div>
</div>
<h2>Containment ladder</h2>
<div class="ladder">
  <div class="cell"><div class="c">${rung("pristine")}</div><div class="n">Pristine</div></div>
  <div class="cell"><div class="c">${rung("throttled")}</div><div class="n">Throttled</div></div>
  <div class="cell"><div class="c">${rung("tarpit")}</div><div class="n">Tarpit</div></div>
  <div class="cell"><div class="c">${rung("quarantined")}</div><div class="n">Quarantined</div></div>
  <div class="cell"><div class="c">${rung("severed")}</div><div class="n">Severed</div></div>
</div>
<h2>Enforcement posture</h2>
<table>
  <tr><td>Mode</td><td style="text-align:right">${m.mode === "enforcing" ? "Enforcing" : "Detect-only"}</td></tr>
  <tr><td>Kill-switch</td><td style="text-align:right">${m.killSwitched ? "Engaged" : "Standby"}</td></tr>
  <tr><td>Tracked processes</td><td style="text-align:right">${m.tracked.toLocaleString()}</td></tr>
  <tr><td>Thresholds (throttle / tarpit / quarantine / sever)</td><td style="text-align:right">${thresholds.throttle_at} / ${thresholds.tarpit_at} / ${thresholds.quarantine_at} / ${thresholds.sever_at}</td></tr>
  <tr><td>Decisions in window (${esc(windowLabel)})</td><td style="text-align:right">${decisionsInWindow}</td></tr>
</table>
<h2>Top enforced binaries (${esc(windowLabel)})</h2>
<table><tr><th>Binary</th><th style="text-align:right">Decisions</th></tr>${topRows}</table>
<h2>Evidence anchor</h2>
<p>Audit chain records: <strong>${m.auditRows.toLocaleString()}</strong>. Tamper-evident head hash:</p>
<p class="mono">${esc(headHash || "—")}</p>
<div class="foot">This report is a point-in-time summary of live enforcement state. Every containment decision is recorded in a hash-chained, tamper-evident audit log; the head hash above anchors this report to that chain.</div>
<script>window.onload=function(){setTimeout(function(){window.print();},250);};</script>
</body></html>`;
}

export default ChokeRoute;
