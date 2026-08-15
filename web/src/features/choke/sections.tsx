// The route's fixed furniture: the two-row top bar, the banners that interrupt
// it, the change-control queue, the active-filter strip and the status bar.
//
// These are split out as ordered siblings rather than one <Chrome> component
// on purpose — the sequence they appear in is the page's priority order, and
// keeping each one addressable means a banner can be added or removed without
// touching the others' markup.
import { ArrowLeft } from "lucide-react";
import type { ApprovalRequest } from "./api";
import type { ChokeState, Decision, KernelPosture, LoadState } from "./types";
import type { PopoverName, StreamInfo } from "./constants";
import { PRESET_DESCRIPTIONS, formatWindow } from "./constants";
import { formatRelative, formatUptime, shortExec } from "./utils";
import { Banner, FilterChip, SegmentedControl } from "./components";
import { NotificationDot } from "./notifications";

export function ChokeTopBar({
  isFleetConsole,
  globalSearch,
  onGlobalSearch,
  mode,
  popover,
  onPopover,
  hostState,
  chokeState,
  streamInfo,
  alertsActive,
  alertBadgeEnabled,
  decisions,
  ackedDecisionIds,
  alertsClearedAt,
  onToggleNotifications,
  onToggleProfile,
  userLabel,
  windowOptions,
  windowMin,
  onWindowMin,
  disabled,
  onPreset,
  trackedCount,
  refreshing,
  onRefreshAll,
  onJail,
}: {
  isFleetConsole: boolean;
  globalSearch: string;
  onGlobalSearch: (value: string) => void;
  mode: string;
  popover: PopoverName;
  onPopover: (next: PopoverName) => void;
  hostState: string;
  chokeState: ChokeState | null;
  streamInfo: StreamInfo;
  alertsActive: boolean;
  alertBadgeEnabled: boolean;
  decisions: Decision[];
  ackedDecisionIds: Set<number>;
  alertsClearedAt: number;
  onToggleNotifications: () => void;
  onToggleProfile: () => void;
  userLabel: string;
  windowOptions: number[];
  windowMin: number;
  onWindowMin: (value: number) => void;
  disabled: boolean;
  onPreset: (name: string) => void;
  trackedCount: number;
  refreshing: boolean;
  onRefreshAll: () => void;
  onJail: () => void;
}) {
  return (
    <header className="choke-topbar">
      <div className="choke-topbar-row choke-topbar-primary" data-panel="topbar-row-1">
        <div className="choke-brand">
          <a href="/" className="choke-back" title="Back to SOC dashboard">
            <ArrowLeft size={15} aria-hidden="true" />
            <span>SOC</span>
          </a>
          <span className="choke-brand-divider" aria-hidden="true" />
          <span className="choke-brand-mark">Choke Gateway</span>
          {/* Which deployment am I looking at? The engine and the console
              serve identical page titles on all four routes, so with both
              open nothing on screen distinguishes a single host from the
              whole fleet — and the actions differ. Cheap to render, and it
              removes a way to act on the wrong system. */}
          <span
            className={`choke-deployment-tag ${isFleetConsole ? "fleet" : "engine"}`}
            title={isFleetConsole
              ? "Multi-tenant console — actions fan out to every agent in this tenant"
              : "Single-tenant engine — actions apply to this host only"}
          >
            {isFleetConsole ? "FLEET" : "THIS HOST"}
          </span>
        </div>
        <input
          data-choke-global-search
          className="choke-search"
          value={globalSearch}
          onChange={(event) => onGlobalSearch(event.target.value)}
          placeholder="Search processes, decisions, policies…"
        />
        {/* Status condensed to a colour-dot + one word; full detail on hover/click. */}
        <div className="choke-status-cluster">
          {/* Enforcement mode merged into the status cluster — a quiet dot+label
              glance (amber = detect-only, green = enforcing, red = kill-switch),
              consistent with host/audit/live. The header's ENFORCEMENT control
              remains the actionable toggle. */}
          <button className={`choke-pill choke-mode-glance mode-${mode}`} type="button" onClick={() => onPopover(popover === "mode" ? null : "mode")} title={`enforcement mode: ${mode}`}>
            <span className="choke-dot" /> {mode}
          </button>
          <button className={`choke-pill host-${hostState}`} type="button" onClick={() => onPopover(popover === "host" ? null : "host")} title={`host ${hostState}`}>
            <span className="choke-dot" /> host
          </button>
          <button className={`choke-pill ${chokeState?.audit?.ok === false ? "danger" : "ok"}`} type="button" onClick={() => onPopover(popover === "audit" ? null : "audit")} title={`audit ${chokeState?.audit?.ok === false ? "broken" : "ok"} · ${chokeState?.audit?.total || 0} rows`}>
            <span className={`choke-dot${chokeState?.audit?.ok === false ? " down" : ""}`} /> audit
          </button>
          <button className={`choke-pill stream-${streamInfo.state}`} type="button" onClick={() => onPopover(popover === "live" ? null : "live")} title={`stream ${streamInfo.state}${streamInfo.lastMessageAt ? ` · ${formatRelative(streamInfo.lastMessageAt)}` : ""}`}>
            <span className="choke-dot" /> live
          </button>
        </div>
        {/* Only the essentials stay in the bar; Cmd, Help, Snapshot, Thaw live in the profile menu. */}
        <div className="choke-user-cluster">
          <button className="choke-icon-button" type="button" onClick={onToggleNotifications} aria-label="Notifications">
            Alerts
            {!alertsActive ? (
              <span className="choke-notif-muted">muted</span>
            ) : (
              <NotificationDot decisions={decisions} acked={ackedDecisionIds} clearedAt={alertsClearedAt} enabled={alertBadgeEnabled} />
            )}
          </button>
          <button className="choke-user-pill" type="button" onClick={onToggleProfile} aria-label="Profile and tools">
            <span className="choke-avatar">{userLabel.slice(0, 1).toUpperCase()}</span>
            {userLabel}
          </button>
        </div>
      </div>

      {/* Operations bar — one calm toolbar: time window · audited incident-response
         presets · scope + the few response controls. Replaces the old sparse two-row
         monitor/respond stack. */}
      <div className="choke-topbar-row choke-ops-row" data-panel="topbar-row-2" data-ir="ir-presets-trail-bar">
        <SegmentedControl values={windowOptions} value={windowMin} format={formatWindow} onChange={onWindowMin} />
        <span className="choke-ops-sep" aria-hidden="true" />
        <span className="choke-preset-label">Incident Response</span>
        <div className="choke-preset-group">
          {Object.keys(PRESET_DESCRIPTIONS).map((name) => (
            <button key={name} type="button" onClick={() => onPreset(name)} disabled={disabled} title="Audited incident-response preset">
              {name}
            </button>
          ))}
        </div>
        <div className="choke-ops-trail">
          <span className="choke-scope-pill">{trackedCount} tracked</span>
          <button
            className={`choke-action-button${refreshing ? " is-refreshing" : ""}`}
            type="button"
            disabled={refreshing}
            onClick={onRefreshAll}
          >
            {refreshing ? <span className="choke-spinner" aria-hidden="true" /> : null}
            {refreshing ? "Refreshing" : "Refresh"}
          </button>
          <span className="choke-ops-sep" aria-hidden="true" />
          <button className="choke-action-button" type="button" onClick={onJail} disabled={disabled}>
            Jail Process
          </button>
          {/* Kill-switch + enforcement mode now live in the Containment Command
              header's control cluster — a single home for the consequential
              controls. The Ctrl+Shift+K shortcut and command palette still work. */}
        </div>
      </div>
    </header>
  );
}

export function ChokeBanners({
  loadState,
  staleSeconds,
  onReconnect,
  kernel,
  mode,
  divergedAgents,
  kernelFired,
}: {
  loadState: LoadState;
  staleSeconds: number;
  onReconnect: () => void;
  kernel?: KernelPosture;
  mode: string;
  divergedAgents: string[];
  kernelFired: number;
}) {
  return (
    <>
      {loadState.kind === "disabled" && (
        <Banner dataPanel="disabled-banner" tone="warn" title="Choke gateway disabled">
          {loadState.message || "choke gateway not enabled"}
        </Banner>
      )}
      {loadState.kind === "error" && (
        <Banner dataPanel="route-error-banner" tone="danger" title="Choke route error">
          {loadState.message}
        </Banner>
      )}
      {staleSeconds > 30 && (
        <Banner dataPanel="stale-stream-banner" tone="warn" title={`Stream silent for ${staleSeconds}s`}>
          <button className="choke-inline-button" type="button" onClick={onReconnect}>
            Force reconnect
          </button>
        </Banner>
      )}

      {/* The mode control on this page governs the engine only. A Tetragon
          policy loaded in enforce mode kills regardless of it — unaudited,
          irreversible, and untouched by the kill-switch. If that is happening
          while this page reads detect-only, the page is lying, and nothing else
          it shows can be trusted to describe the host. */}
      {kernel?.diverged && (
        <Banner
          dataPanel="kernel-divergence-banner"
          tone="danger"
          title="Kernel enforcement is armed outside this console"
        >
          This page reports <strong>{mode}</strong>, but{" "}
          {divergedAgents.length === 1 ? "one agent has" : `${divergedAgents.length} agents have`} a Tetragon
          policy loaded in enforce mode. Those kill without a choke decision, leave no audit row, and the
          kill-switch does not reach them.
          {divergedAgents.length > 0 && (
            <> Affected: <code>{divergedAgents.join(", ")}</code>.</>
          )}
          {kernelFired > 0 && (
            <>
              {" "}
              <strong>{kernelFired} enforcement {kernelFired === 1 ? "action has" : "actions have"} already
              fired</strong> — there is no audit record of what was killed.
            </>
          )}
        </Banner>
      )}
    </>
  );
}

// Change-control queue (threat-model EN-2). A quarantine/sever asked for
// by one operator is HELD here until a second approves it. It sits above
// the fold because a pending request means a threat someone judged worth
// killing is still running — the operator needs to see that, not
// discover it later.
export function ApprovalsQueue({
  pendingApprovals,
  onDecide,
}: {
  pendingApprovals: ApprovalRequest[];
  onDecide: (req: ApprovalRequest, approve: boolean) => void;
}) {
  if (pendingApprovals.length === 0) return null;
  return (
    <section className="choke-approvals" data-panel="approvals-queue">
      <header>
        <h2>
          Awaiting approval
          <span className="choke-approvals-count">{pendingApprovals.length}</span>
        </h2>
        <p>
          These destructive actions have <strong>not</strong> been applied. Each needs a second operator
          to approve it — the operator who requested it cannot.
        </p>
      </header>
      <ul>
        {pendingApprovals.map((req) => (
          <li key={req.id} className={req.mine ? "mine" : ""}>
            <div className="choke-approval-what">
              <strong className="choke-approval-action">{req.action.toUpperCase()}</strong>
              <span className="choke-approval-target">
                {req.scope === "fleet"
                  ? "the entire tenant"
                  : `${req.exec_id ? shortExec(req.exec_id) : ""}${req.pid ? ` (pid ${req.pid})` : ""}`}
              </span>
              {req.agent_id && <code className="choke-approval-agent">{req.agent_id}</code>}
            </div>
            <div className="choke-approval-why">
              <span className="choke-approval-requester">{req.requester}</span>
              {req.reason ? <>: “{req.reason}”</> : null}
            </div>
            <div className="choke-approval-actions">
              {req.mine ? (
                <span className="choke-approval-blocked" title="Dual control: you requested this action">
                  you requested this — another operator must approve
                </span>
              ) : (
                <>
                  <button
                    type="button"
                    className="choke-action-button danger"
                    onClick={() => onDecide(req, true)}
                  >
                    Approve &amp; apply
                  </button>
                  <button
                    type="button"
                    className="choke-action-button"
                    onClick={() => onDecide(req, false)}
                  >
                    Deny
                  </button>
                </>
              )}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}

// Silence is not safety. An agent that never reported its policies is
// unknown, not clean, so it must not be quietly folded into a green
// posture — the divergence check above simply cannot see it.
export function KernelPostureBanner({
  kernel,
  agentsSilent,
  agentsTotal,
}: {
  kernel?: KernelPosture;
  agentsSilent: number;
  agentsTotal: number;
}) {
  if (kernel?.diverged || agentsSilent === 0) return null;
  return (
    <Banner
      dataPanel="kernel-posture-unknown-banner"
      tone="warn"
      title="Kernel posture unverified"
    >
      {agentsSilent} of {agentsTotal} agents did not report their Tetragon policies, so this console
      cannot confirm whether kernel-level enforcement is armed on them. Usually an agent predating the
      field, or one that cannot reach Tetragon.
    </Banner>
  );
}

// Active-filter bar only exists while something is filtered — no empty
// "Filters none" band taking up a row in the common case.
export function ActiveFilterStrip({
  globalSearch,
  procFilter,
  tapeFilterExec,
  onGlobalSearch,
  onProcFilter,
  onTapeFilterExec,
}: {
  globalSearch: string;
  procFilter: string;
  tapeFilterExec: string | null;
  onGlobalSearch: (value: string) => void;
  onProcFilter: (value: string) => void;
  onTapeFilterExec: (value: string | null) => void;
}) {
  if (!globalSearch && !procFilter && !tapeFilterExec) return null;
  return (
    <section className="choke-filter-strip" data-panel="active-filter-strip">
      <span>Active filters</span>
      {globalSearch ? <FilterChip label={`search: ${globalSearch}`} onClear={() => onGlobalSearch("")} /> : null}
      {procFilter ? <FilterChip label={`process: ${procFilter}`} onClear={() => onProcFilter("")} /> : null}
      {tapeFilterExec ? <FilterChip label={`exec: ${shortExec(tapeFilterExec)}`} onClear={() => onTapeFilterExec(null)} /> : null}
      <button className="choke-inline-button" type="button" onClick={() => { onGlobalSearch(""); onProcFilter(""); onTapeFilterExec(null); }}>
        Clear all
      </button>
    </section>
  );
}

export function ChokeStatusBar({
  streamInfo,
  chokeState,
  mode,
  trackedCount,
  decisions,
  userLabel,
  uptimeMs,
  onCopyAuditHead,
}: {
  streamInfo: StreamInfo;
  chokeState: ChokeState | null;
  mode: string;
  trackedCount: number;
  decisions: Decision[];
  userLabel: string;
  uptimeMs: number;
  onCopyAuditHead: () => void;
}) {
  return (
    <footer className="choke-opsbar" data-panel="operations-status-bar">
      <span className={`choke-dot ${streamInfo.state}`} />
      <span>chain <button type="button" onClick={onCopyAuditHead}>{chokeState?.audit?.ok === false ? `broken @ ${chokeState.audit.bad_at || "?"}` : (chokeState?.audit?.head_hash || `${chokeState?.audit?.total || 0} rows`).toString().slice(0, 18)}</button></span>
      <span>mode <strong>{String(mode).toUpperCase()}</strong></span>
      <span>scope <strong>{trackedCount}</strong></span>
      <span>tape <strong>{decisions.length}</strong></span>
      <span>session <strong>{userLabel}</strong> · {formatUptime(uptimeMs)}</span>
    </footer>
  );
}
