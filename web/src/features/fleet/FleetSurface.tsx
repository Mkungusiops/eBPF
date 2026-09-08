import { AlertTriangle } from "lucide-react";
import { useState } from "react";

import { useResponseAuthority } from "../soc/api";
import { ConfirmModal } from "./ConfirmModal";
import type { FleetApi } from "./fleetApi";
import { FleetCgroupPanel } from "./FleetCgroups";
import { FleetControlRail } from "./FleetControlRail";
import { FleetFeedRail } from "./FleetFeeds";
import { FleetKpiStrip } from "./FleetKpiStrip";
import { FleetScopeCaption } from "./FleetScopeCaption";
import { FleetHostsPanel } from "./FleetTable";
import { ToastContainer, useFleetToasts } from "./FleetToasts";
import { POLL_MS, useFleetSnapshot } from "./useFleetSnapshot";
import { useFleetControls } from "./useFleetControls";
import "./fleet.css";
import type { ConfirmState, PollStatus } from "./types";

/**
 * The fleet view: every enrolled host's mode, ladder, kill-switch and drift,
 * and the writes that can be scoped to a named subset of them.
 *
 * It was its own console at /fleet — its own HTML entry, its own topbar, its
 * own four-console nav and its own sign-out — which meant an operator drilling
 * from the estate to a customer to that customer's hosts left the console to do
 * it and met a second set of chrome for one job. It is a surface now, the HOSTS
 * rung of the same drill hierarchy, and it lost the second chrome on the way
 * in: the brand line, the console nav and the sign-out are the SOC shell's.
 *
 * WHAT IT DID NOT LOSE, AND MUST NOT: the customer caption. This surface is
 * mounted full screen, over an opaque backdrop that covers the SOC route's own
 * scope banner, and the shell banner mounted on this entry says nothing unless
 * the scope is unconfirmed — so for a while the estate-wide kill-switch below
 * was armed on a page that named no customer at all. FleetScopeCaption states
 * it here, from the same store the shell reads, so the two cannot give two
 * answers.
 *
 * TWO THINGS IT NO LONGER DECIDES FOR ITSELF, and both were the risk in the
 * move:
 *
 *   • WHETHER THIS ACCOUNT MAY WRITE. It used to read /api/whoami through its
 *     own feed and derive `canRespond`/`identityResolved` from it. Inside the
 *     SOC console the answer comes from the shared store every other
 *     containment surface reads (features/soc/api.ts, useResponseAuthority),
 *     which is fed by the route's own whoami. Getting this wrong in either
 *     direction is the defect that took three rounds to fix on the other
 *     surfaces — an armed rail for a read-only account, or a disarmed one for a
 *     single-tenant operator whose server publishes no `can_respond` at all.
 *   • WHETHER IT IS POLLING. The shell mounts this body lazily and then keeps
 *     it, so `open` is passed down to the read path: a closed surface issues no
 *     fan-out at all.
 *
 * The read path (`useFleetSnapshot`), the write path (`useFleetControls`) and
 * the panels below are still separate because they fail separately — a degraded
 * poll must not disable the rail, and a partial fan-out must not stop the poll.
 */
export interface FleetSurfaceProps {
  /**
   * Whether the surface is on screen. Drives the read path's poll — see the
   * note above — and is passed by the shell that hosts it.
   */
  open: boolean;
  /**
   * The read/write client, injectable for the same reason DevicesRoute takes
   * one: a test can drive the whole surface — the rail, the table, the confirm
   * and the write — with no network and no fake timers. Production passes
   * nothing and gets the module-level default, which is stable.
   */
  api?: FleetApi;
  /** Poll cadence; a seam so a test never has to wait five seconds. */
  pollMs?: number;
}

export function FleetSurface({ open, api, pollMs = POLL_MS }: FleetSurfaceProps) {
  // No useOSTheme() here: the theme is applied once by the route that hosts
  // this surface. A second subscription on the same media query would set the
  // same class from two places.
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null);
  const { toasts, pushToast, dismissToast } = useFleetToasts();
  const feed = useFleetSnapshot(pollMs, { api, active: open });
  const { derived, snapshot, pollStatus } = feed;

  // THE SHARED PREDICATE, TRANSLATED ONCE.
  //
  // `useResponseAuthority` carries four states and `useFleetControls` takes the
  // same four as a (boolean | null, boolean) pair, so this is the whole
  // mapping and it is deliberately in one place:
  //
  //   "loading" → identityResolved false. Nothing is armed while the answer is
  //               in flight, and `canRespond` is passed as null rather than
  //               false so the rail says it is CHECKING rather than telling a
  //               responder their account is read-only.
  //   false     → the server refused. Read-only account.
  //   null      → the server answered and published no `can_respond`: the
  //               single-tenant engine, which has no such permission model.
  //               PERMITTED, or every operator on that engine loses the
  //               emergency controls over a field their server never sends.
  //   true      → permitted.
  const authority = useResponseAuthority();
  const identityResolved = !authority.pending;
  const canRespond = authority.canRespond === "loading" ? null : authority.canRespond;

  const controls = useFleetControls({
    peers: snapshot.peers,
    totalHosts: derived.kpis.total,
    majorityThresholds: derived.majorityThresholds,
    pollStatus,
    canRespond,
    identityResolved,
    pushToast,
    refresh: feed.refresh,
    setConfirmState
  });

  return (
    <div className="fleet-app">
      {/* WHOSE hosts these are, then whether what is on screen is current. The
          caption is first because it qualifies everything under it, including
          the kill-switch. */}
      <FleetScopeCaption />
      <FleetPollStatus pollStatus={pollStatus} pollMs={pollMs} lastUpdated={feed.lastUpdated} />

      {feed.disabledMessage ? (
        <section className="fleet-disabled" aria-live="polite">
          <AlertTriangle size={18} />
          <div>
            <strong>Fleet mode is not enabled on this engine</strong>
            <p>
              {feed.disabledMessage}. Start the engine with <code>--fleet-hosts=/path/to/chokectl.hosts</code>
              to enable cross-host control.
            </p>
          </div>
        </section>
      ) : null}

      {feed.pollError ? (
        <section className="fleet-error" aria-live="polite">
          <AlertTriangle size={18} />
          <span>{feed.pollError}</span>
        </section>
      ) : null}

      <FleetKpiStrip kpis={derived.kpis} />

      <main className="fleet-grid">
        <FleetControlRail
          applyMode={controls.applyMode}
          onApplyMode={controls.setApplyMode}
          selectedCount={controls.selected.size}
          writesDisabled={controls.writesDisabled}
          writesDisabledReason={controls.writesDisabledReason}
          onPreset={controls.requestPreset}
          thresholdDraft={controls.thresholdDraft}
          thresholdDirty={controls.thresholdDirty}
          majorityThresholds={derived.majorityThresholds}
          // Hosts that actually ANSWERED, not hosts configured: the reading is
          // a majority over reported ladders, and a peer that never replied
          // voted in nothing.
          reportingHosts={derived.kpis.healthy}
          ladderNote={controls.ladderNote}
          ladderTemporary={controls.ladderTemporary}
          onThreshold={controls.setThreshold}
          onApplyThresholds={() => void controls.applyThresholds()}
          targetCount={controls.targetCount}
          onKillSwitchOn={controls.requestKillSwitchOn}
          onKillSwitchOff={controls.disengageKillSwitch}
          onThaw={controls.requestThaw}
        />

        <section className="fleet-main">
          <FleetHostsPanel
            rows={derived.rows}
            kpis={derived.kpis}
            selected={controls.selected}
            onSelect={controls.selectHost}
            onSelectAll={controls.selectAll}
            onClear={controls.clearSelection}
            onRefresh={() => void feed.refresh()}
            loading={pollStatus === "loading" || pollStatus === "idle"}
          />

          <FleetCgroupPanel peers={snapshot.peers} cgroupByHost={feed.cgroupByHost} />
        </section>

        <FleetFeedRail decisions={feed.decisions} alerts={feed.alerts} />
      </main>

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
      {confirmState ? <ConfirmModal state={confirmState} onClose={() => setConfirmState(null)} /> : null}
    </div>
  );
}

/**
 * Is what I am looking at current?
 *
 * All that survives of the old topbar's status readout, and the only part of it
 * that was ever this surface's own business — the identity, the console nav and
 * the sign-out all belong to the shell now, and the tenant caption is stated
 * beside this one by FleetScopeCaption, from the shell's store. The dot's
 * colour, the label, the refresh cadence and the wall-clock time of the last
 * successful fan-out stay because nothing in the SOC chrome reports the FLEET
 * fan-out's health: the shell's live pill watches the SSE stream, and this
 * surface has no stream, only a five-second poll across every peer.
 *
 * "connecting" covers both the pre-first-poll idle state and a poll in flight,
 * because to an operator those are the same thing.
 */
function FleetPollStatus({
  pollStatus,
  pollMs,
  lastUpdated
}: {
  pollStatus: PollStatus;
  pollMs: number;
  lastUpdated: Date | null;
}) {
  const statusLabel =
    pollStatus === "connected"
      ? "connected"
      : pollStatus === "disabled"
        ? "disabled"
        : pollStatus === "loading" || pollStatus === "idle"
          ? "connecting"
          : "degraded";
  const tone = pollStatus === "connected" ? "ok" : pollStatus === "disabled" ? "warn" : "err";

  return (
    <div className="fleet-status fleet-surface-status" aria-live="polite">
      <span className={`fleet-dot fleet-dot--${tone} ${pollStatus === "connected" ? "fleet-dot--live" : ""}`} />
      <span>{statusLabel}</span>
      <span className="fleet-status__divider" />
      <span>auto-refresh {pollMs / 1000}s</span>
      {lastUpdated ? (
        <>
          <span className="fleet-status__divider" />
          <span>{lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
        </>
      ) : null}
    </div>
  );
}
