import { AlertTriangle } from "lucide-react";
import { useState } from "react";
import { useOSTheme } from "../../lib/theme";

import { ConfirmModal } from "./ConfirmModal";
import { FleetCgroupPanel } from "./FleetCgroups";
import { FleetControlRail } from "./FleetControlRail";
import { FleetFeedRail } from "./FleetFeeds";
import { FleetKpiStrip } from "./FleetKpiStrip";
import { FleetHostsPanel } from "./FleetTable";
import { ToastContainer, useFleetToasts } from "./FleetToasts";
import { FleetTopbar } from "./FleetTopbar";
import { POLL_MS, useFleetSnapshot } from "./useFleetSnapshot";
import { useFleetControls } from "./useFleetControls";
import "./fleet.css";
import type { ConfirmState } from "./types";

/**
 * The fleet console: one page that reads every configured peer and writes back
 * to as many of them as the operator targets.
 *
 * The read path (`useFleetSnapshot`), the write path (`useFleetControls`) and
 * the panels below are separate because they fail separately — a degraded poll
 * must not disable the rail, and a partial fan-out must not stop the poll.
 */
export default function FleetRoute() {
  // Applies the OS theme + keeps it live; Fleet renders no theme-dependent markup.
  useOSTheme();
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null);
  const { toasts, pushToast, dismissToast } = useFleetToasts();
  const feed = useFleetSnapshot(POLL_MS);
  const { derived, snapshot, pollStatus } = feed;
  const controls = useFleetControls({
    peers: snapshot.peers,
    totalHosts: derived.kpis.total,
    majorityThresholds: derived.majorityThresholds,
    pollStatus,
    pushToast,
    refresh: feed.refresh,
    setConfirmState
  });

  return (
    <div className="fleet-app">
      <FleetTopbar who={feed.who} pollStatus={pollStatus} pollMs={POLL_MS} lastUpdated={feed.lastUpdated} />

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
          onPreset={controls.requestPreset}
          thresholdDraft={controls.thresholdDraft}
          thresholdDirty={controls.thresholdDirty}
          majorityThresholds={derived.majorityThresholds}
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
