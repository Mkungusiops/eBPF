import { useEffect, useMemo, useState } from "react";
import { useOSTheme } from "../../lib/theme";

import { createDevicesApi, type DevicesApi } from "./api";
import {
  ContainmentCommandHeader,
  ContainmentLadder,
  type ViewMode
} from "../common/ContainmentCommand";
import { type Rung } from "../common/enforcement";
import { buildDeviceAssuranceHtml, buildDeviceEvidenceBundle, downloadJson } from "./assuranceReport";
import { ConfirmModal, useConfirmDialog } from "./ConfirmModal";
import { DevicesAssuranceView } from "./DevicesAssurance";
import { DevicesBulkBar } from "./DevicesBulkBar";
import { DevicesBanner, DevicesTopbar } from "./DevicesChrome";
import { DevicesTable } from "./DevicesTable";
import { buildDeviceMetrics } from "./metrics";
import { useDeviceActions } from "./useDeviceActions";
import { useDeviceInventory } from "./useDeviceInventory";
import { useDeviceToast } from "./useDeviceToast";
import "./devices.css";
import type { DeviceAction } from "./types";
import { filterDevices, formatAgo, isBridgeMasterWarning } from "./utils";

export { planeIsActive } from "./utils";

export interface DevicesRouteProps {
  api?: DevicesApi;
  pollMs?: number;
  now?: () => number;
}

/**
 * The device choke console.
 *
 * Everything the route needs from the outside is a parameter: the API, the poll
 * interval and the clock. That is what makes the page testable without a
 * network or a fake timer, and it is why the read path, the write path and the
 * presentation below it can each be exercised on their own.
 */
export function DevicesRoute({
  api: providedApi,
  pollMs = 4000,
  now = () => Date.now()
}: DevicesRouteProps) {
  const api = useMemo(() => providedApi ?? createDevicesApi(), [providedApi]);
  // Theme comes from the OS for every console page — see src/lib/theme.ts.
  const theme = useOSTheme();
  const inventory = useDeviceInventory(api, pollMs);
  const { state, devices, disabledMessage } = inventory;
  const { toast, setToast, pushToast } = useDeviceToast();
  const { options: confirm, requestConfirm, closeConfirm } = useConfirmDialog();

  const [action, setAction] = useState<DeviceAction>("throttle");
  const [reason, setReason] = useState("");
  const [revertAfter, setRevertAfter] = useState("");
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

  const actions = useDeviceActions({
    api,
    state,
    selected: inventory.selected,
    action,
    reason,
    revertAfter,
    pushToast,
    setDisabledMessage: inventory.setDisabledMessage,
    requestConfirm,
    refresh: inventory.refresh,
    clearSelection: inventory.clearSelection
  });

  // ── Containment Command metrics (shared hero + ladder) ──────────────────
  const { metrics: deviceMetrics, countsByRung, protectedCount, planeHealthy } = buildDeviceMetrics(
    state,
    devices,
    disabledMessage
  );
  const deviceQuery = deviceSearch.trim().toLowerCase();
  const visibleDevices = filterDevices(devices, { rungFilter, query: deviceQuery });
  const toggleRungFilter = (rung: Rung) => setRungFilter((prev) => (prev === rung ? null : rung));

  const exportDeviceAssurance = (kind: "report" | "bundle") => {
    const when = new Date();
    const stamp = when.toISOString().replace(/[:.]/g, "-");
    if (kind === "bundle") {
      downloadJson(
        `device-containment-evidence-${stamp}.json`,
        buildDeviceEvidenceBundle({
          metrics: deviceMetrics,
          countsByRung,
          state,
          planeHealthy,
          protectedCount,
          devices,
          when
        })
      );
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
  const allSelected = devices.length > 0 && devices.every((device) => inventory.selected.has(device.mac));
  const modeDisabled = Boolean(disabledMessage || state?.dry_run);
  const bridgeWarning = isBridgeMasterWarning(state);

  return (
    <main className={`devices-route${theme === "light" ? " theme-light" : ""}`}>
      <DevicesTopbar
        search={deviceSearch}
        onSearch={setDeviceSearch}
        state={state}
        disabledMessage={disabledMessage}
        updatedAt={inventory.lastUpdatedAt}
      />
      <div className="devices-layout">

        {disabledMessage ? (
          <DevicesBanner
            live
            title={disabledMessage}
            copy="Start the engine with a device choke interface to enable the data plane."
          />
        ) : null}

        {bridgeWarning ? (
          <DevicesBanner
            live
            tone="warn"
            title="Links are attached, but no forwarded frames have been seen."
            copy="This usually means the program is attached to a bridge master instead of a bridge slave interface."
          />
        ) : null}

        {inventory.error ? (
          <DevicesBanner live tone="warn" title="Device state could not be refreshed." copy={inventory.error} />
        ) : null}

        {/* Containment Command — identical hero + ladder to the Choke Gateway,
            so the network plane and the process plane read as one product. */}
        <section className="devices-grid">
          <ContainmentCommandHeader
            metrics={deviceMetrics}
            viewMode={viewMode}
            onViewMode={setViewMode}
            onToggleMode={modeDisabled ? undefined : actions.toggleMode}
            onKillSwitch={disabledMessage || !state ? undefined : actions.toggleKillSwitch}
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
          <DevicesBanner
            tone="warn"
            title="Dry-run boot flag is set."
            copy="Enforcement is forced off at boot regardless of mode; chokes are audited but never applied."
          />
        ) : null}

        <DevicesBulkBar
          selectedCount={inventory.selected.size}
          action={action}
          reason={reason}
          revertAfter={revertAfter}
          toast={toast}
          loading={inventory.loading}
          refreshing={inventory.refreshing}
          disabled={Boolean(disabledMessage)}
          onAction={setAction}
          onReason={setReason}
          onRevertAfter={setRevertAfter}
          onRefresh={inventory.refresh}
          onChoke={actions.jailSelected}
          onThaw={actions.thawSelected}
        />

        <DevicesTable
          devices={visibleDevices}
          deviceCount={devices.length}
          selected={inventory.selected}
          expanded={inventory.expanded}
          flows={inventory.flows}
          allSelected={allSelected}
          disabled={Boolean(disabledMessage)}
          loading={inventory.loading}
          query={deviceQuery}
          searchTerm={deviceSearch.trim()}
          rungFilter={rungFilter}
          now={now}
          onSelect={inventory.toggleSelected}
          onSelectAll={inventory.setAllSelected}
          onToggleFlows={inventory.toggleFlows}
          onApply={actions.applyToDevice}
          onReadState={actions.readDeviceState}
          onSettled={inventory.refresh}
        />

        <p className="devices-footnote">
          Identity is the MAC, stable across DHCP and IP changes. Quarantine still allows DHCP/DNS so a device can recover. Protected MACs refuse quarantine and sever actions.
          {inventory.lastUpdatedAt ? ` Last refreshed ${formatAgo(new Date(inventory.lastUpdatedAt), now())} ago.` : ""}
        </p>
        </>
        )}
      </div>

      <ConfirmModal options={confirm} onClose={closeConfirm} />
    </main>
  );
}
