import { AssistantPanel } from "../assistant";
import { useEffect, useMemo, useState } from "react";
import { useOSTheme } from "../../lib/theme";

import { createDevicesApi, type DevicesApi } from "./api";
import { readOnlyReason } from "../choke/canRespond";
import {
  AUTHORITY_PENDING_REASON,
  recordResponseAuthority,
  useResponseAuthority,
} from "../soc/api";
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

/**
 * Shown when the permission read did not come back at all, as distinct from
 * one still in flight and from a server that answered "no". The console keeps
 * asking on a bounded backoff (see useDeviceInventory), and Refresh re-asks
 * immediately, so this state ends by itself the moment the server returns —
 * the sentence says so, because a permanently-disabled kill-switch with no
 * explanation is read as a broken console and gets a reload it should not need.
 */
export const AUTHORITY_UNREACHABLE_REASON =
  "Could not reach the server to check what this account may do — retrying; containment stays disabled until it answers. Refresh to retry now.";

export interface DevicesRouteProps {
  api?: DevicesApi;
  pollMs?: number;
  now?: () => number;
  /**
   * Retry cadence for a whoami that did not come back, in the same spirit as
   * `pollMs` and `now`: a seam so a test can rule the automatic retry out and
   * prove that it was REFRESH that re-asked the permission question. Both paths
   * end in the same request, so without this a test can only race the timer.
   */
  whoamiRetryBaseMs?: number;
  /**
   * Deadline for one whoami, threaded through for the same reason: a test must
   * be able to drive a read that NEVER settles — the half-open connection a
   * load balancer leaves behind — to its timeout without an eight-second wait.
   */
  whoamiTimeoutMs?: number;
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
  now = () => Date.now(),
  whoamiRetryBaseMs,
  whoamiTimeoutMs
}: DevicesRouteProps) {
  const baseApi = useMemo(() => providedApi ?? createDevicesApi(), [providedApi]);
  // WHEN the server answers, not only WHAT it answered.
  //
  // `inventory.canRespond` starts at null and stays null for a whoami that has
  // not landed — and null is the single-tenant engine's "the server published
  // no such field", which means PERMITTED. So the two are indistinguishable
  // downstream, and every containment control on this route armed itself for
  // the window between first paint and the first whoami: a read-only operator
  // was shown a live device kill-switch, sever and bulk-choke surface and found
  // out by pressing one.
  //
  // The inventory's whoami read stays the ONE request; this wrapper watches its
  // ANSWER go past and publishes it to the shared authority store
  // (features/soc/api.ts), which is the only place that carries the fourth
  // state — "nobody has answered yet". Wrapping rather than re-fetching keeps a
  // second /api/whoami off the wire and keeps one source of truth.
  const api = useMemo<DevicesApi>(() => {
    const fetchWhoami = baseApi.fetchWhoami?.bind(baseApi);
    if (!fetchWhoami) return baseApi;
    return {
      ...baseApi,
      fetchWhoami: async (options) => {
        const who = await fetchWhoami(options);
        recordResponseAuthority(who.canRespond ?? null);
        return who;
      }
    };
  }, [baseApi]);
  // An api with no whoami source at all is not a question in flight — it is no
  // question. Leaving the store at "loading" for it would withhold containment
  // forever on a deployment that never had a permission model to consult.
  useEffect(() => {
    if (!baseApi.fetchWhoami) recordResponseAuthority(null);
  }, [baseApi]);
  const authority = useResponseAuthority();
  // Theme comes from the OS for every console page — see src/lib/theme.ts.
  const theme = useOSTheme();
  const inventory = useDeviceInventory(api, pollMs, { whoamiRetryBaseMs, whoamiTimeoutMs });
  const { state, devices, disabledMessage } = inventory;
  // The account's own permission, kept apart from the plane's health. A
  // disabled data plane and a read-only operator both stop a write, and telling
  // an operator the wrong one sends them to debug an estate that is fine.
  const readOnlyAccount = inventory.canRespond === false || authority.readOnlyAccount;
  const readOnlyCopy = readOnlyReason("the device plane");
  // Withheld covers all three refusals; the SENTENCE distinguishes them,
  // because "your account is read-only" is a false statement about a responder
  // whose whoami simply has not come back yet — and "still checking" is its own
  // small lie once the request has actually failed and is being retried. An
  // operator staring at a dead kill-switch needs to know which of the three it
  // is: one is theirs to escalate, one resolves itself in a moment, and one
  // says the control plane is unreachable.
  const whoamiUnanswered = authority.pending && inventory.whoamiStatus === "unanswered";
  const writesWithheld = readOnlyAccount || authority.pending;
  const withheldReason = readOnlyAccount
    ? readOnlyCopy
    : whoamiUnanswered
      ? AUTHORITY_UNREACHABLE_REASON
      : authority.pending
        ? AUTHORITY_PENDING_REASON
        : "";
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
    clearSelection: inventory.clearSelection,
    // The request layer, not only the buttons: `false` is the only value this
    // hook has for "refuse", so an unanswered whoami is expressed as one. See
    // the followUp — its toast still says "read-only" for both.
    canRespond: writesWithheld ? false : inventory.canRespond
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
  const modeDisabled = Boolean(disabledMessage || state?.dry_run) || writesWithheld;
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

        {/* First, because it reframes every control below it: they are drawn,
            they are disabled, and it is this account — not the data plane —
            that disabled them. */}
        {readOnlyAccount ? (
          <DevicesBanner live tone="warn" title="Read-only account" copy={readOnlyCopy} />
        ) : null}

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
            onKillSwitch={disabledMessage || !state || writesWithheld ? undefined : actions.toggleKillSwitch}
            disabled={Boolean(disabledMessage) || writesWithheld}
          />
          {/* The reason travels WITH the cluster rather than living only in the
              page banner: an operator reaching for the kill-switch is looking
              at this control, and a disabled button with no sentence beside it
              reads as a broken data plane. The header's own two buttons still
              carry only their generic titles — putting the sentence on the
              button itself needs a prop this route does not own; see the
              followUp. */}
          {withheldReason ? (
            <p className="devices-permission-note" data-panel="containment-command-withheld">
              {withheldReason}
            </p>
          ) : null}
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
          disabled={Boolean(disabledMessage) || writesWithheld}
          blockedReason={withheldReason}
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
          disabled={Boolean(disabledMessage) || writesWithheld}
          blockedReason={withheldReason}
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
          {/* Command lens too, not only Assurance: Command is where an operator
              actually investigates a device. Mounting only into the reporting
              view put the assistant where nobody works. */}
          <AssistantPanel surface="devices" subjectLabel="the device fleet" />
        </>
        )}
      </div>

      <ConfirmModal options={confirm} onClose={closeConfirm} />
    </main>
  );
}
