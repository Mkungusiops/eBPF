/**
 * Bulk actions — the checkbox selection's command surface.
 *
 * It carries the console's toast slot as well, because a bulk write's only
 * feedback is the per-mac result summary and it has to appear next to the
 * button that caused it, not at the far edge of the page.
 */
import { RefreshCcw } from "lucide-react";

import type { DeviceAction } from "./types";
import type { ToastState } from "./useDeviceToast";
import { DEVICE_ACTIONS } from "./utils";

export function DevicesBulkBar({
  selectedCount,
  action,
  reason,
  revertAfter,
  toast,
  loading,
  refreshing,
  disabled,
  onAction,
  onReason,
  onRevertAfter,
  onRefresh,
  onChoke,
  onThaw
}: {
  selectedCount: number;
  action: DeviceAction;
  reason: string;
  revertAfter: string;
  toast: ToastState | null;
  loading: boolean;
  refreshing: boolean;
  disabled: boolean;
  onAction: (action: DeviceAction) => void;
  onReason: (reason: string) => void;
  onRevertAfter: (seconds: string) => void;
  onRefresh: () => void;
  onChoke: () => void;
  onThaw: () => void;
}) {
  return (
    <section className="devices-grid">
      <div className="devices-panel devices-panel--padded">
        <div className="devices-panel-header">
          <div>
            <h2 className="devices-panel-title">Bulk actions</h2>
            <p className="devices-panel-copy">
              Select devices, choose a choke action, add an audit reason, and optionally schedule an auto-revert.
            </p>
          </div>
          <button
            type="button"
            className={`devices-button${refreshing ? " is-refreshing" : ""}`}
            disabled={refreshing || loading}
            onClick={onRefresh}
          >
            <RefreshCcw size={15} aria-hidden="true" />
            {refreshing ? "Refreshing" : "Refresh"}
          </button>
        </div>
        <div className="devices-bulk-row">
          <span className="devices-selected">{selectedCount} selected</span>
          <select
            className="devices-select"
            value={action}
            disabled={disabled}
            onChange={(event) => onAction(event.target.value as DeviceAction)}
            aria-label="Device choke action"
          >
            {DEVICE_ACTIONS.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label} ({item.detail})
              </option>
            ))}
          </select>
          <input
            className="devices-input devices-reason-input"
            value={reason}
            disabled={disabled}
            onChange={(event) => onReason(event.target.value)}
            placeholder="reason (required for audit)"
          />
          <input
            className="devices-input devices-revert-input"
            type="number"
            min="0"
            inputMode="numeric"
            value={revertAfter}
            disabled={disabled}
            onChange={(event) => onRevertAfter(event.target.value)}
            placeholder="revert after (s)"
          />
          <button
            type="button"
            className="devices-button devices-button--danger"
            disabled={disabled}
            onClick={onChoke}
          >
            Choke
          </button>
          <button
            type="button"
            className="devices-button devices-button--good"
            disabled={disabled}
            onClick={onThaw}
          >
            Thaw
          </button>
        </div>
        <div
          className={`devices-toast${toast ? ` devices-toast--${toast.tone}` : ""}`}
          aria-live="polite"
        >
          {toast?.message ?? ""}
        </div>
      </div>
    </section>
  );
}
