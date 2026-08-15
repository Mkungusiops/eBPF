/**
 * The device table: one row per MAC, and — when a row is opened — the flows that
 * device is actually generating plus the ladder that can do something about them.
 *
 * Identity is the MAC, not the IP: a device keeps its row across DHCP renewals
 * and address changes, which is the only reason a choke applied ten minutes ago
 * still points at the same box.
 */
import { ChevronDown, ChevronRight, Network, RotateCcw } from "lucide-react";

import { EnforcementLadder } from "../common/EnforcementLadder";
import { DEVICE_TERMINAL, type Rung } from "../common/enforcement";
import type { DeviceEntry } from "./types";
import type { FlowLoadState } from "./useDeviceInventory";
import { formatAgo, formatBucket, formatBytes, isDeviceStateName, macSlug } from "./utils";

export function DevicesTable({
  devices,
  deviceCount,
  selected,
  expanded,
  flows,
  allSelected,
  disabled,
  loading,
  query,
  searchTerm,
  rungFilter,
  now,
  onSelect,
  onSelectAll,
  onToggleFlows,
  onApply,
  onReadState,
  onSettled
}: {
  /** Rows that survived the ladder filter and the search box. */
  devices: DeviceEntry[];
  /** Every known device, filtered or not — the select-all checkbox needs it. */
  deviceCount: number;
  selected: Set<string>;
  expanded: Set<string>;
  flows: Record<string, FlowLoadState>;
  allSelected: boolean;
  disabled: boolean;
  loading: boolean;
  /** Trimmed + lower-cased search term, and the operator's original casing. */
  query: string;
  searchTerm: string;
  rungFilter: string | null;
  now: () => number;
  onSelect: (mac: string, checked: boolean) => void;
  onSelectAll: (checked: boolean) => void;
  onToggleFlows: (mac: string) => void;
  onApply: (mac: string, rung: Rung, reason: string) => Promise<{ ok: boolean; detail: string }>;
  onReadState: (mac: string) => Promise<string | undefined>;
  onSettled: () => void;
}) {
  return (
    <section className="devices-grid">
      <div className="devices-panel">
        <div className="devices-table-wrap">
          <table className="devices-table">
            <thead>
              <tr>
                <th>
                  <input
                    className="devices-checkbox"
                    type="checkbox"
                    checked={allSelected}
                    disabled={deviceCount === 0 || disabled}
                    onChange={(event) => onSelectAll(event.currentTarget.checked)}
                    aria-label="Select all devices"
                  />
                </th>
                <th>Device</th>
                <th>IP</th>
                <th>Hostname</th>
                <th>State</th>
                <th>Bucket</th>
                <th>Seen</th>
                <th>Src</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => {
                const open = expanded.has(device.mac);
                return (
                  <DeviceRow
                    key={device.mac}
                    device={device}
                    open={open}
                    selected={selected.has(device.mac)}
                    flowState={flows[device.mac]}
                    now={now}
                    disabled={disabled}
                    onSelect={onSelect}
                    onToggleFlows={onToggleFlows}
                    onApply={onApply}
                    onReadState={onReadState}
                    onSettled={onSettled}
                  />
                );
              })}
            </tbody>
          </table>
        </div>
        {devices.length === 0 ? (
          <div className="devices-empty">
            {loading
              ? "Loading device state..."
              : query
                ? `No devices match "${searchTerm}". Clear the search to see all.`
                : rungFilter
                  ? `No ${rungFilter} devices. Clear the ladder filter to see all.`
                  : "No devices observed yet. Generate LAN traffic to populate the table."}
          </div>
        ) : null}
      </div>
    </section>
  );
}

function DeviceRow({
  device,
  open,
  selected,
  flowState,
  now,
  disabled,
  onSelect,
  onToggleFlows,
  onApply,
  onReadState,
  onSettled
}: {
  device: DeviceEntry;
  open: boolean;
  selected: boolean;
  flowState?: FlowLoadState;
  now: () => number;
  disabled: boolean;
  onSelect: (mac: string, checked: boolean) => void;
  onToggleFlows: (mac: string) => void;
  onApply: (mac: string, rung: Rung, reason: string) => Promise<{ ok: boolean; detail: string }>;
  onReadState: (mac: string) => Promise<string | undefined>;
  onSettled: () => void;
}) {
  const stateClass = isDeviceStateName(device.state)
    ? device.state
    : "unknown";
  return (
    <>
      <tr>
        <td>
          <input
            className="devices-checkbox"
            type="checkbox"
            checked={selected}
            disabled={disabled}
            onChange={(event) => onSelect(device.mac, event.currentTarget.checked)}
            aria-label={`Select ${device.mac}`}
          />
        </td>
        <td className="devices-device-cell devices-mono">
          <div className="devices-row-main">
            <button
              type="button"
              className="devices-icon-button"
              onClick={() => onToggleFlows(device.mac)}
              aria-expanded={open}
              aria-controls={`flows-${macSlug(device.mac)}`}
              title={open ? "Collapse device flows" : "Expand device flows"}
            >
              {open ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
            </button>
            <span>{device.mac}</span>
            {device.protected ? <span className="devices-pill devices-pill--muted">protected</span> : null}
            {device.flows ? <span className="devices-pill devices-pill--plain">{device.flows} dst</span> : null}
          </div>
          <div className="devices-device-id">{device.device_id ?? "-"}</div>
        </td>
        <td className="devices-mono">{device.last_ip || "-"}</td>
        <td>{device.hostname || "-"}</td>
        <td>
          <span className={`devices-state devices-state--${stateClass}`}>{device.state || "unknown"}</span>
          {device.revert_pending ? (
            <RotateCcw className="devices-revert" size={14} aria-label="Auto-revert pending" />
          ) : null}
        </td>
        <td className="devices-mono">{formatBucket(device.bucket)}</td>
        <td>{formatAgo(device.last_seen, now())}</td>
        <td>{device.source || "-"}</td>
      </tr>
      {open ? (
        <tr className="devices-flow-row" id={`flows-${macSlug(device.mac)}`}>
          <td colSpan={8}>
            <FlowList state={flowState} />
            {/* Evidence and control in one place: the flows say what this
                device is doing, the ladder does something about it. Same
                component as the correlation graph and Choke Gateway. */}
            <EnforcementLadder
              target={{
                id: device.mac,
                label: device.hostname || device.mac,
                host: device.last_ip || undefined
              }}
              state={device.state || "pristine"}
              policy={DEVICE_TERMINAL}
              apply={(rung, why) => onApply(device.mac, rung, why)}
              readState={() => onReadState(device.mac)}
              onSettled={onSettled}
            />
          </td>
        </tr>
      ) : null}
    </>
  );
}

function FlowList({ state }: { state?: FlowLoadState }) {
  if (!state || state.loading) {
    return <div className="devices-flow-panel">Loading connections...</div>;
  }
  if (state.error) {
    return <div className="devices-flow-panel">{state.error}</div>;
  }
  if (!state.flows?.length) {
    return <div className="devices-flow-panel">No outbound connections observed yet.</div>;
  }
  return (
    <div className="devices-flow-panel">
      <div className="devices-flow-title">Connecting to (device -&gt; destination)</div>
      {state.flows.map((flow) => (
        <div
          className="devices-flow-line devices-mono"
          key={`${flow.dest_ip}:${flow.dest_port ?? 0}:${flow.proto ?? ""}`}
        >
          <Network size={14} aria-hidden="true" />
          <span>
            {flow.dest_ip}:{flow.dest_port || "-"}
          </span>
          <span className="devices-flow-proto">{flow.proto || "unknown"}</span>
          <span>
            {flow.packets ?? 0} pkts / {formatBytes(flow.bytes)}
          </span>
        </div>
      ))}
    </div>
  );
}
