import type {
  DeviceAction,
  DeviceBucket,
  DeviceEntry,
  DeviceFlow,
  DeviceStateCounts,
  DeviceStateName
} from "./types";

/**
 * What the engine says when it was started without a device-choke interface.
 * The route, the flow loader and the action error handler all have to recognise
 * the same 503 and say the same thing, so the copy lives in one place.
 */
export const DISABLED_MESSAGE = "device choke disabled (start with -devchoke-iface)";

export const DEVICE_STATE_ORDER: DeviceStateName[] = [
  "pristine",
  "throttled",
  "tarpit",
  "quarantined",
  "severed"
];

export const DEVICE_ACTIONS: Array<{
  value: DeviceAction;
  label: string;
  detail: string;
}> = [
  { value: "throttle", label: "Throttle", detail: "50/s" },
  { value: "tarpit", label: "Tarpit", detail: "5/s" },
  { value: "quarantine", label: "Quarantine", detail: "1/s, DHCP/DNS allowed" },
  { value: "sever", label: "Sever", detail: "block" }
];

const FLAG = {
  throttle: 1,
  tarpit: 2,
  quarantine: 4,
  sever: 8
} as const;

export function flagName(flags?: number | null): DeviceAction | "none" {
  const value = flags ?? 0;
  if (value & FLAG.sever) return "sever";
  if (value & FLAG.quarantine) return "quarantine";
  if (value & FLAG.tarpit) return "tarpit";
  if (value & FLAG.throttle) return "throttle";
  return "none";
}

export function formatBucket(bucket?: DeviceBucket | null): string {
  if (!bucket) return "-";
  const name = flagName(bucket.flags);
  if (name === "none") return "-";
  return `${name} ${bucket.rate_per_sec ?? 0}/s`;
}

export function formatBytes(bytes?: number | null): string {
  const value = Math.max(0, bytes ?? 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatAgo(input?: string | Date | null, nowMs = Date.now()): string {
  if (!input) return "-";
  const then = input instanceof Date ? input.getTime() : new Date(input).getTime();
  if (!Number.isFinite(then)) return "-";
  const seconds = Math.max(0, Math.floor((nowMs - then) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export function macSlug(mac: string): string {
  return mac.replace(/:/g, "-");
}

export function normalizeCounts(counts?: DeviceStateCounts | null): Required<DeviceStateCounts> {
  return {
    pristine: counts?.pristine ?? 0,
    throttled: counts?.throttled ?? 0,
    tarpit: counts?.tarpit ?? 0,
    quarantined: counts?.quarantined ?? 0,
    severed: counts?.severed ?? 0
  };
}

export function isDeviceStateName(value?: string | null): value is DeviceStateName {
  return DEVICE_STATE_ORDER.includes(value as DeviceStateName);
}

export function sortFlows(flows: DeviceFlow[]): DeviceFlow[] {
  return [...flows].sort((a, b) => {
    const packetDelta = (b.packets ?? 0) - (a.packets ?? 0);
    if (packetDelta !== 0) return packetDelta;
    return (b.bytes ?? 0) - (a.bytes ?? 0);
  });
}

export function summarizeResults(results: Array<{ ok: boolean; error?: string }>, verb: string): string {
  const ok = results.filter((result) => result.ok).length;
  const total = results.length;
  const firstError = results.find((result) => !result.ok && result.error)?.error;
  return firstError ? `${ok}/${total} ${verb}: ${firstError}` : `${ok}/${total} ${verb}`;
}

export function isBridgeMasterWarning(state?: {
  links_attached?: number;
  frames_seen?: number;
} | null): boolean {
  return (state?.links_attached ?? 0) > 0 && (state?.frames_seen ?? 0) === 0;
}

/**
 * Can this data plane actually drop a packet?
 *
 * "noop" means no tc program is attached — the ladder still moves and the
 * device table still reads back "severed", but nothing touches traffic. That is
 * the correct configuration for a host with no bridge to sit inline on, so it
 * is not an error; claiming otherwise is.
 *
 * This existed twice with two different answers. One version excluded "noop"
 * and drove a single status dot; the other treated "noop" as healthy and drove
 * the header's integrity readout, `auditOk`, AND the exported evidence bundle —
 * which recorded `data_plane: "active"` for a plane that cannot enforce. An
 * unknown value is treated as inactive for the same reason: on an artefact
 * someone may hand to an auditor, "I could not tell" must never render as "yes".
 */
export function planeIsActive(dataPlane: string | undefined | null): boolean {
  return Boolean(dataPlane) && dataPlane !== "noop" && dataPlane !== "disabled";
}

/**
 * The device table's two filters, applied together: the ladder rung the
 * operator clicked, and the free-text search box.
 *
 * `query` must already be trimmed and lower-cased — the route needs that same
 * value to decide which empty-state copy to show, so it is computed once there
 * rather than twice.
 */
export function filterDevices(
  devices: DeviceEntry[],
  options: { rungFilter: string | null; query: string }
): DeviceEntry[] {
  return devices.filter((d) => {
    if (options.rungFilter && (d.state || "pristine") !== options.rungFilter) return false;
    if (!options.query) return true;
    return [d.mac, d.last_ip, d.hostname, d.vendor, d.source, d.state]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(options.query);
  });
}
