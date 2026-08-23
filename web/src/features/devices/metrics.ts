/**
 * Raw plane state → the Containment Command contract.
 *
 * The hero, the ladder, the assurance lens and the exported evidence bundle all
 * read from ONE derivation. They used to derive their own: the header called the
 * plane healthy on a rule the status dot disagreed with, and the bundle recorded
 * `data_plane: "active"` for a plane that could not drop a packet. Deriving once
 * is what makes those four surfaces incapable of contradicting each other.
 */
import { computePosture, type CommandMetrics } from "../common/ContainmentCommand";
import { LADDER } from "../common/enforcement";
import type { DeviceDataPlaneState, DeviceEntry } from "./types";
import { normalizeCounts, planeIsActive } from "./utils";

export interface DeviceMetrics {
  metrics: CommandMetrics;
  /** Ladder counts keyed by rung name, for the ladder strip and the exports. */
  countsByRung: Record<string, number>;
  protectedCount: number;
  /** The plane is attached AND the device-choke feature is enabled at all. */
  planeHealthy: boolean;
}

export function buildDeviceMetrics(
  state: DeviceDataPlaneState | null,
  devices: DeviceEntry[],
  disabledMessage: string | null
): DeviceMetrics {
  const counts = normalizeCounts(state?.counts);
  const countsByRung = counts as unknown as Record<string, number>;
  const containedDevices = LADDER.filter((r) => r !== "pristine").reduce((sum, r) => sum + (countsByRung[r] || 0), 0);
  const protectedCount = devices.filter((d) => d.protected).length;
  const deviceMode: "detect-only" | "enforcing" = state?.enforcing ? "enforcing" : "detect-only";
  const planeHealthy = !disabledMessage && planeIsActive(state?.data_plane);
  const metrics: CommandMetrics = {
    subject: "devices",
    mode: deviceMode,
    // Not zero — UNKNOWN. Nothing scores a device on this plane, so there is
    // no number to report, and a zero here pinned the posture dial at 100%.
    activeThreats: null,
    contained: containedDevices,
    tracked: state?.tracked ?? state?.devices_known ?? devices.length,
    auditOk: planeHealthy,
    // Dormant fabrication: invisible today only because integritySub below
    // overrides the label that would render it. Left at 0 it is a trap for
    // whoever removes that override.
    auditRows: null,
    integrityLabel: "Data plane",
    integrityValue: planeHealthy ? "active" : "offline",
    integritySub: `${state?.links_attached ?? 0} links · ${state?.frames_seen ?? 0} frames`,
    // The control plane deliberately sends null when it cannot tell whether
    // the switch is engaged. Boolean() collapsed that to false — the console
    // asserted "not killed" about a state it had no reading for, which is the
    // same bug the process-plane toggle had.
    killSwitched: state?.kill_switched ?? null,
    headline: `${protectedCount}`,
    headlineLabel: "Protected assets",
    posture: computePosture({
      mode: deviceMode,
      activeThreats: null,
      contained: containedDevices,
      auditOk: planeHealthy,
      killSwitched: state?.kill_switched ?? null
    })
  };
  return { metrics, countsByRung, protectedCount, planeHealthy };
}
