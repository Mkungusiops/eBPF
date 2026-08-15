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
    activeThreats: 0,
    contained: containedDevices,
    tracked: state?.tracked ?? state?.devices_known ?? devices.length,
    auditOk: planeHealthy,
    auditRows: 0,
    integrityLabel: "Data plane",
    integrityValue: planeHealthy ? "active" : "offline",
    integritySub: `${state?.links_attached ?? 0} links · ${state?.frames_seen ?? 0} frames`,
    killSwitched: Boolean(state?.kill_switched),
    headline: `${protectedCount}`,
    headlineLabel: "Protected assets",
    posture: computePosture({
      mode: deviceMode,
      activeThreats: 0,
      contained: containedDevices,
      auditOk: planeHealthy,
      killSwitched: Boolean(state?.kill_switched)
    })
  };
  return { metrics, countsByRung, protectedCount, planeHealthy };
}
