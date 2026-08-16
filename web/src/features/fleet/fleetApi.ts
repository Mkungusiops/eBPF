/**
 * FleetApi — the injected seam for the Fleet route.
 *
 * Tier 1A of docs/plan/ai-and-console-reuse.md, done first because fleet is the
 * smallest surface that proves the shape: two hooks, zero components touching
 * the network. Choke goes last, because a mistake there is a mistake in the path
 * that kills processes.
 *
 * NOTE for call sites: `api` is a dependency of the polling effect, so pass a
 * STABLE reference — the module-level default, or one wrapped in useMemo.
 * Constructing one inline in a render re-triggers the poll every render.
 *
 * Mirrors DevicesApi deliberately — same file layout, same `create*Api(request)`
 * factory, same "interface names no transport type" rule — so SOC and Choke have
 * a worked example rather than a description.
 */
import {
  fleetErrorMessage,
  isFleetDisabled,
  readFleetSnapshot,
  readWhoami,
  writeKillSwitch,
  writePreset,
  writeThaw,
  writeThresholds
} from "./api";
import type { PresetName, Thresholds } from "./types";

/** Every call takes a signal: a fleet poll outlives the component that started it. */
export interface FleetApiCallOptions {
  signal?: AbortSignal;
}

export interface FleetSnapshotResponse {
  peers: Awaited<ReturnType<typeof readFleetSnapshot>>["peers"];
  states: Awaited<ReturnType<typeof readFleetSnapshot>>["states"];
  cgroups: Awaited<ReturnType<typeof readFleetSnapshot>>["cgroups"];
  decisions: Awaited<ReturnType<typeof readFleetSnapshot>>["decisions"];
  alerts: Awaited<ReturnType<typeof readFleetSnapshot>>["alerts"];
  devices: Awaited<ReturnType<typeof readFleetSnapshot>>["devices"];
}

export interface FleetApi {
  fetchSnapshot(options?: FleetApiCallOptions): Promise<FleetSnapshotResponse>;
  fetchWhoami(options?: FleetApiCallOptions): Promise<{ user?: string; host?: string; hostname?: string }>;
  applyPreset(name: PresetName, targets: string[] | null, reason: string): Promise<unknown>;
  applyThresholds(thresholds: Thresholds, targets: string[] | null): Promise<unknown>;
  setKillSwitch(on: boolean, targets: string[] | null): Promise<unknown>;
  thaw(reason: string, targets: string[] | null): Promise<unknown>;
  /** Error classification lives behind the seam so a fake can exercise both paths. */
  isDisabled(error: unknown): boolean;
  errorMessage(error: unknown): string;
}

/**
 * The real client. Default argument, so no existing call site changes — the
 * conversion is behaviour-preserving and the Playwright suite stays the
 * contract.
 */
export function createFleetApi(): FleetApi {
  return {
    fetchSnapshot: () => readFleetSnapshot(),
    fetchWhoami: () => readWhoami(),
    applyPreset: (name, targets, reason) => writePreset(name, targets, reason),
    applyThresholds: (thresholds, targets) => writeThresholds(thresholds, targets),
    setKillSwitch: (on, targets) => writeKillSwitch(on, targets),
    thaw: (reason, targets) => writeThaw(reason, targets),
    isDisabled: (error) => isFleetDisabled(error),
    errorMessage: (error) => fleetErrorMessage(error)
  };
}
