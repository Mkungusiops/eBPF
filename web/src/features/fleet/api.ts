import { ApiError, getJSON, postJSON, putJSON } from "../../lib/api";
import type {
  Alert,
  ChokeState,
  CgroupSnapshot,
  Decision,
  FleetDevice,
  FleetEnvelope,
  FleetPeer,
  HostResult,
  PresetName,
  Thresholds
} from "./types";

export function isFleetDisabled(error: unknown): error is ApiError {
  return error instanceof ApiError && error.status === 503;
}

export function fleetErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (typeof error.body === "string" && error.body.trim()) {
      return error.body.trim();
    }
    return error.message;
  }
  return error instanceof Error ? error.message : "fleet request failed";
}

export async function readFleetSnapshot(): Promise<{
  peers: FleetPeer[];
  states: FleetEnvelope<ChokeState>;
  cgroups: FleetEnvelope<CgroupSnapshot>;
  decisions: FleetEnvelope<Decision[]>;
  alerts: FleetEnvelope<Alert[]>;
  devices: FleetEnvelope<FleetDevice[]>;
}> {
  const peersResponse = await getJSON<{ hosts?: FleetPeer[] }>("/api/fleet/hosts");
  const peers = peersResponse.hosts ?? [];

  if (peers.length === 0) {
    return {
      peers,
      states: { hosts: [] },
      cgroups: { hosts: [] },
      decisions: { hosts: [] },
      alerts: { hosts: [] },
      devices: { hosts: [] }
    };
  }

  const [states, cgroups, decisions, alerts, devices] = await Promise.all([
    getJSON<FleetEnvelope<ChokeState>>("/api/fleet/state"),
    getJSON<FleetEnvelope<CgroupSnapshot>>("/api/fleet/cgroups"),
    getJSON<FleetEnvelope<Decision[]>>("/api/fleet/decisions?limit=80"),
    getJSON<FleetEnvelope<Alert[]>>("/api/fleet/alerts"),
    getJSON<FleetEnvelope<FleetDevice[]>>("/api/fleet/devices")
  ]);

  return { peers, states, cgroups, decisions, alerts, devices };
}

export function readWhoami(): Promise<{ user?: string; host?: string; hostname?: string }> {
  return getJSON<{ user?: string; host?: string; hostname?: string }>("/api/whoami");
}

export function writePreset(name: PresetName, targets: string[] | null, reason: string) {
  return postJSON<{ hosts: Array<HostResult<unknown>> }>("/api/fleet/preset", {
    name,
    reason,
    targets
  });
}

export function writeThresholds(thresholds: Thresholds, targets: string[] | null) {
  return putJSON<{ hosts: Array<HostResult<unknown>> }>("/api/fleet/thresholds", {
    ...thresholds,
    targets
  });
}

export function writeKillSwitch(on: boolean, targets: string[] | null) {
  return postJSON<{ hosts: Array<HostResult<unknown>> }>("/api/fleet/kill-switch", {
    on,
    targets
  });
}

export function writeThaw(reason: string, targets: string[] | null) {
  return postJSON<{ hosts: Array<HostResult<unknown>> }>("/api/fleet/thaw", {
    reason,
    targets
  });
}
