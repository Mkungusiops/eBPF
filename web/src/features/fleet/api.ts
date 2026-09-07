import { ApiError, getJSON, postJSON, putJSON } from "../../lib/api";
import type {
  Alert,
  ChokeState,
  CgroupSnapshot,
  Decision,
  FanoutEnvelope,
  FleetDevice,
  FleetEnvelope,
  FleetPeer,
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

export interface FleetWhoami {
  user?: string;
  host?: string;
  hostname?: string;
  /**
   * Whether this account may send containment and configuration writes.
   *
   * `null` is "the server did not say", and it must be read as PERMITTED. Only
   * the multi-tenant control plane publishes `can_respond`; the single-tenant
   * engine has no such concept, so treating a missing field as false would take
   * the emergency controls away from every single-tenant operator on the
   * grounds of a permission model their server does not implement.
   */
  canRespond: boolean | null;
}

export async function readWhoami(): Promise<FleetWhoami> {
  const raw = await getJSON<{
    user?: string;
    host?: string;
    hostname?: string;
    can_respond?: unknown;
  }>("/api/whoami");
  return {
    user: raw.user,
    host: raw.host,
    hostname: raw.hostname,
    canRespond: typeof raw.can_respond === "boolean" ? raw.can_respond : null
  };
}

export function writePreset(name: PresetName, targets: string[] | null, reason: string) {
  return postJSON<FanoutEnvelope>("/api/fleet/preset", {
    name,
    reason,
    targets
  });
}

export function writeThresholds(thresholds: Thresholds, targets: string[] | null) {
  return putJSON<FanoutEnvelope>("/api/fleet/thresholds", {
    ...thresholds,
    targets
  });
}

/**
 * The kill-switch carries a reason because the engine audits one:
 * `handleChokeKillSwitch` records the transition with the operator's
 * `reason`, and the console used to leave that field empty on the single
 * widest-blast-radius toggle on the platform — the audit row said who and when
 * but never why.
 */
export function writeKillSwitch(on: boolean, targets: string[] | null, reason: string) {
  return postJSON<FanoutEnvelope>("/api/fleet/kill-switch", {
    on,
    reason,
    targets
  });
}

export function writeThaw(reason: string, targets: string[] | null) {
  return postJSON<FanoutEnvelope>("/api/fleet/thaw", {
    reason,
    targets
  });
}
