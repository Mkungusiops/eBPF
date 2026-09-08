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

/**
 * The six-request fan-out behind one poll — AND THE SIGNAL THAT CANCELS IT.
 *
 * `options` is threaded into every getJSON below rather than dropped at this
 * boundary. That is not tidiness: useFleetSnapshot aborts its controller when
 * the operator closes the surface or the console unmounts, and until the signal
 * reached `fetch` the abort cancelled nothing — the six requests ran to
 * completion against every configured peer, and the only reason the hook's own
 * test looked right was that its FAKE api recorded the signal it was handed.
 * lib/api.ts spreads ApiOptions into the RequestInit it builds, so a signal
 * passed here is the signal on the wire.
 *
 * The peer list is awaited first and the other five are not issued at all when
 * no peer is configured, so an abort between the two stages stops five requests
 * that were never sent rather than five that were.
 */
export async function readFleetSnapshot(options?: { signal?: AbortSignal }): Promise<{
  peers: FleetPeer[];
  states: FleetEnvelope<ChokeState>;
  cgroups: FleetEnvelope<CgroupSnapshot>;
  decisions: FleetEnvelope<Decision[]>;
  alerts: FleetEnvelope<Alert[]>;
  devices: FleetEnvelope<FleetDevice[]>;
}> {
  const peersResponse = await getJSON<{ hosts?: FleetPeer[] }>("/api/fleet/hosts", options);
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
    getJSON<FleetEnvelope<ChokeState>>("/api/fleet/state", options),
    getJSON<FleetEnvelope<CgroupSnapshot>>("/api/fleet/cgroups", options),
    getJSON<FleetEnvelope<Decision[]>>("/api/fleet/decisions?limit=80", options),
    getJSON<FleetEnvelope<Alert[]>>("/api/fleet/alerts", options),
    getJSON<FleetEnvelope<FleetDevice[]>>("/api/fleet/devices", options)
  ]);

  return { peers, states, cgroups, decisions, alerts, devices };
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
