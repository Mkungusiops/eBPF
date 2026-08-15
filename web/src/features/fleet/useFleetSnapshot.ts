/**
 * The fleet console's read path: one fan-out poll across every configured peer,
 * plus the derivations every panel reads from.
 *
 * `pollStatus` is deliberately four-valued rather than a boolean. "disabled"
 * means the engine was started without `--fleet-hosts` and there is nothing to
 * poll — a configuration answer, not a failure — while "degraded" means the
 * fan-out itself failed. Collapsing the two would tell an operator their fleet
 * was broken when it was simply never configured.
 *
 * The derivations are memoised on the exact slice they read: the decision and
 * alert feeds re-merge only when their own host payloads change, so a peer
 * list refresh does not re-sort 80 decisions.
 */
import { useCallback, useEffect, useMemo, useState } from "react";

import { fleetErrorMessage, isFleetDisabled, readFleetSnapshot, readWhoami } from "./api";
import { deriveFleet, mergeHostPayloads, type MergedAlert, type MergedDecision } from "./fleetLogic";
import type {
  CgroupSnapshot,
  DerivedFleet,
  FleetStateSnapshot,
  HostResult,
  PollStatus
} from "./types";

export const POLL_MS = 5000;

export interface FleetSnapshotFeed {
  who: string;
  snapshot: FleetStateSnapshot;
  pollStatus: PollStatus;
  disabledMessage: string;
  pollError: string;
  lastUpdated: Date | null;
  derived: DerivedFleet;
  decisions: MergedDecision[];
  alerts: MergedAlert[];
  cgroupByHost: Map<string, HostResult<CgroupSnapshot>>;
  refresh: () => Promise<void>;
}

export function emptySnapshot(): FleetStateSnapshot {
  return {
    peers: [],
    states: [],
    cgroups: [],
    decisions: [],
    alerts: [],
    devices: []
  };
}

export function useFleetSnapshot(pollMs: number = POLL_MS): FleetSnapshotFeed {
  const [who, setWho] = useState("...");
  const [snapshot, setSnapshot] = useState<FleetStateSnapshot>(() => emptySnapshot());
  const [pollStatus, setPollStatus] = useState<PollStatus>("idle");
  const [disabledMessage, setDisabledMessage] = useState("");
  const [pollError, setPollError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  useEffect(() => {
    readWhoami()
      .then((identity) => setWho(identity.user ?? "operator"))
      .catch(() => setWho("operator"));
  }, []);

  const refresh = useCallback(async () => {
    setPollStatus((current) => (current === "idle" ? "loading" : current));
    try {
      const next = await readFleetSnapshot();
      setSnapshot({
        peers: next.peers,
        states: next.states.hosts ?? [],
        cgroups: next.cgroups.hosts ?? [],
        decisions: next.decisions.hosts ?? [],
        alerts: next.alerts.hosts ?? [],
        devices: next.devices.hosts ?? []
      });
      setDisabledMessage("");
      setPollError("");
      setPollStatus(next.peers.length === 0 ? "degraded" : "connected");
      setLastUpdated(new Date());
    } catch (error) {
      if (isFleetDisabled(error)) {
        setSnapshot(emptySnapshot());
        setDisabledMessage(fleetErrorMessage(error));
        setPollStatus("disabled");
        setPollError("");
        return;
      }
      setPollStatus("degraded");
      setPollError(fleetErrorMessage(error));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => void refresh(), pollMs);
    return () => window.clearInterval(interval);
  }, [pollMs, refresh]);

  const derived = useMemo(
    () => deriveFleet(snapshot.peers, snapshot.states, snapshot.devices),
    [snapshot.devices, snapshot.peers, snapshot.states]
  );
  const decisions = useMemo(
    () => mergeHostPayloads(snapshot.decisions, 60),
    [snapshot.decisions]
  );
  const alerts = useMemo(() => mergeHostPayloads(snapshot.alerts, 50), [snapshot.alerts]);
  const cgroupByHost = useMemo(
    () => new Map(snapshot.cgroups.map((result) => [result.name, result])),
    [snapshot.cgroups]
  );

  return {
    who,
    snapshot,
    pollStatus,
    disabledMessage,
    pollError,
    lastUpdated,
    derived,
    decisions,
    alerts,
    cgroupByHost,
    refresh
  };
}
