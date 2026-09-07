import { createFleetApi, type FleetApi } from "./fleetApi";

const defaultFleetApi = createFleetApi();
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
import { useCallback, useEffect, useMemo, useState, useRef } from "react";

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
  /**
   * Whether this account may write, straight from whoami — `null` when the
   * server did not say. Kept null on a whoami failure too: an unreachable
   * identity endpoint is an outage, and revoking the operator's controls over
   * an outage would be a permission claim the console cannot support.
   */
  canRespond: boolean | null;
  /**
   * False until whoami has answered one way or the other (including by
   * failing). While it is false the answer is IN FLIGHT and `canRespond`'s
   * null means "not asked yet", not "the server did not say" — the write rail
   * must stay closed, or a read-only account gets an armed rail on first paint
   * whenever /api/whoami is slower than the fleet snapshot.
   */
  identityResolved: boolean;
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

export function useFleetSnapshot(
  pollMs: number = POLL_MS,
  // Injected; defaults to the real client so no call site changes.
  api: FleetApi = defaultFleetApi
): FleetSnapshotFeed {
  // One controller for the whole hook. Every fetch carries its signal and the
  // cleanup aborts it, so a poll started before unmount cannot resolve into a
  // dead component — the missing-AbortSignal bug named in the Tier 1A plan.
  const abortRef = useRef<AbortController | null>(null);
  const [who, setWho] = useState("...");
  const [canRespond, setCanRespond] = useState<boolean | null>(null);
  // Three states, not two: loading, answered-without-the-field (permitted), and
  // an explicit false. Only the last two may arm or disarm anything.
  const [identityResolved, setIdentityResolved] = useState(false);
  const [snapshot, setSnapshot] = useState<FleetStateSnapshot>(() => emptySnapshot());
  const [pollStatus, setPollStatus] = useState<PollStatus>("idle");
  const [disabledMessage, setDisabledMessage] = useState("");
  const [pollError, setPollError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  useEffect(() => {
    api.fetchWhoami()
      .then((identity) => {
        setWho(identity.user ?? "operator");
        setCanRespond(identity.canRespond ?? null);
      })
      .catch(() => setWho("operator"))
      // Resolved on failure too: an unreachable identity endpoint is an outage,
      // and holding the rail closed forever over one would take the emergency
      // controls away from an operator the server never refused.
      .finally(() => setIdentityResolved(true));
  }, [api]);

  const refresh = useCallback(async () => {
    setPollStatus((current) => (current === "idle" ? "loading" : current));
    // A controller per poll, created HERE rather than in an effect: effect
    // ordering meant the first call could run before the ref was assigned and
    // went out with no signal at all — the exact bug this was meant to fix,
    // silently reintroduced one layer down. Abort any previous poll so a slow
    // one cannot land after a newer one.
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const next = await api.fetchSnapshot({ signal: controller.signal });
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
      if (api.isDisabled(error)) {
        setSnapshot(emptySnapshot());
        setDisabledMessage(api.errorMessage(error));
        setPollStatus("disabled");
        setPollError("");
        return;
      }
      setPollStatus("degraded");
      setPollError(api.errorMessage(error));
    }
  }, [api]);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => void refresh(), pollMs);
    return () => {
      window.clearInterval(interval);
      // Abort the in-flight poll, not just the timer. Clearing the interval
      // stops FUTURE polls; without this the one already in flight still
      // resolves and calls setState on an unmounted component.
      abortRef.current?.abort();
    };
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
    canRespond,
    identityResolved,
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
