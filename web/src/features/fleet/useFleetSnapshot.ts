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
 *
 * IT NO LONGER READS whoami, AND THAT IS THE POINT OF THE MOVE. The fleet
 * console used to be its own page, so it asked /api/whoami itself and derived
 * its own answer to "may this account write?" from `can_respond`. It is now a
 * surface inside the SOC console, where that question has exactly one answer —
 * the shared authority store in features/soc/api.ts, which is the only place
 * that also carries "nobody has answered yet". A second read publishing a
 * second answer is the drift that armed a refused control on three surfaces
 * already; the claims that read path used to carry (an answered whoami with no
 * `can_respond` means PERMITTED, and nothing is armed while the answer is in
 * flight) now live over the shared store and are pinned in FleetSurface.test.tsx.
 *
 * `active` is the other half of the move. A closed surface must not poll: this
 * is a six-endpoint fan-out every five seconds, and ModalShell keeps a body
 * mounted once it has been opened, so "mounted" and "on screen" are no longer
 * the same thing.
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

export interface FleetSnapshotOptions {
  /** Injected; defaults to the real client so no call site has to name it. */
  api?: FleetApi;
  /**
   * Whether the surface hosting this feed is on screen. False stops the poll
   * dead — no first read, no interval, and the in-flight request aborted —
   * because the surface's shell keeps the body mounted after the operator
   * closes it, and a closed panel fanning six requests across every peer every
   * five seconds is cost nobody asked for.
   */
  active?: boolean;
}

export function useFleetSnapshot(
  pollMs: number = POLL_MS,
  { api = defaultFleetApi, active = true }: FleetSnapshotOptions = {}
): FleetSnapshotFeed {
  // One controller for the whole hook. Every fetch carries its signal and the
  // cleanup aborts it, so a poll started before unmount cannot resolve into a
  // dead component — the missing-AbortSignal bug named in the Tier 1A plan.
  const abortRef = useRef<AbortController | null>(null);
  /**
   * Whether a fan-out is still out there.
   *
   * A TICK MUST NEVER CANCEL A POLL. Once the signal actually reached fetch,
   * the old "abort the previous one on every call" rule stopped being a
   * tie-breaker and became a starvation bug: the engine gives its peer fan-out
   * a 6s timeout (engine/internal/api/fleet.go) against this hook's 5s poll, so
   * ONE hung peer means every tick kills the request in flight and the next one
   * inherits the same hung peer. The surface then sits at "connecting" with an
   * empty host table for ever — and silently, because an abort is deliberately
   * not reported as a fault. Before the signal was wired the same fan-out
   * merely landed late; now it never lands at all.
   */
  const inFlightRef = useRef(false);
  const [snapshot, setSnapshot] = useState<FleetStateSnapshot>(() => emptySnapshot());
  const [pollStatus, setPollStatus] = useState<PollStatus>("idle");
  const [disabledMessage, setDisabledMessage] = useState("");
  const [pollError, setPollError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const run = useCallback(async (supersede: boolean) => {
    // The timer YIELDS to a poll already running; an operator does not. A
    // Refresh press and the re-read after a containment write are single acts
    // that must produce fresh rows, so they cancel and restart — which cannot
    // starve anything, because nothing repeats them on a timer.
    if (inFlightRef.current) {
      if (!supersede) return;
      abortRef.current?.abort();
    }
    setPollStatus((current) => (current === "idle" ? "loading" : current));
    // A controller per poll, created HERE rather than in an effect: effect
    // ordering meant the first call could run before the ref was assigned and
    // went out with no signal at all — the exact bug this was meant to fix,
    // silently reintroduced one layer down. Ordering needs no tie-breaker now:
    // skipping a tick while one is in flight means there is only ever one.
    const controller = new AbortController();
    abortRef.current = controller;
    inFlightRef.current = true;
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
      // AN ABORT IS NOT A DEGRADED FLEET. This poll was cancelled on purpose —
      // the operator closed the surface, the console unmounted, or a newer poll
      // superseded this one — and `api.isDisabled` says false for an
      // AbortError, so without this the cleanup's own abort fell through to the
      // degraded branch below and left "degraded" + a red banner behind on a
      // body ModalShell keeps mounted. Re-opening the surface then painted the
      // failure of the poll that closing it had killed, until the next one
      // resolved. Asked of the controller rather than of the error, because a
      // fake api (and a browser that rejects with something else) need not
      // produce a DOMException named AbortError for the abort to be the cause.
      if (controller.signal.aborted) return;
      if (api.isDisabled(error)) {
        setSnapshot(emptySnapshot());
        setDisabledMessage(api.errorMessage(error));
        setPollStatus("disabled");
        setPollError("");
        return;
      }
      setPollStatus("degraded");
      setPollError(api.errorMessage(error));
    } finally {
      // Only the poll that is still the current one may say the line is clear.
      // A superseded poll's finally runs while its replacement is already out.
      if (abortRef.current === controller) inFlightRef.current = false;
    }
  }, [api]);

  /** An operator's own re-read: supersedes whatever is in flight. */
  const refresh = useCallback(() => run(true), [run]);

  useEffect(() => {
    // Nothing at all while the surface is closed — not even the first read.
    // Returning before the interval is set is what makes "a closed surface does
    // not poll" true of the very first render as well as of every one after it.
    if (!active) return;
    void run(true);
    // The TICK does not supersede — see inFlightRef.
    const interval = window.setInterval(() => void run(false), pollMs);
    return () => {
      window.clearInterval(interval);
      // Abort the in-flight poll, not just the timer. Clearing the interval
      // stops FUTURE polls; without this the one already in flight still
      // resolves and calls setState on an unmounted component — and the same
      // applies when the operator closes the surface, which runs this cleanup.
      abortRef.current?.abort();
    };
  }, [active, pollMs, run]);

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
