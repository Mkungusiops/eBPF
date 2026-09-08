// Everything this route knows about the host, and every way it finds out.
//
// One hook owns the nine snapshot endpoints, their staggered poll intervals,
// the SSE catch-up rules and the reachability probe, because they are one
// concern with one failure mode: if the gateway stops answering, all of it has
// to degrade together and say so once, not nine times. "Together" is literal
// and was not free — every read here, the probe included, runs on the same
// client deadline and the same teardown controller, because the one read left
// unbounded is the one that goes on reporting a healthy host.
import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import {
  CHOKE_READ_TIMEOUT_MS,
  getAlerts,
  getApprovals,
  getBuckets,
  getCgroups,
  getChokeState,
  getCircuits,
  getDecisions,
  getSystemHealth,
  getWhoami,
  isAbortError,
  isDisabledError,
  isTimeoutError,
  probeEndpoint,
} from "./api";
import type { ApprovalRequest, ChokeReadOptions } from "./api";
import type { useStream } from "../../lib/stream";
import type {
  Alert,
  BucketEntry,
  CgroupMap,
  ChokeState,
  CircuitEntry,
  Decision,
  HostPingResult,
  LoadState,
  ToastMessage,
  Whoami,
} from "./types";
import { CIRCUIT_CAP, DECISION_CAP, HOST_ENDPOINTS, type StreamInfo } from "./constants";
import { useInterval } from "./hooks";

export interface ChokeData {
  loadState: LoadState;
  chokeState: ChokeState | null;
  setChokeState: Dispatch<SetStateAction<ChokeState | null>>;
  circuits: CircuitEntry[];
  buckets: BucketEntry[];
  cgroups: CgroupMap;
  decisions: Decision[];
  alerts: Alert[];
  systemHealth: Record<string, unknown> | null;
  whoami: Whoami | null;
  approvals: ApprovalRequest[];
  hostPings: HostPingResult[];
  streamInfo: StreamInfo;
  now: number;
  refreshing: boolean;
  refreshAll: () => Promise<void>;
  refreshState: () => Promise<void>;
  refreshCircuits: () => Promise<void>;
  refreshApprovals: () => Promise<void>;
  pingHost: () => Promise<void>;
}

/**
 * Deadline for one identity read.
 *
 * A whoami that REJECTS is handled below by the self-disarming retry. One that
 * never settles is a different animal, and it is the shape a half-open
 * connection through a load balancer takes — the control-plane outage this
 * estate has actually seen. `refreshAll` awaits this read among the others, so
 * an unbounded one never releases `refreshing`: the Refresh button stays
 * spinning and DISABLED (see sections.tsx) for the rest of the session, which
 * takes the operator's manual recovery away exactly when the control plane is
 * sick. Bounding the read makes silence settle as a failure, which the retry
 * interval already knows how to recover from.
 */
const WHOAMI_TIMEOUT_MS = 8000;

export function useChokeData({
  pushToast,
  sharedStream,
  whoamiTimeoutMs = WHOAMI_TIMEOUT_MS,
  readTimeoutMs = CHOKE_READ_TIMEOUT_MS,
}: {
  pushToast: (message: string, kind?: ToastMessage["kind"]) => void;
  sharedStream: ReturnType<typeof useStream>;
  /** Injectable so a test can drive a hung read to its deadline; see above. */
  whoamiTimeoutMs?: number;
  /**
   * Deadline for every SNAPSHOT read (state, circuits, buckets, cgroups,
   * decisions, alerts, health, approvals), injectable for the same reason as
   * the identity deadline: a test must be able to drive a hung read to its
   * timeout without waiting eight real seconds, and without fake timers, which
   * deadlock the act() flush these async reads run through.
   *
   * whoami keeps its own knob because the two are pinned by different tests and
   * one of them must be able to hang while the other answers.
   */
  readTimeoutMs?: number;
}): ChokeData {
  const [loadState, setLoadState] = useState<LoadState>({ kind: "loading" });
  const [chokeState, setChokeState] = useState<ChokeState | null>(null);
  const [circuits, setCircuits] = useState<CircuitEntry[]>([]);
  const [buckets, setBuckets] = useState<BucketEntry[]>([]);
  const [cgroups, setCgroups] = useState<CgroupMap>({});
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [systemHealth, setSystemHealth] = useState<Record<string, unknown> | null>(null);
  const [whoami, setWhoami] = useState<Whoami | null>(null);
  // EN-2 change-control queue: destructive actions awaiting a second operator.
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [hostPings, setHostPings] = useState<HostPingResult[]>([]);
  const [streamInfo, setStreamInfo] = useState<StreamInfo>({
    state: "connecting",
    retries: 0,
    lastMessageAt: 0,
    totalMessages: 0,
    messagesByMinute: [],
  });
  const [now, setNow] = useState(Date.now());
  const [refreshing, setRefreshing] = useState(false);
  const snapshotDebounceRef = useRef<number | null>(null);
  const processedStreamBatchRef = useRef(0);
  const previousStreamStateRef = useRef(sharedStream.state);

  // Read chokeState through a ref so handleFailure stays referentially stable.
  // Depending on chokeState directly churned its identity on every state
  // refresh, which cascaded through refreshState→refreshAll and re-fired the
  // mount effect on a loop — leaving the Refresh button stuck on "Refreshing".
  const chokeStateRef = useRef(chokeState);
  chokeStateRef.current = chokeState;

  // When the state endpoint last ANSWERED. Only read once it stops answering,
  // to say on screen how old the snapshot the page is still rendering is.
  const lastStateOkRef = useRef(0);

  /**
   * One controller for every read this hook starts, aborted when the route
   * unmounts. Without it a poll or a refresh already in flight still resolves
   * after teardown and writes state into a dead tree — and, with the deadlines
   * below, still holds a socket open on a gateway that is already struggling.
   *
   * The cleanup arms a REPLACEMENT rather than leaving the ref aborted: React's
   * StrictMode tears the effect down and sets it up again on the same hook
   * instance without re-rendering, and a permanently aborted controller there
   * would abort every read for the life of the mount.
   */
  const readAbortRef = useRef<AbortController | null>(null);
  if (readAbortRef.current === null) readAbortRef.current = new AbortController();
  useEffect(() => {
    return () => {
      readAbortRef.current?.abort();
      readAbortRef.current = new AbortController();
    };
  }, []);
  const readOptions = useCallback(
    (): ChokeReadOptions => ({ signal: readAbortRef.current?.signal, timeoutMs: readTimeoutMs }),
    [readTimeoutMs],
  );

  const handleFailure = useCallback(
    (error: unknown, fallback: string) => {
      // A read this hook cancelled is not a gateway fault, and reporting it as
      // one would put a red banner and a toast in front of an operator who had
      // simply navigated away and back.
      if (isAbortError(error)) return;
      if (isDisabledError(error)) {
        setLoadState({ kind: "disabled", message: String(error.body || "choke gateway not enabled") });
        return;
      }
      const message = error instanceof Error ? error.message : fallback;
      if (!chokeStateRef.current) setLoadState({ kind: "error", message });
      pushToast(message || fallback, "err");
    },
    [pushToast],
  );

  const refreshState = useCallback(async () => {
    try {
      const state = await getChokeState(readOptions());
      setChokeState(state);
      lastStateOkRef.current = Date.now();
      setLoadState({ kind: "ready" });
    } catch (error) {
      // MID-SESSION SILENCE IS A PERSISTENT FACT, NOT A TOAST.
      //
      // handleFailure raises the route banner only while no snapshot has ever
      // arrived, which is right for the other reads — one failed panel does not
      // make the page a lie. The state read is different: it is the snapshot
      // the counts, the mode and the Containment Command header are drawn from,
      // so once it stops answering the page goes on rendering a reading of the
      // host that is no longer true, and a toast that fades was the only thing
      // that ever said so. An operator deciding whether to fire containment has
      // to be able to see, while they decide, that this is the last good
      // snapshot and not the current one — the same debt the SOC route pays
      // with its stale-stream banner.
      //
      // Only a TIMEOUT escalates: a 503 is the gateway ANSWERING that it is
      // switched off, which is the disabled banner's sentence and not this one,
      // and a 5xx or a refused connection is a read that failed loudly and is
      // already retried on the ten-second poll below.
      if (isTimeoutError(error) && chokeStateRef.current) {
        const ageSeconds = Math.max(0, Math.round((Date.now() - lastStateOkRef.current) / 1000));
        setLoadState({
          kind: "error",
          message: `${error.message}. Every reading below is the last good snapshot, from ${ageSeconds}s ago — not the current state of the host.`,
        });
        pushToast(error.message, "err");
        return;
      }
      // On cold start the same timeout arrives here as a ChokeTimeoutError
      // whose message says "unreachable", so the route banner says that instead
      // of the disabled banner's "gateway not enabled" — the gateway answering
      // that it is off and the gateway not answering at all are different facts
      // about the host, and only one of them is a setting.
      handleFailure(error, "failed to refresh choke state");
    }
  }, [handleFailure, pushToast, readOptions]);

  const refreshCircuits = useCallback(async () => {
    try {
      const rows = await getCircuits(readOptions());
      const capped =
        rows.length > CIRCUIT_CAP
          ? [...rows].sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, CIRCUIT_CAP)
          : rows;
      setCircuits(capped);
    } catch (error) {
      handleFailure(error, "failed to refresh circuits");
    }
  }, [handleFailure, readOptions]);

  const refreshBuckets = useCallback(async () => {
    try {
      setBuckets(await getBuckets(readOptions()));
    } catch (error) {
      handleFailure(error, "failed to refresh BPF buckets");
    }
  }, [handleFailure, readOptions]);

  const refreshCgroups = useCallback(async () => {
    try {
      setCgroups(await getCgroups(readOptions()));
    } catch (error) {
      handleFailure(error, "failed to refresh cgroups");
    }
  }, [handleFailure, readOptions]);

  const refreshDecisions = useCallback(async () => {
    try {
      setDecisions((await getDecisions(400, readOptions())).slice(0, DECISION_CAP));
    } catch (error) {
      handleFailure(error, "failed to refresh decisions");
    }
  }, [handleFailure, readOptions]);

  const refreshAlerts = useCallback(async () => {
    try {
      setAlerts(await getAlerts(200, readOptions()));
    } catch (error) {
      // An abort is a teardown, not an empty alert list: blanking the table on
      // unmount would repaint the route empty for a frame on the way back in.
      if (isAbortError(error)) return;
      setAlerts([]);
    }
  }, [readOptions]);

  const refreshSystemHealth = useCallback(async () => {
    try {
      setSystemHealth(await getSystemHealth(readOptions()));
    } catch (error) {
      if (isAbortError(error)) return;
      setSystemHealth(null);
    }
  }, [readOptions]);

  // whoami is this route's AUTHORITY read, and it is on none of the staggered
  // snapshot polls below — it only runs inside refreshAll. So a single failed
  // whoami (a blip, a restart, a proxy hiccup) left `whoami` null, which
  // ChokeRoute publishes as "the question is still open", which withholds every
  // containment control. The operator's console then stayed disabled until they
  // noticed and pressed Refresh, or the tab lost and regained visibility —
  // during an incident, neither is a recovery path.
  //
  // So a failure arms its own retry rather than adding a ninth permanent poll:
  // the flag below is only true while whoami is unanswered, and the interval
  // stops the moment the server speaks.
  const [whoamiUnanswered, setWhoamiUnanswered] = useState(true);
  const refreshWhoami = useCallback(async () => {
    try {
      // The deadline lives in the client (see ChokeTimeoutError) rather than in
      // a race written out here, so the identity read is bounded the same way
      // every other read on this route now is, and one hung request cannot
      // outlive the refresh that started it.
      const identity = await getWhoami({ signal: readAbortRef.current?.signal, timeoutMs: whoamiTimeoutMs });
      setWhoami(identity);
      setWhoamiUnanswered(false);
    } catch (error) {
      // An abort is this route being torn down, not an answer about the
      // account: leave the last real answer standing and let the next mount
      // ask again.
      if (isAbortError(error)) return;
      // Silence and a refusal-to-connect are the same thing to this route: no
      // authority, so containment stays withheld and the retry stays armed.
      setWhoami(null);
      setWhoamiUnanswered(true);
    }
  }, [whoamiTimeoutMs]);

  // ASKED ONLY WHERE IT EXISTS, rather than asked everywhere and forgiven.
  //
  // Dual control is a control-plane feature: /api/approvals is registered by
  // engine/internal/controlplane and NOT by engine/internal/api, so on the
  // single-tenant engine this request is a 404 every time. The old spelling
  // issued it regardless and swallowed the failure — which reads as harmless
  // and is not: web/e2e/probe/deployment.probe.spec.ts asserts that the
  // console never asks a deployment for a route it does not serve, and the
  // suite's own notes call a panel that quietly calls an unimplemented route a
  // class this codebase has shipped three times. It went unnoticed here only
  // because the request used to be queued behind the state read and the page
  // navigated away before the 404 landed; bounding the reads made the same
  // wrong request visible.
  //
  // `policy_scope` is the discriminator the SERVER states: "fleet" on the
  // control plane, absent on the engine (verified against both live
  // deployments 2026-09-08). It is documented as a deployment capability
  // rather than a permission — the control plane emits it identically for
  // every principal — so it answers "does this deployment have an approvals
  // queue" without the console guessing from the shape of some other field.
  const servesApprovals = whoami !== null && whoami.policy_scope === "fleet";

  const refreshApprovals = useCallback(async () => {
    if (!servesApprovals) {
      setApprovals([]);
      return;
    }
    try {
      const res = await getApprovals(readOptions());
      setApprovals(res.approvals || []);
    } catch (error) {
      if (isAbortError(error)) return;
      setApprovals([]);
    }
  }, [readOptions, servesApprovals]);

  /**
   * Every read at once, and NONE of them in front of the others.
   *
   * The state read used to be awaited on its own line before the settled batch,
   * which made it a single point of failure for the whole control: `refreshing`
   * is cleared in the finally and disables the Refresh button (sections.tsx),
   * so one state read that never came back left the operator's only manual
   * recovery spinning and unpressable for the session, with the seven other
   * reads never even issued. Each read now carries its own deadline and lands
   * or fails on its own, so a slow gateway costs the panels it actually serves
   * and nothing else.
   */
  const refreshAll = useCallback(async () => {
    setRefreshing(true);
    try {
      await Promise.allSettled([
        refreshState(),
        refreshCircuits(),
        refreshBuckets(),
        refreshCgroups(),
        refreshDecisions(),
        refreshAlerts(),
        refreshSystemHealth(),
        refreshWhoami(),
        refreshApprovals(),
      ]);
    } finally {
      setRefreshing(false);
    }
  }, [
    refreshAlerts,
    refreshBuckets,
    refreshCgroups,
    refreshCircuits,
    refreshDecisions,
    refreshState,
    refreshSystemHealth,
    refreshWhoami,
    refreshApprovals,
  ]);

  const scheduleSnapshotCatchup = useCallback(() => {
    if (snapshotDebounceRef.current != null) window.clearTimeout(snapshotDebounceRef.current);
    snapshotDebounceRef.current = window.setTimeout(() => {
      void refreshState();
      void refreshCircuits();
      void refreshCgroups();
      snapshotDebounceRef.current = null;
    }, 750);
  }, [refreshCgroups, refreshCircuits, refreshState]);

  /**
   * The reachability probe behind the header's host pill.
   *
   * On the same client deadline and the same teardown controller as every other
   * read on this route (`readOptions`), because it was neither: a bare fetch
   * with no deadline and no signal never settles against a half-open connection
   * through a load balancer, so `hostPings` kept its last good reading and the
   * pill went on saying "host ok" while every other read had already timed out
   * — and four sockets per probe were left open, every eight seconds, on a
   * gateway that was already struggling. A probe that times out is now a probe
   * that FAILED, which is what the pill reports.
   *
   * A probe the route CANCELLED says nothing about the host, so a teardown
   * leaves the previous reading standing rather than painting the host down on
   * the way out — and on the way back in, where that stale "down" would be the
   * first thing an operator saw.
   */
  const pingHost = useCallback(async (): Promise<void> => {
    const checkedAt = Date.now();
    const results = await Promise.all(
      HOST_ENDPOINTS.map(async (path): Promise<HostPingResult | null> => {
        const started = performance.now();
        try {
          const probe = await probeEndpoint(path, readOptions());
          return {
            path,
            ok: probe.ok,
            status: probe.status,
            rtt_ms: Math.round(performance.now() - started),
            checked_at: checkedAt,
          };
        } catch (error) {
          if (isAbortError(error)) return null;
          return {
            path,
            ok: false,
            rtt_ms: Math.round(performance.now() - started),
            checked_at: checkedAt,
            // A ChokeTimeoutError's message says "unreachable" and names the
            // endpoint; the host popover renders it verbatim.
            error: error instanceof Error ? error.message : "request failed",
          };
        }
      }),
    );
    if (results.some((result) => result === null)) return;
    setHostPings(results as HostPingResult[]);
  }, [readOptions]);

  useEffect(() => {
    void refreshAll();
  }, [refreshAll]);

  useEffect(() => {
    setStreamInfo((prev) => ({
      ...prev,
      state: sharedStream.state,
      retries: sharedStream.retries,
      lastMessageAt: sharedStream.lastMessageAt || prev.lastMessageAt,
      totalMessages: sharedStream.messageCount,
    }));
  }, [sharedStream.lastMessageAt, sharedStream.messageCount, sharedStream.retries, sharedStream.state]);

  useEffect(() => {
    const previous = previousStreamStateRef.current;
    if (sharedStream.state === "live" && (previous === "reconnect" || previous === "down")) {
      void refreshState();
      void refreshCircuits();
      void refreshDecisions();
      void refreshCgroups();
    }
    previousStreamStateRef.current = sharedStream.state;
  }, [refreshCgroups, refreshCircuits, refreshDecisions, refreshState, sharedStream.state]);

  useEffect(() => {
    if (sharedStream.batchId === 0 || processedStreamBatchRef.current === sharedStream.batchId) return;
    processedStreamBatchRef.current = sharedStream.batchId;
    const timestamp = sharedStream.lastEventAt || Date.now();
    setStreamInfo((prev) => {
      const recent = [
        ...prev.messagesByMinute,
        ...sharedStream.latestBatch.map(() => timestamp),
      ].filter((value) => timestamp - value <= 60000);
      return { ...prev, messagesByMinute: recent };
    });
    for (const envelope of sharedStream.latestBatch) {
      if (envelope.type === "decision" && envelope.payload && typeof envelope.payload === "object") {
        const decision = envelope.payload as Decision;
        setDecisions((prev) => [decision, ...prev.filter((row) => row.id !== decision.id)].slice(0, DECISION_CAP));
        scheduleSnapshotCatchup();
      }
    }
  }, [scheduleSnapshotCatchup, sharedStream.batchId, sharedStream.lastEventAt, sharedStream.latestBatch]);

  useEffect(() => {
    return () => {
      if (snapshotDebounceRef.current != null) window.clearTimeout(snapshotDebounceRef.current);
    };
  }, []);

  useEffect(() => {
    const onVisibility = () => {
      if (document.visibilityState !== "visible") return;
      const silent = Date.now() - (streamInfo.lastMessageAt || 0);
      void refreshAll();
      if (silent > 10000 || streamInfo.state !== "live") sharedStream.reconnect();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, [refreshAll, sharedStream, streamInfo.lastMessageAt, streamInfo.state]);

  // Staggered on purpose: eight endpoints on one timer produce a synchronised
  // burst against the engine every N seconds. Cheap reads poll fast, the
  // expensive circuit/state snapshots poll slow, and everything but the clock
  // and the reachability probe stops once the gateway reports itself disabled.
  useInterval(() => setNow(Date.now()), 1000);
  useInterval(() => void refreshBuckets(), 5000, loadState.kind !== "disabled");
  useInterval(() => void refreshSystemHealth(), 5000, loadState.kind !== "disabled");
  useInterval(() => void refreshCircuits(), 7000, loadState.kind !== "disabled");
  useInterval(() => void refreshAlerts(), 8000, loadState.kind !== "disabled");
  useInterval(() => void pingHost(), 8000, true);
  useInterval(() => void refreshCgroups(), 9000, loadState.kind !== "disabled");
  useInterval(() => void refreshState(), 10000, loadState.kind !== "disabled");
  // The authority retry. Deliberately NOT gated on `loadState`: a gateway that
  // reports itself disabled still has an identity endpoint, and the operator
  // whose whoami failed needs it answered before the gateway comes back, not
  // after. It disarms itself as soon as whoami answers once.
  useInterval(() => void refreshWhoami(), 6000, whoamiUnanswered);

  return {
    loadState,
    chokeState,
    setChokeState,
    circuits,
    buckets,
    cgroups,
    decisions,
    alerts,
    systemHealth,
    whoami,
    approvals,
    hostPings,
    streamInfo,
    now,
    refreshing,
    refreshAll,
    refreshState,
    refreshCircuits,
    refreshApprovals,
    pingHost,
  };
}
