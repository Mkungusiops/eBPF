// Everything this route knows about the host, and every way it finds out.
//
// One hook owns the nine snapshot endpoints, their staggered poll intervals,
// the SSE catch-up rules and the reachability probe, because they are one
// concern with one failure mode: if the gateway stops answering, all of it has
// to degrade together and say so once, not nine times.
import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import {
  getAlerts,
  getApprovals,
  getBuckets,
  getCgroups,
  getChokeState,
  getCircuits,
  getDecisions,
  getSystemHealth,
  getWhoami,
  isDisabledError,
} from "./api";
import type { ApprovalRequest } from "./api";
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

export function useChokeData({
  pushToast,
  sharedStream,
}: {
  pushToast: (message: string, kind?: ToastMessage["kind"]) => void;
  sharedStream: ReturnType<typeof useStream>;
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
  const handleFailure = useCallback(
    (error: unknown, fallback: string) => {
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
      const state = await getChokeState();
      setChokeState(state);
      setLoadState({ kind: "ready" });
    } catch (error) {
      handleFailure(error, "failed to refresh choke state");
    }
  }, [handleFailure]);

  const refreshCircuits = useCallback(async () => {
    try {
      const rows = await getCircuits();
      const capped =
        rows.length > CIRCUIT_CAP
          ? [...rows].sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, CIRCUIT_CAP)
          : rows;
      setCircuits(capped);
    } catch (error) {
      handleFailure(error, "failed to refresh circuits");
    }
  }, [handleFailure]);

  const refreshBuckets = useCallback(async () => {
    try {
      setBuckets(await getBuckets());
    } catch (error) {
      handleFailure(error, "failed to refresh BPF buckets");
    }
  }, [handleFailure]);

  const refreshCgroups = useCallback(async () => {
    try {
      setCgroups(await getCgroups());
    } catch (error) {
      handleFailure(error, "failed to refresh cgroups");
    }
  }, [handleFailure]);

  const refreshDecisions = useCallback(async () => {
    try {
      setDecisions((await getDecisions(400)).slice(0, DECISION_CAP));
    } catch (error) {
      handleFailure(error, "failed to refresh decisions");
    }
  }, [handleFailure]);

  const refreshAlerts = useCallback(async () => {
    try {
      setAlerts(await getAlerts(200));
    } catch {
      setAlerts([]);
    }
  }, []);

  const refreshSystemHealth = useCallback(async () => {
    try {
      setSystemHealth(await getSystemHealth());
    } catch {
      setSystemHealth(null);
    }
  }, []);

  const refreshWhoami = useCallback(async () => {
    try {
      setWhoami(await getWhoami());
    } catch {
      setWhoami(null);
    }
  }, []);

  // The approvals queue is only served by the fleet control plane; the
  // single-host engine has no such endpoint, so a 404 here is expected and must
  // not surface as an error on that deployment.
  const refreshApprovals = useCallback(async () => {
    try {
      const res = await getApprovals();
      setApprovals(res.approvals || []);
    } catch {
      setApprovals([]);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    setRefreshing(true);
    try {
      await refreshState();
      await Promise.allSettled([
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

  const pingHost = useCallback(async (): Promise<void> => {
    const checkedAt = Date.now();
    const results = await Promise.all(
      HOST_ENDPOINTS.map(async (path) => {
        const started = performance.now();
        try {
          const response = await fetch(path, { method: "GET" });
          return {
            path,
            ok: response.ok,
            status: response.status,
            rtt_ms: Math.round(performance.now() - started),
            checked_at: checkedAt,
          };
        } catch (error) {
          return {
            path,
            ok: false,
            rtt_ms: Math.round(performance.now() - started),
            checked_at: checkedAt,
            error: error instanceof Error ? error.message : "request failed",
          };
        }
      }),
    );
    setHostPings(results);
  }, []);

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
