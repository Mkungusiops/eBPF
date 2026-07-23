import React, {
  type CSSProperties,
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Command as CommandPrimitive } from "cmdk";
import { ArrowLeft, X } from "lucide-react";
import { EventReplay } from "../../components/EventReplay";
import { VirtualList } from "../../components/VirtualList";
import {
  annotateCircuit,
  applyPreset as applyPresetApi,
  bulkManualAction,
  copyToClipboard,
  forensicSnapshot,
  forgetCircuits,
  getAlerts,
  getBuckets,
  getCgroups,
  getChokeState,
  getCircuits,
  getDecisions,
  getProc,
  getProcesses,
  getProcess,
  getSystemHealth,
  getWhoami,
  jailProcesses,
  manualAction,
  previewPolicy,
  setMode,
  thawQuarantine,
  releaseProcess,
  toggleKillSwitch,
  updateThresholds,
  verifyChain,
  isDisabledError,
} from "./api";
import { useStream } from "../../lib/stream";
import { useOSTheme } from "../../lib/theme";
import type {
  Alert,
  BucketEntry,
  CgroupMap,
  ChokeAction,
  ChokeState,
  CircuitEntry,
  ConfirmRequest,
  Decision,
  HostPingResult,
  LoadState,
  PolicyPreviewResponse,
  ProcessDetailPayload,
  SysProcDetail,
  SysProcEntry,
  Thresholds,
  ToastMessage,
  Whoami,
} from "./types";
import {
  ACTIONS,
  DEFAULT_THRESHOLDS,
  STATE_ORDER,
  basename,
  bucketFlagsLabel,
  bucketizeDecisions,
  circuitMatches,
  classifyProc,
  countByState,
  countCgroupPids,
  decisionMatches,
  deriveProcSignals,
  formatRelative,
  formatTime,
  formatUptime,
  getCgroupPids,
  normalizeThresholds,
  originLabel,
  parseSearch,
  readJsonStorage,
  shortExec,
  sortBuckets,
  stateForScore,
  summarizeAlerts,
  tapeTextMatches,
  thresholdsAscending,
  topK,
  writeJsonStorage,
} from "./utils";
import { EnforcementLadder } from "../common/EnforcementLadder";
import { ACTION_FOR_RUNG, LADDER, PROCESS_TERMINAL, type Rung } from "../common/enforcement";
import {
  ContainmentCommandHeader,
  ContainmentLadder,
  computePosture,
  type CommandMetrics,
  type ViewMode
} from "../common/ContainmentCommand";
import "./ChokeRoute.css";

const PROC_RENDER_CAP = 300;
const DECISION_CAP = 400;
const CIRCUIT_CAP = 2000;
const HOST_ENDPOINTS = ["/api/whoami", "/api/choke/state", "/api/choke/circuits", "/api/decisions?limit=1"];
const WINDOW_OPTIONS = [5, 30, 60, 1440];

type PopoverName = "host" | "live" | "audit" | "mode" | null;

type DrillState =
  | { kind: "closed" }
  | { kind: "loading"; execId: string }
  | { kind: "ready"; execId: string; payload: ProcessDetailPayload }
  | { kind: "error"; execId: string; message: string };

type JailDetail =
  | { kind: "closed" }
  | { kind: "loading"; process: SysProcEntry }
  | { kind: "ready"; process: SysProcEntry; detail: SysProcDetail }
  | { kind: "error"; process: SysProcEntry; message: string };

interface ChokeRouteProps {}

function useInterval(callback: () => void, delayMs: number | null, enabled = true): void {
  const ref = useRef(callback);
  useEffect(() => {
    ref.current = callback;
  }, [callback]);
  useEffect(() => {
    if (!enabled || delayMs == null) return;
    const id = window.setInterval(() => ref.current(), delayMs);
    return () => window.clearInterval(id);
  }, [delayMs, enabled]);
}

function useStoredSet(key: string): [Set<number>, (next: Set<number>) => void] {
  const [value, setValue] = useState<Set<number>>(() => new Set(readJsonStorage<number[]>(key, [])));
  const setStored = useCallback(
    (next: Set<number>) => {
      setValue(new Set(next));
      writeJsonStorage(key, Array.from(next).slice(-5000));
    },
    [key],
  );
  return [value, setStored];
}

function useStoredBoolean(key: string, fallback: boolean): [boolean, (next: boolean | ((prev: boolean) => boolean)) => void] {
  const [value, setValue] = useState<boolean>(() => Boolean(readJsonStorage<boolean>(key, fallback)));
  const setStored = useCallback(
    (next: boolean | ((prev: boolean) => boolean)) => {
      setValue((prev) => {
        const resolved = typeof next === "function" ? (next as (current: boolean) => boolean)(prev) : next;
        writeJsonStorage(key, resolved);
        return resolved;
      });
    },
    [key],
  );
  return [value, setStored];
}

// Choke's stylesheet keys off its own "choke-theme-light" class, so on top of
// the shared OS theme (which sets .theme-light/.theme-dark + the favicon) this
// mirrors the state onto Choke's class.
function useChokeTheme(): "dark" | "light" {
  const theme = useOSTheme();
  useEffect(() => {
    const light = theme === "light";
    document.documentElement.classList.toggle("choke-theme-light", light);
    document.body.classList.toggle("choke-theme-light", light);
  }, [theme]);
  return theme;
}

export function ChokeRoute(): React.ReactElement {
  const theme = useChokeTheme();
  const sharedStream = useStream();
  const [loadState, setLoadState] = useState<LoadState>({ kind: "loading" });
  const [chokeState, setChokeState] = useState<ChokeState | null>(null);
  const [circuits, setCircuits] = useState<CircuitEntry[]>([]);
  const [buckets, setBuckets] = useState<BucketEntry[]>([]);
  const [cgroups, setCgroups] = useState<CgroupMap>({});
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [systemHealth, setSystemHealth] = useState<Record<string, unknown> | null>(null);
  const [whoami, setWhoami] = useState<Whoami | null>(null);
  const [globalSearch, setGlobalSearch] = useState("");
  const [procFilter, setProcFilter] = useState("");
  const [tapeSearch, setTapeSearch] = useState("");
  const [stateFilters, setStateFilters] = useState<Set<string>>(
    () => new Set(["throttled", "tarpit", "quarantined", "severed"]),
  );
  const [tapeActions, setTapeActions] = useState<Set<string>>(() => new Set(ACTIONS));
  const [windowMin, setWindowMinState] = useState<number>(() => readJsonStorage("choke.window", 30));
  const [selectedExecs, setSelectedExecs] = useState<Set<string>>(new Set());
  const [selectedDecisionIds, setSelectedDecisionIds] = useState<Set<number>>(new Set());
  const [ackedDecisionIds, setAckedDecisionIds] = useStoredSet("choke.tape.acked");
  const [alertsActive, setAlertsActive] = useStoredBoolean("soc.notifications", true);
  const [alertBadgeEnabled, setAlertBadgeEnabled] = useStoredBoolean("choke.alerts.badge", true);
  const [hideAcked, setHideAcked] = useState(false);
  const [groupTape, setGroupTape] = useState(false);
  const [tapeFilterExec, setTapeFilterExec] = useState<string | null>(null);
  const [autoScrollTape, setAutoScrollTape] = useState(true);
  const [density, setDensity] = useState<"normal" | "compact">("normal");
  const [viewMode, setViewMode] = useState<ViewMode>(() =>
    readJsonStorage<ViewMode>("choke.viewMode", "command") === "assurance" ? "assurance" : "command"
  );
  useEffect(() => writeJsonStorage("choke.viewMode", viewMode), [viewMode]);
  const [confirm, setConfirm] = useState<ConfirmRequest | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [popover, setPopover] = useState<PopoverName>(null);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  // "Clear all" in the alerts drawer hides everything up to this instant; newer
  // severed decisions still surface afterwards. Kept in state (session-scoped).
  const [alertsClearedAt, setAlertsClearedAt] = useState(0);
  const [profileOpen, setProfileOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [jailOpen, setJailOpen] = useState(false);
  const [jailDetail, setJailDetail] = useState<JailDetail>({ kind: "closed" });
  const [drill, setDrill] = useState<DrillState>({ kind: "closed" });
  const [policyYaml, setPolicyYaml] = useState(DEFAULT_POLICY);
  const [policyPreview, setPolicyPreview] = useState<PolicyPreviewResponse | null>(null);
  const [policyError, setPolicyError] = useState("");
  const [policyChecking, setPolicyChecking] = useState(false);
  const [hostPings, setHostPings] = useState<HostPingResult[]>([]);
  const [streamInfo, setStreamInfo] = useState({
    state: "connecting" as "connecting" | "live" | "reconnect" | "down",
    retries: 0,
    lastMessageAt: 0,
    totalMessages: 0,
    messagesByMinute: [] as number[],
  });
  const [now, setNow] = useState(Date.now());
  const [refreshing, setRefreshing] = useState(false);
  const tapeRef = useRef<HTMLDivElement | null>(null);
  const bootMs = useRef(Date.now());
  const snapshotDebounceRef = useRef<number | null>(null);
  const processedStreamBatchRef = useRef(0);
  const previousStreamStateRef = useRef(sharedStream.state);

  const pushToast = useCallback((message: string, kind: ToastMessage["kind"] = "ok") => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((prev) => [...prev, { id, kind, message }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, 3200);
  }, []);

  const setWindowMin = useCallback((value: number) => {
    const next = WINDOW_OPTIONS.includes(value) ? value : 30;
    setWindowMinState(next);
    writeJsonStorage("choke.window", next);
  }, []);

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
  }, [refreshAll, sharedStream.reconnect, streamInfo.lastMessageAt, streamInfo.state]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const active = document.activeElement;
      const typing =
        active instanceof HTMLInputElement ||
        active instanceof HTMLTextAreaElement ||
        active instanceof HTMLSelectElement ||
        active?.getAttribute("contenteditable") === "true";

      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen(true);
        return;
      }
      if (event.key === "Escape") {
        if (commandOpen) return setCommandOpen(false);
        if (helpOpen) return setHelpOpen(false);
        if (drill.kind !== "closed") return setDrill({ kind: "closed" });
        if (jailOpen) return setJailOpen(false);
        if (confirm) return setConfirm(null);
        if (popover) return setPopover(null);
        if (notificationsOpen) return setNotificationsOpen(false);
        if (profileOpen) return setProfileOpen(false);
        if (selectedExecs.size) return setSelectedExecs(new Set());
      }
      if (typing) return;
      if (event.key === "?") setHelpOpen(true);
      if (event.key === "/") {
        event.preventDefault();
        document.querySelector<HTMLInputElement>("[data-choke-global-search]")?.focus();
      }
      if (event.key === "J") setJailOpen(true);
      if (event.key === "K") openKillSwitchConfirm();
      if (event.key === "g") window.location.href = "/";
      if (["c", "f", "m", "d"].includes(event.key)) {
        const map: Record<string, string> = { c: "containment", f: "forensic", m: "maintenance", d: "default" };
        openPresetConfirm(map[event.key]);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });

  useInterval(() => setNow(Date.now()), 1000);
  useInterval(() => void refreshBuckets(), 5000, loadState.kind !== "disabled");
  useInterval(() => void refreshSystemHealth(), 5000, loadState.kind !== "disabled");
  useInterval(() => void refreshCircuits(), 7000, loadState.kind !== "disabled");
  useInterval(() => void refreshAlerts(), 8000, loadState.kind !== "disabled");
  useInterval(() => void pingHost(), 8000, true);
  useInterval(() => void refreshCgroups(), 9000, loadState.kind !== "disabled");
  useInterval(() => void refreshState(), 10000, loadState.kind !== "disabled");

  const thresholds = normalizeThresholds(chokeState?.thresholds);
  const mode = chokeState?.kill_switched ? "kill-switched" : chokeState?.mode || "detect-only";
  const stateCounts = chokeState?.counts || countByState(circuits, thresholds);
  const parsedSearch = useMemo(() => parseSearch(globalSearch), [globalSearch]);
  const alertCounts = useMemo(() => summarizeAlerts(alerts), [alerts]);
  const searchFilteredCircuits = useMemo(() => {
    const local = procFilter.trim().toLowerCase();
    return circuits
      .filter((entry) => stateFilters.has(entry.state || "pristine"))
      .filter((entry) => circuitMatches(entry, parsedSearch))
      .filter((entry) => {
        if (!local) return true;
        return [
          entry.pid,
          entry.binary,
          entry.exec_id,
          entry.args,
          entry.state,
          originLabel(entry),
        ]
          .join(" ")
          .toLowerCase()
          .includes(local);
      })
      .sort((a, b) => (b.score || 0) - (a.score || 0));
  }, [circuits, parsedSearch, procFilter, stateFilters]);
  const visibleCircuits = useMemo(() => searchFilteredCircuits.slice(0, PROC_RENDER_CAP), [searchFilteredCircuits]);
  const truncatedCircuits = searchFilteredCircuits.length > PROC_RENDER_CAP;

  const filteredDecisions = useMemo(() => {
    const cutoff = now - windowMin * 60000;
    return decisions
      .filter((decision) => tapeActions.has(decision.action || ""))
      .filter((decision) => {
        const time = decision.timestamp ? new Date(decision.timestamp).getTime() : 0;
        return time >= cutoff;
      })
      .filter((decision) => !tapeFilterExec || decision.exec_id === tapeFilterExec)
      .filter((decision) => !hideAcked || !ackedDecisionIds.has(decision.id || 0))
      .filter((decision) => tapeTextMatches(decision, tapeSearch))
      .filter((decision) => decisionMatches(decision, parsedSearch))
      .slice(0, DECISION_CAP);
  }, [ackedDecisionIds, decisions, hideAcked, now, parsedSearch, tapeActions, tapeFilterExec, tapeSearch, windowMin]);

  const groupedDecisions = useMemo(() => {
    if (!groupTape) return filteredDecisions.map((decision) => ({ decision, count: 0 }));
    const grouped: Array<{ decision: Decision; count: number }> = [];
    let index = 0;
    while (index < filteredDecisions.length) {
      const head = filteredDecisions[index];
      let count = 0;
      let cursor = index + 1;
      while (cursor < filteredDecisions.length && filteredDecisions[cursor].exec_id === head.exec_id) {
        count += 1;
        cursor += 1;
      }
      grouped.push({ decision: head, count });
      index = cursor;
    }
    return grouped;
  }, [filteredDecisions, groupTape]);

  const currentWindowDecisions = useMemo(() => {
    const cutoff = now - windowMin * 60000;
    return decisions.filter((decision) => {
      const time = decision.timestamp ? new Date(decision.timestamp).getTime() : 0;
      return time >= cutoff;
    });
  }, [decisions, now, windowMin]);

  const bucketSeconds = Math.max(1, Math.floor((windowMin * 60) / 30));
  const velocityBuckets = bucketizeDecisions(decisions, now, bucketSeconds, 30);
  const topBinaries = topK(currentWindowDecisions, (decision) => decision.binary || undefined, 5);
  const topReasons = topK(currentWindowDecisions, (decision) => (decision.reason || "").replace(/\s+\d+\s*$/, ""), 5);
  const selectedEntries = useMemo(
    () => circuits.filter((entry) => selectedExecs.has(entry.exec_id)),
    [circuits, selectedExecs],
  );
  const staleSeconds = streamInfo.lastMessageAt ? Math.floor((now - streamInfo.lastMessageAt) / 1000) : 0;
  const disabled = loadState.kind === "disabled";

  // ── Containment Command metrics (shared hero + ladder) ──────────────────
  // Contained = anything on a rung above pristine. Active threats = uncontained
  // processes already scoring at/over the first enforcement threshold — the
  // ones an operator should be acting on right now.
  const containedCount = LADDER.filter((r) => r !== "pristine").reduce((sum, r) => sum + (stateCounts[r] || 0), 0);
  const activeThreats = useMemo(
    () =>
      circuits.filter(
        (c) => (!c.state || c.state === "pristine") && (c.score || 0) >= (thresholds.throttle_at || 20)
      ).length,
    [circuits, thresholds.throttle_at]
  );
  const enforceMode: "detect-only" | "enforcing" = chokeState?.mode === "enforcing" ? "enforcing" : "detect-only";
  const auditOk = chokeState?.audit?.ok !== false;
  const commandMetrics: CommandMetrics = {
    subject: "processes",
    mode: enforceMode,
    activeThreats,
    contained: containedCount,
    tracked: chokeState?.tracked || circuits.length,
    auditOk,
    auditRows: chokeState?.audit?.total || 0,
    killSwitched: Boolean(chokeState?.kill_switched),
    headline: `${(currentWindowDecisions.length / Math.max(1, windowMin)).toFixed(1)} /min`,
    headlineLabel: "Decision rate",
    posture: computePosture({
      mode: enforceMode,
      activeThreats,
      contained: containedCount,
      auditOk,
      killSwitched: Boolean(chokeState?.kill_switched)
    })
  };
  const activeRung = stateFilters.size === 1 ? (Array.from(stateFilters)[0] as string) : null;
  const toggleRungFilter = useCallback((rung: Rung) => {
    setStateFilters((prev) =>
      prev.size === 1 && prev.has(rung)
        ? new Set<string>(["throttled", "tarpit", "quarantined", "severed"])
        : new Set<string>([rung])
    );
  }, []);

  const userLabel = String(whoami?.username || whoami?.user || "operator");
  const hostState = hostPings[0]?.ok === false ? "down" : hostPings[0] && hostPings[0].rtt_ms > 800 ? "slow" : "ok";

  useEffect(() => {
    if (!autoScrollTape || !tapeRef.current) return;
    tapeRef.current.scrollTop = 0;
  }, [autoScrollTape, groupedDecisions.length]);

  async function pingHost(): Promise<void> {
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
  }

  function toggleSetValue<T>(set: Set<T>, value: T): Set<T> {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    return next;
  }

  function openManualConfirm(entry: CircuitEntry, action: ChokeAction): void {
    setConfirm({
      title: `${action.toUpperCase()} pid ${entry.pid || "-"}`,
      body: `${entry.binary || "(unknown)"} (${shortExec(entry.exec_id)})`,
      danger: action === "sever" || action === "quarantine",
      confirmLabel: action,
      reasonRequired: true,
      withRevert: action !== "sever",
      onConfirm: async ({ reason, revert_after_seconds }) => {
        await manualAction({
          exec_id: entry.exec_id,
          pid: entry.pid,
          binary: entry.binary,
          action,
          reason,
          revert_after_seconds,
        });
        pushToast(`${action} applied`, "ok");
        await refreshAll();
      },
    });
  }

  function openBulkConfirm(action: ChokeAction): void {
    if (selectedEntries.length === 0) return;
    setConfirm({
      title: `${action.toUpperCase()} ${selectedEntries.length} process${selectedEntries.length === 1 ? "" : "es"}`,
      body: selectedEntries.map((entry) => entry.binary || shortExec(entry.exec_id)).join(", "),
      danger: action === "sever" || action === "quarantine",
      confirmLabel: action,
      reasonRequired: true,
      withRevert: action !== "sever",
      onConfirm: async ({ reason, revert_after_seconds }) => {
        const response = await bulkManualAction({
          targets: selectedEntries.map((entry) => ({
            exec_id: entry.exec_id,
            pid: entry.pid,
            binary: entry.binary,
          })),
          action,
          reason,
          revert_after_seconds,
        });
        const results = response.results || [];
        const ok = results.filter((result) => result.ok).length;
        pushToast(`bulk ${action}: ${ok}/${results.length || selectedEntries.length} ok`, ok === results.length ? "ok" : "warn");
        setSelectedExecs(new Set());
        await refreshAll();
      },
    });
  }

  function openBulkForgetConfirm(): void {
    const execIds = Array.from(selectedExecs);
    if (execIds.length === 0) return;
    setConfirm({
      title: `Forget ${execIds.length} circuit${execIds.length === 1 ? "" : "s"}`,
      body: "Live state is removed; audit history remains hash-chained.",
      confirmLabel: "forget",
      onConfirm: async () => {
        await forgetCircuits(execIds);
        pushToast(`forgot ${execIds.length} circuits`, "ok");
        setSelectedExecs(new Set());
        await refreshAll();
      },
    });
  }

  function openKillSwitchConfirm(): void {
    const target = !chokeState?.kill_switched;
    setConfirm({
      title: target ? "Engage kill-switch" : "Disengage kill-switch",
      body: target
        ? "Every enforcer is bypassed. Decisions still write to the audit chain."
        : "Future decisions can reach the active enforcer chain again.",
      danger: target,
      confirmLabel: target ? "engage" : "disengage",
      onConfirm: async () => {
        await toggleKillSwitch(target);
        pushToast(target ? "kill-switch engaged" : "kill-switch disengaged", target ? "warn" : "ok");
        await refreshState();
      },
    });
  }

  function openPresetConfirm(name: string): void {
    setConfirm({
      title: `Apply preset: ${name}`,
      body: PRESET_DESCRIPTIONS[name] || "Apply gateway posture preset.",
      danger: name === "containment" || name === "maintenance",
      confirmLabel: "apply",
      reasonRequired: true,
      onConfirm: async ({ reason }) => {
        await applyPresetApi(name, reason);
        pushToast(`preset ${name} applied`, "ok");
        await refreshState();
      },
    });
  }

  function openThawConfirm(): void {
    setConfirm({
      title: "Thaw quarantined cgroup",
      body: "Frozen processes resume. This is audited as a gateway decision.",
      confirmLabel: "thaw",
      reasonRequired: true,
      onConfirm: async ({ reason }) => {
        await thawQuarantine(reason);
        pushToast("quarantine thawed", "ok");
        await refreshAll();
      },
    });
  }

  function openModeConfirm(enforcing: boolean): void {
    setConfirm({
      title: enforcing ? "Switch to enforcing" : "Switch to detect-only",
      body: enforcing
        ? "Real kernel calls will fire for future decisions."
        : "Decisions will be recorded without hitting kernel enforcers.",
      danger: enforcing,
      confirmLabel: enforcing ? "enforce" : "detect-only",
      reasonRequired: true,
      onConfirm: async ({ reason }) => {
        await setMode(enforcing, reason);
        pushToast(enforcing ? "mode set to enforcing" : "mode set to detect-only", "ok");
        await refreshState();
      },
    });
  }

  async function openDrill(execId: string): Promise<void> {
    setDrill({ kind: "loading", execId });
    try {
      setDrill({ kind: "ready", execId, payload: await getProcess(execId) });
    } catch (error) {
      setDrill({
        kind: "error",
        execId,
        message: error instanceof Error ? error.message : "process detail failed",
      });
    }
  }

  async function runPolicyPreview(): Promise<void> {
    setPolicyError("");
    setPolicyChecking(true);
    try {
      const response = await previewPolicy(policyYaml);
      setPolicyPreview(response);
      if (response.valid === false) setPolicyError((response.errors || []).join("; "));
    } catch (error) {
      setPolicyPreview(null);
      setPolicyError(error instanceof Error ? error.message : "preview failed");
    } finally {
      setPolicyChecking(false);
    }
  }

  // Generate a policy from the current tracked snapshot so "Preview matches"
  // produces real hits — the bundled sample targets throttled shells, which a
  // box where everything is severed will never match (looking broken).
  function insertLivePolicy(): void {
    const yaml = buildLivePolicy(circuits);
    setPolicyYaml(yaml);
    setPolicyPreview(null);
    setPolicyError("");
  }

  async function downloadSnapshot(): Promise<void> {
    try {
      const blob = await forensicSnapshot();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `choke-forensic-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      pushToast("snapshot downloaded", "ok");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "snapshot failed", "err");
    }
  }

  // Assurance-lens export: a board-ready printable report, or a machine-readable
  // evidence bundle (the audit head hash + posture + containment ladder) for
  // audit / cyber-insurance. Both are built from the same live data as the view.
  function exportAssuranceReport(kind: "report" | "bundle"): void {
    const when = new Date();
    const stamp = when.toISOString().replace(/[:.]/g, "-");
    const headHash = String(chokeState?.audit?.head_hash || chokeState?.audit?.head || "");
    if (kind === "bundle") {
      const bundle = {
        generated_at: when.toISOString(),
        generated_by: userLabel,
        subject: "processes",
        posture: commandMetrics.posture,
        mode: commandMetrics.mode,
        kill_switch: commandMetrics.killSwitched ? "engaged" : "standby",
        active_threats: commandMetrics.activeThreats,
        contained: commandMetrics.contained,
        tracked: commandMetrics.tracked,
        audit: { intact: commandMetrics.auditOk, records: commandMetrics.auditRows, head_hash: headHash || null },
        containment_ladder: LADDER.reduce<Record<string, number>>((acc, r) => ({ ...acc, [r]: stateCounts[r] || 0 }), {}),
        thresholds,
        window_minutes: windowMin,
        decisions_in_window: currentWindowDecisions.length,
        top_binaries: topBinaries.map((b) => ({ binary: b.key, decisions: b.count }))
      };
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `containment-evidence-${stamp}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      pushToast("evidence bundle downloaded", "ok");
      return;
    }
    const html = buildAssuranceReportHtml({
      metrics: commandMetrics,
      stateCounts,
      thresholds,
      decisionsInWindow: currentWindowDecisions.length,
      windowLabel: formatWindow(windowMin),
      topBinaries,
      headHash,
      user: userLabel,
      when
    });
    const win = window.open("", "_blank");
    if (!win) {
      pushToast("popup blocked — allow popups to print the report", "err");
      return;
    }
    win.document.write(html);
    win.document.close();
    pushToast("board report opened — Print → Save as PDF", "ok");
  }

  async function handleAuditVerify(): Promise<void> {
    try {
      const response = await verifyChain();
      setChokeState((prev) => ({ ...(prev || {}), audit: response as ChokeState["audit"] }));
      pushToast(response.ok === false ? "audit chain broken" : "audit chain verified", response.ok === false ? "err" : "ok");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "audit verify failed", "err");
    }
  }

  async function copyAuditHead(): Promise<void> {
    const audit = chokeState?.audit;
    const value = String(audit?.head_hash || audit?.head || audit?.tip || audit?.total || "");
    if (!value) return;
    pushToast((await copyToClipboard(value)) ? "copied" : "copy failed", "ok");
  }

  const commandItems = useMemo(
    () => [
      { group: "preset", label: "Apply containment preset", run: () => openPresetConfirm("containment") },
      { group: "preset", label: "Apply forensic preset", run: () => openPresetConfirm("forensic") },
      { group: "preset", label: "Apply maintenance preset", run: () => openPresetConfirm("maintenance") },
      { group: "preset", label: "Apply default preset", run: () => openPresetConfirm("default") },
      { group: "action", label: "Open jail picker", run: () => setJailOpen(true) },
      { group: "action", label: "Toggle kill-switch", run: openKillSwitchConfirm },
      { group: "action", label: "Thaw quarantine", run: openThawConfirm },
      { group: "action", label: "Download forensic snapshot", run: () => void downloadSnapshot() },
      { group: "view", label: "Toggle density", run: () => setDensity((prev) => (prev === "compact" ? "normal" : "compact")) },
      { group: "view", label: "Show help", run: () => setHelpOpen(true) },
      ...circuits.slice(0, 25).map((entry) => ({
        group: "process",
        label: `Drill in pid ${entry.pid || "-"} ${entry.binary || "(unknown)"}`,
        run: () => void openDrill(entry.exec_id),
      })),
    ],
    [circuits],
  );

  return (
    <div className="choke-route" data-theme={theme}>
      <header className="choke-topbar">
        <div className="choke-topbar-row choke-topbar-primary" data-panel="topbar-row-1">
          <div className="choke-brand">
            <a href="/" className="choke-back" title="Back to SOC dashboard">
              <ArrowLeft size={15} aria-hidden="true" />
              <span>SOC</span>
            </a>
            <span className="choke-brand-divider" aria-hidden="true" />
            <span className="choke-brand-mark">Choke Gateway</span>
            <button className="choke-link-pill choke-mode-pill" type="button" onClick={() => setPopover(popover === "mode" ? null : "mode")}>
              <ModeBadge mode={mode} />
            </button>
          </div>
          <input
            data-choke-global-search
            className="choke-search"
            value={globalSearch}
            onChange={(event) => setGlobalSearch(event.target.value)}
            placeholder="Search processes, decisions, policies…"
          />
          {/* Status condensed to a colour-dot + one word; full detail on hover/click. */}
          <div className="choke-status-cluster">
            <button className={`choke-pill host-${hostState}`} type="button" onClick={() => setPopover(popover === "host" ? null : "host")} title={`host ${hostState}`}>
              <span className="choke-dot" /> host
            </button>
            <button className={`choke-pill ${chokeState?.audit?.ok === false ? "danger" : "ok"}`} type="button" onClick={() => setPopover(popover === "audit" ? null : "audit")} title={`audit ${chokeState?.audit?.ok === false ? "broken" : "ok"} · ${chokeState?.audit?.total || 0} rows`}>
              <span className={`choke-dot${chokeState?.audit?.ok === false ? " down" : ""}`} /> audit
            </button>
            <button className={`choke-pill stream-${streamInfo.state}`} type="button" onClick={() => setPopover(popover === "live" ? null : "live")} title={`stream ${streamInfo.state}${streamInfo.lastMessageAt ? ` · ${formatRelative(streamInfo.lastMessageAt)}` : ""}`}>
              <span className="choke-dot" /> live
            </button>
          </div>
          {/* Only the essentials stay in the bar; Cmd, Help, Snapshot, Thaw live in the profile menu. */}
          <div className="choke-user-cluster">
            <button className="choke-icon-button" type="button" onClick={() => setNotificationsOpen((open) => !open)} aria-label="Notifications">
              Alerts
              {!alertsActive ? (
                <span className="choke-notif-muted">muted</span>
              ) : (
                <NotificationDot decisions={decisions} acked={ackedDecisionIds} clearedAt={alertsClearedAt} enabled={alertBadgeEnabled} />
              )}
            </button>
            <button className="choke-user-pill" type="button" onClick={() => setProfileOpen((open) => !open)} aria-label="Profile and tools">
              <span className="choke-avatar">{userLabel.slice(0, 1).toUpperCase()}</span>
              {userLabel}
            </button>
          </div>
        </div>

        {/* Operations bar — one calm toolbar: time window · audited incident-response
           presets · scope + the few response controls. Replaces the old sparse two-row
           monitor/respond stack. */}
        <div className="choke-topbar-row choke-ops-row" data-panel="topbar-row-2" data-ir="ir-presets-trail-bar">
          <SegmentedControl values={WINDOW_OPTIONS} value={windowMin} format={formatWindow} onChange={setWindowMin} />
          <span className="choke-ops-sep" aria-hidden="true" />
          <span className="choke-preset-label">Incident Response</span>
          <div className="choke-preset-group">
            {Object.keys(PRESET_DESCRIPTIONS).map((name) => (
              <button key={name} type="button" onClick={() => openPresetConfirm(name)} disabled={disabled} title="Audited incident-response preset">
                {name}
              </button>
            ))}
          </div>
          <div className="choke-ops-trail">
            <span className="choke-scope-pill">{chokeState?.tracked || circuits.length} tracked</span>
            <button
              className={`choke-action-button${refreshing ? " is-refreshing" : ""}`}
              type="button"
              disabled={refreshing}
              onClick={() => void refreshAll()}
            >
              {refreshing ? <span className="choke-spinner" aria-hidden="true" /> : null}
              {refreshing ? "Refreshing" : "Refresh"}
            </button>
            <span className="choke-ops-sep" aria-hidden="true" />
            <button className="choke-action-button" type="button" onClick={() => setJailOpen(true)} disabled={disabled}>
              Jail Process
            </button>
            {/* Kill-switch + enforcement mode now live in the Containment Command
                header's control cluster — a single home for the consequential
                controls. The Ctrl+Shift+K shortcut and command palette still work. */}
          </div>
        </div>
      </header>

      {(popover || notificationsOpen || profileOpen) ? (
        <button
          type="button"
          className="choke-floating-scrim"
          aria-label="Close floating panel"
          onClick={() => {
            setPopover(null);
            setNotificationsOpen(false);
            setProfileOpen(false);
          }}
        />
      ) : null}

      <LayeredPanels
        popover={popover}
        hostPings={hostPings}
        streamInfo={streamInfo}
        chokeState={chokeState}
        mode={mode}
        onPing={() => void pingHost()}
        onSnapshot={() => void refreshAll()}
        onReconnect={sharedStream.reconnect}
        onAuditVerify={() => void handleAuditVerify()}
        onAuditCopy={() => void copyAuditHead()}
        onModeToggle={openModeConfirm}
        onKillSwitch={openKillSwitchConfirm}
        onPreset={openPresetConfirm}
        onClose={() => setPopover(null)}
      />

      {notificationsOpen && (
        <NotificationsPanel
          decisions={decisions}
          acked={ackedDecisionIds}
          clearedAt={alertsClearedAt}
          alertsActive={alertsActive}
          badgeEnabled={alertBadgeEnabled}
          onClose={() => setNotificationsOpen(false)}
          onToggleAlerts={() => setAlertsActive((value) => !value)}
          onToggleBadge={() => setAlertBadgeEnabled((value) => !value)}
          onAck={(ids) => {
            const next = new Set(ackedDecisionIds);
            ids.forEach((id) => next.add(id));
            setAckedDecisionIds(next);
          }}
          onClear={() => setAlertsClearedAt(Date.now())}
          onOpenDrill={(execId) => void openDrill(execId)}
        />
      )}

      {profileOpen && (
        <ProfilePanel
          userLabel={userLabel}
          bootMs={bootMs.current}
          decisionsSeen={decisions.length}
          ackedCount={ackedDecisionIds.size}
          theme={theme}
          density={density}
          windowMin={windowMin}
          onDensity={() => setDensity((prev) => (prev === "compact" ? "normal" : "compact"))}
          onWindow={setWindowMin}
          onSnapshot={() => void downloadSnapshot()}
          onCommand={() => { setProfileOpen(false); setCommandOpen(true); }}
          onHelp={() => { setProfileOpen(false); setHelpOpen(true); }}
          onThaw={() => { setProfileOpen(false); openThawConfirm(); }}
          onClose={() => setProfileOpen(false)}
        />
      )}

      {loadState.kind === "disabled" && (
        <Banner dataPanel="disabled-banner" tone="warn" title="Choke gateway disabled">
          {loadState.message || "choke gateway not enabled"}
        </Banner>
      )}
      {loadState.kind === "error" && (
        <Banner dataPanel="route-error-banner" tone="danger" title="Choke route error">
          {loadState.message}
        </Banner>
      )}
      {staleSeconds > 30 && (
        <Banner dataPanel="stale-stream-banner" tone="warn" title={`Stream silent for ${staleSeconds}s`}>
          <button className="choke-inline-button" type="button" onClick={sharedStream.reconnect}>
            Force reconnect
          </button>
        </Banner>
      )}

      {/* Active-filter bar only exists while something is filtered — no empty
         "Filters none" band taking up a row in the common case. */}
      {globalSearch || procFilter || tapeFilterExec ? (
        <section className="choke-filter-strip" data-panel="active-filter-strip">
          <span>Active filters</span>
          {globalSearch ? <FilterChip label={`search: ${globalSearch}`} onClear={() => setGlobalSearch("")} /> : null}
          {procFilter ? <FilterChip label={`process: ${procFilter}`} onClear={() => setProcFilter("")} /> : null}
          {tapeFilterExec ? <FilterChip label={`exec: ${shortExec(tapeFilterExec)}`} onClear={() => setTapeFilterExec(null)} /> : null}
          <button className="choke-inline-button" type="button" onClick={() => { setGlobalSearch(""); setProcFilter(""); setTapeFilterExec(null); }}>
            Clear all
          </button>
        </section>
      ) : null}

      {/* Containment Command — the shared hero. The UVP made visual: graduated,
          reversible, audited containment, with the Command⇄Assurance lens. */}
      <ContainmentCommandHeader
        metrics={commandMetrics}
        viewMode={viewMode}
        onViewMode={setViewMode}
        onToggleMode={() => openModeConfirm(enforceMode !== "enforcing")}
        onKillSwitch={openKillSwitchConfirm}
        disabled={disabled}
      />
      <ContainmentLadder counts={stateCounts} activeRung={activeRung} onRungClick={toggleRungFilter} subject="processes" />

      {viewMode === "assurance" ? (
        <AssuranceView
          metrics={commandMetrics}
          stateCounts={stateCounts}
          thresholds={thresholds}
          decisions={currentWindowDecisions}
          windowMin={windowMin}
          topBinaries={topBinaries}
          velocityBuckets={velocityBuckets}
          auditHash={chokeState?.audit?.head_hash}
          onVerifyAudit={() => void handleAuditVerify()}
          onCopyAudit={() => void copyAuditHead()}
          onExport={exportAssuranceReport}
        />
      ) : (
      <>
      <section className="choke-ti-ribbon" data-panel="threat-intelligence-ribbon">
        <MiniPanel title="Decision Velocity" meta={`${currentWindowDecisions.length} in ${formatWindow(windowMin)}`}>
          <div className="choke-velocity">
            <strong>{(currentWindowDecisions.length / Math.max(1, windowMin)).toFixed(windowMin <= 60 ? 1 : 0)}</strong>
            <span>/ min avg</span>
          </div>
          <Sparkline bars={velocityBuckets} tone="accent" />
        </MiniPanel>
        <MiniPanel title="Top Offenders" meta={`${topBinaries.length} binaries`}>
          <RankedList rows={topBinaries} onPick={(key) => setGlobalSearch(`binary:${key}`)} />
        </MiniPanel>
        <MiniPanel title="Signal Patterns" meta={`${topReasons.length} reasons`}>
          <RankedList rows={topReasons} onPick={(key) => setGlobalSearch(`"${key}"`)} />
        </MiniPanel>
        <MiniPanel title="System Health" meta={chokeState?.audit?.ok === false ? "chain broken" : mode}>
          <div className="choke-kv-mini">
            <span>audit</span><strong>{chokeState?.audit?.ok === false ? "broken" : `${chokeState?.audit?.total || 0} rows`}</strong>
            <span>tracked</span><strong>{chokeState?.tracked || circuits.length}</strong>
            <span>bpf</span><strong>{buckets.length}</strong>
            <span>cgroups</span><strong>{countCgroupPids(cgroups)}</strong>
          </div>
        </MiniPanel>
      </section>

      <main className="choke-grid">
        <section className="choke-left-rail">
          <Panel dataPanel="engine-stack-panel" title="Engine Stack">
            <EngineStack health={systemHealth} disabled={disabled} />
          </Panel>
          <Panel dataPanel="state-ladder-panel" title="State Ladder">
            <StateLadder counts={stateCounts} />
          </Panel>
          <ThresholdPanel
            dataPanel="thresholds-panel"
            thresholds={thresholds}
            circuits={circuits}
            disabled={disabled}
            onCommit={async (next) => {
              await updateThresholds(next);
              pushToast("thresholds committed", "ok");
              await refreshState();
            }}
          />
          <Panel dataPanel="cgroup-tiers-panel" title="Cgroup Tiers">
            <CgroupTiers cgroups={cgroups} />
          </Panel>
          <Panel dataPanel="choke-map-bpf-mirror" title="Choke Map / BPF Mirror">
            <BucketList buckets={buckets} />
          </Panel>
        </section>

        <section className="choke-center">
          <Panel
            dataPanel="tracked-processes-list"
            title="Tracked Processes"
            actions={
              <>
                <span className="choke-muted">{visibleCircuits.length} / {circuits.length}</span>
                <button className="choke-inline-button" type="button" onClick={() => setDensity((prev) => (prev === "compact" ? "normal" : "compact"))}>
                  {density === "compact" ? "Comfort" : "Compact"}
                </button>
              </>
            }
          >
            <div className="choke-table-toolbar">
              <input value={procFilter} onChange={(event) => setProcFilter(event.target.value)} placeholder="filter binary, pid, exec_id, origin" />
              <div className="choke-chip-row">
                {["throttled", "tarpit", "quarantined", "severed", "pristine"].map((state) => (
                  <button
                    key={state}
                    className={`choke-chip ${stateFilters.has(state) ? "on" : ""}`}
                    type="button"
                    onClick={() => setStateFilters((prev) => toggleSetValue(prev, state))}
                  >
                    {state}
                  </button>
                ))}
              </div>
            </div>
            <ProcessTable
              rows={visibleCircuits}
              selected={selectedExecs}
              density={density}
              alertCounts={alertCounts}
              truncated={truncatedCircuits}
              total={searchFilteredCircuits.length}
              onSelect={(execId) => setSelectedExecs((prev) => toggleSetValue(prev, execId))}
              onSelectAll={() => setSelectedExecs(new Set(visibleCircuits.map((entry) => entry.exec_id)))}
              onClear={() => setSelectedExecs(new Set())}
              onAction={openManualConfirm}
              onDrill={(execId) => void openDrill(execId)}
              onFilterBinary={(binary) => setGlobalSearch(`binary:${binary}`)}
              onFilterExec={setTapeFilterExec}
              onCopy={async (value) => pushToast((await copyToClipboard(value)) ? "copied" : "copy failed", "ok")}
            />
          </Panel>
        </section>

        <section className="choke-right-rail">
          <Panel
            dataPanel="decision-tape"
            title="Decision Tape"
            actions={<span className={`choke-live-indicator ${streamInfo.state}`}>{filteredDecisions.length} / {formatWindow(windowMin)}</span>}
          >
            {/* Stacked, grouped toolbar (BPF-mirror style): full-width search, then a clean
               filter row — action facets divided from display toggles. */}
            <div className="choke-tape-toolbar">
              <input
                className="choke-tape-search"
                value={tapeSearch}
                onChange={(event) => setTapeSearch(event.target.value)}
                placeholder="Search reason, pid, exec_id, binary or /regex/"
              />
              <div className="choke-tape-filters" role="group" aria-label="Decision tape filters">
                {["throttle", "tarpit", "quarantine", "sever", "thaw"].map((action) => (
                  <button
                    key={action}
                    type="button"
                    className={`choke-chip ${tapeActions.has(action) ? "on" : ""}`}
                    onClick={() => setTapeActions((prev) => toggleSetValue(prev, action))}
                  >
                    {action}
                  </button>
                ))}
                <button type="button" className={`choke-chip ${groupTape ? "on" : ""}`} onClick={() => setGroupTape((prev) => !prev)}>
                  group
                </button>
                <button type="button" className={`choke-chip ${hideAcked ? "on" : ""}`} onClick={() => setHideAcked((prev) => !prev)}>
                  hide acked
                </button>
                <button type="button" className={`choke-chip ${autoScrollTape ? "on" : ""}`} onClick={() => setAutoScrollTape((prev) => !prev)}>
                  auto
                </button>
              </div>
              <div className="choke-tape-spark" aria-label="Decision rate, last 40s">
                <Sparkline bars={bucketizeDecisions(decisions, now, 1, 40)} tone="danger" />
              </div>
            </div>
            {bucketizeDecisions(decisions, now, 1, 1)[0] > 5 && (
              <div className="choke-burst-banner">
                {bucketizeDecisions(decisions, now, 1, 1)[0]} decisions in 1s
                <button type="button" onClick={() => setGroupTape(true)}>Group by exec_id</button>
              </div>
            )}
            <DecisionTape
              refEl={tapeRef}
              rows={groupedDecisions}
              selected={selectedDecisionIds}
              acked={ackedDecisionIds}
              onSelect={(id) => setSelectedDecisionIds((prev) => toggleSetValue(prev, id))}
              onDrill={(execId) => void openDrill(execId)}
              onFilterExec={setTapeFilterExec}
              onAck={(ids) => {
                const next = new Set(ackedDecisionIds);
                ids.forEach((id) => next.add(id));
                setAckedDecisionIds(next);
              }}
              onUnack={(ids) => {
                const next = new Set(ackedDecisionIds);
                ids.forEach((id) => next.delete(id));
                setAckedDecisionIds(next);
              }}
              onCopy={async (value) => pushToast((await copyToClipboard(value)) ? "copied" : "copy failed", "ok")}
            />
          </Panel>
        </section>
      </main>

      {selectedExecs.size > 0 && (
        <div className="choke-bulkbar" data-panel="bulk-action-bar">
          <span>{selectedExecs.size} selected</span>
          {ACTIONS.map((action) => (
            <button key={action} type="button" onClick={() => openBulkConfirm(action)}>{action}</button>
          ))}
          <button type="button" onClick={openBulkForgetConfirm}>forget</button>
          <button type="button" onClick={() => setSelectedExecs(new Set())}>clear</button>
        </div>
      )}

      <section className="choke-policy-workbench" data-panel="policy-workbench">
        <Panel title="Policy Workbench" actions={<span className="choke-muted">dry-run · evaluates against the live snapshot, never installs</span>}>
          <div className="choke-policy-grid">
            <div className="choke-policy-editor">
              <textarea value={policyYaml} onChange={(event) => setPolicyYaml(event.target.value)} spellCheck={false} />
              <div className="choke-policy-actions">
                <button className="choke-action-button" type="button" onClick={() => { setPolicyYaml(DEFAULT_POLICY); setPolicyPreview(null); setPolicyError(""); }}>Insert sample</button>
                <button className="choke-action-button" type="button" onClick={insertLivePolicy} title="Build a policy from the processes currently tracked so preview returns real matches">Build from live</button>
                <button className="choke-action-button ok" type="button" onClick={() => void runPolicyPreview()} disabled={disabled || policyChecking}>{policyChecking ? "Checking…" : "Preview matches"}</button>
              </div>
            </div>
            <PolicyPreview preview={policyPreview} error={policyError} checking={policyChecking} circuits={circuits} />
          </div>
        </Panel>
      </section>
      </>
      )}

      <ProcessDrill
        drill={drill}
        onClose={() => setDrill({ kind: "closed" })}
        onRefresh={() => void refreshAll()}
        onForget={async (execId) => {
          await forgetCircuits([execId]);
          pushToast("forgot circuit", "ok");
          setDrill({ kind: "closed" });
          await refreshAll();
        }}
        onAnnotate={async (execId, note) => {
          await annotateCircuit(execId, note);
          pushToast(note ? "note saved" : "note cleared", "ok");
          await refreshCircuits();
        }}
        onCopy={async (value) => pushToast((await copyToClipboard(value)) ? "copied" : "copy failed", "ok")}
      />

      <JailPicker
        open={jailOpen}
        disabled={disabled}
        detail={jailDetail}
        onClose={() => setJailOpen(false)}
        onInspect={async (process) => {
          setJailDetail({ kind: "loading", process });
          try {
            setJailDetail({ kind: "ready", process, detail: await getProc(process.pid) });
          } catch (error) {
            setJailDetail({ kind: "error", process, message: error instanceof Error ? error.message : "live proc failed" });
          }
        }}
        onOpenDrill={(process) => {
          if (process.exec_id) void openDrill(process.exec_id);
          else setJailDetail({ kind: "loading", process });
        }}
        onAction={async ({ pids, action, reason, descendants, revert_after_seconds }) => {
          const response = await jailProcesses({ pids, action, reason, descendants, revert_after_seconds });
          const results = response.results || [];
          const ok = results.filter((result) => result.ok).length;
          pushToast(`jail ${action}: ${ok}/${results.length || pids.length} ok`, ok === results.length ? "ok" : "warn");
          await refreshAll();
        }}
        pushToast={pushToast}
      />

      {commandOpen && <CommandPalette items={commandItems} onClose={() => setCommandOpen(false)} />}
      {confirm && <ConfirmModal request={confirm} onClose={() => setConfirm(null)} pushToast={pushToast} />}
      {helpOpen && <HelpModal onClose={() => setHelpOpen(false)} />}
      <ToastStack toasts={toasts} />

      <footer className="choke-opsbar" data-panel="operations-status-bar">
        <span className={`choke-dot ${streamInfo.state}`} />
        <span>chain <button type="button" onClick={() => void copyAuditHead()}>{chokeState?.audit?.ok === false ? `broken @ ${chokeState.audit.bad_at || "?"}` : (chokeState?.audit?.head_hash || `${chokeState?.audit?.total || 0} rows`).toString().slice(0, 18)}</button></span>
        <span>mode <strong>{String(mode).toUpperCase()}</strong></span>
        <span>scope <strong>{chokeState?.tracked || circuits.length}</strong></span>
        <span>tape <strong>{decisions.length}</strong></span>
        <span>session <strong>{userLabel}</strong> · {formatUptime(now - bootMs.current)}</span>
      </footer>
    </div>
  );
}

function DriverPill({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <div className={`choke-assur-driver ${good ? "good" : "warn"}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

// The Assurance lens: the same live containment data, read for a CISO/board —
// posture with a transparent breakdown, control effectiveness, audit-chain
// integrity, enforcement + reversibility, and one-click board-ready evidence.
function AssuranceView({
  metrics,
  stateCounts,
  thresholds,
  decisions,
  windowMin,
  topBinaries,
  velocityBuckets,
  auditHash,
  onVerifyAudit,
  onCopyAudit,
  onExport
}: {
  metrics: CommandMetrics;
  stateCounts: Record<string, number>;
  thresholds: Thresholds;
  decisions: Decision[];
  windowMin: number;
  topBinaries: Array<{ key: string; count: number }>;
  velocityBuckets: number[];
  auditHash?: string;
  onVerifyAudit: () => void;
  onCopyAudit: () => void;
  onExport: (kind: "report" | "bundle") => void;
}) {
  const needing = metrics.activeThreats + metrics.contained;
  const coverage = needing === 0 ? 100 : Math.round((metrics.contained / needing) * 100);
  const postureTone = metrics.posture >= 80 ? "good" : metrics.posture >= 55 ? "warn" : "bad";
  const enforcing = metrics.mode === "enforcing";
  const hashShort = auditHash ? `${auditHash.slice(0, 24)}…` : "—";
  return (
    <section className="choke-assurance" data-panel="assurance-view">
      <div className="choke-assur-grid">
        <article className={`choke-assur-card span2 tone-${postureTone}`}>
          <header>
            <h3>Security posture</h3>
            <span className="choke-assur-score">
              {metrics.posture}
              <small>/100</small>
            </span>
          </header>
          <div className="choke-assur-drivers">
            <DriverPill label="Containment coverage" value={`${coverage}%`} good={coverage >= 80} />
            <DriverPill label="Enforcement" value={enforcing ? "Enforcing" : "Detect-only"} good={enforcing} />
            <DriverPill label="Audit chain" value={metrics.auditOk ? "Intact" : "Broken"} good={metrics.auditOk} />
            <DriverPill label="Kill-switch" value={metrics.killSwitched ? "Engaged" : "Standby"} good={!metrics.killSwitched} />
          </div>
          <p className="choke-assur-note">
            Posture is containment coverage adjusted for enforcement mode, audit-chain integrity and kill-switch state.
            {enforcing ? "" : " Switch to Enforcing to apply decisions to the kernel and lift this score."}
          </p>
        </article>

        <article className="choke-assur-card">
          <header>
            <h3>Control effectiveness</h3>
          </header>
          <div className="choke-assur-bigstat">
            <strong>{coverage}%</strong>
            <span>threats contained</span>
          </div>
          <div className="choke-assur-bar">
            <span style={{ width: `${coverage}%` }} />
          </div>
          <div className="choke-assur-kv">
            <span>Contained</span>
            <strong>{metrics.contained}</strong>
            <span>Active threats</span>
            <strong className={metrics.activeThreats ? "danger" : ""}>{metrics.activeThreats}</strong>
          </div>
        </article>

        <article className="choke-assur-card">
          <header>
            <h3>Audit integrity</h3>
          </header>
          <div className={`choke-assur-audit ${metrics.auditOk ? "ok" : "bad"}`}>
            {metrics.auditOk ? "Chain intact" : "CHAIN BROKEN"}
          </div>
          <div className="choke-assur-kv">
            <span>Records</span>
            <strong>{metrics.auditRows.toLocaleString()}</strong>
          </div>
          <code className="choke-assur-hash" title={auditHash || ""}>
            {hashShort}
          </code>
          <div className="choke-assur-actions">
            <button type="button" className="choke-action-button" onClick={onVerifyAudit}>
              Verify chain
            </button>
            <button type="button" className="choke-action-button" onClick={onCopyAudit}>
              Copy head
            </button>
          </div>
        </article>

        <article className="choke-assur-card">
          <header>
            <h3>Enforcement &amp; reversibility</h3>
          </header>
          <div className="choke-assur-kv wide">
            <span>Mode</span>
            <strong>{enforcing ? "Enforcing" : "Detect-only"}</strong>
            <span>Throttle ≥</span>
            <strong>{thresholds.throttle_at}</strong>
            <span>Tarpit ≥</span>
            <strong>{thresholds.tarpit_at}</strong>
            <span>Quarantine ≥</span>
            <strong>{thresholds.quarantine_at}</strong>
            <span>Sever ≥</span>
            <strong>{thresholds.sever_at}</strong>
            <span>Auto-revert</span>
            <strong>available</strong>
          </div>
        </article>

        <article className="choke-assur-card">
          <header>
            <h3>Containment activity · {formatWindow(windowMin)}</h3>
          </header>
          <div className="choke-assur-bigstat">
            <strong>{decisions.length}</strong>
            <span>decisions</span>
          </div>
          <Sparkline bars={velocityBuckets} tone="accent" />
          <ul className="choke-assur-top">
            {topBinaries.length === 0 ? (
              <li className="choke-muted">no decisions in window</li>
            ) : (
              topBinaries.map((b) => (
                <li key={b.key}>
                  <span className="truncate">{basename(b.key)}</span>
                  <strong>{b.count}</strong>
                </li>
              ))
            )}
          </ul>
        </article>

        <article className="choke-assur-card span2 choke-assur-export">
          <header>
            <h3>Board-ready evidence</h3>
          </header>
          <p>
            Export a point-in-time containment summary for leadership, audit, or cyber-insurance — every figure is
            backed by the tamper-evident decision chain.
          </p>
          <div className="choke-assur-actions">
            <button type="button" className="choke-action-button ok" onClick={() => onExport("report")}>
              Board report
            </button>
            <button type="button" className="choke-action-button" onClick={() => onExport("bundle")}>
              Evidence bundle (JSON)
            </button>
          </div>
        </article>
      </div>
    </section>
  );
}

function buildAssuranceReportHtml(args: {
  metrics: CommandMetrics;
  stateCounts: Record<string, number>;
  thresholds: Thresholds;
  decisionsInWindow: number;
  windowLabel: string;
  topBinaries: Array<{ key: string; count: number }>;
  headHash: string;
  user: string;
  when: Date;
}): string {
  const { metrics: m, stateCounts, thresholds, decisionsInWindow, windowLabel, topBinaries, headHash, user, when } = args;
  const esc = (s: string) =>
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
  const needing = m.activeThreats + m.contained;
  const coverage = needing === 0 ? 100 : Math.round((m.contained / needing) * 100);
  const tone = m.posture >= 80 ? "#2f9e5e" : m.posture >= 55 ? "#c9871f" : "#d23a4f";
  const rung = (r: string) => stateCounts[r] || 0;
  const topRows =
    topBinaries.length === 0
      ? `<tr><td colspan="2" style="color:#888">no decisions in window</td></tr>`
      : topBinaries.map((b) => `<tr><td>${esc(b.key)}</td><td style="text-align:right">${b.count}</td></tr>`).join("");
  return `<!doctype html><html><head><meta charset="utf-8">
<title>Containment Assurance Report</title>
<style>
  * { box-sizing: border-box; }
  body { font: 13px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; color: #1a2230; margin: 0; padding: 40px; background: #fff; }
  .head { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #1a2230; padding-bottom: 14px; }
  .head h1 { margin: 0; font-size: 22px; letter-spacing: -0.01em; }
  .head .sub { color: #667085; font-size: 12px; margin-top: 4px; }
  .posture { text-align: center; }
  .posture .num { font-size: 44px; font-weight: 800; color: ${tone}; line-height: 1; }
  .posture .lbl { font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; color: #667085; }
  .tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 22px 0; }
  .tile { border: 1px solid #e3e7ee; border-radius: 8px; padding: 14px; }
  .tile .v { font-size: 24px; font-weight: 700; }
  .tile .l { font-size: 10px; letter-spacing: 0.09em; text-transform: uppercase; color: #667085; margin-top: 4px; }
  h2 { font-size: 13px; letter-spacing: 0.08em; text-transform: uppercase; color: #667085; border-bottom: 1px solid #e3e7ee; padding-bottom: 6px; margin: 26px 0 12px; }
  table { width: 100%; border-collapse: collapse; }
  td, th { padding: 7px 8px; border-bottom: 1px solid #eef1f5; text-align: left; }
  .ladder { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
  .ladder .cell { border: 1px solid #e3e7ee; border-radius: 8px; padding: 12px; text-align: center; }
  .ladder .cell .c { font-size: 22px; font-weight: 700; }
  .ladder .cell .n { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #667085; }
  .mono { font-family: ui-monospace, Menlo, monospace; font-size: 11px; word-break: break-all; color: #344054; }
  .foot { margin-top: 30px; padding-top: 12px; border-top: 1px solid #e3e7ee; color: #98a2b3; font-size: 11px; }
  @media print { body { padding: 0; } }
</style></head><body>
<div class="head">
  <div>
    <h1>Containment Assurance Report</h1>
    <div class="sub">Process enforcement · generated ${esc(when.toLocaleString())} · by ${esc(user)}</div>
  </div>
  <div class="posture"><div class="num">${m.posture}</div><div class="lbl">Posture / 100</div></div>
</div>
<div class="tiles">
  <div class="tile"><div class="v" style="color:${m.activeThreats ? "#d23a4f" : "#2f9e5e"}">${m.activeThreats}</div><div class="l">Active threats</div></div>
  <div class="tile"><div class="v">${m.contained}</div><div class="l">Contained</div></div>
  <div class="tile"><div class="v">${coverage}%</div><div class="l">Threats contained</div></div>
  <div class="tile"><div class="v" style="color:${m.auditOk ? "#2f9e5e" : "#d23a4f"}">${m.auditOk ? "Intact" : "BROKEN"}</div><div class="l">Audit chain</div></div>
</div>
<h2>Containment ladder</h2>
<div class="ladder">
  <div class="cell"><div class="c">${rung("pristine")}</div><div class="n">Pristine</div></div>
  <div class="cell"><div class="c">${rung("throttled")}</div><div class="n">Throttled</div></div>
  <div class="cell"><div class="c">${rung("tarpit")}</div><div class="n">Tarpit</div></div>
  <div class="cell"><div class="c">${rung("quarantined")}</div><div class="n">Quarantined</div></div>
  <div class="cell"><div class="c">${rung("severed")}</div><div class="n">Severed</div></div>
</div>
<h2>Enforcement posture</h2>
<table>
  <tr><td>Mode</td><td style="text-align:right">${m.mode === "enforcing" ? "Enforcing" : "Detect-only"}</td></tr>
  <tr><td>Kill-switch</td><td style="text-align:right">${m.killSwitched ? "Engaged" : "Standby"}</td></tr>
  <tr><td>Tracked processes</td><td style="text-align:right">${m.tracked.toLocaleString()}</td></tr>
  <tr><td>Thresholds (throttle / tarpit / quarantine / sever)</td><td style="text-align:right">${thresholds.throttle_at} / ${thresholds.tarpit_at} / ${thresholds.quarantine_at} / ${thresholds.sever_at}</td></tr>
  <tr><td>Decisions in window (${esc(windowLabel)})</td><td style="text-align:right">${decisionsInWindow}</td></tr>
</table>
<h2>Top enforced binaries (${esc(windowLabel)})</h2>
<table><tr><th>Binary</th><th style="text-align:right">Decisions</th></tr>${topRows}</table>
<h2>Evidence anchor</h2>
<p>Audit chain records: <strong>${m.auditRows.toLocaleString()}</strong>. Tamper-evident head hash:</p>
<p class="mono">${esc(headHash || "—")}</p>
<div class="foot">This report is a point-in-time summary of live enforcement state. Every containment decision is recorded in a hash-chained, tamper-evident audit log; the head hash above anchors this report to that chain.</div>
<script>window.onload=function(){setTimeout(function(){window.print();},250);};</script>
</body></html>`;
}

function Panel({ title, children, actions, dataPanel }: { title: string; children: ReactNode; actions?: ReactNode; dataPanel?: string }) {
  return (
    <section className="choke-panel" data-panel={dataPanel}>
      <header className="choke-panel-header">
        <h2>{title}</h2>
        {actions ? <div className="choke-panel-actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}

function MiniPanel({ title, meta, children }: { title: string; meta?: string; children: ReactNode }) {
  return (
    <div className="choke-mini-panel">
      <header><span>{title}</span><small>{meta}</small></header>
      {children}
    </div>
  );
}

function Banner({ title, children, tone, dataPanel }: { title: string; children: ReactNode; tone: "warn" | "danger"; dataPanel: string }) {
  return (
    <div className={`choke-banner ${tone}`} data-panel={dataPanel} role="status" aria-live="polite">
      <strong>{title}</strong>
      <span>{children}</span>
    </div>
  );
}

function StateBadge({ state }: { state?: string }) {
  const value = state || "pristine";
  return <span className={`choke-state-badge state-${value}`}>{value}</span>;
}

function ModeBadge({ mode }: { mode?: string }) {
  const value = mode || "detect-only";
  return <span className={`choke-mode-badge mode-${value}`}>{value}</span>;
}

function Sparkline({ bars, tone = "accent" }: { bars: number[]; tone?: "accent" | "warn" | "danger" }) {
  const peak = Math.max(1, ...bars);
  return (
    <div className={`choke-spark ${tone}`} aria-hidden="true">
      {bars.map((bar, index) => (
        <span key={index} style={{ height: `${bar === 0 ? 2 : Math.max(2, Math.round((bar / peak) * 28))}px` }} />
      ))}
    </div>
  );
}

function SegmentedControl({
  values,
  value,
  format,
  onChange,
}: {
  values: number[];
  value: number;
  format: (value: number) => string;
  onChange: (value: number) => void;
}) {
  return (
    <div className="choke-segmented">
      {values.map((item) => (
        <button key={item} type="button" className={item === value ? "active" : ""} onClick={() => onChange(item)}>
          {format(item)}
        </button>
      ))}
    </div>
  );
}

function StateLadder({ counts }: { counts: Partial<Record<string, number>> }) {
  const max = Math.max(1, ...STATE_ORDER.map((state) => counts[state] || 0));
  return (
    <div className="choke-ladder">
      {STATE_ORDER.map((state) => {
        const count = counts[state] || 0;
        return (
          <div key={state} className="choke-ladder-row">
            <StateBadge state={state} />
            <span className="choke-ladder-track"><span style={{ width: `${(count / max) * 100}%` }} /></span>
            <strong>{count}</strong>
          </div>
        );
      })}
    </div>
  );
}

type EngineFactStatus = "ok" | "warn" | "danger" | "neutral";
interface EngineFact {
  label: string;
  value: string;
  hint?: string;
  status: EngineFactStatus;
}

// Translate the raw /api/system-health object into plain-language facts a SOC
// lead can read at a glance — no JSON blobs. Each fact carries a status colour.
function buildEngineFacts(health: Record<string, unknown>): EngineFact[] {
  const obj = (v: unknown): Record<string, unknown> =>
    v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  const str = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));

  const tetra = obj(health.tetragon);
  const bpf = obj(health.bpf);
  const store = obj(health.store);
  const auth = obj(health.auth);
  const obs = obj(health.observability);

  const connected = tetra.connected === true;
  const bpfBackend = str(bpf.backend);
  const isNoop = bpfBackend === "" || bpfBackend === "noop";
  const attached = Number(bpf.attached_links ?? 0);
  const expected = Number(bpf.expected_links ?? 0);
  const storeBackend = str(store.backend).toLowerCase();
  const storeTarget = str(store.target);
  const metricsOn = obs.metrics_enabled === true;

  const facts: EngineFact[] = [
    {
      label: "Kernel sensor",
      value: connected ? "Connected" : "Disconnected",
      hint: connected ? "Tetragon eBPF event feed is live" : "No live syscall/exec events from the kernel",
      status: connected ? "ok" : "danger"
    },
    {
      label: "Enforcement plane",
      value: isNoop ? "Detect-only" : `eBPF · ${attached}/${expected || attached} attached`,
      hint: isNoop ? "Decisions are logged, not applied to the kernel" : "Choke actions enforced in-kernel",
      status: isNoop ? "warn" : bpf.healthy === true ? "ok" : "warn"
    },
    {
      label: "Event store",
      value: storeBackend === "postgres" ? "PostgreSQL" : storeBackend === "sqlite" ? "SQLite" : storeBackend || "—",
      hint: storeTarget ? storeTarget.replace(/^.*\//, "…/") : "decision + audit chain persistence",
      status: "neutral"
    },
    {
      label: "Sign-in security",
      value: "bcrypt · CSRF · sessions",
      hint: str(auth.rate_limit) ? `rate limit ${str(auth.rate_limit)}` : "hardened auth",
      status: "ok"
    },
    {
      label: "Telemetry",
      value: metricsOn ? "Metrics on" : "Metrics off",
      hint: `${str(obs.log_format) || "text"} logs · ${str(obs.log_level) || "info"} level`,
      status: "neutral"
    },
    { label: "Uptime", value: str(health.uptime) || "—", status: "neutral" },
    { label: "Build", value: `v${str(health.version) || "?"}`, status: "neutral" }
  ];
  return facts;
}

function EngineStack({ health, disabled }: { health: Record<string, unknown> | null; disabled: boolean }) {
  if (disabled) return <EmptyState title="Gateway disabled" body="Subsystem health is unavailable until the choke gateway is enabled." />;
  if (!health) return <LoadingState label="loading subsystem health" />;
  if (Object.keys(health).length === 0) return <EmptyState title="No subsystem data" body="The health endpoint returned an empty object." />;
  const facts = buildEngineFacts(health);
  return (
    <div className="choke-facts">
      {facts.map((fact) => (
        <div key={fact.label} className="choke-fact">
          <span className={`choke-fact-dot status-${fact.status}`} aria-hidden="true" />
          <div className="choke-fact-body">
            <span className="choke-fact-label">{fact.label}</span>
            <strong className="choke-fact-value">{fact.value}</strong>
            {fact.hint ? <span className="choke-fact-hint">{fact.hint}</span> : null}
          </div>
        </div>
      ))}
    </div>
  );
}

function ThresholdPanel({
  thresholds,
  circuits,
  disabled,
  onCommit,
  dataPanel,
}: {
  thresholds: Thresholds;
  circuits: CircuitEntry[];
  disabled: boolean;
  onCommit: (thresholds: Thresholds) => Promise<void>;
  dataPanel: string;
}) {
  const [draft, setDraft] = useState<Thresholds>(thresholds);
  const [saving, setSaving] = useState(false);
  useEffect(() => setDraft(thresholds), [thresholds]);

  const blast = useMemo(() => {
    const before = countByState(circuits, thresholds);
    const after: Record<string, number> = { pristine: 0, throttled: 0, tarpit: 0, quarantined: 0, severed: 0 };
    circuits.forEach((entry) => {
      after[stateForScore(entry.score || 0, draft)] += 1;
    });
    return STATE_ORDER.map((state) => ({ state, before: before[state], after: after[state] || 0 }));
  }, [circuits, draft, thresholds]);

  function patch(key: keyof Thresholds, value: number): void {
    setDraft((prev) => {
      const next = { ...prev, [key]: value };
      if (next.throttle_at >= next.tarpit_at) next.tarpit_at = next.throttle_at + 1;
      if (next.tarpit_at >= next.quarantine_at) next.quarantine_at = next.tarpit_at + 1;
      if (next.quarantine_at >= next.sever_at) next.sever_at = next.quarantine_at + 1;
      return next;
    });
  }

  return (
    <Panel dataPanel={dataPanel} title="Thresholds" actions={<span className={thresholdsAscending(draft) ? "choke-ok" : "choke-danger"}>{thresholdsAscending(draft) ? "ascending" : "invalid"}</span>}>
      <div className="choke-threshold-track">
        {(["throttle_at", "tarpit_at", "quarantine_at", "sever_at"] as Array<keyof Thresholds>).map((key) => (
          <input
            key={key}
            type="range"
            min={1}
            max={120}
            value={draft[key]}
            onChange={(event) => patch(key, Number(event.target.value))}
            disabled={disabled}
            aria-label={key}
          />
        ))}
      </div>
      <div className="choke-threshold-inputs">
        {(["throttle_at", "tarpit_at", "quarantine_at", "sever_at"] as Array<keyof Thresholds>).map((key) => (
          <label key={key}>
            <span>{key.replace("_at", "")}</span>
            <input type="number" min={1} value={draft[key]} onChange={(event) => patch(key, Number(event.target.value))} disabled={disabled} />
          </label>
        ))}
      </div>
      <div className="choke-blast">
        {blast.map((row) => (
          <div key={row.state}>
            <StateBadge state={row.state} />
            <span>{row.before} -&gt; {row.after}</span>
            <strong className={row.after - row.before > 0 ? "warn" : ""}>{row.after - row.before > 0 ? "+" : ""}{row.after - row.before}</strong>
          </div>
        ))}
      </div>
      <div className="choke-panel-footer">
        <button className="choke-inline-button" type="button" onClick={() => setDraft(thresholds)}>Cancel</button>
        <button
          className="choke-action-button warn"
          type="button"
          disabled={disabled || saving || !thresholdsAscending(draft)}
          onClick={async () => {
            setSaving(true);
            try {
              await onCommit(draft);
            } finally {
              setSaving(false);
            }
          }}
        >
          {saving ? "Saving" : "Commit thresholds"}
        </button>
      </div>
    </Panel>
  );
}

function CgroupTiers({ cgroups }: { cgroups: CgroupMap }) {
  const tiers = [
    { key: "choke-throttled", state: "throttled" },
    { key: "choke-tarpit", state: "tarpit" },
    { key: "choke-quarantined", state: "quarantined" },
  ];
  const max = Math.max(1, ...tiers.map((tier) => getCgroupPids(cgroups[tier.key]).length));
  return (
    <div className="choke-cgroup-list">
      {tiers.map((tier) => {
        const pids = getCgroupPids(cgroups[tier.key]);
        return (
          <div key={tier.key}>
            <StateBadge state={tier.state} />
            <span className="choke-meter"><span style={{ width: `${(pids.length / max) * 100}%` }} /></span>
            <strong>{pids.length}</strong>
            <small>{pids.slice(0, 8).join(", ") || "empty"}</small>
          </div>
        );
      })}
    </div>
  );
}

function BucketList({ buckets }: { buckets: BucketEntry[] }) {
  const sorted = sortBuckets(buckets);
  const rows = sorted.slice(0, 80);
  const totalRate = sorted.reduce((sum, bucket) => sum + Number(bucket.rate_per_sec || 0), 0);
  const depleted = sorted.filter((bucket) => Number(bucket.tokens || 0) <= 0).length;
  const stateCounts = sorted.reduce<Record<string, number>>((acc, bucket) => {
    const state = bucketFlagsLabel(bucket.flags);
    acc[state] = (acc[state] || 0) + 1;
    return acc;
  }, {});
  const activeStates = ["sever", "quarantine", "tarpit", "throttle", "observe"].filter((state) => stateCounts[state]);

  if (rows.length === 0) return <EmptyState title="No BPF bucket rows" body="Detect-only mode or no active transitions can leave the map empty." />;
  return (
    <div className="choke-bpf-mirror">
      <div className="choke-bpf-summary" aria-label="BPF mirror summary">
        <div>
          <span>Mirrored PIDs</span>
          <strong>{sorted.length}</strong>
        </div>
        <div>
          <span>Budget</span>
          <strong>{totalRate}/s</strong>
        </div>
        <div>
          <span>Depleted</span>
          <strong>{depleted}</strong>
        </div>
      </div>

      <div className="choke-bpf-state-strip" aria-label="BPF states">
        {activeStates.map((state) => (
          <span key={state}>
            <StateBadge state={state} />
            <strong>{stateCounts[state]}</strong>
          </span>
        ))}
      </div>

      <div className="choke-bucket-list" aria-label="Kernel token buckets mirrored from BPF">
        {rows.map((bucket) => {
          const state = bucketFlagsLabel(bucket.flags);
          const burst = Math.max(1, Number(bucket.burst || 0));
          const tokens = Math.max(0, Math.min(burst, Number(bucket.tokens || 0)));
          const tokenPct = Math.round((tokens / burst) * 100);
          const tokenLabel = tokens <= 0 ? "depleted" : tokenPct < 35 ? "low headroom" : "available";
          return (
            <div className={`choke-bucket-row state-${state}`} key={`${bucket.pid}-${bucket.flags}`}>
              <div className="choke-bucket-title">
                <strong>PID {bucket.pid}</strong>
                <StateBadge state={state} />
              </div>
              <div className="choke-bucket-meter" title={`${bucket.tokens}/${bucket.burst} tokens available`}>
                <span style={{ width: `${tokenPct}%` }} />
              </div>
              <div className="choke-bucket-meta">
                <span><strong>{bucket.rate_per_sec}/s</strong> rate limit</span>
                <span><strong>{bucket.tokens}/{bucket.burst}</strong> tokens</span>
                <em>{tokenLabel}</em>
              </div>
            </div>
          );
        })}
      </div>
      {sorted.length > rows.length ? <span className="choke-muted">+{sorted.length - rows.length} more mirrored buckets</span> : null}
    </div>
  );
}

const PROCESS_TABLE_COLUMNS = [
  { key: "select", label: "select" },
  { key: "state", label: "status" },
  { key: "pid", label: "process id" },
  { key: "binary", label: "binary" },
  { key: "origin", label: "origin" },
  { key: "exec", label: "exec id" },
  { key: "score", label: "risk" },
  { key: "actions", label: "actions" },
] as const;

function ProcessTableHeader() {
  return (
    <div className="choke-process-head">
      {PROCESS_TABLE_COLUMNS.map((column) => (
        <span key={column.key} data-choke-col={column.key}>
          {column.label}
        </span>
      ))}
    </div>
  );
}

function ProcessTable({
  rows,
  selected,
  density,
  alertCounts,
  truncated,
  total,
  onSelect,
  onSelectAll,
  onClear,
  onAction,
  onDrill,
  onFilterBinary,
  onFilterExec,
  onCopy,
}: {
  rows: CircuitEntry[];
  selected: Set<string>;
  density: "normal" | "compact";
  alertCounts: Map<string, number>;
  truncated: boolean;
  total: number;
  onSelect: (execId: string) => void;
  onSelectAll: () => void;
  onClear: () => void;
  onAction: (entry: CircuitEntry, action: ChokeAction) => void;
  onDrill: (execId: string) => void;
  onFilterBinary: (binary: string) => void;
  onFilterExec: (execId: string) => void;
  onCopy: (value: string) => void;
}) {
  if (rows.length === 0) return <EmptyState title="No tracked processes match" body="Clear filters or wait for the next circuit snapshot." />;
  return (
    <div className={`choke-process-table ${density}`}>
      <div className="choke-process-bulkbar" role="group" aria-label="Tracked process selection">
        <button type="button" onClick={onSelectAll}>Select all visible</button>
        <button type="button" onClick={onClear}>Clear selection</button>
        <span>{selected.size} selected</span>
      </div>
      <VirtualList
        className="choke-process-virtual"
        items={rows}
        estimateSize={density === "compact" ? 34 : 48}
        getKey={(entry) => entry.exec_id}
        before={<ProcessTableHeader />}
        renderItem={(entry) => {
          const selectedRow = selected.has(entry.exec_id);
          return (
            <div className={`choke-process-row ${selectedRow ? "selected" : ""}`}>
              <input type="checkbox" checked={selectedRow} onChange={() => onSelect(entry.exec_id)} aria-label={`Select ${entry.exec_id}`} />
              <StateBadge state={entry.state} />
              <button type="button" className="choke-link-text" data-choke-col="pid" onClick={() => onCopy(String(entry.pid || ""))}>{entry.pid || "-"}</button>
              <button type="button" className="choke-link-text truncate" data-choke-col="binary" title={entry.binary} onClick={() => entry.binary && onFilterBinary(entry.binary)}>{entry.binary || "(unknown)"}</button>
              <span className="truncate" data-choke-col="origin">{originLabel(entry) || "-"}</span>
              <button type="button" className="choke-link-text choke-exec-cell" data-choke-col="exec" title={entry.exec_id} onClick={() => onDrill(entry.exec_id)}>
                <span className="choke-execid-mono">{entry.exec_id || "-"}</span>
                <span className="choke-exec-badges">
                  {entry.annotation?.note ? <em>note</em> : null}
                  {entry.revert_pending ? <em>revert</em> : null}
                  {(alertCounts.get(entry.exec_id) || 0) > 0 ? <em>{alertCounts.get(entry.exec_id)} alerts</em> : null}
                </span>
              </button>
              <span className="choke-score" data-choke-col="score">
                <strong>{entry.score || 0}</strong><span><span style={{ width: `${Math.min(100, entry.score || 0)}%` }} /></span>
              </span>
              <span className="choke-row-actions" data-choke-col="actions">
                {ACTIONS.map((action) => (
                  <button key={action} type="button" onClick={() => onAction(entry, action)}>{action.slice(0, 3)}</button>
                ))}
                <button type="button" onClick={() => onFilterExec(entry.exec_id)}>tape</button>
              </span>
            </div>
          );
        }}
      />
      {truncated ? <div className="choke-table-tail">{total - rows.length} more match. Narrow the filter to inspect them.</div> : null}
    </div>
  );
}

function DecisionTape({
  refEl,
  rows,
  selected,
  acked,
  onSelect,
  onDrill,
  onFilterExec,
  onAck,
  onUnack,
  onCopy,
}: {
  refEl: React.MutableRefObject<HTMLDivElement | null>;
  rows: Array<{ decision: Decision; count: number }>;
  selected: Set<number>;
  acked: Set<number>;
  onSelect: (id: number) => void;
  onDrill: (execId: string) => void;
  onFilterExec: (execId: string) => void;
  onAck: (ids: number[]) => void;
  onUnack: (ids: number[]) => void;
  onCopy: (value: string) => void;
}) {
  const selectedIds = Array.from(selected);
  return (
    <div className="choke-tape-wrap">
      <div className="choke-tape-head"><span /> <span>time</span><span>action</span><span>exec_id / reason</span><span>tools</span></div>
      <VirtualList
        className="choke-tape"
        viewportRef={refEl}
        items={rows}
        estimateSize={58}
        getKey={({ decision }) => `${decision.id || 0}-${decision.exec_id}`}
        empty={<EmptyState title="No decisions match" body="The tape is filtered by time, action, search, and ack state." />}
        renderItem={({ decision, count }) => {
          const id = decision.id || 0;
          return (
            <div key={`${id}-${decision.exec_id}`} className={`choke-tape-row ${selected.has(id) ? "selected" : ""} ${acked.has(id) ? "acked" : ""}`}>
              <input type="checkbox" checked={selected.has(id)} onChange={() => onSelect(id)} aria-label={`Select decision ${id}`} />
              <span>{formatTime(decision.timestamp)}</span>
              <StateBadge state={decision.to_state || decision.action} />
              <button type="button" className="choke-tape-main" onClick={() => decision.exec_id && onDrill(decision.exec_id)}>
                <strong className="choke-execid-mono">{decision.exec_id || "-"}</strong>
                <span>{decision.reason || decision.binary || "-"}</span>
                {decision.pid ? <em>pid {decision.pid}</em> : null}
                {count > 0 ? <em>+{count}</em> : null}
                {decision.dry_run ? <em>dry-run</em> : null}
                {acked.has(id) ? <em>acked</em> : null}
              </button>
              <div className="choke-tape-actions">
                {decision.exec_id ? <button type="button" onClick={() => onFilterExec(decision.exec_id || "")}>filter</button> : null}
                <button type="button" onClick={() => onCopy(JSON.stringify(decision))}>copy</button>
              </div>
            </div>
          );
        }}
      />
      {selected.size > 0 ? (
        <div className="choke-tape-bulkbar">
          <span>{selected.size} selected</span>
          <button type="button" onClick={() => onAck(selectedIds)}>ack</button>
          <button type="button" onClick={() => onUnack(selectedIds)}>unack</button>
          <button type="button" onClick={() => onCopy(rows.filter((row) => selected.has(row.decision.id || 0)).map((row) => JSON.stringify(row.decision)).join("\n"))}>copy JSONL</button>
        </div>
      ) : null}
    </div>
  );
}

function RankedList({ rows, onPick }: { rows: Array<{ key: string; count: number }>; onPick: (key: string) => void }) {
  if (rows.length === 0) return <span className="choke-muted">no decisions in window</span>;
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <div className="choke-ranked-list">
      {rows.map((row) => (
        <button key={row.key} type="button" onClick={() => onPick(row.key)}>
          <span className="truncate">{basename(row.key)}</span>
          <strong>{row.count}</strong>
          <em style={{ width: `${(row.count / max) * 100}%` }} />
        </button>
      ))}
    </div>
  );
}

function PolicyPreview({
  preview,
  error,
  checking,
  circuits,
}: {
  preview: PolicyPreviewResponse | null;
  error: string;
  checking: boolean;
  circuits: CircuitEntry[];
}) {
  if (checking) return <LoadingState label="Evaluating policy" />;
  if (error) return <ErrorState title="Policy invalid" body={error} />;
  if (!preview) {
    return (
      <EmptyState
        title="No preview yet"
        body="Edit the policy and hit Preview matches to dry-run it against the live snapshot. 'Build from live' seeds one that matches what's tracked right now."
      />
    );
  }
  if (preview.valid === false) return <ErrorState title="Policy invalid" body={(preview.errors || []).join("; ")} />;

  const doc = preview.policy;
  const matches = preview.matches || [];
  const scanned = preview.scanned ?? circuits.length;
  const targetStates = doc?.match?.states && doc.match.states.length > 0 ? doc.match.states : ["any non-pristine"];
  const buckets = doc?.buckets || [];
  const denySyscalls = doc?.deny_syscalls || [];
  const denyPaths = doc?.deny_paths || [];

  // Live state distribution so an empty match set is explained, not mysterious.
  const liveStates = new Map<string, number>();
  for (const c of circuits) {
    const s = c.state || "pristine";
    liveStates.set(s, (liveStates.get(s) || 0) + 1);
  }
  const liveSummary = STATE_ORDER.map((s) => (liveStates.get(s) ? `${s}×${liveStates.get(s)}` : null))
    .filter(Boolean)
    .join(" · ");

  return (
    <div className="choke-preview">
      <div className="choke-preview-head">
        <span className="choke-preview-ok">valid</span>
        <strong>{doc?.metadata?.name || "unnamed"}</strong>
        <span className="choke-preview-count">{matches.length} matched · {scanned} scanned</span>
      </div>
      {doc?.metadata?.description ? <p className="choke-preview-desc">{doc.metadata.description}</p> : null}

      <div className="choke-preview-effects">
        <div><span>targets</span><strong>{(doc?.match?.binaries || []).join(", ") || "—"}</strong></div>
        <div><span>when state</span><strong>{targetStates.join(", ")}</strong></div>
        {buckets.length > 0 ? (
          <div><span>throttles</span><strong>{buckets.map((b) => `${b.dimension} @ ${b.rate_per_sec ?? "?"}/s`).join(", ")}</strong></div>
        ) : null}
        {denySyscalls.length > 0 ? <div><span>deny syscalls</span><strong>{denySyscalls.join(", ")}</strong></div> : null}
        {denyPaths.length > 0 ? <div><span>deny paths</span><strong>{denyPaths.join(", ")}</strong></div> : null}
      </div>

      {matches.length === 0 ? (
        <div className="choke-preview-nomatch">
          <strong>No live matches</strong>
          <span>
            Nothing in the tracked snapshot ({scanned} processes) matches these binaries in state{" "}
            {targetStates.join("/")}.
          </span>
          {liveSummary ? <span>Live states: {liveSummary}.</span> : null}
          <span className="choke-muted">Use “Build from live” to target what’s actually running.</span>
        </div>
      ) : (
        <div className="choke-preview-list">
          {matches.slice(0, 50).map((entry) => (
            <div key={entry.exec_id || entry.pid}>
              <StateBadge state={entry.state} />
              <span>{entry.pid || "-"}</span>
              <span className="truncate" title={entry.binary || ""}>{entry.binary || "(unknown)"}</span>
              <strong>{entry.score || 0}</strong>
            </div>
          ))}
          {matches.length > 50 ? <span className="choke-muted">+{matches.length - 50} more</span> : null}
        </div>
      )}
    </div>
  );
}

function ProcessDrill({
  drill,
  onClose,
  onForget,
  onAnnotate,
  onCopy,
  onRefresh,
}: {
  drill: DrillState;
  onClose: () => void;
  onForget: (execId: string) => Promise<void>;
  onRefresh: () => void;
  onAnnotate: (execId: string, note: string) => Promise<void>;
  onCopy: (value: string) => void;
}) {
  const [note, setNote] = useState("");
  useEffect(() => {
    if (drill.kind === "ready") setNote(drill.payload.annotation?.note || "");
  }, [drill]);
  if (drill.kind === "closed") return null;
  const entry = drill.kind === "ready" ? drill.payload.entry || { exec_id: drill.execId } : { exec_id: drill.execId };
  const chain = drill.kind === "ready" ? drill.payload.chain || [] : [];
  const decisions = drill.kind === "ready" ? drill.payload.decisions || [] : [];
  const events = drill.kind === "ready" ? drill.payload.events || [] : [];
  const firstProcess = chain[0]?.binary || entry.binary || "process";
  const lastProcess = chain[chain.length - 1]?.binary || entry.binary || "process";
  const fullExecId = entry.exec_id || drill.execId;
  const score = entry.score || 0;
  // Two narratives for two audiences. The technical one is unchanged (analyst
  // language: chain depth, exec_id, kernel-event counts). The plain-English one
  // translates the same facts into what a non-technical stakeholder — an exec,
  // an IR lead briefing leadership — needs: what ran, how dangerous, what we
  // did, and that it is on the audit record. Same data, no jargon.
  const startName = basename(firstProcess);
  const endName = basename(lastProcess);
  const riskWord = score >= 120 ? "high" : score >= 50 ? "elevated" : "low";
  const stateWord = entry.state || "pristine";
  const CONTAINMENT_PHRASE: Record<string, string> = {
    pristine: "It is being watched, but no containment has been applied yet.",
    throttled: "It was slowed down (throttled) so it can do less while analysts review it.",
    tarpit: "It was placed in a tarpit — its actions are deliberately delayed to stall it.",
    quarantined: "It was frozen (quarantined) and can do nothing until an operator releases it.",
    severed: "It was shut down (killed) and blocked from restarting."
  };
  const narrative =
    drill.kind === "ready"
      ? `${chain.length || 1}-process chain starting from ${firstProcess} currently resolves to ${lastProcess}. ${decisions.length} audited decision${decisions.length === 1 ? "" : "s"} and ${events.length} kernel event${events.length === 1 ? "" : "s"} are linked to this exec_id. Aggregate suspicion score: ${score}.`
      : "";
  const plainNarrative =
    drill.kind === "ready"
      ? `A program called ${endName}${startName && startName !== endName ? ` (launched from ${startName})` : ""} drew attention on this host. It tripped ${events.length} kernel-level security signal${events.length === 1 ? "" : "s"}, giving it a ${riskWord} suspicion score of ${score}. ${CONTAINMENT_PHRASE[stateWord] || CONTAINMENT_PHRASE.pristine} Every step it took and every response is recorded in the tamper-evident audit trail (${decisions.length} logged decision${decisions.length === 1 ? "" : "s"}).`
      : "";
  return (
    <aside className="choke-slideover" data-panel="process-drill-in-slide-over" role="dialog" aria-modal="true">
      <header>
        <h2>Process drill-in</h2>
        <button type="button" onClick={onClose}>Close</button>
      </header>
      {drill.kind === "loading" ? <LoadingState label="loading process detail" /> : null}
      {drill.kind === "error" ? <ErrorState title="Drill failed" body={drill.message} /> : null}
      {drill.kind === "ready" ? (
        <div className="choke-drill-body">
          <div className="choke-drill-hero">
            <StateBadge state={entry.state} />
            <strong>{entry.binary || "(unknown process)"}</strong>
            <span>pid {entry.pid || "-"} · uid {entry.uid || "-"} · {formatTime(entry.last_seen || entry.start_time)} · {originLabel(entry) || "local origin"}</span>
            <button type="button" className="choke-execid-full" title="Click to copy full exec_id" onClick={() => onCopy(fullExecId)}>
              <span className="choke-execid-label">exec_id</span>
              <code>{fullExecId || "-"}</code>
            </button>
          </div>
          <div className="choke-drill-stats">
            <div><span>Score</span><strong>{entry.score || 0}</strong></div>
            <div><span>Decisions</span><strong>{decisions.length}</strong></div>
            <div><span>Events</span><strong>{events.length}</strong></div>
            <div><span>Chain depth</span><strong>{chain.length || 1}</strong></div>
          </div>
          <section>
            <h3>Response</h3>
            {/* The same ladder the correlation graph uses. Choke Gateway has
                more detail and no visualisation; the graph has visualisation
                and less detail — but the enforcement control is identical, so
                an operator never has to relearn it when switching surface. */}
            <EnforcementLadder
              target={{
                id: entry.exec_id || drill.execId,
                label: entry.binary || "(unknown process)",
                pid: entry.pid,
                host: originLabel(entry) || undefined
              }}
              state={entry.state || "pristine"}
              policy={PROCESS_TERMINAL}
              apply={async (rung, why) => {
                const execId = entry.exec_id || drill.execId;
                try {
                  if (rung === "pristine") {
                    await releaseProcess(execId, entry.pid, why);
                  } else {
                    await manualAction({
                      exec_id: execId,
                      pid: entry.pid,
                      binary: entry.binary,
                      action: ACTION_FOR_RUNG[rung] as ChokeAction,
                      reason: why
                    });
                  }
                  return { ok: true, detail: `${ACTION_FOR_RUNG[rung]} accepted` };
                } catch (error) {
                  return { ok: false, detail: (error as Error).message || "action failed" };
                }
              }}
              readState={async () => {
                const list = await getCircuits();
                return list.find((c) => c.exec_id === (entry.exec_id || drill.execId))?.state;
              }}
              onSettled={onRefresh}
            />
            <div className="choke-row-actions wide">
              <button type="button" onClick={() => void onForget(drill.execId)}>forget</button>
              <button type="button" onClick={() => onCopy(entry.exec_id || drill.execId)}>copy exec_id</button>
              {entry.pid ? <button type="button" onClick={() => onCopy(String(entry.pid))}>copy pid</button> : null}
            </div>
          </section>
          <section>
            <h3>Narrative</h3>
            <div className="choke-drill-narrative choke-narrative-plain">
              <span className="choke-narrative-tag">In plain English</span>
              <p>{plainNarrative}</p>
            </div>
            <div className="choke-drill-narrative choke-narrative-tech">
              <span className="choke-narrative-tag">Technical</span>
              <p>{narrative}</p>
            </div>
          </section>
          <section>
            <h3>Operator note</h3>
            <textarea value={note} onChange={(event) => setNote(event.target.value)} />
            <button className="choke-action-button ok" type="button" onClick={() => void onAnnotate(drill.execId, note)}>Save note</button>
          </section>
          <section>
            <h3>Process lineage</h3>
            {chain.length === 0 ? <span className="choke-muted">none</span> : null}
            {chain.map((node) => (
              <div key={node.exec_id || node.pid} className="choke-drill-row">
                <span>{node.pid || "-"}</span>
                <strong>{node.binary || "(unknown)"}</strong>
                <em>{node.score || 0}</em>
              </div>
            ))}
          </section>
          <section>
            <h3>Indicators</h3>
            <div className="choke-drill-row">
              <span>proc</span>
              <strong>{entry.binary || "(unknown)"}</strong>
              <em>{entry.state || "pristine"}</em>
            </div>
            <div className="choke-drill-row choke-drill-row-exec">
              <span>exec</span>
              <strong className="choke-execid-mono">{fullExecId || "-"}</strong>
              <em>{entry.revert_pending ? "revert pending" : "active"}</em>
            </div>
          </section>
          <section>
            <h3>Decisions</h3>
            {decisions.length === 0 ? <span className="choke-muted">none</span> : null}
            {decisions.slice(0, 20).map((decision) => (
              <div key={decision.id || `${decision.timestamp}-${decision.action}`} className="choke-drill-row">
                <span>{formatTime(decision.timestamp)}</span>
                <StateBadge state={decision.to_state || decision.action} />
                <strong>{decision.reason || decision.action}</strong>
              </div>
            ))}
          </section>
          <section>
            <h3>Event timeline</h3>
            <EventReplay
              events={events.map((event) => ({
                id: String(event.id || `${event.timestamp}-${event.event_type}`),
                time: event.timestamp ?? "",
                kind: event.event_type || "-",
                detail: event.policy_name || event.args || ""
              }))}
              emptyLabel="No process events for this exec."
            />
          </section>
        </div>
      ) : null}
    </aside>
  );
}

function JailPicker({
  open,
  disabled,
  detail,
  onClose,
  onInspect,
  onOpenDrill,
  onAction,
  pushToast,
}: {
  open: boolean;
  disabled: boolean;
  detail: JailDetail;
  onClose: () => void;
  onInspect: (process: SysProcEntry) => void;
  onOpenDrill: (process: SysProcEntry) => void;
  onAction: (payload: { pids: number[]; action: ChokeAction; reason: string; descendants: boolean; revert_after_seconds?: number }) => Promise<void>;
  pushToast: (message: string, kind?: ToastMessage["kind"]) => void;
}) {
  const [processes, setProcesses] = useState<SysProcEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("");
  const [chips, setChips] = useState(() => readJsonStorage("choke.jail.filters", { user: true, system: true, kernel: false, tracked: false, high: false }));
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [reason, setReason] = useState("");
  const [descendants, setDescendants] = useState(false);
  const [revert, setRevert] = useState(false);
  const [revertSeconds, setRevertSeconds] = useState(300);
  const [sortKey, setSortKey] = useState<"score" | "pid" | "ppid" | "uid" | "comm" | "state">("score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const refresh = useCallback(async () => {
    if (!open || disabled) return;
    setLoading(true);
    try {
      setProcesses(await getProcesses());
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "process list failed", "err");
    } finally {
      setLoading(false);
    }
  }, [disabled, open, pushToast]);

  useEffect(() => {
    if (!open) return;
    setSelected(new Set());
    void refresh();
  }, [open, refresh]);
  useInterval(() => void refresh(), 4000, open && !disabled);

  useEffect(() => writeJsonStorage("choke.jail.filters", chips), [chips]);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return processes
      .filter((process) => {
        const cls = classifyProc(process);
        if (!chips[cls as keyof typeof chips]) return false;
        if (chips.tracked && !process.tracked) return false;
        if (chips.high && (process.score || 0) < 5) return false;
        if (!q) return true;
        return [process.pid, process.ppid, process.uid, process.comm, process.exe, process.cmdline, process.state].join(" ").toLowerCase().includes(q);
      })
      .sort((a, b) => {
        const dir = sortDir === "asc" ? 1 : -1;
        let diff = 0;
        if (sortKey === "score") diff = (a.score || 0) - (b.score || 0);
        else if (sortKey === "pid") diff = a.pid - b.pid;
        else if (sortKey === "ppid") diff = (a.ppid || 0) - (b.ppid || 0);
        else if (sortKey === "uid") diff = (a.uid || 0) - (b.uid || 0);
        else if (sortKey === "comm") diff = (a.comm || "").localeCompare(b.comm || "");
        else diff = (a.state || "").localeCompare(b.state || "");
        return diff === 0 ? a.pid - b.pid : diff * dir;
      });
  }, [chips, filter, processes, sortDir, sortKey]);

  function toggleChip(key: keyof typeof chips): void {
    setChips((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  async function submit(action: ChokeAction, explicitPid?: number): Promise<void> {
    const pids = explicitPid ? [explicitPid] : Array.from(selected);
    if (pids.length === 0) return pushToast("select at least one process", "err");
    if (!reason.trim()) return pushToast("reason required for audit", "err");
    await onAction({
      pids,
      action,
      reason: reason.trim(),
      descendants,
      revert_after_seconds: revert ? revertSeconds : undefined,
    });
    onClose();
  }

  if (!open) return null;
  return (
    <div className="choke-modal-backdrop" data-panel="jail-process-picker-modal" role="dialog" aria-modal="true">
      <div className="choke-jail-modal">
        <header>
          <h2>Jail a process</h2>
          <span>{visible.length} / {processes.length} processes</span>
          <button type="button" onClick={refresh}>{loading ? "Refreshing" : "Refresh"}</button>
          <button type="button" onClick={onClose}>Close</button>
        </header>
        {disabled ? <ErrorState title="Gateway disabled" body="The process picker is unavailable while /api/choke/processes returns 503." /> : null}
        <div className="choke-jail-tools">
          <input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="filter pid, comm, exe, cmdline, uid" />
          {(["user", "system", "kernel", "tracked", "high"] as Array<keyof typeof chips>).map((chip) => (
            <button key={chip} type="button" className={`choke-chip ${chips[chip] ? "on" : ""}`} onClick={() => toggleChip(chip)}>
              {chip}
            </button>
          ))}
        </div>
        <div className="choke-jail-grid">
          <div className="choke-jail-list">
            <div className="choke-jail-head">
              <input
                type="checkbox"
                checked={visible.length > 0 && visible.every((process) => selected.has(process.pid))}
                onChange={(event) => setSelected(event.target.checked ? new Set(visible.map((process) => process.pid)) : new Set())}
              />
              {(["pid", "ppid", "uid", "comm", "score", "state"] as const).map((key) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => {
                    if (sortKey === key) setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
                    else {
                      setSortKey(key);
                      setSortDir(key === "comm" || key === "state" ? "asc" : "desc");
                    }
                  }}
                >
                  {key}{sortKey === key ? (sortDir === "asc" ? " up" : " down") : ""}
                </button>
              ))}
            </div>
            {visible.length === 0 ? <EmptyState title="No processes match" body="Clear the search or enable more chips." /> : null}
            {visible.slice(0, 1000).map((process) => {
              const checked = selected.has(process.pid);
              return (
                <div key={process.pid} className={`choke-jail-row ${checked ? "selected" : ""}`}>
                  <input type="checkbox" checked={checked} onChange={() => setSelected((prev) => toggleNumber(prev, process.pid))} />
                  <button type="button" onClick={() => onInspect(process)}>{process.pid}</button>
                  <span>{process.ppid || "-"}</span>
                  <span>{process.uid ?? "-"}</span>
                  <span className="truncate" title={process.exe || process.comm}>{process.exe || process.comm || "-"}</span>
                  <span>{process.score || 0}</span>
                  <StateBadge state={process.state || "pristine"} />
                  <span className="choke-row-actions">
                    {ACTIONS.map((action) => <button key={action} type="button" onClick={() => void submit(action, process.pid)}>{action.slice(0, 3)}</button>)}
                    <button type="button" onClick={() => onOpenDrill(process)}>detail</button>
                  </span>
                </div>
              );
            })}
          </div>
          <div className="choke-jail-inspect">
            <JailInspect detail={detail} />
          </div>
        </div>
        <footer>
          <div className="choke-row-actions wide">
            {ACTIONS.map((action) => <button key={action} type="button" onClick={() => void submit(action)}>{action}</button>)}
          </div>
          <input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="audit reason (required)" />
          <label><input type="checkbox" checked={descendants} onChange={(event) => setDescendants(event.target.checked)} /> include descendants</label>
          <label><input type="checkbox" checked={revert} onChange={(event) => setRevert(event.target.checked)} /> auto-revert</label>
          <select value={revertSeconds} onChange={(event) => setRevertSeconds(Number(event.target.value))} disabled={!revert}>
            <option value={60}>1 min</option>
            <option value={300}>5 min</option>
            <option value={900}>15 min</option>
            <option value={3600}>1 hour</option>
          </select>
          <span>{selected.size} selected</span>
        </footer>
      </div>
    </div>
  );
}

function JailInspect({ detail }: { detail: JailDetail }) {
  if (detail.kind === "closed") return <EmptyState title="No process selected" body="Select a row to inspect live /proc state, signals, and lineage shell." />;
  const process = detail.process;
  const signals = deriveProcSignals(process);
  return (
    <div>
      <h3>{process.exe || process.comm || `pid ${process.pid}`}</h3>
      <div className="choke-jail-meta">
        <span>pid {process.pid}</span>
        <span>ppid {process.ppid || "-"}</span>
        <span>uid {process.uid ?? "-"}</span>
        <span>score {process.score || 0}</span>
        <StateBadge state={process.state || "pristine"} />
      </div>
      <code>{process.cmdline || process.comm || ""}</code>
      <div className="choke-chip-row">
        {signals.length ? signals.map((signal) => <span key={signal} className="choke-signal-chip">{signal}</span>) : <span className="choke-muted">no local risk signals</span>}
      </div>
      {detail.kind === "loading" ? <LoadingState label="loading live /proc state" /> : null}
      {detail.kind === "error" ? <ErrorState title="Live state failed" body={detail.message} /> : null}
      {detail.kind === "ready" ? (
        <div className="choke-kv-list">
          <div><span>status</span><strong>{detail.detail.status || "-"}</strong></div>
          <div><span>threads</span><strong>{detail.detail.threads || 0}</strong></div>
          <div><span>rss</span><strong>{detail.detail.vm_rss_kb || 0} KB</strong></div>
          <div><span>fds</span><strong>{detail.detail.num_fds || 0}</strong></div>
          <div><span>conns</span><strong>{detail.detail.num_conns || 0}</strong></div>
          <div><span>cwd</span><strong>{detail.detail.cwd || "-"}</strong></div>
        </div>
      ) : null}
    </div>
  );
}

function LayeredPanels({
  popover,
  hostPings,
  streamInfo,
  chokeState,
  mode,
  onPing,
  onSnapshot,
  onReconnect,
  onAuditVerify,
  onAuditCopy,
  onModeToggle,
  onKillSwitch,
  onPreset,
  onClose,
}: {
  popover: PopoverName;
  hostPings: HostPingResult[];
  streamInfo: { state: string; retries: number; lastMessageAt: number; totalMessages: number; messagesByMinute: number[] };
  chokeState: ChokeState | null;
  mode: string;
  onPing: () => void;
  onSnapshot: () => void;
  onReconnect: () => void;
  onAuditVerify: () => void;
  onAuditCopy: () => void;
  onModeToggle: (enforcing: boolean) => void;
  onKillSwitch: () => void;
  onPreset: (name: string) => void;
  onClose: () => void;
}) {
  if (!popover) return null;
  return (
    <div className="choke-popover" data-panel={`pill-popover-${popover}`} role="dialog" aria-modal="false">
      {popover === "host" ? (
        <>
          <PopoverHeader title="Host reachability" onClose={onClose} />
          <div className="choke-kv-list">
            {hostPings.map((ping) => (
              <div key={ping.path}><span>{ping.path}</span><strong>{ping.ok ? "ok" : `down ${ping.status || ""}`} · {ping.rtt_ms}ms</strong></div>
            ))}
          </div>
          <div className="choke-popover-actions">
            <button type="button" onClick={onPing}>Ping all</button>
          </div>
        </>
      ) : null}
      {popover === "live" ? (
        <>
          <PopoverHeader title="Live data stream" onClose={onClose} />
          <div className="choke-kv-list">
            <div><span>state</span><strong>{streamInfo.state}</strong></div>
            <div><span>last message</span><strong>{formatRelative(streamInfo.lastMessageAt)}</strong></div>
            <div><span>retries</span><strong>{streamInfo.retries}</strong></div>
            <div><span>total messages</span><strong>{streamInfo.totalMessages}</strong></div>
            <div><span>msg/sec</span><strong>{(streamInfo.messagesByMinute.length / 60).toFixed(2)}</strong></div>
          </div>
          <div className="choke-popover-actions">
            <button type="button" onClick={onSnapshot}>Snapshot now</button>
            <button type="button" onClick={onReconnect}>Force reconnect</button>
          </div>
        </>
      ) : null}
      {popover === "audit" ? (
        <>
          <PopoverHeader title="Audit chain" onClose={onClose} />
          <div className="choke-kv-list">
            <div><span>status</span><strong>{chokeState?.audit?.ok === false ? "broken" : "verified"}</strong></div>
            <div><span>decisions</span><strong>{chokeState?.audit?.total || 0}</strong></div>
            <div><span>head</span><strong>{String(chokeState?.audit?.head_hash || chokeState?.audit?.head || chokeState?.audit?.tip || "-").slice(0, 32)}</strong></div>
            {chokeState?.audit?.ok === false ? <div><span>bad at</span><strong>{chokeState.audit.bad_at}</strong></div> : null}
          </div>
          <div className="choke-popover-actions">
            <button type="button" onClick={onAuditCopy}>Copy head</button>
            <button type="button" onClick={onAuditVerify}>Re-verify now</button>
          </div>
        </>
      ) : null}
      {popover === "mode" ? (
        <>
          <PopoverHeader title="Enforcement mode" onClose={onClose} />
          <div className="choke-kv-list">
            <div><span>mode</span><strong>{mode}</strong></div>
            <div><span>dry-run</span><strong>{chokeState?.dry_run ? "on" : "off"}</strong></div>
            <div><span>kill-switch</span><strong>{chokeState?.kill_switched ? "engaged" : "standby"}</strong></div>
            <div><span>tracked</span><strong>{chokeState?.tracked || 0}</strong></div>
          </div>
          <div className="choke-popover-actions">
            <button type="button" onClick={() => onModeToggle(mode !== "enforcing")}>{mode === "enforcing" ? "Switch to detect-only" : "Switch to enforcing"}</button>
            <button type="button" onClick={onKillSwitch}>Kill-switch</button>
          </div>
          <div className="choke-chip-row">{Object.keys(PRESET_DESCRIPTIONS).map((name) => <button key={name} type="button" className="choke-chip" onClick={() => onPreset(name)}>{name}</button>)}</div>
        </>
      ) : null}
    </div>
  );
}

function PopoverHeader({ title, onClose }: { title: string; onClose: () => void }) {
  return (
    <header className="choke-popover-header">
      <h3>{title}</h3>
      <button type="button" className="choke-popover-close" onClick={onClose} aria-label={`Close ${title}`}>
        <X size={15} aria-hidden="true" />
      </button>
    </header>
  );
}

// Severity ladder for the alerts feed, highest first. Drives both ordering
// and the colour of each row's StateBadge.
const ALERT_SEVERITY: Array<{ state: string; label: string }> = [
  { state: "severed", label: "Critical" },
  { state: "quarantined", label: "High" },
  { state: "tarpit", label: "Medium" },
  { state: "throttled", label: "Low" },
];
const ALERT_RANK: Record<string, number> = { severed: 4, quarantined: 3, tarpit: 2, throttled: 1 };

// A decision's effective severity state: prefer the state it moved to, else
// derive it from the action verb.
function decisionState(decision: Decision): string {
  if (decision.to_state && decision.to_state !== "pristine") return decision.to_state;
  const fromAction: Record<string, string> = {
    sever: "severed",
    quarantine: "quarantined",
    tarpit: "tarpit",
    throttle: "throttled",
  };
  return fromAction[decision.action || ""] || decision.to_state || "pristine";
}

interface AlertGroup {
  key: string;
  state: string;
  binary: string;
  reason: string;
  count: number;
  ids: number[];
  unread: number;
  latestTs: number;
  execId?: string;
}

function NotificationsPanel({
  decisions,
  acked,
  clearedAt,
  alertsActive,
  badgeEnabled,
  onClose,
  onToggleAlerts,
  onToggleBadge,
  onAck,
  onClear,
  onOpenDrill,
}: {
  decisions: Decision[];
  acked: Set<number>;
  clearedAt: number;
  alertsActive: boolean;
  badgeEnabled: boolean;
  onClose: () => void;
  onToggleAlerts: () => void;
  onToggleBadge: () => void;
  onAck: (ids: number[]) => void;
  onClear: () => void;
  onOpenDrill: (execId: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set());

  // Collapse the raw decision tape into deduplicated alert groups keyed by
  // severity + binary + reason, so a burst of identical severs reads as one
  // row with a ×N count instead of dozens of repeats.
  const groups = useMemo<AlertGroup[]>(() => {
    const map = new Map<string, AlertGroup>();
    for (const decision of decisions) {
      const ts = new Date(decision.timestamp || 0).getTime();
      if (clearedAt && ts <= clearedAt) continue;
      const state = decisionState(decision);
      if (!ALERT_RANK[state]) continue; // only constraining escalations are alerts
      const binary = decision.binary || "";
      const reason = decision.reason || basename(decision.binary) || "decision";
      const key = `${state}|${binary}|${reason}`;
      let group = map.get(key);
      if (!group) {
        group = { key, state, binary, reason, count: 0, ids: [], unread: 0, latestTs: 0, execId: decision.exec_id };
        map.set(key, group);
      }
      group.count += 1;
      if (ts >= group.latestTs) {
        group.latestTs = ts;
        if (decision.exec_id) group.execId = decision.exec_id;
      }
      if (decision.id) {
        group.ids.push(decision.id);
        if (!acked.has(decision.id)) group.unread += 1;
      }
    }
    return [...map.values()].sort(
      (a, b) => (ALERT_RANK[b.state] || 0) - (ALERT_RANK[a.state] || 0) || b.latestTs - a.latestTs,
    );
  }, [decisions, clearedAt, acked]);

  const sevCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const group of groups) counts.set(group.state, (counts.get(group.state) || 0) + group.count);
    return counts;
  }, [groups]);

  const q = query.trim().toLowerCase();
  const visible = groups.filter(
    (group) =>
      (sevFilter.size === 0 || sevFilter.has(group.state)) &&
      (!q || group.reason.toLowerCase().includes(q) || group.binary.toLowerCase().includes(q)),
  );
  const totalUnread = groups.reduce((sum, group) => sum + group.unread, 0);
  const totalEvents = groups.reduce((sum, group) => sum + group.count, 0);
  const visibleIds = visible.flatMap((group) => group.ids);

  function toggleSeverity(state: string): void {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(state)) next.delete(state);
      else next.add(state);
      return next;
    });
  }

  return (
    <aside className="choke-floating-panel alerts" data-panel="notifications-panel">
      <header>
        <h3>Alerts</h3>
        <span className="choke-notif-count">
          {alertsActive ? `${totalUnread} unread · ${groups.length} grouped` : "silenced"}
        </span>
        <button type="button" className="choke-popover-close" onClick={onClose} aria-label="Close alerts">
          <X size={15} aria-hidden="true" />
        </button>
      </header>

      <div className="choke-alert-controlbar">
        <button type="button" className={!alertsActive ? "active" : ""} onClick={onToggleAlerts}>
          {alertsActive ? "Silence alerts" : "Resume alerts"}
        </button>
        <button type="button" className={!badgeEnabled ? "active" : ""} disabled={!alertsActive} onClick={onToggleBadge}>
          {badgeEnabled ? "Hide 400 badge" : "Show badge"}
        </button>
      </div>

      <div className="choke-alert-sevbar">
        {ALERT_SEVERITY.filter(({ state }) => sevCounts.get(state)).map(({ state, label }) => (
          <button
            key={state}
            type="button"
            className={`choke-alert-sevchip state-${state} ${sevFilter.has(state) ? "active" : ""}`}
            onClick={() => toggleSeverity(state)}
            title={`${label} (${state})`}
          >
            {label} <strong>{sevCounts.get(state)}</strong>
          </button>
        ))}
      </div>

      <input
        className="choke-alert-search"
        type="search"
        value={query}
        placeholder="filter by reason or binary"
        onChange={(event) => setQuery(event.target.value)}
      />

      <div className="choke-alert-list">
        {visible.length === 0 ? (
          <EmptyState
            title={groups.length === 0 ? "No alerts" : "No alerts match"}
            body={groups.length === 0 ? "Constraining decisions (throttle → sever) appear here, grouped by cause." : "Adjust the severity chips or search."}
          />
        ) : null}
        {visible.slice(0, 120).map((group) => (
          <button
            key={group.key}
            type="button"
            className={`choke-alert-row ${group.unread > 0 ? "unread" : "read"}`}
            onClick={() => group.execId && onOpenDrill(group.execId)}
            title={group.execId ? "Open process detail" : "No linked process"}
          >
            <StateBadge state={group.state} />
            <span className="choke-alert-reason">{group.reason}</span>
            <span className="choke-alert-meta">
              {group.binary ? <code className="truncate">{basename(group.binary)}</code> : null}
              <em>{formatRelative(group.latestTs)}</em>
            </span>
            {group.count > 1 ? <span className="choke-alert-count">×{group.count}</span> : null}
          </button>
        ))}
      </div>

      <footer>
        <button type="button" disabled={!totalUnread} onClick={() => onAck(visibleIds)}>
          Mark all read
        </button>
        <button type="button" className="danger" disabled={groups.length === 0} onClick={onClear}>
          Clear all
        </button>
      </footer>
    </aside>
  );
}

function ProfilePanel({
  userLabel,
  bootMs,
  decisionsSeen,
  ackedCount,
  theme,
  density,
  windowMin,
  onDensity,
  onWindow,
  onSnapshot,
  onCommand,
  onHelp,
  onThaw,
  onClose,
}: {
  userLabel: string;
  bootMs: number;
  decisionsSeen: number;
  ackedCount: number;
  theme: string;
  density: string;
  windowMin: number;
  onDensity: () => void;
  onWindow: (value: number) => void;
  onSnapshot: () => void;
  onCommand: () => void;
  onHelp: () => void;
  onThaw: () => void;
  onClose: () => void;
}) {
  return (
    <aside className="choke-floating-panel profile" data-panel="admin-profile-dropdown-avatar">
      <header>
        <h3>{userLabel}</h3>
        <span>Operator</span>
        <button type="button" className="choke-popover-close" onClick={onClose} aria-label="Close profile">
          <X size={15} aria-hidden="true" />
        </button>
      </header>
      <div className="choke-profile-tools">
        <button type="button" onClick={onCommand}>Command palette</button>
        <button type="button" onClick={onHelp}>Help &amp; shortcuts</button>
      </div>
      <div className="choke-kv-list">
        <div><span>session</span><strong>{formatUptime(Date.now() - bootMs)}</strong></div>
        <div><span>decisions seen</span><strong>{decisionsSeen}</strong></div>
        <div><span>acked</span><strong>{ackedCount}</strong></div>
        <div><span>theme</span><strong>{theme} (follows OS)</strong></div>
        <div><span>density</span><button type="button" onClick={onDensity}>{density}</button></div>
      </div>
      <label className="choke-profile-window">Default window
        <select value={windowMin} onChange={(event) => onWindow(Number(event.target.value))}>
          {WINDOW_OPTIONS.map((value) => <option key={value} value={value}>{formatWindow(value)}</option>)}
        </select>
      </label>
      <div className="choke-popover-actions">
        <button type="button" onClick={onSnapshot}>Snapshot</button>
        <button type="button" onClick={onThaw}>Thaw all</button>
        <a href="/api/logout">Sign out</a>
      </div>
    </aside>
  );
}

function CommandPalette({ items, onClose }: { items: Array<{ group: string; label: string; run: () => void }>; onClose: () => void }) {
  function run(item: { run: () => void }) {
    item.run();
    onClose();
  }
  return (
    <div className="choke-modal-backdrop command" data-panel="command-palette" role="dialog" aria-modal="true" onClick={(event) => event.target === event.currentTarget && onClose()}>
      <CommandPrimitive className="choke-command-card" label="Choke command palette">
        <CommandPrimitive.Input
          autoFocus
          onKeyDown={(event) => {
            if (event.key === "Escape") onClose();
          }}
          placeholder="Type a command"
        />
        <CommandPrimitive.List>
          <CommandPrimitive.Empty>
            <EmptyState title="No results" body="Try preset, jail, snapshot, theme, or a process name." />
          </CommandPrimitive.Empty>
          {items.map((item) => (
            <CommandPrimitive.Item
              key={`${item.group}-${item.label}`}
              value={`${item.group} ${item.label}`}
              onSelect={() => run(item)}
            >
              <span>{item.group}</span><strong>{item.label}</strong>
            </CommandPrimitive.Item>
          ))}
        </CommandPrimitive.List>
      </CommandPrimitive>
    </div>
  );
}

function ConfirmModal({ request, onClose, pushToast }: { request: ConfirmRequest; onClose: () => void; pushToast: (message: string, kind?: ToastMessage["kind"]) => void }) {
  const [reason, setReason] = useState(request.initialReason || "");
  const [revert, setRevert] = useState(false);
  const [revertSeconds, setRevertSeconds] = useState(300);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(): Promise<void> {
    if (request.reasonRequired && !reason.trim()) {
      setError("reason required for audit");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await request.onConfirm({
        reason: reason.trim(),
        revert_after_seconds: request.withRevert && revert ? revertSeconds : undefined,
      });
      onClose();
    } catch (err) {
      const message = err instanceof Error ? err.message : "action failed";
      setError(message);
      pushToast(message, "err");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="choke-modal-backdrop" data-panel="confirm-modal" role="dialog" aria-modal="true" onClick={(event) => event.target === event.currentTarget && onClose()}>
      <div className={`choke-confirm ${request.danger ? "danger" : ""}`}>
        <h2>{request.title}</h2>
        <p>{request.body}</p>
        {request.reasonRequired ? <input autoFocus value={reason} onChange={(event) => setReason(event.target.value)} placeholder="audit reason" /> : null}
        {request.withRevert ? (
          <label><input type="checkbox" checked={revert} onChange={(event) => setRevert(event.target.checked)} /> auto-revert
            <select value={revertSeconds} onChange={(event) => setRevertSeconds(Number(event.target.value))} disabled={!revert}>
              <option value={60}>1 min</option>
              <option value={300}>5 min</option>
              <option value={900}>15 min</option>
              <option value={3600}>1 hour</option>
            </select>
          </label>
        ) : null}
        {error ? <span className="choke-form-error">{error}</span> : null}
        <footer>
          <button type="button" onClick={onClose}>Cancel</button>
          <button className={request.danger ? "danger" : "ok"} type="button" disabled={busy} onClick={() => void submit()}>{busy ? "Working" : request.confirmLabel || "Confirm"}</button>
        </footer>
      </div>
    </div>
  );
}

function HelpModal({ onClose }: { onClose: () => void }) {
  const rows = [
    ["Ctrl+K", "Command palette"],
    ["?", "Help"],
    ["/", "Focus search"],
    ["J", "Jail picker"],
    ["K", "Kill-switch"],
    ["c/f/m/d", "IR presets"],
    ["t", "Theme"],
    ["g", "SOC dashboard"],
    ["Esc", "Close top layer"],
  ];
  return (
    <div className="choke-modal-backdrop" data-panel="help-modal" role="dialog" aria-modal="true" onClick={(event) => event.target === event.currentTarget && onClose()}>
      <div className="choke-help">
        <header><h2>Keyboard map</h2><button type="button" onClick={onClose}>Close</button></header>
        <div>{rows.map(([key, desc]) => <p key={key}><kbd>{key}</kbd><span>{desc}</span></p>)}</div>
      </div>
    </div>
  );
}

function ToastStack({ toasts }: { toasts: ToastMessage[] }) {
  return (
    <div className="choke-toasts" aria-live="polite">
      {toasts.map((toast) => <div key={toast.id} className={toast.kind}>{toast.message}</div>)}
    </div>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return <div className="choke-empty"><strong>{title}</strong><span>{body}</span></div>;
}

function LoadingState({ label }: { label: string }) {
  return <div className="choke-empty loading"><strong>{label}</strong><span>Waiting for the API response.</span></div>;
}

function ErrorState({ title, body }: { title: string; body: string }) {
  return <div className="choke-empty error"><strong>{title}</strong><span>{body}</span></div>;
}

function FilterChip({ label, onClear }: { label: string; onClear: () => void }) {
  return <button className="choke-filter-chip" type="button" onClick={onClear}>{label} x</button>;
}

function NotificationDot({
  decisions,
  acked,
  clearedAt,
  enabled,
}: {
  decisions: Decision[];
  acked: Set<number>;
  clearedAt: number;
  enabled: boolean;
}) {
  if (!enabled) return null;
  const unread = decisions.filter((decision) => {
    const ts = new Date(decision.timestamp || 0).getTime();
    if (clearedAt && ts <= clearedAt) return false;
    if (!ALERT_RANK[decisionState(decision)]) return false;
    return !acked.has(decision.id || 0);
  }).length;
  return unread > 0 ? <span className="choke-notif-dot">{unread >= DECISION_CAP ? `${DECISION_CAP}` : unread}</span> : null;
}

function toggleNumber(set: Set<number>, value: number): Set<number> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

function formatWindow(value: number): string {
  if (value < 60) return `${value}m`;
  if (value === 1440) return "24h";
  return `${Math.floor(value / 60)}h`;
}

function formatHealthValue(value: unknown): string {
  if (value == null) return "-";
  if (typeof value === "boolean") return value ? "ok" : "off";
  if (typeof value === "number" || typeof value === "string") return String(value);
  if (Array.isArray(value)) return `${value.length} items`;
  if (typeof value === "object") {
    const asRecord = value as Record<string, unknown>;
    if (typeof asRecord.ok === "boolean") return asRecord.ok ? "ok" : "fail";
    if (typeof asRecord.status === "string") return asRecord.status;
    return JSON.stringify(value).slice(0, 80);
  }
  return String(value);
}

const PRESET_DESCRIPTIONS: Record<string, string> = {
  containment: "Aggressive thresholds for active incidents: throttle early, sever late.",
  forensic: "Engages kill-switch so evidence is recorded while enforcement is bypassed.",
  maintenance: "Raises thresholds above normal scores for planned maintenance windows.",
  default: "Restores everyday 10/30/60/100 thresholds and normal posture.",
};

// buildLivePolicy synthesises a ChokePolicy from the current tracked snapshot
// so "Preview matches" returns real hits. It targets the most common
// non-pristine binary and the exact states it is currently in — guaranteeing
// the dry-run demonstrates the workbench actually evaluates live data.
function buildLivePolicy(circuits: CircuitEntry[]): string {
  const active = circuits.filter((c) => (c.state || "pristine") !== "pristine");
  if (active.length === 0) return DEFAULT_POLICY;

  const byBinary = new Map<string, number>();
  for (const c of active) {
    const b = c.binary || "";
    if (b) byBinary.set(b, (byBinary.get(b) || 0) + 1);
  }
  const topBinary = [...byBinary.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || active[0].binary || "/bin/sh";
  const states = [...new Set(active.filter((c) => c.binary === topBinary).map((c) => c.state || "pristine"))]
    .filter((s) => s !== "pristine");
  const stateLines = (states.length > 0 ? states : ["severed"]).map((s) => `    - ${s}`).join("\n");

  return `apiVersion: chokegw/v1
kind: ChokePolicy
metadata:
  name: live-${basename(topBinary).replace(/[^a-z0-9]+/gi, "-").toLowerCase() || "match"}
  description: Auto-generated from the live snapshot to target ${basename(topBinary)}
match:
  binaries:
    - ${topBinary}
  states:
${stateLines}
buckets:
  - dimension: egress.connect
    rate_per_sec: 5
    burst: 10
`;
}

const DEFAULT_POLICY = `apiVersion: chokegw/v1
kind: ChokePolicy
metadata:
  name: shells-throttle
match:
  binaries:
    - /bin/bash
    - /bin/sh
  states:
    - throttled
buckets:
  - dimension: egress.connect
    rate_per_sec: 5
    burst: 10
`;

export default ChokeRoute;
