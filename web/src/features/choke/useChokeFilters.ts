// Every filter on the page, and the views derived from them.
//
// The gateway has three independent search surfaces — the global DSL box, the
// process-list filter, and the tape's text/regex box — and they compose rather
// than override each other. Holding them together with the memos they feed is
// what keeps "what the operator asked for" in one place; splitting them across
// the render tree is how a filtered list and its "N / M" caption drift apart.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Rung } from "../common/enforcement";
import type { Alert, CircuitEntry, Decision } from "./types";
import { DECISION_CAP, PROC_RENDER_CAP } from "./constants";
import {
  ACTIONS,
  bucketizeDecisions,
  circuitMatches,
  decisionMatches,
  originLabel,
  parseSearch,
  readJsonStorage,
  summarizeAlerts,
  tapeTextMatches,
  topK,
  writeJsonStorage,
} from "./utils";

export function useChokeFilters({
  windowOptions,
  circuits,
  decisions,
  alerts,
  now,
  ackedDecisionIds,
}: {
  windowOptions: number[];
  circuits: CircuitEntry[];
  decisions: Decision[];
  alerts: Alert[];
  now: number;
  ackedDecisionIds: Set<number>;
}) {
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
  const [hideAcked, setHideAcked] = useState(false);
  const [groupTape, setGroupTape] = useState(false);
  const [tapeFilterExec, setTapeFilterExec] = useState<string | null>(null);
  const [autoScrollTape, setAutoScrollTape] = useState(true);
  const tapeRef = useRef<HTMLDivElement | null>(null);

  const setWindowMin = useCallback(
    (value: number) => {
      const next = windowOptions.includes(value) ? value : 30;
      setWindowMinState(next);
      writeJsonStorage("choke.window", next);
    },
    [windowOptions],
  );

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

  // The shared containment ladder doubles as a filter: clicking a rung narrows
  // the process list to it, clicking the active rung restores the default
  // "everything above pristine" view.
  const activeRung = stateFilters.size === 1 ? (Array.from(stateFilters)[0] as string) : null;
  const toggleRungFilter = useCallback((rung: Rung) => {
    setStateFilters((prev) =>
      prev.size === 1 && prev.has(rung)
        ? new Set<string>(["throttled", "tarpit", "quarantined", "severed"])
        : new Set<string>([rung])
    );
  }, []);

  useEffect(() => {
    if (!autoScrollTape || !tapeRef.current) return;
    tapeRef.current.scrollTop = 0;
  }, [autoScrollTape, groupedDecisions.length]);

  return {
    globalSearch,
    setGlobalSearch,
    procFilter,
    setProcFilter,
    tapeSearch,
    setTapeSearch,
    stateFilters,
    setStateFilters,
    tapeActions,
    setTapeActions,
    windowMin,
    setWindowMin,
    selectedExecs,
    setSelectedExecs,
    selectedDecisionIds,
    setSelectedDecisionIds,
    hideAcked,
    setHideAcked,
    groupTape,
    setGroupTape,
    tapeFilterExec,
    setTapeFilterExec,
    autoScrollTape,
    setAutoScrollTape,
    tapeRef,
    alertCounts,
    searchFilteredCircuits,
    visibleCircuits,
    truncatedCircuits,
    filteredDecisions,
    groupedDecisions,
    currentWindowDecisions,
    velocityBuckets,
    topBinaries,
    topReasons,
    selectedEntries,
    activeRung,
    toggleRungFilter,
  };
}
