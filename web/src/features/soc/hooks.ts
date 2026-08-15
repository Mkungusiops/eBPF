// The dashboard's data plumbing: snapshot polling, server-computed window
// stats, the ticking clock, and localStorage-backed operator preferences.
//
// These are the only places in the SOC feature that own an interval or touch
// localStorage. Keeping them together means the polling cadences (30s snapshot,
// 15s stats, 1s clock) are visible side by side rather than scattered through a
// render function.
import { useCallback, useEffect, useState } from "react";
import type * as React from "react";
import {
  EMPTY_SOC_SNAPSHOT,
  type AlertStats,
  fetchAlertStats,
  MAX_BUFFERED_ALERTS,
  MAX_BUFFERED_DECISIONS,
  MAX_BUFFERED_EVENTS,
  fetchSocSnapshot,
  normalizeAlert,
  normalizeEvent
} from "./api";
import type { StreamFrame } from "../../lib/types";
import type { SocDecision, SocSnapshot } from "./types";

export function useSocData() {
  const [snapshot, setSnapshot] = useState<SocSnapshot>(EMPTY_SOC_SNAPSHOT);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [statuses, setStatuses] = useState<Record<string, number | undefined>>({});
  const [truncated, setTruncated] = useState({ alerts: false, events: false });

  const load = useCallback(async (signal?: AbortSignal, quiet = false) => {
    if (!quiet) setLoading(true);
    const read = await fetchSocSnapshot(signal);
    if (signal?.aborted) return;
    setSnapshot(read.snapshot);
    setErrors(read.errors);
    setStatuses(read.statuses);
    setTruncated(read.truncated);
    setLoading(false);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    const interval = window.setInterval(() => void load(undefined, true), 30_000);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [load]);

  // Manual refresh: refetch every snapshot endpoint and keep the spinner up for
  // a floor of 500ms so the action always reads as "did something" even when the
  // live stream already has the data warm.
  const refresh = useCallback(() => {
    setLoading(true);
    const started = Date.now();
    void load(undefined, true).finally(() => {
      const wait = Math.max(0, 500 - (Date.now() - started));
      window.setTimeout(() => setLoading(false), wait);
    });
  }, [load]);

  return {
    snapshot,
    setSnapshot,
    loading,
    errors,
    statuses,
    truncated,
    refresh
  };
}

export function applySocStreamBatch(
  setSnapshot: React.Dispatch<React.SetStateAction<SocSnapshot>>,
  batch: StreamFrame[]
) {
  setSnapshot((current) => {
    let next = current;
    for (const frame of batch) {
      if (frame.type === "alert") {
        const alert = normalizeAlert(frame.payload);
        next = {
          ...next,
          alerts: [alert, ...next.alerts.filter((item) => item.id !== alert.id)].slice(0, MAX_BUFFERED_ALERTS)
        };
      } else if (frame.type === "event" || frame.type === "process_exit") {
        const socEvent = normalizeEvent(frame.payload);
        next = {
          ...next,
          events: [socEvent, ...next.events.filter((item) => item.id !== socEvent.id)].slice(0, MAX_BUFFERED_EVENTS)
        };
      } else if (frame.type === "decision") {
        next = {
          ...next,
          decisions: [normalizeDecisionFrame(frame.payload), ...next.decisions].slice(0, MAX_BUFFERED_DECISIONS)
        };
      }
    }
    return next;
  });
}

function normalizeDecisionFrame(value: unknown): SocDecision {
  const record = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const timestamp = stringValue(record.timestamp || record.Timestamp) || new Date().toISOString();
  return {
    id: stringValue(record.id || record.ID || record.decision_id) || `decision-${timestamp}`,
    action: stringValue(record.action || record.Action) || "observe",
    state: stringValue(record.state || record.State),
    target: stringValue(record.target || record.Target || record.exec_id || record.ExecID),
    reason: stringValue(record.reason || record.Reason),
    timestamp
  };
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

/**
 * Server-computed counts for the selected window.
 *
 * The dashboard's counts, deltas, posture score and timeline used to be derived
 * in the browser by filtering the alert buffer. That is only correct while the
 * buffer spans the window — at this fleet's rate it spans roughly twenty
 * minutes, so every range above 30m was a fraction of itself presented as a
 * total, and the "vs prior" delta compared against a window that was never
 * loaded (printing "+313 vs prior 24h" when the honest answer was unknown).
 *
 * Returns null while loading, or when the server has no such endpoint — the
 * caller then falls back to computing from the buffer, which stays correct for
 * the short ranges where the buffer really does cover the window.
 */
export function useAlertStats(rangeMin: number, buckets: number) {
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [supported, setSupported] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const tick = async () => {
      const next = await fetchAlertStats(rangeMin, buckets, controller.signal);
      if (cancelled) return;
      if (next) {
        setStats(next);
        setSupported(true);
      } else {
        // Do not keep the previous window's numbers on screen when the range
        // changed and the new fetch failed; stale counts under a new label are
        // exactly the class of lie this replaces.
        setStats(null);
        setSupported(false);
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), 15_000);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [buckets, rangeMin]);

  return { stats, supported };
}

export function useNow(intervalMs: number) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(interval);
  }, [intervalMs]);
  return now;
}

export function useLocalJsonState<T>(key: string, fallback: T): [T, React.Dispatch<React.SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => readLocalJson(key, fallback));
  useEffect(() => {
    writeLocalJson(key, value);
  }, [key, value]);
  return [value, setValue];
}

function readLocalJson<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const value = window.localStorage.getItem(key);
    return value == null ? fallback : (JSON.parse(value) as T);
  } catch {
    return fallback;
  }
}

function writeLocalJson<T>(key: string, value: T) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Local persistence is operator convenience. Decode/write failures must not break the SOC route.
  }
}
