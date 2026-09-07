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
  type DecisionStats,
  fetchAlertStats,
  fetchDecisionStats,
  MAX_BUFFERED_ALERTS,
  MAX_BUFFERED_DECISIONS,
  MAX_BUFFERED_EVENTS,
  fetchSocSnapshot,
  normalizeAlert,
  normalizeEvent
} from "./api";
import { estateTypicalRate, weightedHourlyRates } from "./risk";
import type { StreamFrame } from "../../lib/types";
import type { SocAlert, SocDecision, SocEvent, SocSnapshot } from "./types";

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
    // MERGE, never replace. The console opens the SSE stream and this poll at
    // the same time, so every frame the stream delivers while the request is in
    // flight has already been written into the buffer by applySocStreamBatch —
    // and a bare `setSnapshot(read.snapshot)` erased exactly those, leaving the
    // live pill counting frames the list never showed, with no reconnect and no
    // error to explain the gap. The window is the whole round-trip, which on a
    // loaded estate is when frames arrive fastest: the first alerts of an
    // incident are the ones it dropped.
    setSnapshot((current) => mergeSocSnapshot(current, read.snapshot, read.errors));
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

/**
 * Union a polled snapshot into the buffer the live stream has been filling.
 *
 * De-duplicated by the record's OWN identity (see eventIdentity/alertIdentity —
 * not `item.id`, which is positional on the control plane), then ordered
 * newest-first by timestamp so a frame that arrived mid-poll sits where it
 * belongs in the tail rather than wherever the concatenation put it. Records
 * with an unparseable timestamp sort last rather than to the top, so a bad row
 * cannot push real telemetry off the visible head of the list.
 *
 * `errors` is the poll's own per-feed error map. A feed that FAILED has no
 * authority over what still exists — its empty array is an outage, not an
 * answer — so a failed feed merges without evicting anything.
 *
 * Everything that is not a feed (whoami, version, policies, health…) is a fresh
 * read of server state and is taken from the poll unchanged.
 */
export function mergeSocSnapshot(
  current: SocSnapshot,
  polled: SocSnapshot,
  errors: Record<string, string> = {}
): SocSnapshot {
  return {
    ...polled,
    alerts: mergeFeed(polled.alerts, current.alerts, MAX_BUFFERED_ALERTS, alertIdentity, !errors.alerts),
    events: mergeFeed(polled.events, current.events, MAX_BUFFERED_EVENTS, eventIdentity, !errors.events),
    decisions: mergeFeed(polled.decisions, current.decisions, MAX_BUFFERED_DECISIONS, decisionIdentity, !errors.decisions)
  };
}

/**
 * The merge is a UNION WITH EVICTION, not an accumulator.
 *
 * The poll is authoritative about what still exists in the stretch of time it
 * covers; the union exists only so a frame the SSE stream delivered DURING the
 * request is not erased by the response that raced it. Without the eviction
 * half, nothing could ever leave a buffer — a manual Refresh included — so a
 * row the server had stopped returning (deleted, retention-expired, or filtered
 * out server-side) stayed on screen indefinitely and kept feeding the counters
 * that are supposed to be honest about the estate.
 *
 * The stretch the poll covers runs from the newest record it returned back to:
 *   • all time, when the response came back SHORT of the cap — the server had
 *     nothing older to give, so absence there is deletion;
 *   • the oldest record it returned, when the response came back AT the cap —
 *     the response was truncated, and the buffer legitimately reaches further
 *     back than one page, so older buffered rows are kept.
 * Anything NEWER than the newest polled record is the in-flight case and is
 * always kept.
 *
 * An empty successful poll is deliberately NOT treated as authoritative: it
 * carries no window to be authoritative over, and the console cannot tell a
 * genuinely empty feed from one endpoint that answered 200 with nothing while
 * the stream is live. Those rows age out of the selected window instead.
 */
function mergeFeed<T extends { timestamp: string }>(
  polled: T[],
  buffered: T[],
  cap: number,
  identity: (item: T) => string,
  authoritative: boolean
): T[] {
  const at = (item: T) => {
    const parsed = Date.parse(item.timestamp);
    return Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed;
  };
  const seen = new Set(polled.map(identity));
  const times = polled.map(at);
  const evicting = authoritative && polled.length > 0;
  const newest = evicting ? Math.max(...times) : Number.POSITIVE_INFINITY;
  const floor = evicting && polled.length >= cap ? Math.min(...times) : Number.NEGATIVE_INFINITY;

  const kept = buffered.filter((item) => {
    if (seen.has(identity(item))) return false; // the poll returned it; its copy wins
    if (!evicting) return true;
    const time = at(item);
    if (time > newest) return true; // arrived while the request was in flight
    if (time < floor) return true; // older than this truncated page could reach
    return false; // the poll covered this instant and did not return it
  });

  const merged = [...polled, ...kept];
  return merged.sort((a, b) => at(b) - at(a)).slice(0, cap);
}

/**
 * What identifies a feed record ACROSS POLLS.
 *
 * NOT `item.id`. The normalisers synthesise an id from the record's POSITION in
 * the response when the payload carries none — `${eventType}-${timestamp}-${index}`
 * for events, `alert-${index}` for alerts, `decision-${timestamp}-${index}` for
 * decisions — and the multi-tenant control plane's eventView emits no id field
 * at all. On that deployment every polled event id is therefore positional: the
 * same real event moves index as newer events arrive, comes back under a new
 * id, and an id-keyed merge kept BOTH copies. The buffer filled with duplicates
 * of one event up to MAX_BUFFERED_EVENTS, inflating the stream list and every
 * counter derived from it.
 *
 * So a positional id is treated as the non-identifier it is, and the record is
 * keyed by what the payload actually pins it by: agent, process instance, pid,
 * kind, timestamp and payload. A server-supplied id still wins when there is
 * one — including the exec_id normalizeAlert falls back to, which is stable.
 *
 * The residual limit is precision, and it is the safe direction: normalizeTimestamp
 * rounds the wire's RFC3339Nano to milliseconds, so two records identical in
 * every one of those fields AND inside the same millisecond count as one. That
 * under-counts by at most the duplicate; the id-keyed version over-counted one
 * event without limit.
 */
export function eventIdentity(event: SocEvent): string {
  return memoIdentity(event, computeEventIdentity);
}

export function alertIdentity(alert: SocAlert): string {
  return memoIdentity(alert, computeAlertIdentity);
}

export function decisionIdentity(decision: SocDecision): string {
  return memoIdentity(decision, computeDecisionIdentity);
}

/**
 * Identity is computed ONCE PER RECORD and remembered against the record itself.
 *
 * A content key is ten fields, a map and a join: cheap once, ruinous in a loop.
 * Every caller here asks for the identity of every record it holds — the poll
 * merge over the whole buffer, the stream merge over the whole buffer, the
 * paused list over the whole buffer — and the stream merge does it during a
 * flood, which is the one moment this panel exists for. Measured against the
 * buffer's own cap, a 500-frame batch over 2000 buffered events spent 644ms
 * building the same 2000 keys over and over, in a single uninterrupted tick:
 * a tab that stops responding exactly when an operator is watching an incident.
 *
 * Memoising HERE rather than in the loop that was profiled means no call site
 * can reintroduce the cost by adding another pass over the buffer.
 *
 * Keyed by the record object, because that is what "the same record" means to
 * every caller: the normalisers mint a record and nothing writes to one again,
 * so a cached key cannot go stale. A WeakMap, so records that fall off the end
 * of a capped buffer cost nothing to forget.
 */
const identityMemo = new WeakMap<object, string>();

function memoIdentity<T extends object>(record: T, compute: (record: T) => string): string {
  const cached = identityMemo.get(record);
  if (cached !== undefined) return cached;
  const key = compute(record);
  identityMemo.set(record, key);
  return key;
}

function computeEventIdentity(event: SocEvent): string {
  const stable = nonPositionalId(event.id, `${event.eventType}-${event.timestamp}-`);
  if (stable) return `id:${stable}`;
  return contentKey([
    event.agent,
    event.execId,
    event.pid,
    event.eventType,
    event.timestamp,
    event.process,
    event.args,
    event.path,
    event.destIp,
    event.destPort
  ]);
}

function computeAlertIdentity(alert: SocAlert): string {
  const stable = nonPositionalId(alert.id, "alert-");
  if (stable) return `id:${stable}`;
  return contentKey([alert.agent, alert.execId, alert.pid, alert.severity, alert.policyName, alert.timestamp, alert.title]);
}

function computeDecisionIdentity(decision: SocDecision): string {
  const stable = nonPositionalId(decision.id, `decision-${decision.timestamp}-`);
  if (stable) return `id:${stable}`;
  return contentKey([decision.timestamp, decision.action, decision.state, decision.target, decision.reason]);
}

/** An id that is the synthetic `<prefix><index>` shape is positional, not an identifier. */
function nonPositionalId(id: string | undefined, syntheticPrefix: string): string | undefined {
  if (!id) return undefined;
  if (id.startsWith(syntheticPrefix) && /^\d+$/.test(id.slice(syntheticPrefix.length))) return undefined;
  return id;
}

function contentKey(parts: Array<string | number | undefined>): string {
  // A 0x01 separator rather than a printable one: a process path or an argument
  // string can contain any printable character, and a key built with one of
  // those would let two different records collide by shifting a field boundary.
  return parts.map((part) => (part === undefined ? "" : String(part))).join("\u0001");
}

export function applySocStreamBatch(
  setSnapshot: React.Dispatch<React.SetStateAction<SocSnapshot>>,
  batch: StreamFrame[]
) {
  // ONE PASS OVER THE BUFFER PER BATCH, not one per frame.
  //
  // This used to rebuild the snapshot inside a loop over the batch, filtering
  // the entire buffer for every single frame — O(frames x buffer) identity
  // comparisons, each one a ten-field content key. A batch is whatever arrived
  // in one animation frame (stores/stream.ts) and is uncapped, so a flood of
  // 500 frames against a full 2000-event buffer meant a million key builds in
  // one synchronous tick: 644ms of blocked main thread, during precisely the
  // burst the live tail is there to show. The frames are normalised once, the
  // buffer is walked once, and identity is memoised per record on top of that.
  const alerts: SocAlert[] = [];
  const events: SocEvent[] = [];
  const decisions: SocDecision[] = [];
  for (const frame of batch) {
    if (frame.type === "alert") alerts.push(normalizeAlert(frame.payload));
    else if (frame.type === "event" || frame.type === "process_exit") events.push(normalizeEvent(frame.payload));
    else if (frame.type === "decision") decisions.push(normalizeDecisionFrame(frame.payload));
  }
  // A batch of nothing this snapshot models (heartbeats, unknown frame types)
  // must not schedule a state update: the old loop left `next === current` and
  // React bailed out, and that bail-out is what keeps a chatty stream from
  // re-rendering the whole dashboard for frames it does not display.
  if (alerts.length === 0 && events.length === 0 && decisions.length === 0) return;
  setSnapshot((current) => ({
    ...current,
    alerts: alerts.length ? prependArrivals(alerts, current.alerts, MAX_BUFFERED_ALERTS, alertIdentity) : current.alerts,
    events: events.length ? prependArrivals(events, current.events, MAX_BUFFERED_EVENTS, eventIdentity) : current.events,
    decisions: decisions.length
      ? prependArrivals(decisions, current.decisions, MAX_BUFFERED_DECISIONS, decisionIdentity)
      : current.decisions
  }));
}

/**
 * Put a batch of arrivals on the head of a buffer, newest first, keyed by
 * identity rather than by `item.id`.
 *
 * Identity for the same reason the poll merge uses it: a frame the control
 * plane sends carries no id of its own, so the normaliser stamps it with index
 * 0 — and an id-keyed replace would let every such frame evict the previous one
 * as a "duplicate".
 *
 * The batch is walked BACKWARDS so the last frame to arrive ends up at row 0
 * and a repeat within one batch is represented by its latest copy, which is
 * what the per-frame prepend produced. Buffered records the batch re-delivers
 * are dropped in favour of the arriving copy, and the walk stops as soon as the
 * cap is reached rather than filtering a buffer whose tail is about to be cut.
 */
function prependArrivals<T>(arrived: T[], buffered: T[], cap: number, identity: (item: T) => string): T[] {
  const keys = new Set<string>();
  const head: T[] = [];
  for (let i = arrived.length - 1; i >= 0 && head.length < cap; i -= 1) {
    const key = identity(arrived[i]);
    if (keys.has(key)) continue;
    keys.add(key);
    head.push(arrived[i]);
  }
  for (let i = 0; i < buffered.length && head.length < cap; i += 1) {
    if (keys.has(identity(buffered[i]))) continue; // the stream just re-delivered it
    head.push(buffered[i]);
  }
  return head;
}

function normalizeDecisionFrame(value: unknown): SocDecision {
  const record = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const timestamp = stringValue(record.timestamp || record.Timestamp) || new Date().toISOString();
  return {
    // The SAME synthetic shape api.ts's normalizeDecision uses, so a decision
    // that arrives by stream and again by poll produces one identity rather
    // than two spellings of the same fallback.
    id: stringValue(record.id || record.ID || record.decision_id) || `decision-${timestamp}-0`,
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

/**
 * Server-computed decision counts for the selected window.
 *
 * Same shape and cadence as useAlertStats, and the same honesty rule: a failed
 * fetch clears the numbers rather than leaving the previous window's on screen
 * under a new label. `supported` false means the caller must fall back to the
 * buffered count AND say it is a floor.
 */
export function useDecisionStats(rangeMin: number) {
  const [stats, setStats] = useState<DecisionStats | null>(null);
  const [supported, setSupported] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const tick = async () => {
      const next = await fetchDecisionStats(rangeMin, controller.signal);
      if (cancelled) return;
      if (next) {
        setStats(next);
        setSupported(true);
      } else {
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
  }, [rangeMin]);

  return { stats, supported };
}

/**
 * The estate's own typical weighted alert rate, from a week of hourly buckets.
 *
 * A SEPARATE, SLOW fetch, deliberately not folded into useAlertStats. That hook
 * re-requests every 15 seconds and re-requests again whenever the operator
 * changes range; a seven-day aggregate on that cadence is the request pattern
 * that took the control plane down on 2026-08-05. This one is fixed at 7 days
 * regardless of the selected range — the baseline is a property of the estate,
 * not of the window being viewed — and refreshes every ten minutes, because a
 * week's median does not move faster than that.
 *
 * Returns null while loading, when the endpoint is absent, or when there is too
 * little history to say. The caller must treat null as UNKNOWN and fall back to
 * the fixed scale, saying so — not as zero.
 */
export function useEstateBaseline() {
  const [typicalRate, setTypicalRate] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const windowMin = 7 * 24 * 60;
    const buckets = 168; // one per hour across the week
    const tick = async () => {
      const next = await fetchAlertStats(windowMin, buckets, controller.signal);
      if (cancelled) return;
      if (!next || next.buckets.length === 0) {
        setTypicalRate(null);
        return;
      }
      const bucketMinutes = windowMin / next.buckets.length;
      setTypicalRate(
        estateTypicalRate(
          weightedHourlyRates(
            next.buckets.map((b) => ({
              critical: b.counts.critical,
              high: b.counts.high,
              medium: b.counts.medium
            })),
            bucketMinutes
          )
        )
      );
    };
    void tick();
    const id = window.setInterval(() => void tick(), 600_000);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, []);

  return typicalRate;
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
