// Everything the dashboard DERIVES from a snapshot for the selected window.
//
// The route used to compute all of this inline, which meant the honesty rules —
// when a count may be shown as a measurement, when a delta is meaningful, which
// panels a short buffer actually affects — were interleaved with 500 lines of
// JSX. They are decisions about what the console is allowed to claim, so they
// live together here and the route only renders the answer.
import { useMemo } from "react";
import {
  TIMELINE_BUCKETS,
  buildTimeline,
  classifyAlert,
  compareAlerts,
  countSeverities,
  groupAlertList,
  matchesQuery,
  processSummary,
  serverTimeline,
  topProcessRows
} from "./analytics";
import { SEVERITIES, type AckState, type SortField } from "./dashboard";
import { useAlertStats } from "./hooks";
import {
  aggregateNetwork,
  eventSpark,
  eventsPerSecond,
  extractIocs,
  filterEvents,
  mitreCoverage
} from "./telemetry";
import { RISK_HALF_SCALE_PER_HOUR, riskScoreFromRate } from "./risk";
import type { Severity, SocSnapshot } from "./types";

export function useSocWindowModel({
  snapshot,
  rangeMin,
  now,
  truncated,
  errors,
  statuses,
  query,
  hideBaseline,
  filterUnack,
  groupAlerts,
  sortField,
  ackStates,
  pinnedAlerts,
  timelineHidden,
  streamFilter,
  streamHideNoise
}: {
  snapshot: SocSnapshot;
  rangeMin: number;
  now: number;
  truncated: { alerts: boolean; events: boolean };
  errors: Record<string, string>;
  statuses: Record<string, number | undefined>;
  query: string;
  hideBaseline: boolean;
  filterUnack: boolean;
  groupAlerts: boolean;
  sortField: SortField;
  ackStates: Record<string, AckState>;
  pinnedAlerts: string[];
  timelineHidden: Severity[];
  streamFilter: string;
  streamHideNoise: boolean;
}) {
  const rangeAlerts = useMemo(() => {
    const cutoff = now - rangeMin * 60_000;
    return snapshot.alerts.filter((alert) => Date.parse(alert.timestamp) >= cutoff);
  }, [now, rangeMin, snapshot.alerts]);

  const previousRangeAlerts = useMemo(() => {
    const windowMs = rangeMin * 60_000;
    const start = now - windowMs * 2;
    const end = now - windowMs;
    return snapshot.alerts.filter((alert) => {
      const ts = Date.parse(alert.timestamp);
      return ts >= start && ts < end;
    });
  }, [now, rangeMin, snapshot.alerts]);

  const rangeEvents = useMemo(() => {
    const cutoff = now - rangeMin * 60_000;
    return snapshot.events.filter((event) => Date.parse(event.timestamp) >= cutoff);
  }, [now, rangeMin, snapshot.events]);

  // Server-computed counts win whenever available; the buffer-derived versions
  // are the fallback for servers without the endpoint. See useAlertStats.
  const { stats: serverStats, supported: statsSupported } = useAlertStats(rangeMin, TIMELINE_BUCKETS);
  const bufferCounts = useMemo(() => countSeverities(rangeAlerts), [rangeAlerts]);
  const bufferPreviousCounts = useMemo(() => countSeverities(previousRangeAlerts), [previousRangeAlerts]);
  const counts = serverStats ? serverStats.counts : bufferCounts;
  const previousCounts = serverStats ? serverStats.previous : bufferPreviousCounts;
  const hiddenTimelineSet = useMemo(() => new Set(timelineHidden), [timelineHidden]);
  const filteredAlerts = useMemo(() => {
    const pinned = new Set(pinnedAlerts);
    const filtered = rangeAlerts
      .filter((alert) => !hideBaseline || classifyAlert(alert) !== "baseline")
      .filter((alert) => !filterUnack || (ackStates[alert.id] || "new") === "new")
      .filter((alert) => matchesQuery(alert, query))
      .sort((a, b) => compareAlerts(a, b, sortField, pinned));
    return groupAlerts ? groupAlertList(filtered) : filtered.map((alert) => ({ ...alert, groupCount: 1, members: [alert] }));
  }, [ackStates, filterUnack, groupAlerts, hideBaseline, pinnedAlerts, query, rangeAlerts, sortField]);

  // Posture is a RATE — weighted alerts per hour — not a cumulative count.
  //
  // It used to be `critical*8 + high*3 + medium` clamped to 100, which measured
  // the window selector as much as the estate: the same host at the same instant
  // read 0 / 3 / 31 / 100 as the range widened 5m → 24h, because a longer window
  // simply contains more alerts. It also saturated at THIRTEEN criticals
  // (13 * 8 = 104), so any busy tenant sat pegged at "Critical 100/100"
  // permanently and the gauge distinguished nothing.
  //
  // Dividing by the window makes the number a property of the estate, so the
  // four ranges agree when the estate is steady and disagree only when the rate
  // genuinely changed.
  const weightedAlerts = useMemo(() => counts.critical * 8 + counts.high * 3 + counts.medium, [counts]);
  const previousWeightedAlerts = useMemo(
    () => previousCounts.critical * 8 + previousCounts.high * 3 + previousCounts.medium,
    [previousCounts]
  );
  const riskPerHour = rangeMin > 0 ? (weightedAlerts * 60) / rangeMin : 0;
  const previousRiskPerHour = rangeMin > 0 ? (previousWeightedAlerts * 60) / rangeMin : 0;
  const riskScore = riskScoreFromRate(riskPerHour);
  // Nothing "pegs" any more — the curve is asymptotic, so there is always
  // headroom and a worsening estate always moves the dial. Saturated now means
  // the rate is an order of magnitude past half-scale, which is a real reading
  // rather than an artefact of the clamp.
  const riskSaturated = riskPerHour >= RISK_HALF_SCALE_PER_HOUR * 10;
  const riskLabel = riskScore >= 80 ? "critical" : riskScore >= 45 ? "high" : riskScore >= 18 ? "elevated" : "low";
  const openContainment = useMemo(() => {
    let critical = 0;
    let high = 0;
    for (const alert of rangeAlerts) {
      if ((ackStates[alert.id] || "new") !== "new") continue;
      if (alert.severity === "critical") critical += 1;
      else if (alert.severity === "high") high += 1;
    }
    return { critical, high };
  }, [ackStates, rangeAlerts]);
  // Decisions scoped to the selected window. The exec band sits under a window
  // selector and every other cell in it is windowed, so an all-time count there
  // read as "actions taken in the last 5m" when it meant "ever".
  const rangeDecisions = useMemo(() => {
    const cutoff = now - rangeMin * 60_000;
    return snapshot.decisions.filter((decision) => Date.parse(decision.timestamp) >= cutoff);
  }, [now, rangeMin, snapshot.decisions]);
  const eps = useMemo(() => eventsPerSecond(snapshot.events, now), [now, snapshot.events]);
  const activeProcesses = useMemo(() => processSummary(rangeAlerts, rangeEvents), [rangeAlerts, rangeEvents]);
  const bufferTimeline = useMemo(() => buildTimeline(rangeAlerts, rangeMin, now, hiddenTimelineSet), [
    hiddenTimelineSet,
    now,
    rangeAlerts,
    rangeMin
  ]);
  // The server returns the same bucket shape the client builds, so the timeline
  // renders identically either way — but over the FULL window rather than the
  // slice of it the buffer happens to hold.
  const timeline = useMemo(
    () => (serverStats ? serverTimeline(serverStats, hiddenTimelineSet) : bufferTimeline),
    [bufferTimeline, hiddenTimelineSet, serverStats]
  );
  const severitySparks = useMemo(() => {
    const buckets = buildTimeline(rangeAlerts, rangeMin, now, new Set(), 12);
    return Object.fromEntries(SEVERITIES.map((severity) => [severity, buckets.map((bucket) => bucket.counts[severity])])) as Record<
      Severity,
      number[]
    >;
  }, [now, rangeAlerts, rangeMin]);
  const eventSparkValues = useMemo(() => eventSpark(snapshot.events, now), [now, snapshot.events]);
  const mitreRows = useMemo(
    () => mitreCoverage(rangeEvents, snapshot.policies, snapshot.policyStats),
    [rangeEvents, snapshot.policies, snapshot.policyStats]
  );
  // Technique attribution is a join through policy metadata (see mitreCoverage).
  // A server that publishes no `mitre` on any policy can never produce a row, so
  // an empty coverage panel there means "not mapped", not "nothing observed" —
  // and the two must not render the same. The multi-tenant control plane omitted
  // the field entirely, which is why this panel read empty on every tenant.
  //
  // Claim the stronger "not mapped" only on positive evidence: policies came
  // back and none carried a technique. An empty policy list means the tenant has
  // no telemetry yet, which says nothing about the server's mapping.
  const techniqueMapped = useMemo(
    () => snapshot.policies.length === 0 || snapshot.policies.some((policy) => Boolean(policy.mitre)),
    [snapshot.policies]
  );
  const topProcesses = useMemo(() => topProcessRows(rangeAlerts), [rangeAlerts]);
  const iocs = useMemo(() => extractIocs(rangeAlerts, rangeEvents), [rangeAlerts, rangeEvents]);
  const networkRows = useMemo(() => aggregateNetwork(rangeEvents), [rangeEvents]);
  const visibleEvents = useMemo(
    () => filterEvents(snapshot.events, streamFilter, streamHideNoise).slice(0, 200),
    [snapshot.events, streamFilter, streamHideNoise]
  );
  // Does the console actually hold the whole selected window?
  //
  // The buffers are capped, and both feeds arrive newest-first, so a range
  // longer than the buffer covers is served silently: the panels render a
  // partial window that looks like a complete quiet one. At ~2 events/s a 2000
  // event buffer is ~16 minutes, so the 30m and 60m ranges under-report by
  // construction. A feed is short only if it came back FULL (older records
  // exist server-side) and its oldest held record starts after the window did.
  const windowCoverage = useMemo(() => {
    const windowMs = rangeMin * 60_000;
    const windowStart = now - windowMs;
    const oldest = (items: Array<{ timestamp: string }>) =>
      items.length ? Math.min(...items.map((item) => Date.parse(item.timestamp))) : undefined;
    const oldestEvent = truncated.events ? oldest(snapshot.events) : undefined;
    const oldestAlert = truncated.alerts ? oldest(snapshot.alerts) : undefined;
    const shortBy = (value?: number) => (value !== undefined && value > windowStart ? value - windowStart : 0);
    const eventsShortMs = shortBy(oldestEvent);
    const alertsShortMs = shortBy(oldestAlert);
    // The feeds reach back different distances — alerts are far rarer than
    // events, so 1000 alerts can span hours while 2000 events span minutes.
    // Coverage is therefore set by the SHORTEST feed, not the longest: taking
    // the longest printed "holds the most recent 89m, not the full 30m", which
    // is both self-contradictory and the opposite of the truth.
    const shortMs = Math.max(eventsShortMs, alertsShortMs);
    const shortFeeds = [eventsShortMs ? "events" : "", alertsShortMs ? "alerts" : ""].filter(Boolean);
    // Coverage is reported PER FEED, because the two panels groups are bound by
    // different buffers and they run out at very different distances: alerts are
    // far rarer than events, so 1000 alerts routinely span an hour or more while
    // 2000 events span ~25 minutes. Collapsing them into one worst-case number
    // told the operator their alert queue was truncated to 25m of a 30m window
    // when it in fact held 319 of 320 alerts — a disclosure that fires when
    // nothing is missing is one operators learn to dismiss, which costs them the
    // times it is real.
    return {
      complete: shortMs === 0,
      shortFeeds,
      // What the limiting feed covers — kept for the no-serverStats notice,
      // which is about the counts as a whole rather than any one panel.
      coveredMs: Math.max(0, windowMs - shortMs),
      // Alerts drive the alert queue and the top-process rows.
      alerts: { short: alertsShortMs > 0, coveredMs: Math.max(0, windowMs - alertsShortMs) },
      // Events drive the network/IOC panels.
      events: { short: eventsShortMs > 0, coveredMs: Math.max(0, windowMs - eventsShortMs) }
    };
  }, [now, rangeMin, snapshot.alerts, snapshot.events, truncated.alerts, truncated.events]);

  const activeEndpointErrors = Object.entries(errors).filter(([, error]) => error);
  // When the alert or event feed is failing, what is left in the buffer is
  // whatever the live stream has pushed since the last SUCCESSFUL load — not a
  // sample of the window, and not a floor either. Every count, delta, sparkline
  // and posture score derived from it is unfounded, so they must not be
  // rendered as measurements. Observed in production: with all five store-backed
  // endpoints returning 500, a 24h window displayed 15 alerts and a "+53 vs
  // prior 24h" posture move, both invented by the gap.
  // Counts are unfounded only when we had to derive them from the buffer AND
  // that buffer's feed is failing. With server-computed stats the counts stand
  // on their own, even if the row feeds are down.
  const countsUnfounded = !serverStats && Boolean(errors.alerts || errors.events);
  // The control plane reports store reachability on /api/system-health. When
  // the store is the fault, every store-backed endpoint fails together and the
  // list of five 500s says nothing an operator can act on — the subsystem does.
  const storeFault = snapshot.health.storeOk === false ? snapshot.health.storeError || "central store unreachable" : "";
  const disabledEndpoints = Object.entries(statuses)
    .filter(([, status]) => status === 503)
    .map(([key]) => key);

  return {
    rangeAlerts,
    rangeEvents,
    rangeDecisions,
    filteredAlerts,
    serverStats,
    statsSupported,
    counts,
    previousCounts,
    hiddenTimelineSet,
    riskScore,
    riskLabel,
    riskPerHour,
    previousRiskPerHour,
    riskSaturated,
    openContainment,
    eps,
    activeProcesses,
    timeline,
    severitySparks,
    eventSparkValues,
    mitreRows,
    techniqueMapped,
    topProcesses,
    iocs,
    networkRows,
    visibleEvents,
    windowCoverage,
    activeEndpointErrors,
    countsUnfounded,
    storeFault,
    disabledEndpoints
  };
}

export type SocWindowModel = ReturnType<typeof useSocWindowModel>;
