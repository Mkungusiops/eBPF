// Everything the dashboard DERIVES from a snapshot for the selected window.
//
// The route used to compute all of this inline, which meant the honesty rules —
// when a count may be shown as a measurement, when a delta is meaningful, which
// panels a short buffer actually affects — were interleaved with 500 lines of
// JSX. They are decisions about what the console is allowed to claim, so they
// live together here and the route only renders the answer.
import { useMemo, useRef } from "react";
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
import { eventIdentity, useAlertStats, useDecisionStats, useEstateBaseline } from "./hooks";
import {
  aggregateNetwork,
  eventSpark,
  eventsPerSecond,
  extractIocs,
  filterEvents,
  mitreCoverage
} from "./telemetry";
import { estateHalfScale, riskScoreAgainst } from "./risk";
import type { Severity, SocEvent, SocSnapshot } from "./types";

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
  streamHideNoise,
  streamPaused
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
  streamPaused: boolean;
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
  const { stats: decisionStats, supported: decisionStatsSupported } = useDecisionStats(rangeMin);
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

  // Scaled to THIS ESTATE's own typical rate, not a fixed constant.
  //
  // The fixed 200/hr half-scale gave the dial no dynamic range on a busy
  // estate: it sat near the top permanently and distinguished nothing, which is
  // the clamp defect one layer out. Measuring against the estate's own normal
  // means a quiet estate that gets busy moves, and a busy estate that gets
  // worse also moves.
  //
  // The trade is real and is disclosed rather than hidden: an estate that is
  // chronically bad now reads "normal". That is why riskPerHour and
  // riskBaselineRate are both handed to the band — the dial answers "compared
  // with usual here", and the absolute numbers beside it answer "and how bad is
  // usual". Neither is sufficient alone.
  const riskBaselineRate = useEstateBaseline();
  const riskHalfScale = estateHalfScale(riskBaselineRate);
  const riskScore = riskScoreAgainst(riskPerHour, riskHalfScale);
  // The prior window's score, on the SAME half-scale, so the band can show a
  // delta in the dial's own units.
  //
  // The band used to be handed `riskPerHour - previousRiskPerHour` — a
  // difference of weighted alerts per HOUR — and printed it immediately under a
  // gauge reading 0..100. Live on the engine that rendered as "100/100" above
  // "-9252 vs prior 5m": the dial had not moved at all and the number beneath
  // it claimed a five-figure fall. Two units, one visual group, and no reader
  // can reconcile them. The rate is still on screen in the line below, where it
  // is labelled "weighted alerts/hr" and means something.
  const previousRiskScore = riskScoreAgainst(previousRiskPerHour, riskHalfScale);
  // Nothing "pegs" any more — the curve is asymptotic, so there is always
  // headroom and a worsening estate always moves the dial. Saturated now means
  // the rate is an order of magnitude past half-scale, which is a real reading
  // rather than an artefact of the clamp.
  const riskSaturated = riskPerHour >= riskHalfScale * 10;
  // The label is CAPPED BY WHAT IS ACTUALLY ON FIRE.
  //
  // The score is now relative to the estate's own baseline, so 86/100 means
  // "roughly twenty times your usual rate" — a true and useful statement. But
  // the word "Critical" beside it is read as "critical alerts are happening",
  // and the tiles immediately to its right said 0 critical and 0 high while the
  // dial said Critical. Two readings of one estate contradicting each other on
  // one screen is how a console loses an operator's trust, and the earlier
  // metric-honesty pass fixed four defects of exactly this kind.
  //
  // So severity language now requires severity: "critical" needs a critical
  // alert in the window, "high" needs a high or a critical. The NUMBER is
  // untouched — a busy-for-you estate still reads 86 and still moves — only the
  // word is held to what the alert counts can support.
  const severityCeiling = counts.critical > 0 ? 3 : counts.high > 0 ? 2 : 1;
  const rawBand = riskScore >= 80 ? 3 : riskScore >= 45 ? 2 : riskScore >= 18 ? 1 : 0;
  const band = Math.min(rawBand, severityCeiling);
  const riskLabel = band >= 3 ? "critical" : band >= 2 ? "high" : band >= 1 ? "elevated" : "low";
  // Counted from the SERVER's window totals, not the browser buffer.
  //
  // These two numbers sit directly beside the CRITICAL and HIGH KPI tiles,
  // which have always used `counts` (server-side, whole window). This one
  // counted the capped alert buffer instead, so the same screen reported 52
  // priority alerts here and 88 in the tiles two inches away, for the same five
  // minutes. The executive band's own header comment warns about exactly this
  // mixing of populations; it was mixing them.
  //
  // Ack state is browser-local, so it is only knowable for alerts the buffer
  // holds. Subtracting it from the server totals is exact while the buffer
  // covers the window, and outside it can only UNDER-subtract — which leaves
  // the queue reading longer than it is, the safe direction for a number whose
  // job is "how much containment work is outstanding".
  const openContainment = useMemo(() => {
    let ackedCritical = 0;
    let ackedHigh = 0;
    for (const alert of rangeAlerts) {
      if ((ackStates[alert.id] || "new") === "new") continue;
      if (alert.severity === "critical") ackedCritical += 1;
      else if (alert.severity === "high") ackedHigh += 1;
    }
    return {
      critical: Math.max(0, counts.critical - ackedCritical),
      high: Math.max(0, counts.high - ackedHigh)
    };
  }, [ackStates, counts, rangeAlerts]);
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
  // PAUSE FREEZES THE LIST, NOT THE INGEST.
  //
  // `paused` used to reach nothing but a pill label and `.is-paused { opacity:
  // .62 }`: rows kept arriving and scrolling under the cursor of the operator
  // who had just pressed Pause, so a click landed on whatever had moved into
  // that position and they opened the drill panel for an event they never saw.
  //
  // What is held is the SET of events the buffer held at the pause edge — not a
  // snapshot of the rendered rows — so the filter and the self-noise toggle
  // still work on the frozen list, and nothing is dropped: everything that
  // arrives while held is still written to the buffer (the KPIs, the timeline
  // and the graph stay live), still counted below, and appears in one piece on
  // resume. A pause that discarded frames would be worse than no pause, because
  // the gap it left would be invisible.
  // HELD BY IDENTITY, NOT BY `event.id`.
  //
  // On the control plane the event feed carries no id, so the normaliser
  // synthesises one from the record's POSITION in the response — which means
  // every 30s poll hands the same real event back under a new id. A pause set
  // captured from `event.id` therefore matched nothing after the first poll:
  // the frozen list emptied itself while the operator was reading it, and the
  // readout beside it counted every row in the buffer as "arrived while held",
  // including the ones that had been on screen before Pause was pressed. Both
  // halves of the disclosure were wrong at once.
  //
  // eventIdentity is what makes two copies of a record the same record across
  // polls (see hooks.ts), and it is memoised per record, so keying the held set
  // by it costs one pass over the buffer at the pause edge and a lookup per row
  // after that.
  const heldEventKeysRef = useRef<Set<string> | null>(null);
  if (!streamPaused) heldEventKeysRef.current = null;
  else if (!heldEventKeysRef.current) heldEventKeysRef.current = new Set(snapshot.events.map(eventIdentity));
  const heldEventKeys = streamPaused ? heldEventKeysRef.current : null;
  const visibleEvents = useMemo(() => {
    const source: SocEvent[] = heldEventKeys
      ? snapshot.events.filter((event) => heldEventKeys.has(eventIdentity(event)))
      : snapshot.events;
    return filterEvents(source, streamFilter, streamHideNoise).slice(0, 200);
  }, [heldEventKeys, snapshot.events, streamFilter, streamHideNoise]);
  // How many frames reached the buffer while the list was held. The stream
  // panel prints it, so a paused list that has stopped moving is distinguishable
  // from an estate that has gone quiet.
  const heldEventCount = heldEventKeys
    ? snapshot.events.reduce((count, event) => (heldEventKeys.has(eventIdentity(event)) ? count : count + 1), 0)
    : 0;
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

  // How much of the loaded buffer falls OUTSIDE the selected window.
  //
  // An empty panel is read as "nothing happened", and at a five-minute window
  // on a live estate that is wrong: this rig had 2 alerts in 5m and 1,841 in
  // 24h, so every context panel rendered an empty state while the data sat one
  // click away. Telling the operator to "widen the range" is advice; telling
  // them there are 1,839 alerts they are not looking at is a fact, and it is
  // the difference between a panel they learn to ignore and one that points
  // somewhere.
  const beyondWindow = useMemo(
    () => ({
      alerts: Math.max(0, snapshot.alerts.length - rangeAlerts.length),
      events: Math.max(0, snapshot.events.length - rangeEvents.length)
    }),
    [snapshot.alerts.length, snapshot.events.length, rangeAlerts.length, rangeEvents.length]
  );

  return {
    beyondWindow,
    rangeAlerts,
    rangeEvents,
    rangeDecisions,
    filteredAlerts,
    serverStats,
    statsSupported,
    decisionStats,
    decisionStatsSupported,
    counts,
    previousCounts,
    hiddenTimelineSet,
    riskScore,
    previousRiskScore,
    riskLabel,
    riskPerHour,
    previousRiskPerHour,
    riskSaturated,
    // The estate's own typical rate, or null when there is too little history.
    // Handed out so the band can state what the dial is measuring against —
    // a baseline-relative score with the baseline hidden is a number nobody
    // can check.
    riskBaselineRate,
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
    heldEventCount,
    windowCoverage,
    activeEndpointErrors,
    countsUnfounded,
    storeFault,
    disabledEndpoints
  };
}

export type SocWindowModel = ReturnType<typeof useSocWindowModel>;
