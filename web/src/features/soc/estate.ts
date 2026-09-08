// THE ESTATE-WIDE READ: the wire document behind the provider's cross-customer
// view, and the model the view renders.
//
// GET /api/estate/summary (engine/internal/controlplane/estate.go) is built on
// one rule, and this module exists to carry that rule across the wire intact:
//
//   EVERY TOTAL SHIPS WITH THE PARTS IT WAS FOLDED FROM, AND A CUSTOMER WHOSE
//   READ FAILED IS NOT A ZERO.
//
// An aggregate an operator cannot break down per customer is the same defect as
// a console presenting one customer as the whole estate, one level up: the
// figure is on screen, the question "which customer produced it?" has no
// answer, and nothing about it looks wrong. So the tenant rows — not the
// totals — are the primary data here too: `estateTiles` derives each tile's
// decomposition from the rows the server published, and says so when the
// server's own total disagrees with them.
//
// The second rule is about absence. A tenant that could not be read contributes
// NOTHING and is carried through as `status: "unread"` with the reason. It is
// never normalised into a zero, because "this customer had no alerts" and "we
// could not look at this customer" lead to opposite decisions on a shift, and
// an estate view that conflates them under-reports an outage as a calm night.
//
// TELEMETRY THROUGHPUT IS DELIBERATELY ABSENT from the payload — the store has
// no windowed count-by-kind primitive, so the endpoint omitted it rather than
// guessing. There is no field for it here, and the view renders no slot for it:
// an empty tile would read as "zero events", which is a stronger claim than the
// server is able to make.
import { useCallback, useEffect, useState } from "react";
import { socApiGet } from "./api";

type AnyRecord = Record<string, unknown>;

/** One customer's contribution — the unit every total on this view folds over. */
export interface EstateTenantRow {
  tenant: string;
  /**
   * "read" or "unread". Anything the server did not explicitly call "read" is
   * treated as unread: a row whose status this console does not recognise has
   * counters of unknown provenance, and the safe reading of not knowing is not
   * to add them to an estate total.
   */
  status: "read" | "unread";
  unreadReason?: string;

  alerts: number;
  alertsBySeverity: Record<string, number>;
  /** False when this tenant's alert count is a floor rather than an exact count. */
  alertsExact: boolean;

  decisions: number;
  decisionsByAction: Record<string, number>;

  /** Processes held right now. Severed processes are counted apart: they are dead, and a release cannot undo them. */
  contained: number;
  severed: number;

  agents: number;
  agentsFresh: number;
  /** Telemetry lost permanently to the uplink buffer cap — an evidence gap. */
  droppedRecords: number;

  /** 0-100, higher is worse, scored on the estate's shared fixed scale. */
  posture: number;
  weightedAlertsPerHour: number;
  techniques: Record<string, number>;
}

export interface EstateTotals {
  alerts: number;
  alertsBySeverity: Record<string, number>;
  alertsExact: boolean;
  decisions: number;
  decisionsByAction: Record<string, number>;
  contained: number;
  severed: number;
  agents: number;
  agentsFresh: number;
  droppedRecords: number;
}

/**
 * The estate's risk, stated the only way it can be stated honestly: by naming
 * the worst customer. There is no estate average in this payload and there must
 * never be one on screen — a mean hides one customer on fire behind nine quiet
 * ones, which is exactly the situation an MSSP console exists to surface.
 */
export interface EstatePosture {
  worstScore: number;
  worstTenant?: string;
  concernThreshold: number;
  tenantsAtOrAboveConcern: number;
  tenantsBelowConcern: number;
  /** Tenants with no known posture because their read failed. They are NOT "below concern". */
  tenantsUnscored: number;
  scale?: string;
  note?: string;
}

/** The mode across tenants, carrying the split that produced it. */
export interface EstateTechnique {
  technique?: string;
  count: number;
  byTenant: Record<string, number>;
  sampled: boolean;
  alertsWithoutTechnique: number;
  note?: string;
}

export interface EstateSummary {
  windowMin: number;
  tenantsTotal: number;
  tenantsRead: number;
  tenantsUnread: number;
  totals: EstateTotals;
  posture: EstatePosture;
  top: EstateTechnique;
  rosterSource?: string;
  tenants: EstateTenantRow[];
  /** Whether the fan-out ran out of time, so some customers are unread for that reason. */
  budgetExceeded: boolean;
  maxTenants?: number;
}

/* ------------------------------------------------------------- the wire read */

function asRecord(value: unknown): AnyRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as AnyRecord) : {};
}

function pick(record: AnyRecord, ...keys: string[]): unknown {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(record, key)) return record[key];
  }
  return undefined;
}

function asNumber(value: unknown, fallback: number): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

function asOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

/** A `map[string]int` off the wire, with non-numeric members dropped rather than coerced to 0. */
function asCountMap(value: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, raw] of Object.entries(asRecord(value))) {
    if (typeof raw === "number" && Number.isFinite(raw)) out[key] = raw;
  }
  return out;
}

function normalizeTenantRow(value: unknown): EstateTenantRow {
  const record = asRecord(value);
  // Strictly === "read". See EstateTenantRow.status: an unrecognised status is
  // unread, so a future server state cannot quietly fold unknown counters into
  // an estate total.
  const read = pick(record, "status", "Status") === "read";
  return {
    tenant: asOptionalString(pick(record, "tenant", "tenant_id", "tenantId")) || "",
    status: read ? "read" : "unread",
    unreadReason: asOptionalString(pick(record, "unread_reason", "unreadReason")),
    alerts: asNumber(pick(record, "alerts"), 0),
    alertsBySeverity: asCountMap(pick(record, "alerts_by_severity", "alertsBySeverity")),
    // Absent => NOT exact. A server that does not say whether a count is a
    // floor has not promised that it is exact, and inheriting "exact" from
    // silence is how a floor gets presented as a total.
    alertsExact: pick(record, "alerts_exact", "alertsExact") === true,
    decisions: asNumber(pick(record, "decisions"), 0),
    decisionsByAction: asCountMap(pick(record, "decisions_by_action", "decisionsByAction")),
    contained: asNumber(pick(record, "contained_processes", "contained"), 0),
    severed: asNumber(pick(record, "severed_processes", "severed"), 0),
    agents: asNumber(pick(record, "agents"), 0),
    agentsFresh: asNumber(pick(record, "agents_fresh", "agentsFresh"), 0),
    droppedRecords: asNumber(pick(record, "dropped_records", "droppedRecords"), 0),
    posture: asNumber(pick(record, "posture"), 0),
    weightedAlertsPerHour: asNumber(pick(record, "weighted_alerts_per_hour", "weightedAlertsPerHour"), 0),
    techniques: asCountMap(pick(record, "techniques"))
  };
}

export function normalizeEstateSummary(value: unknown): EstateSummary {
  const record = asRecord(value);
  const totals = asRecord(pick(record, "totals"));
  const posture = asRecord(pick(record, "posture"));
  const top = asRecord(pick(record, "top_technique", "topTechnique"));
  const bounds = asRecord(pick(record, "bounds"));
  const tenants = (Array.isArray(pick(record, "tenants")) ? (pick(record, "tenants") as unknown[]) : [])
    .map(normalizeTenantRow)
    // A row with no tenant name cannot be attributed to a customer, and an
    // unattributable part is exactly what this view refuses to render.
    .filter((row) => row.tenant);
  return {
    windowMin: asNumber(pick(record, "window_min", "windowMin"), 0),
    // Counted from the rows when the server does not say, so the header cannot
    // claim more customers than the view can show.
    tenantsTotal: asNumber(pick(record, "tenants_total", "tenantsTotal"), tenants.length),
    tenantsRead: asNumber(pick(record, "tenants_read", "tenantsRead"), tenants.filter((t) => t.status === "read").length),
    tenantsUnread: asNumber(
      pick(record, "tenants_unread", "tenantsUnread"),
      tenants.filter((t) => t.status !== "read").length
    ),
    totals: {
      alerts: asNumber(pick(totals, "alerts"), 0),
      alertsBySeverity: asCountMap(pick(totals, "alerts_by_severity", "alertsBySeverity")),
      alertsExact: pick(totals, "alerts_exact", "alertsExact") === true,
      decisions: asNumber(pick(totals, "decisions"), 0),
      decisionsByAction: asCountMap(pick(totals, "decisions_by_action", "decisionsByAction")),
      contained: asNumber(pick(totals, "contained_processes", "contained"), 0),
      severed: asNumber(pick(totals, "severed_processes", "severed"), 0),
      agents: asNumber(pick(totals, "agents"), 0),
      agentsFresh: asNumber(pick(totals, "agents_fresh", "agentsFresh"), 0),
      droppedRecords: asNumber(pick(totals, "dropped_records", "droppedRecords"), 0)
    },
    posture: {
      worstScore: asNumber(pick(posture, "worst_score", "worstScore"), 0),
      worstTenant: asOptionalString(pick(posture, "worst_tenant", "worstTenant")),
      concernThreshold: asNumber(pick(posture, "concern_threshold", "concernThreshold"), 0),
      tenantsAtOrAboveConcern: asNumber(pick(posture, "tenants_at_or_above_concern", "tenantsAtOrAboveConcern"), 0),
      tenantsBelowConcern: asNumber(pick(posture, "tenants_below_concern", "tenantsBelowConcern"), 0),
      tenantsUnscored: asNumber(pick(posture, "tenants_unscored", "tenantsUnscored"), 0),
      scale: asOptionalString(pick(posture, "scale")),
      note: asOptionalString(pick(posture, "note"))
    },
    top: {
      technique: asOptionalString(pick(top, "technique")),
      count: asNumber(pick(top, "count"), 0),
      byTenant: asCountMap(pick(top, "by_tenant", "byTenant")),
      sampled: pick(top, "sampled") === true,
      alertsWithoutTechnique: asNumber(pick(top, "alerts_without_technique", "alertsWithoutTechnique"), 0),
      note: asOptionalString(pick(top, "note"))
    },
    rosterSource: asOptionalString(pick(record, "roster_source", "rosterSource")),
    tenants,
    budgetExceeded: pick(bounds, "budget_exceeded", "budgetExceeded") === true,
    maxTenants: typeof pick(bounds, "max_tenants") === "number" ? (pick(bounds, "max_tenants") as number) : undefined
  };
}

/* ------------------------------------------------------- tiles and their parts */

/** One customer's share of one tile, or the fact that the customer was not read. */
export interface EstateContribution {
  tenant: string;
  status: "read" | "unread";
  /** Undefined for an unread tenant — there is no number, and 0 would be a claim. */
  value?: number;
  detail?: string;
  unreadReason?: string;
}

export interface EstateTile {
  key: string;
  label: string;
  value: number;
  /** The one-line reading under the number: the severity or action split, freshness, and so on. */
  sub: string;
  /**
   * True when the tile's number is a FLOOR rather than a count — a scan bound
   * was hit, or a customer went unread and is therefore missing from the total.
   */
  floor: boolean;
  contributions: EstateContribution[];
  /**
   * Set when the total the SERVER published does not equal the sum of the parts
   * it published beside it. It should be impossible (the endpoint folds the
   * totals out of exactly these rows), which is precisely why it is surfaced
   * rather than silently trusted: a total whose parts do not add up is not a
   * total an operator can check, and this console's whole rule is that they
   * can.
   */
  partsMismatch?: { sumOfParts: number };
}

function splitLabel(counts: Record<string, number>, keys: string[]): string {
  const parts = keys.filter((key) => (counts[key] || 0) > 0).map((key) => `${counts[key]} ${key}`);
  return parts.join(" · ");
}

/**
 * The tiles, each folded over the rows the server published.
 *
 * `value` is the SERVER's total — this view reports what the endpoint said, it
 * does not quietly recompute it — while `contributions` and `partsMismatch`
 * come from the rows, so the number and its decomposition are on screen
 * together and can be checked against each other.
 */
export function estateTiles(summary: EstateSummary): EstateTile[] {
  const read = summary.tenants.filter((row) => row.status === "read");
  const unreadPresent = summary.tenants.some((row) => row.status !== "read") || summary.tenantsUnread > 0;

  const build = (
    key: string,
    label: string,
    value: number,
    sub: string,
    per: (row: EstateTenantRow) => number,
    detail?: (row: EstateTenantRow) => string | undefined,
    floor = false
  ): EstateTile => {
    const contributions: EstateContribution[] = summary.tenants.map((row) =>
      row.status === "read"
        ? { tenant: row.tenant, status: "read", value: per(row), detail: detail?.(row) }
        : {
            tenant: row.tenant,
            status: "unread",
            // No `value`: an unread customer contributed nothing measurable, and
            // rendering 0 here is the false all-clear this view exists to avoid.
            unreadReason: row.unreadReason || "this customer could not be read"
          }
    );
    contributions.sort((a, b) => {
      // Unread last — unknown is not calm, and burying it among the quiet
      // customers is how an outage reads as a good night. Then largest first,
      // then by name so equal contributors do not reshuffle between polls.
      if ((a.status === "read") !== (b.status === "read")) return a.status === "read" ? -1 : 1;
      if ((b.value ?? 0) !== (a.value ?? 0)) return (b.value ?? 0) - (a.value ?? 0);
      return a.tenant.localeCompare(b.tenant);
    });
    const sumOfParts = read.reduce((sum, row) => sum + per(row), 0);
    return {
      key,
      label,
      value,
      sub,
      // A total missing a customer is a floor, whatever the customers it did
      // read could promise.
      floor: floor || unreadPresent,
      contributions,
      partsMismatch: sumOfParts === value ? undefined : { sumOfParts }
    };
  };

  return [
    build(
      "alerts",
      "Alerts",
      summary.totals.alerts,
      splitLabel(summary.totals.alertsBySeverity, ["critical", "high", "medium", "low", "info"]) || "no alerts in this window",
      (row) => row.alerts,
      (row) => splitLabel(row.alertsBySeverity, ["critical", "high", "medium"]) || undefined,
      !summary.totals.alertsExact
    ),
    build(
      "decisions",
      "Response actions",
      summary.totals.decisions,
      splitLabel(summary.totals.decisionsByAction, ["sever", "quarantine", "tarpit", "throttle"]) ||
        "no containment ran in this window",
      (row) => row.decisions,
      (row) => splitLabel(row.decisionsByAction, ["sever", "quarantine", "tarpit", "throttle"]) || undefined
    ),
    build(
      "contained",
      "Processes held",
      summary.totals.contained,
      "held right now, releasable",
      (row) => row.contained
    ),
    build(
      "severed",
      "Processes severed",
      summary.totals.severed,
      // Counted apart from "held" rather than added to it: a severed process is
      // dead, a release cannot undo it, and one combined figure would overstate
      // what the provider still has in hand.
      "already killed — not releasable",
      (row) => row.severed
    ),
    build(
      "agents",
      "Agents enrolled",
      summary.totals.agents,
      `${summary.totals.agentsFresh} reporting inside the freshness window`,
      (row) => row.agents,
      (row) => `${row.agentsFresh}/${row.agents} fresh`
    ),
    build(
      "dropped",
      "Records dropped",
      summary.totals.droppedRecords,
      // The one estate number where a rise means the PLATFORM is failing rather
      // than the customer being attacked.
      "telemetry lost to uplink buffers — evidence the estate does not have",
      (row) => row.droppedRecords
    )
  ];
}

/**
 * Every customer, in the order the view states it renders them: worst posture
 * first, and customers that could not be read LAST.
 *
 * The endpoint already sorts this way, and the console sorts again anyway —
 * not from distrust, but because the table's caption tells the operator what
 * the order means. A caption that describes an order the console does not
 * enforce is a caption that quietly becomes false the day the server changes,
 * and burying an unread customer among the quiet ones is exactly how an outage
 * reads as a good night.
 */
export function orderedTenants(summary: EstateSummary): EstateTenantRow[] {
  return [...summary.tenants].sort((a, b) => {
    if ((a.status === "read") !== (b.status === "read")) return a.status === "read" ? -1 : 1;
    if (a.posture !== b.posture) return b.posture - a.posture;
    return a.tenant.localeCompare(b.tenant);
  });
}

/** The customers this response could not read, in the order they should be chased. */
export function unreadTenants(summary: EstateSummary): EstateTenantRow[] {
  return summary.tenants
    .filter((row) => row.status !== "read")
    .sort((a, b) => a.tenant.localeCompare(b.tenant));
}

/* --------------------------------------------------------------- the read hook */

export interface EstateRead {
  summary: EstateSummary | null;
  loading: boolean;
  /** The failure to report, or null. Never accompanied by a summary. */
  error: string | null;
  /**
   * The server does not serve this endpoint (404) — an older control plane, or
   * an account it refuses. Distinguished from `error` because it is not an
   * outage: the console degrades to the per-customer view it had before the
   * estate view existed rather than showing a failure the operator cannot act
   * on. Note the endpoint 404s (never 403) so a refusal cannot confirm that an
   * estate view exists to be denied.
   */
  notOffered: boolean;
  readAt: number | null;
  refresh: () => void;
}

const IDLE: EstateRead = {
  summary: null,
  loading: false,
  error: null,
  notOffered: false,
  readAt: null,
  refresh: () => {}
};

export async function fetchEstateSummary(
  windowMin: number,
  signal?: AbortSignal
): Promise<Omit<EstateRead, "loading" | "refresh">> {
  const result = await socApiGet<unknown>(`/api/estate/summary?window_min=${Math.max(1, Math.round(windowMin))}`, null, signal);
  if (!result.ok) {
    if (result.status === 404) return { summary: null, error: null, notOffered: true, readAt: Date.now() };
    // NO SUMMARY ALONGSIDE AN ERROR. A partially-filled estate rendered beside
    // a small error line is read as the estate; the view shows the failure
    // instead, because "we could not read the book of business" is the finding.
    return { summary: null, error: result.error || "the estate summary could not be read", notOffered: false, readAt: Date.now() };
  }
  return { summary: normalizeEstateSummary(result.data), error: null, notOffered: false, readAt: Date.now() };
}

/**
 * Read the estate summary, for a cross-tenant operator with no customer
 * selected and for nobody else.
 *
 * `enabled` carries BOTH halves of that condition, and the request is issued
 * from this effect alone: a tenant-bound operator must not send it (the control
 * plane 404s them by design, so it would put a permanent refusal in the network
 * log of a console that is working perfectly), and a provider who has selected
 * one customer is looking at that customer — an estate figure fetched behind
 * their back is a number nothing on screen accounts for.
 */
export function useEstateSummary(enabled: boolean, windowMin: number): EstateRead {
  const [state, setState] = useState<Omit<EstateRead, "loading" | "refresh">>({
    summary: null,
    error: null,
    notOffered: false,
    readAt: null
  });
  const [loading, setLoading] = useState(false);
  const [nonce, setNonce] = useState(0);
  const refresh = useCallback(() => setNonce((value) => value + 1), []);

  useEffect(() => {
    if (!enabled) {
      // Not merely "stop asking": drop the last answer too. Holding it would
      // let a stale estate reappear the moment the operator clears their
      // customer selection, above a "read at" stamp from another minute.
      setState({ summary: null, error: null, notOffered: false, readAt: null });
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    let live = true;
    setLoading(true);
    void fetchEstateSummary(windowMin, controller.signal).then((next) => {
      if (!live) return;
      setLoading(false);
      // An aborted read is not an answer about the estate: keep what is on
      // screen rather than replacing it with a failure the operator caused by
      // changing the window.
      if (next.error === "aborted") return;
      setState(next);
    });
    return () => {
      live = false;
      controller.abort();
    };
  }, [enabled, nonce, windowMin]);

  if (!enabled) return IDLE;
  return { ...state, loading, refresh };
}
