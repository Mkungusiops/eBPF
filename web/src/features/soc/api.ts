import type {
  Severity,
  SocAlert,
  SocAttack,
  SocDecision,
  SocEvent,
  SocHoneypot,
  SocPolicy,
  SocPolicyStat,
  SocProcessDetail,
  SocReadResult,
  SocSnapshot,
  SocSnapshotRead,
  SocSystemHealth,
  SocVersion,
  SocWhoami
} from "./types";
import { useEffect, useState, useSyncExternalStore } from "react";
import { ApiError, getJSON, postForm, postJSON } from "../../lib/api";
import { adoptPersistedTenant, selectedTenantNow } from "../../lib/tenantScope";

/**
 * THE CUSTOMER SWITCHER'S STORE LIVES IN lib/tenantScope.ts, and is re-exported
 * here so the surfaces that grew around it keep importing it from the feature
 * they belong to.
 *
 * It moved because the scope has to be applied where EVERY request goes out —
 * lib/api.ts's funnel and lib/stream.tsx's SSE URL — and lib/ cannot import a
 * feature. Re-exported rather than copied: two stores would drift, and a drift
 * here means the panels reading one customer while the kill-switch fires at
 * another.
 */
export {
  adoptPersistedTenant,
  selectedTenantNow,
  setSelectedTenant,
  tenantScopedPath,
  useSelectedTenant
} from "../../lib/tenantScope";

type AnyRecord = Record<string, unknown>;

// policyScope defaults to the NARROWER claim: before any server has
// answered, a change reaches one host at most.
const EMPTY_WHOAMI: SocWhoami = { user: "operator", host: "localhost", policyScope: "host" };
const EMPTY_VERSION: SocVersion = { sha: "", labMode: false };
const EMPTY_HEALTH: SocSystemHealth = { status: "unknown", details: {} };

export const EMPTY_SOC_SNAPSHOT: SocSnapshot = {
  whoami: EMPTY_WHOAMI,
  version: EMPTY_VERSION,
  alerts: [],
  events: [],
  decisions: [],
  policies: [],
  policyStats: [],
  attacks: [],
  honeypots: [],
  health: EMPTY_HEALTH
};

// How many records the console holds in memory. These are also the caps the
// live stream trims to (see applySocStreamBatch) — if the two disagree, the
// first stream frame after a poll silently throws away everything the poll
// fetched beyond the smaller cap.
//
// The buffers are finite, so a long range can ask for more history than the
// console holds. That is disclosed rather than hidden: fetchSocSnapshot reports
// `truncated` per feed and the dashboard renders a notice, because a window
// quietly missing its oldest events looks exactly like a quiet window.
export const MAX_BUFFERED_ALERTS = 1000;
export const MAX_BUFFERED_EVENTS = 2000;

// Decisions previously used `?limit=1`, which capped the "Response actions"
// tile at 1 no matter how many containments a tenant had run — the number read
// as "1 decision in this window" when it meant "at least one decision exists".
export const MAX_BUFFERED_DECISIONS = 200;

const ENDPOINTS = {
  whoami: "/api/whoami",
  version: "/api/version",
  alerts: `/api/alerts?limit=${MAX_BUFFERED_ALERTS}`,
  events: `/api/events?limit=${MAX_BUFFERED_EVENTS}`,
  decisions: `/api/decisions?limit=${MAX_BUFFERED_DECISIONS}`,
  policies: "/api/policies",
  policyStats: "/api/policy-stats",
  attacks: "/api/attacks",
  honeypots: "/api/honeypots",
  health: "/api/system-health"
} as const;

export async function socApiGet<T>(
  path: string,
  fallback: T,
  signal?: AbortSignal
): Promise<SocReadResult<T>> {
  try {
    // The customer on screen is named on this request by the funnel in
    // lib/api.ts, not here. Nothing about that is optional for a read: one
    // that forgets the parameter does not fail, it silently answers about the
    // operator's default customer, and the panel it fills says nothing about
    // which one. With no selection the funnel leaves the path untouched, so a
    // tenant-bound console sends exactly what it always did.
    const data = await getJSON<T>(path, { signal });
    return { ok: true, data, status: 200 };
  } catch (error) {
    if ((error as Error).name === "AbortError") {
      return { ok: false, data: fallback, error: "aborted" };
    }
    if (error instanceof ApiError) {
      return {
        ok: false,
        data: fallback,
        status: error.status,
        disabled: error.status === 503,
        error: error.message || `HTTP ${error.status}`
      };
    }
    return { ok: false, data: fallback, error: error instanceof Error ? error.message : String(error) };
  }
}

export async function fetchSocSnapshot(signal?: AbortSignal): Promise<SocSnapshotRead> {
  // THE CUSTOMER THIS POLL IS ABOUT, read once, before the ten reads go out.
  // The funnel names the same selection on each of them (whoami and version
  // excepted — see UNSCOPED_PATHS), and the whoami returned is stamped with
  // this value, so the caption on the screen always describes the rows
  // underneath it rather than whatever the selection happens to be by the time
  // the responses land. A switch mid-poll is caught below by comparing the two.
  const scopedTo = selectedTenantNow();
  const entries = await Promise.all([
    socApiGet<unknown>(ENDPOINTS.whoami, null, signal).then((result) => ["whoami", result] as const),
    socApiGet<unknown>(ENDPOINTS.version, null, signal).then((result) => ["version", result] as const),
    socApiGet<unknown>(ENDPOINTS.alerts, [], signal).then((result) => ["alerts", result] as const),
    socApiGet<unknown>(ENDPOINTS.events, [], signal).then((result) => ["events", result] as const),
    socApiGet<unknown>(ENDPOINTS.decisions, [], signal).then((result) => ["decisions", result] as const),
    socApiGet<unknown>(ENDPOINTS.policies, [], signal).then((result) => ["policies", result] as const),
    socApiGet<unknown>(ENDPOINTS.policyStats, [], signal).then((result) => ["policyStats", result] as const),
    socApiGet<unknown>(ENDPOINTS.attacks, [], signal).then((result) => ["attacks", result] as const),
    socApiGet<unknown>(ENDPOINTS.honeypots, [], signal).then((result) => ["honeypots", result] as const),
    socApiGet<unknown>(ENDPOINTS.health, null, signal).then((result) => ["health", result] as const)
  ]);

  const map = Object.fromEntries(entries) as Record<keyof typeof ENDPOINTS, SocReadResult<unknown>>;
  const errors: Record<string, string> = {};
  const statuses: Record<string, number | undefined> = {};

  // Endpoints a production deployment deliberately does NOT serve.
  //
  // Attack Sim and Honeypots are lab-only and answer 404 unless the server was
  // started with -lab-mode. That is a configuration, not a fault, and routing
  // it into `errors` would light the notices strip and the band's
  // "telemetry feed down" path over two panels the operator is not supposed to
  // have — inventing an outage out of a deliberate omission. A 404 here means
  // "not offered"; any other failure on them is still a real error.
  const OPTIONAL_ENDPOINTS = new Set(["attacks", "honeypots"]);

  for (const [key, result] of entries) {
    statuses[key] = result.status;
    if (!result.ok && result.error && result.error !== "aborted") {
      if (OPTIONAL_ENDPOINTS.has(key) && result.status === 404) continue;
      errors[key] = result.error;
    }
  }

  const alerts = unwrapList(map.alerts.data, ["alerts", "items", "data"]).map(normalizeAlert);
  const events = unwrapList(map.events.data, ["events", "items", "data"]).map(normalizeEvent);

  const whoami = normalizeWhoami(map.whoami.data);
  // Only a whoami that actually ANSWERED may change what the console believes
  // about this operator's authority. A failed read normalises to the empty
  // record, whose canRespond is null — publishing that would read as "the
  // server did not say", i.e. permitted, and one flaky poll would re-arm every
  // containment control for a read-only account.
  recordResponseAuthority(map.whoami.ok ? whoami.canRespond : undefined);

  // THE OPERATOR SWITCHED CUSTOMERS WHILE THIS POLL WAS IN FLIGHT.
  //
  // These rows are the PREVIOUS customer's, and the caller merges what it is
  // given into the buffer the newly selected customer is filling — so handing
  // them over would put one customer's alerts, events and decisions on another
  // customer's dashboard, where they can be selected and contained. The feeds
  // are dropped and the identity kept: an empty poll is deliberately not
  // authoritative in mergeSocSnapshot, so nothing already on screen is evicted
  // either. The refresh the switch triggers is already on its way.
  if (selectedTenantNow() !== scopedTo) {
    return {
      snapshot: scopeSnapshotToTenant(
        { ...EMPTY_SOC_SNAPSHOT, whoami, version: normalizeVersion(map.version.data) },
        selectedTenantNow()
      ),
      truncated: { alerts: false, events: false },
      // No errors and no statuses: nothing failed. Reporting these reads as
      // failures would light the notices strip over a customer switch.
      errors: {},
      statuses: {}
    };
  }

  return {
    snapshot: {
      whoami: stampViewingTenant(whoami, scopedTo),
      version: normalizeVersion(map.version.data),
      alerts: alerts.slice(0, MAX_BUFFERED_ALERTS),
      events: events.slice(0, MAX_BUFFERED_EVENTS),
      decisions: unwrapList(map.decisions.data, ["decisions", "items", "data"]).map(normalizeDecision).slice(0, MAX_BUFFERED_DECISIONS),
      policies: unwrapList(map.policies.data, ["policies", "items", "data"]).map(normalizePolicy),
      policyStats: unwrapList(map.policyStats.data, ["stats", "policies", "items", "data"]).map(normalizePolicyStat),
      attacks: unwrapList(map.attacks.data, ["attacks", "items", "data"]).map(normalizeAttack),
      honeypots: unwrapList(map.honeypots.data, ["honeypots", "files", "items", "data"]).map(normalizeHoneypot),
      health: normalizeHealth(map.health.data)
    },
    // A feed that came back exactly full is a feed the server had more of. The
    // dashboard pairs this with the oldest record it holds to decide whether
    // the selected range actually fits in the buffer.
    truncated: {
      alerts: alerts.length >= MAX_BUFFERED_ALERTS,
      events: events.length >= MAX_BUFFERED_EVENTS
    },
    errors,
    statuses
  };
}

/* ------------------------------------------------- server-computed stats */

/** Severity counts keyed by severity name; every key is always present. */
export type SeverityCounts = Record<Severity, number>;

export interface AlertStatsBucket {
  at: string;
  counts: SeverityCounts;
  total: number;
}

/**
 * Server-computed counts for a window.
 *
 * The console cannot derive these itself for any range longer than its record
 * buffer spans (~20 minutes on a busy tenant), and the "vs prior" delta needs a
 * preceding window that was never in the buffer at all. Both are computed where
 * the rows are and shipped as counts.
 */
export interface AlertStats {
  from: string;
  to: string;
  counts: SeverityCounts;
  previous: SeverityCounts;
  total: number;
  buckets: AlertStatsBucket[];
  /** The window held more alerts than the server would scan; counts are a floor. */
  truncated?: boolean;
}

function normalizeCounts(value: unknown): SeverityCounts {
  const record = asRecord(value);
  const out: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const key of Object.keys(out) as Severity[]) {
    out[key] = asNumber(record[key], 0);
  }
  return out;
}

/**
 * Fetch server-computed stats for a window.
 *
 * Returns null when the server does not provide the endpoint (an older build,
 * or a store backend that cannot range-scan). The caller falls back to
 * computing from the buffer, which is correct for short windows and is what the
 * console did everywhere before this existed.
 */
/**
 * Server-computed enforcement-decision counts for a window.
 *
 * The console used to count rows in a buffer capped at MAX_BUFFERED_DECISIONS
 * (200), so any window those rows did not span reported exactly 200 — a fetch
 * limit rendered as a measurement, on the executive band. Counts belong where
 * the rows are, for the same reason AlertStats exists.
 */
export interface DecisionStats {
  from: string;
  to: string;
  total: number;
  previous: number;
  actions: Record<string, number>;
  dryRun: number;
  /**
   * The window held more decisions than the server's scan bound, so total is a
   * floor. Stated rather than hidden: moving an unmarked under-count from the
   * browser to the server would not fix this tile, it would just relocate the
   * lie.
   */
  truncated: boolean;
}

/**
 * Returns null when the server has no /api/decision-stats — an older engine or
 * a control plane that has not grown the endpoint yet. The caller must treat
 * null as UNKNOWN and fall back to the buffered count WITH its floor
 * disclosure, never as zero.
 */
export async function fetchDecisionStats(
  windowMin: number,
  signal?: AbortSignal
): Promise<DecisionStats | null> {
  const result = await socApiGet<unknown>(`/api/decision-stats?window_min=${windowMin}`, null, signal);
  if (!result.ok || !result.data) return null;
  const record = asRecord(result.data);
  const actions: Record<string, number> = {};
  for (const [key, value] of Object.entries(asRecord(record.actions))) {
    actions[key] = asNumber(value, 0);
  }
  return {
    from: asOptionalString(record.from) || "",
    to: asOptionalString(record.to) || "",
    total: asNumber(record.total, 0),
    previous: asNumber(record.previous, 0),
    actions,
    dryRun: asNumber(record.dry_run, 0),
    truncated: asOptionalBoolean(record.truncated) ?? false
  };
}

export async function fetchAlertStats(
  windowMin: number,
  buckets: number,
  signal?: AbortSignal
): Promise<AlertStats | null> {
  const result = await socApiGet<unknown>(
    `/api/alert-stats?window_min=${windowMin}&buckets=${buckets}`,
    null,
    signal
  );
  if (!result.ok || !result.data) return null;
  const record = asRecord(result.data);
  const rawBuckets = unwrapList(record.buckets, ["buckets", "items"]);
  return {
    from: asOptionalString(record.from) || "",
    to: asOptionalString(record.to) || "",
    counts: normalizeCounts(record.counts),
    previous: normalizeCounts(record.previous),
    total: asNumber(record.total, 0),
    truncated: asOptionalBoolean(record.truncated) ?? false,
    buckets: rawBuckets.map((item) => {
      const b = asRecord(item);
      return {
        at: asOptionalString(b.at) || "",
        counts: normalizeCounts(b.counts),
        total: asNumber(b.total, 0)
      };
    })
  };
}

export async function fetchProcessDetail(execId: string, signal?: AbortSignal): Promise<SocReadResult<SocProcessDetail>> {
  const empty: SocProcessDetail = { execId, chain: [], events: [] };
  const result = await socApiGet<unknown>(`/api/process/${encodeURIComponent(execId)}`, empty, signal);
  if (!result.ok) {
    return { ...result, data: empty };
  }
  return { ...result, data: normalizeProcessDetail(execId, result.data) };
}

// No standalone policy-stats fetch. It existed for one caller — the kprobe
// board's fast self-poll, which wanted per-probe rate movement sooner than the
// 30s shared snapshot could show it. That board was replaced by
// SensorHealthBody, which asks a different question (is detection running, and
// is evidence being lost) and answers it from the snapshot's `policyStats`
// filled by fetchSocSnapshot above. Nothing else called the export, so it is
// gone rather than left advertising a cadence no panel uses.

/* --------------------------------------------------------------------- Fleet */

export interface FleetProbeResult {
  url: string;
  reachable: boolean;
  status?: number;
  rtt_ms?: number;
  error?: string;
}

// Probes run on the backend, not in the browser. A cross-origin probe from the
// console is blocked by mixed content, missing CORS headers and SameSite=Lax
// cookies all at once, which renders healthy peers as DOWN. The server has
// none of those constraints. See internal/fleetprobe.
export async function probeFleetHosts(urls: string[], signal?: AbortSignal): Promise<FleetProbeResult[]> {
  if (urls.length === 0) return [];
  const body = await postJSON<{ hosts?: FleetProbeResult[] }>("/api/fleet/probe", { urls }, { signal });
  return body.hosts ?? [];
}

export function runSocAttack(id: string): Promise<unknown> {
  const form = new URLSearchParams();
  form.set("id", id);
  // Scoped by the funnel like every other write: the lab simulator injects
  // telemetry into a tenant, and firing it into the operator's default customer
  // while the screen shows another one is the same aiming defect as a
  // misdirected containment, with the evidence landing in the wrong customer's
  // timeline.
  return postForm("/api/run-attack", form);
}

export function jailSocAlert({
  alert,
  action,
  reason,
  descendants,
  revertAfterSeconds
}: {
  alert: SocAlert;
  action: "throttle" | "tarpit" | "quarantine" | "sever";
  reason: string;
  descendants: boolean;
  revertAfterSeconds?: number;
}): Promise<unknown> {
  // exec_id FIRST. It is the only identifier an alert reliably carries, and
  // omitting it broke containment from an alert on BOTH deployments.
  //
  // A live alert is {description, event_ids, exec_id, id, score, severity,
  // timestamp, title} — no pid and no binary. So `alert.pid` was always
  // undefined (pids: []) and `alert.process` was the BASE64 EXEC_ID, because
  // normalizeAlert falls back `process = … || execId`. The request was
  // therefore {pids: [], binary: "aXAtMTcyLTMx…"}: the control plane does not
  // decode `binary` at all, and the engine matches it against p.Exe/p.Comm
  // where a base64 string matches nothing. Both answered 400, on the primary
  // triage-to-contain path of the product.
  //
  // Both backends already prefer exec_id when resolving a target, so sending it
  // fixes both at once. pid and binary stay as corroborating hints for the
  // engine's process-table match when the drill panel has resolved them.
  // THE REQUEST, NOT ONLY THE BUTTON. Every containment control is rendered by
  // a component that reads useResponseAuthority, and every one of those is a
  // separate chance to forget. This is the single point every jail passes
  // through, so the rule that nothing fires while the answer is in flight — or
  // after the server has refused — is enforced where it cannot be bypassed by a
  // surface that gated on the wrong flag.
  const withheld = responseWithheldReason();
  if (withheld) return Promise.reject(new Error(withheld));
  // THE CUSTOMER THIS CONTAINMENT IS AIMED AT is named on the request by the
  // funnel (lib/api.ts), from the same selection the reads that drew this alert
  // carried. The control plane reads ?tenant= on writes exactly as it does on
  // reads (authorizeRespondAs) and resolves a tenant-less write to the
  // operator's own default, so a provider console that re-scoped its panels but
  // sent this unscoped would kill a process for a customer nobody was looking
  // at.
  return postJSON("/api/choke/jail", {
    exec_id: alert.execId,
    pids: alert.pid ? [alert.pid] : [],
    binary: alert.pid || !alert.process || alert.process === alert.execId ? undefined : alert.process,
    descendants,
    action,
    reason,
    revert_after_seconds: revertAfterSeconds || 0
  });
}

export function normalizeAlert(value: unknown, index = 0): SocAlert {
  const record = asRecord(value);
  const execId = asOptionalString(pick(record, "exec_id", "execId", "ExecID", "execID", "id", "ID"));
  const id =
    asOptionalString(pick(record, "alert_id", "alertId", "id", "ID")) ||
    execId ||
    `alert-${index}`;
  const severity = normalizeSeverity(pick(record, "severity", "Severity", "level", "Level"));
  const score = asNumber(pick(record, "score", "Score", "risk", "Risk"), severityDefaultScore(severity));
  const policyName = asOptionalString(pick(record, "policy_name", "PolicyName", "policy", "Policy"));
  const process =
    asOptionalString(pick(record, "process", "Process", "binary", "Binary", "image", "Image", "comm", "Comm")) ||
    execId;
  const title =
    asOptionalString(pick(record, "title", "Title", "message", "Message", "summary", "Summary")) ||
    policyName ||
    process ||
    "Security alert";
  const description =
    asOptionalString(pick(record, "description", "Description", "details", "Details", "args", "Args")) ||
    "No description supplied by the API.";

  return {
    id,
    title,
    description,
    severity,
    score,
    timestamp: normalizeTimestamp(pick(record, "timestamp", "Timestamp", "time", "Time", "created_at", "CreatedAt")),
    policyName,
    execId,
    pid: asOptionalNumber(pick(record, "pid", "PID")),
    process,
    args: asOptionalString(pick(record, "args", "Args", "arguments", "Arguments")),
    mitreId: asOptionalString(pick(record, "mitre_id", "mitreId", "MITRE", "technique", "Technique")),
    tactic: asOptionalString(pick(record, "tactic", "Tactic")),
    agent: asOptionalString(pick(record, "agent", "Agent", "agent_id", "agentId", "host", "Host")),
    raw: value
  };
}

export function normalizeEvent(value: unknown, index = 0): SocEvent {
  const record = asRecord(value);
  const execId = asOptionalString(pick(record, "exec_id", "execId", "ExecID", "execID"));
  const pid = asOptionalNumber(pick(record, "pid", "PID"));
  const eventType =
    asOptionalString(pick(record, "event_type", "eventType", "EventType", "type", "Type")) || "event";
  const process = asOptionalString(pick(record, "process", "Process", "binary", "Binary", "image", "Image", "comm", "Comm"));
  const timestamp = normalizeTimestamp(pick(record, "timestamp", "Timestamp", "time", "Time"));

  return {
    id: asOptionalString(pick(record, "id", "ID", "event_id", "eventId")) || `${eventType}-${timestamp}-${index}`,
    eventType,
    timestamp,
    process,
    args: asOptionalString(pick(record, "args", "Args", "arguments", "Arguments")),
    execId,
    pid,
    // Dropped here until 2026-08-21, which quietly cost the single-tenant
    // correlation graph every one of its lineage edges: the engine sends
    // parent_pid on every exec, the normaliser discarded it, and the graph was
    // left with only the chain embedded in an alert title.
    parentPid: asOptionalNumber(pick(record, "parent_pid", "parentPid", "ParentPID", "ppid", "PPID")),
    policyName: asOptionalString(pick(record, "policy_name", "PolicyName", "policy", "Policy")),
    severity: normalizeOptionalSeverity(pick(record, "severity", "Severity", "level", "Level")),
    path: asOptionalString(pick(record, "path", "Path", "file", "File", "filename", "Filename")),
    remoteIp: asOptionalString(pick(record, "remote_ip", "remoteIp", "RemoteIP", "source_ip", "SourceIP")),
    destIp: asOptionalString(pick(record, "dest_ip", "destIp", "DestIP", "destination_ip", "DestinationIP")),
    destPort: asOptionalNumber(pick(record, "dest_port", "destPort", "DestPort", "port", "Port")),
    agent: asOptionalString(pick(record, "agent", "Agent", "agent_id", "agentId", "host", "Host")),
    proto: asOptionalString(pick(record, "proto", "Proto", "protocol", "Protocol")),
    raw: value
  };
}

function normalizeDecision(value: unknown, index: number): SocDecision {
  const record = asRecord(value);
  const timestamp = normalizeTimestamp(pick(record, "timestamp", "Timestamp", "time", "Time"));
  return {
    id: asOptionalString(pick(record, "id", "ID", "decision_id", "DecisionID")) || `decision-${timestamp}-${index}`,
    action: asOptionalString(pick(record, "action", "Action")) || "observe",
    state: asOptionalString(pick(record, "state", "State")),
    target: asOptionalString(pick(record, "target", "Target", "exec_id", "ExecID", "binary", "Binary")),
    reason: asOptionalString(pick(record, "reason", "Reason")),
    timestamp,
    ok: asOptionalBoolean(pick(record, "ok", "OK", "success", "Success")),
    outcome: asOptionalString(pick(record, "outcome", "Outcome"))
  };
}

/**
 * What actually happened to a decision, as text an operator can rely on.
 *
 * Preference order matters. An explicit boolean wins if a backend ever sends
 * one; otherwise the engine's own `outcome` string is the record of truth; and
 * when neither exists the answer is "unknown" — never "ok". Exports used to
 * synthesise `ok: d.ok !== false`, and since no backend sends `ok`, every row
 * exported as successful, including ones whose outcome literally began
 * "skipped:".
 */
export function decisionOutcome(d: { ok?: boolean; outcome?: string }): string {
  if (typeof d.ok === "boolean") return d.ok ? "ok" : "failed";
  const text = (d.outcome || "").trim();
  return text || "unknown";
}

/**
 * WHETHER THIS PRINCIPAL MAY RESPOND — the one place the console decides it.
 *
 * `true`  — the server said yes; behave exactly as before.
 * `false` — the server said no. Every containment and write control is
 *           disabled and says why, in the language of permission. It is not an
 *           outage and it is not a missing feature: the deployment can do this,
 *           this account may not ask for it.
 * `null`  — the server ANSWERED WITHOUT the field. The single-tenant engine
 *           publishes no `can_respond` because it has no concept of an
 *           operator who may not contain, so that absence must read as
 *           PERMITTED. Treating it as denial would take a working console's
 *           controls away.
 *
 * "loading" — NOBODY HAS ANSWERED YET, and it is a fourth state rather than a
 *           shade of `null` because collapsing the two is what armed every
 *           containment surface on first paint. The module state starts here,
 *           before the first whoami has been read, and a read-only account's
 *           console painted a live, enabled kill-switch for as long as that
 *           first poll took. Loading is not permission: while the answer is in
 *           flight nothing may be armed, and the surface says it is checking
 *           rather than claiming the account is read-only — which would be its
 *           own lie for the operator who turns out to be a responder.
 *
 * It lives here, beside the normaliser that reads the field off the wire,
 * because three surfaces re-deriving "may this operator respond?" is how the
 * fourth copy drifts and re-arms a control the server refuses.
 */
export type ResponseAuthority = boolean | null;

/**
 * What the console currently KNOWS, which is one more thing than what the
 * server can say: `ResponseAuthority` plus "the question is still open".
 * Only `recordResponseAuthority` ever leaves the loading state, and only a
 * whoami that actually answered may call it.
 */
export type ResponseAuthorityState = ResponseAuthority | "loading";

export type SocWhoamiWithAuthority = SocWhoami & { canRespond: ResponseAuthority } & SocIdentity;

/** Shown wherever containment is withheld because of who is asking. */
export const READ_ONLY_ACCOUNT_REASON =
  "Your account is read-only, so containment is not available to you. Ask an administrator for responder access.";

/**
 * Shown wherever containment is withheld because the answer has not arrived.
 * Deliberately NOT the read-only sentence: telling a responder their account
 * is read-only for the first second of every session is a different false
 * statement, and the one they would report as a bug.
 */
export const AUTHORITY_PENDING_REASON =
  "Checking what this account may do — containment stays disabled until the server answers.";

let responseAuthority: ResponseAuthorityState = "loading";
const responseAuthorityListeners = new Set<() => void>();

export function responseAuthorityNow(): ResponseAuthorityState {
  return responseAuthority;
}

/**
 * Whether a containment request may be SENT at all, independent of which
 * button was rendered, and the sentence to report when it may not.
 *
 * useResponseAuthority (below) is a RENDERING decision, and every rendering
 * decision lives in a component this module does not own. This is the one place
 * every containment request in this feature passes through, so it is where
 * "nothing fires while the answer is in flight" can be made true of the request
 * rather than only of the button that was drawn.
 */
function responseWithheldReason(): string | null {
  if (responseAuthority === "loading") return AUTHORITY_PENDING_REASON;
  if (responseAuthority === false) return READ_ONLY_ACCOUNT_REASON;
  return null;
}

/**
 * Record what whoami just said about this principal.
 *
 * `undefined` means whoami did not answer this poll — a network blip, a 503,
 * an aborted refresh. That must NOT be confused with a server that answered
 * without the field: re-arming the kill-switch for a known read-only operator
 * because one poll failed is precisely the failure this whole file is fixing,
 * so a non-answer leaves the last real answer standing — and when there has
 * never been one, leaves the state at "loading", which withholds. A console
 * whose whoami never succeeds does not know what this account may do, and the
 * safe reading of not knowing is not to arm anything.
 */
export function recordResponseAuthority(next: ResponseAuthority | undefined): void {
  if (next === undefined || next === responseAuthority) return;
  responseAuthority = next;
  for (const listener of responseAuthorityListeners) listener();
}

function subscribeResponseAuthority(listener: () => void): () => void {
  responseAuthorityListeners.add(listener);
  return () => responseAuthorityListeners.delete(listener);
}

/**
 * What a component needs to render the gate: whether to disable, and the
 * sentence to show when it does.
 *
 * TWO withheld flags rather than one, because there are two different reasons
 * to withhold a control and they must not be told to the operator
 * interchangeably:
 *
 * `withheld`       — the one flag a control's `disabled` should read. True while
 *                    the answer is in flight AND when the server refused.
 * `withheldReason` — the sentence that goes with whichever of the two it is.
 * `readOnlyAccount`— strictly "the server said no". Unchanged, and deliberately
 *                    NOT true during loading: every surface that renders the
 *                    words "Read-only account" keys off this, and printing that
 *                    over a responder's session for the first second is a lie of
 *                    its own.
 * `reason`         — the read-only sentence, or null. Unchanged.
 *
 * `reason` stays null when nothing is withheld so a surface cannot accidentally
 * print a denial it is not applying.
 */
export function useResponseAuthority(): {
  canRespond: ResponseAuthorityState;
  readOnlyAccount: boolean;
  pending: boolean;
  withheld: boolean;
  reason: string | null;
  withheldReason: string | null;
} {
  const canRespond = useSyncExternalStore(subscribeResponseAuthority, responseAuthorityNow, responseAuthorityNow);
  const readOnlyAccount = canRespond === false;
  const pending = canRespond === "loading";
  return {
    canRespond,
    readOnlyAccount,
    pending,
    withheld: pending || readOnlyAccount,
    reason: readOnlyAccount ? READ_ONLY_ACCOUNT_REASON : null,
    withheldReason: readOnlyAccount ? READ_ONLY_ACCOUNT_REASON : pending ? AUTHORITY_PENDING_REASON : null
  };
}

/**
 * WHO THE OPERATOR IS TO THE ESTATE, as distinct from which host answered.
 *
 * `crossTenant` — this principal reaches customers by naming them rather than
 *   by belonging to one. Their `tenants` list is empty BY DESIGN (the control
 *   plane refuses to enumerate the provider's customer roster over whoami), so
 *   the console cannot and must not derive the estate identity from element 0
 *   of it — which is exactly what it did, and is why a provider's console
 *   displayed one customer's name as the whole book of business.
 * `viewingTenant` — the single tenant whose rows are ON SCREEN. Every number on
 *   the dashboard is that one customer's. It is not a claim about reach; it is
 *   the caption the screen was missing. It starts as the tenant the SERVER
 *   resolves this session's tenant-less reads to, and becomes the customer the
 *   operator switched to — stamped by fetchSocSnapshot from the same selection
 *   the request carried, so the caption and the rows underneath it cannot
 *   describe different customers.
 * `serverTenant` — what the server itself resolves a TENANT-LESS request to,
 *   kept unmodified beside it. It is not the caption for the dashboard: it is
 *   how the console knows which customer an unscoped request would reach, and
 *   so which customer a surface that does not go through the scoped funnel is
 *   really answering about. The assistant is that surface — its client fetches
 *   for itself, and the control plane's tool loop reads with the session cookie
 *   alone — so SocRoute captions its scope chip with this rather than with the
 *   selection. Everything else on the route, the SSE tail included, now travels
 *   through the funnel and is the selected customer's.
 */
export interface SocIdentity {
  crossTenant: boolean;
  viewingTenant?: string;
  serverTenant?: string;
}

/**
 * Read the identity fields back off a whoami that has been through the
 * normaliser. `SocSnapshot["whoami"]` is typed as the narrower `SocWhoami`, so
 * the fields are present at runtime but not in that type; this is the one
 * place that reconciles the two, rather than a cast at every call site.
 *
 * Defensive rather than trusting: a snapshot built from the empty whoami (no
 * server has answered) has neither field, and must read as "tenant-bound,
 * nothing to caption" — never as a cross-tenant session, which would put a
 * provider banner over a single-tenant engine's console.
 */
export function socIdentityOf(whoami: SocWhoami | undefined | null): SocIdentity {
  const record = whoami as (SocWhoami & Partial<SocIdentity>) | undefined | null;
  return {
    crossTenant: record?.crossTenant === true,
    viewingTenant: record?.viewingTenant || undefined,
    serverTenant: record?.serverTenant || undefined
  };
}

/* ------------------------------------------- the customer this console shows */

/** One customer, as the switcher needs them (GET /api/tenants). */
export interface TenantRosterEntry {
  tenantId: string;
  displayName?: string;
  status?: string;
  /** Agents enrolled, and how many are reporting inside the freshness window. */
  agents: number;
  agentsFresh: number;
}

export interface TenantRoster {
  /** Customers this operator may switch to. */
  offered: TenantRosterEntry[];
  /**
   * Whether the endpoint ANSWERED. A tenant-bound account is refused with 404
   * — the same refusal an account gets from a server too old to serve the
   * roster at all — so this is "we were told", never "there are none".
   */
  answered: boolean;
  /**
   * Which roster the server read: the enrolled-customer table, or the
   * heartbeat registry, which cannot see a customer whose fleet is offline.
   * Shown to the operator, because a switcher silently missing a quiet
   * customer is worse than one that explains itself.
   */
  source?: string;
}

const NO_ROSTER: TenantRoster = { offered: [], answered: false };

/**
 * Read the provider's customer roster FOR THE BOOT DRIVER, and hand the answer
 * on to the switcher.
 *
 * This is app/tenantHydration.ts's entry point: it is how the shell confirms a
 * remembered customer before any scoped request is released. The dashboard's
 * switcher needs the very same list, and asking for it again is not merely a
 * wasted request — the control plane AUDITS every read of /api/tenants against
 * the account, so a second one puts a second row in a customer's access trail
 * for a page the operator opened once. The answer is therefore parked here for
 * useTenantRoster to take (takeHydratedRoster), which is why the caching lives
 * on this function rather than on the raw read below: only the driver's read
 * feeds it, so the hook can never be served an answer it fetched itself.
 *
 * A roster that did not answer is NOT parked. It is no evidence either way
 * (see adoptPersistedTenant), so the switcher is left free to ask again rather
 * than inheriting a transient failure as "this account reaches no customers"
 * for the life of the page.
 *
 * A 404 is the documented refusal for an account without a cross-tenant role
 * (the control plane refuses with 404 rather than 403 so the refusal cannot
 * confirm that a roster exists). It is a normal answer here, not an outage:
 * the caller renders no switcher and the dashboard is untouched.
 */
export async function fetchTenantRoster(signal?: AbortSignal): Promise<TenantRoster> {
  const roster = await readTenantRoster(signal);
  hydratedRoster = roster.answered ? roster : null;
  return roster;
}

/** The driver's answer, waiting for the switcher to take it. */
let hydratedRoster: TenantRoster | null = null;

/**
 * The roster the boot driver has already been given, taken ONCE.
 *
 * Cleared as it is handed over so that it can only ever stand in for the one
 * mount that follows the boot read. A later reader — a remount, a second
 * component — gets nothing and asks the server, because by then the parked
 * list is a stale claim about which customers this account reaches.
 */
function takeHydratedRoster(): TenantRoster | null {
  const roster = hydratedRoster;
  hydratedRoster = null;
  return roster;
}

/** The raw read. Everything that caches or adopts is built on top of it. */
async function readTenantRoster(signal?: AbortSignal): Promise<TenantRoster> {
  const result = await socApiGet<unknown>("/api/tenants", null, signal);
  if (!result.ok || !result.data) return NO_ROSTER;
  const record = asRecord(result.data);
  const offered = unwrapList(result.data, ["tenants", "items", "data"])
    .map((value) => {
      const row = asRecord(value);
      return {
        tenantId: asOptionalString(pick(row, "tenant_id", "tenantId", "tenant", "id")) || "",
        displayName: asOptionalString(pick(row, "display_name", "displayName", "name")),
        status: asOptionalString(pick(row, "status", "Status")),
        agents: asNumber(pick(row, "agents", "Agents"), 0),
        agentsFresh: asNumber(pick(row, "agents_fresh", "agentsFresh"), 0)
      };
    })
    // A row with no tenant id cannot be switched to, and rendering it would put
    // a blank, selectable customer in the list.
    .filter((entry) => entry.tenantId);
  return { offered, answered: true, source: asOptionalString(record.source) };
}

/**
 * The customer list the switcher offers: read at most ONCE per page load, and
 * for a cross-tenant operator only.
 *
 * `enabled` is whoami's `cross_tenant`. A tenant-bound operator holds exactly
 * one tenant, so asking would be noise on every console in the estate — and
 * the endpoint refuses them anyway, which would put a 404 in the network log
 * of a console that is working perfectly.
 */
export function useTenantRoster(enabled: boolean): TenantRoster & { loading: boolean } {
  const [roster, setRoster] = useState<TenantRoster>(NO_ROSTER);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    // THE BOOT DRIVER'S ANSWER, IF THERE IS ONE. A console opened with a
    // remembered customer has just read this exact list to confirm it
    // (app/tenantHydration.ts), and every read of /api/tenants is audited per
    // tenant, so asking again writes a duplicate row into a customer's access
    // trail for one page load. Taking it also means adoptPersistedTenant has
    // already run against it — the driver adopts as part of the same answer —
    // so it is not re-run here.
    const parked = takeHydratedRoster();
    if (parked) {
      setRoster(parked);
      return;
    }
    let live = true;
    setLoading(true);
    // No abort signal: the request is worth finishing even if this mount does
    // not survive it, and `live` already stops a late answer touching state.
    void readTenantRoster().then((result) => {
      if (!live) return;
      setLoading(false);
      setRoster(result);
      // The roster is the only evidence that a persisted choice is still
      // reachable, so adopting it is part of the same answer.
      adoptPersistedTenant(result);
    });
    return () => {
      live = false;
    };
  }, [enabled]);
  return { ...roster, loading };
}

/**
 * The snapshot to hold while a newly selected customer's data is loading.
 *
 * EVERY BUFFERED ROW GOES. The polled snapshot is merged into what is already
 * on screen (mergeSocSnapshot) so that a live frame arriving mid-request is not
 * erased — which means that without this, the customer being switched away
 * from would keep contributing alerts, events and decisions to the customer
 * being switched to. Those rows are not merely wrong on a tile: they are
 * clickable, and containment fired from one would be aimed by this console at
 * the customer now selected.
 *
 * The identity survives, because whoami describes the account and not the
 * customer, and dropping it would flash "localhost" over the top bar on every
 * switch. Its `viewingTenant` is stamped with the new selection so the banner,
 * the host pill and anything exported name the customer whose rows the console
 * is now holding — which, until the first response lands, is none.
 */
export function scopeSnapshotToTenant(snapshot: SocSnapshot, tenant: string | null): SocSnapshot {
  return {
    ...EMPTY_SOC_SNAPSHOT,
    whoami: stampViewingTenant(snapshot.whoami, tenant),
    version: snapshot.version
  };
}

/**
 * Say which customer a whoami document is captioning, when the console — not
 * the server — chose it.
 *
 * Written as a spread rather than a property literal because `viewingTenant`
 * lives on the normalised record and not on the narrower SocWhoami type that
 * SocSnapshot declares; see socIdentityOf, which reconciles the same two.
 */
function stampViewingTenant(whoami: SocWhoami, tenant: string | null): SocWhoami {
  if (!tenant) return whoami;
  const stamp: Partial<SocIdentity> = { viewingTenant: tenant };
  return { ...whoami, ...stamp };
}

function normalizeWhoami(value: unknown): SocWhoamiWithAuthority {
  const record = asRecord(value);
  const canRespondRaw = pick(record, "can_respond", "canRespond");
  return {
    user: asOptionalString(pick(record, "user", "username", "Username", "name", "Name")) || EMPTY_WHOAMI.user,
    host:
      asOptionalString(pick(record, "host", "hostname", "Hostname", "engine_host", "EngineHost")) ||
      EMPTY_WHOAMI.host,
    role: asOptionalString(pick(record, "role", "Role")),
    // Strictly === true. Absent, null, "" and 0 must all read as "this
    // deployment cannot push", because the plane that cannot is the one that
    // never sends the field.
    canPushPolicy: pick(record, "can_push_policy", "canPushPolicy") === true,
    // NOT strictly === true, and that asymmetry is the whole point. This field
    // is about WHO is asking, not about what the deployment can do: the
    // multi-tenant control plane publishes it from authz.CanRespond, the
    // single-tenant engine has no notion of a principal who may not respond and
    // sends nothing at all. Reading absence as `false` would strip the engine's
    // console of every containment control it legitimately owns, so absence
    // stays `null` — "the server did not say" — and only an explicit boolean
    // decides anything. Dropping the field entirely, which is what this
    // normaliser did until 2026-09-02, armed the whole kill-switch surface for
    // an account the control plane 404s: the operator learned they were
    // read-only by pressing sever on a live host and watching nothing happen.
    canRespond: typeof canRespondRaw === "boolean" ? canRespondRaw : null,
    // Taken from what the server SAYS, not inferred from the shape of another
    // field. The previous version keyed off whether "tenants" was an array,
    // which broke for a cross-tenant MSOC admin — they have no tenant list, so
    // the control plane's own console would have claimed single-host scope for
    // the one operator most likely to push to a fleet.
    //
    // Anything other than an explicit "fleet" is treated as "host": the
    // narrower promise is the safe default for an older server that says
    // nothing.
    policyScope: pick(record, "policy_scope", "policyScope") === "fleet" ? "fleet" : "host",
    // Strictly === true. A server that does not send the field is a
    // single-tenant engine or an older control plane, and neither has a
    // cross-tenant principal to describe — inventing one would caption a
    // console that has exactly one customer with "you are the provider".
    crossTenant: pick(record, "cross_tenant", "crossTenant") === true,
    // The tenant whose data is ON SCREEN. Carried through even for a
    // tenant-bound operator, where it simply equals their own tenant; the
    // surface only captions it when it would otherwise be unstated.
    //
    // This is what the SERVER resolves a tenant-less read to. When the operator
    // has switched customers, fetchSocSnapshot overwrites it with the customer
    // the request actually named — the normaliser is left describing the wire
    // document alone, so a test of it can never be passed by the selection.
    viewingTenant: asOptionalString(pick(record, "viewing_tenant", "viewingTenant")) || undefined,
    // The same value, never overwritten. Keeping the server's own answer is
    // what lets the route tell a scoped read from an unscoped connection.
    serverTenant: asOptionalString(pick(record, "viewing_tenant", "viewingTenant")) || undefined
  };
}

export function normalizeVersion(value: unknown): SocVersion {
  const record = asRecord(value);
  return {
    sha: asOptionalString(pick(record, "sha", "SHA", "version", "Version", "build", "Build")) || "",
    startedAt: asOptionalString(pick(record, "started_at", "startedAt", "StartTime", "start_time")),
    // Absent => false. A server that does not report the field is treated as a
    // production deployment, so the lab surfaces stay hidden rather than being
    // offered against endpoints that answer 404.
    labMode: asOptionalBoolean(pick(record, "lab_mode", "labMode", "LabMode")) ?? false
  };
}

export function normalizePolicy(value: unknown): SocPolicy {
  const record = asRecord(value);
  const rawSensors = unwrapList(pick(record, "sensors", "Sensors", "kprobes", "Kprobes"), ["items"]);
  return {
    name: asOptionalString(pick(record, "name", "Name", "policy_name", "PolicyName")) || "unnamed-policy",
    description: asOptionalString(pick(record, "description", "Description")),
    mitre: asOptionalString(pick(record, "mitre", "MITRE", "mitre_id", "MitreID")),
    yaml: asOptionalString(pick(record, "yaml", "YAML", "source", "Source")),
    // Where that body came from: "host" (read off the monitored machine, which
    // only the single-tenant engine can do) or "shipped" (the source the
    // control-plane build carries, for a policy running on a fleet it cannot
    // read kernels from). The console states which, rather than presenting
    // both as the same kind of fact.
    yamlSource: asOptionalString(pick(record, "yaml_source", "yamlSource")),
    sensors: rawSensors.map((item) => asOptionalString(item)).filter((item): item is string => Boolean(item)),
    // Real kernel state, from the heartbeat via /api/policies. Undefined on a
    // server that does not serve it; the card renders "unknown" rather than
    // asserting the policy is loaded.
    loadedAgents: asOptionalNumber(pick(record, "loaded_agents", "loadedAgents")),
    kernelMode: asOptionalString(pick(record, "kernel_mode", "kernelMode")),
    // Absent field => the server could not tell us. Present-and-zero => it
    // asked and the answer was none. Only the second is an alarm.
    kernelStateKnown: pick(record, "loaded_agents", "loadedAgents") !== undefined,
    expected: asOptionalBoolean(pick(record, "expected")) ?? false
  };
}

function normalizePolicyStat(value: unknown): SocPolicyStat {
  const record = asRecord(value);
  return {
    name: asOptionalString(pick(record, "name", "Name", "policy", "Policy")) || "policy",
    posts: asNumber(pick(record, "posts", "Posts", "npost", "NPost", "count", "Count"), 0),
    ratePerMin: asOptionalNumber(pick(record, "rate_per_min", "ratePerMin", "RatePerMin", "rate")),
    memoryBytes: asMemoryBytes(pick(record, "memory_bytes", "memoryBytes", "MemoryBytes", "kernel_memory", "KernelMemory", "memory")),
    status: asOptionalString(pick(record, "status", "Status", "state", "State"))
  };
}

function normalizeAttack(value: unknown): SocAttack {
  const record = asRecord(value);
  const name = asOptionalString(pick(record, "name", "Name", "title", "Title"));
  return {
    id: asOptionalString(pick(record, "id", "ID", "script", "Script")) || name || "attack",
    name: name || asOptionalString(pick(record, "id", "ID")) || "Attack",
    description: asOptionalString(pick(record, "description", "Description")),
    severity: normalizeOptionalSeverity(pick(record, "severity", "Severity"))
  };
}

function normalizeHoneypot(value: unknown): SocHoneypot {
  const record = asRecord(value);
  return {
    path: asOptionalString(pick(record, "path", "Path", "file", "File")) || "/decoy",
    description: asOptionalString(pick(record, "description", "Description")),
    hits: asNumber(pick(record, "hits", "Hits", "count", "Count"), 0),
    lastSeen: asOptionalString(pick(record, "last_seen", "lastSeen", "LastSeen")),
    bytes: asOptionalNumber(pick(record, "bytes", "Bytes"))
  };
}

function normalizeHealth(value: unknown): SocSystemHealth {
  const record = asRecord(value);
  return {
    status: asOptionalString(pick(record, "status", "Status", "state", "State")) || EMPTY_HEALTH.status,
    host: asOptionalString(pick(record, "host", "Host", "hostname", "Hostname")),
    tetragon: asOptionalString(pick(record, "tetragon", "Tetragon")),
    // The control plane reports the store as {ok, error}. It is the single
    // fault that takes every other read endpoint down at once, so the console
    // can name it instead of listing five anonymous HTTP 500s.
    storeOk: asOptionalBoolean(pick(asRecord(pick(record, "store", "Store")), "ok", "OK")),
    storeError: asOptionalString(pick(asRecord(pick(record, "store", "Store")), "error", "Error")),
    choke: asOptionalString(pick(record, "choke", "Choke")),
    kernel: asOptionalString(pick(record, "kernel", "Kernel")),
    uptime: asOptionalString(pick(record, "uptime", "Uptime")),
    details: record
  };
}

function normalizeProcessDetail(execId: string, value: unknown): SocProcessDetail {
  const record = asRecord(value);
  const chain = unwrapList(pick(record, "chain", "Chain", "lineage", "Lineage"), ["items"]).map((node) => {
    const n = asRecord(node);
    return {
      execId: asOptionalString(pick(n, "exec_id", "execId", "ExecID")),
      pid: asOptionalNumber(pick(n, "pid", "PID")),
      binary: asOptionalString(pick(n, "binary", "Binary", "process", "Process", "comm", "Comm")),
      args: asOptionalString(pick(n, "args", "Args")),
      timestamp: asOptionalString(pick(n, "timestamp", "Timestamp"))
    };
  });
  const events = unwrapList(pick(record, "events", "Events"), ["items"]).map(normalizeEvent);
  return {
    execId,
    chain,
    events,
    origin: asRecord(pick(record, "origin", "Origin"))
  };
}

function unwrapList(value: unknown, keys: string[]): unknown[] {
  if (Array.isArray(value)) return value;
  const record = asRecord(value);
  for (const key of keys) {
    const candidate = record[key];
    if (Array.isArray(candidate)) return candidate;
  }
  return [];
}

function asRecord(value: unknown): AnyRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as AnyRecord) : {};
}

function pick(record: AnyRecord, ...keys: string[]): unknown {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(record, key)) return record[key];
  }
  return undefined;
}

function asOptionalString(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
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

function asOptionalNumber(value: unknown): number | undefined {
  const parsed = asNumber(value, Number.NaN);
  return Number.isFinite(parsed) ? parsed : undefined;
}

// Tetragon reports a policy's BPF-map footprint as a formatted string ("4.37 MB",
// "512 KB"), not a raw byte count, so it is parsed here (a raw number is accepted
// too) into SocPolicyStat.memoryBytes. NOTE: the memory column that made this
// parse necessary belonged to the kprobe board, and no surface renders
// memoryBytes since SensorHealthBody replaced it — the normalisation is kept
// because the field is still declared on the type and the wire still sends it,
// not because anything shows it.
function asMemoryBytes(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string") return undefined;
  const match = /([\d.]+)\s*([KMGT]?)i?B/i.exec(value.trim());
  if (!match) return asOptionalNumber(value);
  const scale: Record<string, number> = { "": 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4 };
  return Number.parseFloat(match[1]) * (scale[match[2].toUpperCase()] ?? 1);
}

function asOptionalBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return undefined;
}

function normalizeSeverity(value: unknown): Severity {
  return normalizeOptionalSeverity(value) || "info";
}

function normalizeOptionalSeverity(value: unknown): Severity | undefined {
  const raw = asOptionalString(value)?.toLowerCase();
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low" || raw === "info") {
    return raw;
  }
  if (raw === "warn" || raw === "warning") return "medium";
  if (raw === "error" || raw === "danger") return "high";
  return undefined;
}

function severityDefaultScore(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 90;
    case "high":
      return 70;
    case "medium":
      return 40;
    case "low":
      return 15;
    case "info":
      return 5;
  }
}

function normalizeTimestamp(value: unknown): string {
  const raw = asOptionalString(value);
  if (!raw) return new Date().toISOString();
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return new Date().toISOString();
  return date.toISOString();
}

// ── Choke Gateway: live ladder state + enforcement ─────────────────────────
// These hit identical paths on BOTH deployments. The single-tenant engine
// enforces in-kernel locally; the multi-tenant control plane dispatches a
// fleet-signed command to the owning agent and waits for its ack.
//
// A tenant is named only when a provider operator has switched the console to
// one, and it is the funnel in lib/api.ts that names it. Without a selection
// the request goes as it always did: the engine has no tenants, and the control
// plane resolves the write to the operator's own default (authorizeRespondAs).

/** Where a process sits on the ladder, keyed by exec_id. */
export interface ChokeCircuit {
  execId: string;
  pid?: number;
  binary: string;
  state: string; // pristine | throttled | tarpit | quarantined | severed
  score: number;
  lastSeen?: string;
}

export async function fetchChokeCircuits(signal?: AbortSignal): Promise<ChokeCircuit[]> {
  const result = await socApiGet<unknown>("/api/choke/circuits", [], signal);
  if (!result.ok) return [];
  return unwrapList(result.data, ["circuits", "items", "data"]).map((value) => {
    const record = asRecord(value);
    return {
      execId: asOptionalString(pick(record, "exec_id", "execId", "ExecID")) || "",
      pid: asOptionalNumber(pick(record, "pid", "PID")),
      binary: asOptionalString(pick(record, "binary", "Binary", "exe", "comm")) || "",
      state: asOptionalString(pick(record, "state", "State")) || "pristine",
      score: asNumber(pick(record, "score", "Score"), 0),
      lastSeen: asOptionalString(pick(record, "last_seen", "lastSeen"))
    };
  }).filter((c) => c.execId);
}

/** The rungs an operator can move a process to. "pristine" releases (thaw). */
export type ChokeAction = "throttle" | "tarpit" | "quarantine" | "sever" | "pristine";

export interface ChokeActionResult {
  ok: boolean;
  detail: string;
}

/**
 * Apply an enforcement action to one process.
 *
 * "pristine" maps to the thaw endpoint — the ladder is monotonic, so returning
 * to pristine is a release, not a downward step. Everything else is a jail at
 * that tier. The reason is mandatory server-side for quarantine/sever; it is
 * sent for every action so the audit records intent uniformly.
 */
export async function applyChokeAction(
  action: ChokeAction,
  target: { execId: string; pid?: number; binary?: string },
  reason: string
): Promise<ChokeActionResult> {
  // Same gate as jailSocAlert, and for the same reason: the ladder is driven
  // from three different surfaces. Reported as a failed action rather than
  // thrown, because that is this function's contract — it never rejects.
  const withheld = responseWithheldReason();
  if (withheld) return { ok: false, detail: withheld };
  // Scoped by the funnel for the same reason jailSocAlert is: the ladder moves
  // a real process on a real host, and which customer's host that is comes from
  // the URL.
  const path = action === "pristine" ? "/api/choke/thaw" : "/api/choke/manual";
  const body =
    action === "pristine"
      ? { exec_id: target.execId, pid: target.pid, reason }
      : { exec_id: target.execId, pid: target.pid, binary: target.binary, action, reason };
  try {
    const data = await postJSON<unknown>(path, body);
    const record = asRecord(data);
    // The control plane answers {ok,detail} after waiting for the agent ack — a
    // dispatch that no agent picked up returns ok:false and must NOT read as
    // success. The engine answers with the decision it just applied.
    const ok = record.ok === undefined ? true : Boolean(record.ok);
    const detail =
      asOptionalString(pick(record, "detail", "Detail", "outcome", "Outcome", "error", "Error")) ||
      (ok ? `${action} applied` : `${action} was not applied`);
    return { ok, detail };
  } catch (error) {
    return { ok: false, detail: (error as Error).message || `${action} failed` };
  }
}
