import type {
  Alert,
  AuditState,
  ChokeState,
  Decision,
  DerivedFleet,
  DriftResult,
  FanoutEnvelope,
  FanoutHost,
  FanoutReport,
  FleetDevice,
  FleetKpis,
  FleetPeer,
  HostResult,
  KillState,
  Thresholds
} from "./types";

export const EMPTY_KPIS: FleetKpis = {
  total: 0,
  healthy: 0,
  enforcing: 0,
  killed: 0,
  killUnknown: 0,
  drift: 0,
  auditOk: 0,
  auditBroken: 0,
  auditUnsupported: 0,
  auditTotal: 0,
  tracked: 0,
  quarantined: 0,
  tarpit: 0,
  throttled: 0,
  deviceHosts: 0,
  devices: 0
};

export function majority<T>(values: T[]): T | null {
  const counts = new Map<T, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  let best: T | null = null;
  let bestCount = 0;
  for (const [value, count] of counts) {
    if (count > bestCount) {
      best = value;
      bestCount = count;
    }
  }
  return best;
}

export function thresholdKey(thresholds?: Thresholds | null): string {
  if (!thresholds) {
    return "?";
  }
  return [
    thresholds.throttle_at,
    thresholds.tarpit_at,
    thresholds.quarantine_at,
    thresholds.sever_at
  ].join("/");
}

export function validateThresholds(thresholds: Thresholds): string | null {
  const { throttle_at, tarpit_at, quarantine_at, sever_at } = thresholds;
  if ([throttle_at, tarpit_at, quarantine_at, sever_at].some((value) => !Number.isFinite(value))) {
    return "All four threshold values are required.";
  }
  if ([throttle_at, tarpit_at, quarantine_at, sever_at].some((value) => value <= 0)) {
    return "All thresholds must be greater than zero.";
  }
  if (!(throttle_at < tarpit_at && tarpit_at < quarantine_at && quarantine_at < sever_at)) {
    return "Thresholds must be strictly ascending: throttle < tarpit < quarantine < sever.";
  }
  return null;
}

/**
 * The kill-switch as the server actually reported it.
 *
 * Three outcomes, because there are three. `kill_switched: null` is what the
 * multi-tenant control plane sends for every host — no heartbeat field carries
 * the agent's switch — and `undefined` is a server that omitted the field
 * entirely. Neither is "off", and the console spent both of them as one:
 * `data.kill_switched ? "on" : "off"`.
 */
export function killStateOf(state?: ChokeState | null): KillState {
  if (typeof state?.kill_switched !== "boolean") {
    return "unknown";
  }
  return state.kill_switched ? "on" : "off";
}

/**
 * Which of the three audit outcomes a host is in.
 *
 * Shared by the reducer and the host table so they cannot disagree: the table
 * used to decide "broken" on `bad_at != null`, which quietly re-classified a
 * host reporting {ok:false} with no offending index — a BROKEN chain in the
 * KPIs — as one that maintains no chain at all.
 */
export function classifyAudit(audit?: AuditState | null): "ok" | "broken" | "unmaintained" {
  if (!audit || audit.supported === false) {
    return "unmaintained";
  }
  return audit.ok ? "ok" : "broken";
}

export function detectDrift(stateResults: Array<HostResult<ChokeState>>): DriftResult {
  const okRows = stateResults.filter((row) => row.ok && row.data);
  // EXCLUDED from the vote, not merely displayed differently. A host that did
  // not report its kill-switch cannot be evidence for what the fleet's
  // kill-switch majority is; counting it as "off" let a fleet that reported
  // nothing at all elect an "off" majority, against which a genuinely
  // kill-switched host then looked like the drifted one.
  const reportedKill = okRows
    .map((row) => killStateOf(row.data))
    .filter((value): value is "on" | "off" => value !== "unknown");
  return {
    mode: majority(okRows.map((row) => row.data?.mode ?? "?")),
    kill: majority(reportedKill),
    thresholds: majority(okRows.map((row) => thresholdKey(row.data?.thresholds)))
  };
}

export function deriveFleet(
  peers: FleetPeer[],
  stateResults: Array<HostResult<ChokeState>>,
  deviceResults: Array<HostResult<FleetDevice[]>> = []
): DerivedFleet {
  const byHost = new Map(stateResults.map((result) => [result.name, result]));
  const drift = detectDrift(stateResults);
  const kpis: FleetKpis = { ...EMPTY_KPIS, total: peers.length };
  const rows = peers.map((peer) => {
    const result = byHost.get(peer.name);
    const data = result?.data;
    const reachable = Boolean(result?.ok && data);
    const killState = reachable ? killStateOf(data) : "unknown";

    if (reachable && data) {
      kpis.healthy += 1;
      kpis.tracked += data.tracked ?? 0;
      if (data.mode === "enforcing") {
        kpis.enforcing += 1;
      }
      if (killState === "on") {
        kpis.killed += 1;
      } else if (killState === "unknown") {
        kpis.killUnknown += 1;
      }
      // Three outcomes, not two. A host that does not chain centrally, or
      // reports no audit block at all, is NOT a host with a broken chain —
      // counting it as one told an operator their tamper-evidence had failed.
      const auditClass = classifyAudit(data.audit);
      if (auditClass === "unmaintained") {
        kpis.auditUnsupported += 1;
      } else if (auditClass === "ok") {
        kpis.auditOk += 1;
      } else {
        kpis.auditBroken += 1;
      }
      if (typeof data.audit?.total === "number") {
        kpis.auditTotal += data.audit.total;
      }
      kpis.quarantined += data.counts?.quarantined ?? 0;
      kpis.tarpit += data.counts?.tarpit ?? 0;
      kpis.throttled += data.counts?.throttled ?? 0;
    }

    const driftMode = reachable && data?.mode !== drift.mode;
    // A host that did not report its kill-switch does not drift on it. It was
    // being compared as "off" against a majority it had itself voted "off"
    // into, so the field agreed with itself and quietly certified a fleet
    // nobody had measured.
    const driftKill = reachable && killState !== "unknown" && killState !== drift.kill;
    const driftThresholds = reachable && thresholdKey(data?.thresholds) !== drift.thresholds;
    if (driftMode || driftKill || driftThresholds) {
      kpis.drift += 1;
    }

    return {
      peer,
      result,
      reachable,
      killState,
      driftMode,
      driftKill,
      driftThresholds
    };
  });

  for (const result of deviceResults) {
    if (result.ok && Array.isArray(result.data)) {
      kpis.deviceHosts += 1;
      kpis.devices += result.data.length;
    }
  }

  const majorityThresholds = thresholdFromKey(drift.thresholds);
  return { rows, kpis, drift, majorityThresholds };
}

export function thresholdFromKey(key?: string | null): Thresholds | null {
  if (!key || key === "?") {
    return null;
  }
  const values = key.split("/").map((value) => Number(value));
  if (values.length !== 4 || values.some((value) => !Number.isFinite(value))) {
    return null;
  }
  return {
    throttle_at: values[0],
    tarpit_at: values[1],
    quarantine_at: values[2],
    sever_at: values[3]
  };
}

export function mergeHostPayloads<T extends { timestamp?: string }>(
  hostResults: Array<HostResult<T[]>>,
  limit: number
): Array<T & { _host: string }> {
  const merged: Array<T & { _host: string }> = [];
  for (const host of hostResults) {
    if (!host.ok || !Array.isArray(host.data)) {
      continue;
    }
    for (const item of host.data) {
      merged.push({ ...item, _host: host.name });
    }
  }
  return merged
    .sort((a, b) => (b.timestamp ?? "").localeCompare(a.timestamp ?? ""))
    .slice(0, limit);
}

export function formatTime(value?: string): string {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value.slice(11, 19) || value;
  }
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function actionClass(action?: string): string {
  const normalized = (action ?? "").toLowerCase();
  if (normalized.includes("sever")) return "fleet-action--sever";
  if (normalized.includes("quarantine")) return "fleet-action--quarantine";
  if (normalized.includes("tarpit")) return "fleet-action--tarpit";
  if (normalized.includes("throttle")) return "fleet-action--throttle";
  if (normalized.includes("allow")) return "fleet-action--allow";
  return "fleet-action--default";
}

export function severityTone(severity?: string): "danger" | "warn" | "info" | "muted" {
  const normalized = (severity ?? "info").toLowerCase();
  if (normalized.includes("crit")) return "danger";
  if (normalized.includes("high")) return "warn";
  if (normalized.includes("med")) return "info";
  return "muted";
}

/**
 * Reads a fan-out write's response into the coverage it actually claimed.
 *
 * Two servers answer these four routes with two shapes. The single-tenant
 * engine returns a per-peer `hosts` array; the multi-tenant control plane
 * historically returned only `{applied, total, detail}`. The console read
 * `result.hosts ?? []` off both, so every control-plane write — one that may
 * have reached every agent in the tenant — was summarised from an empty list
 * and rendered "0/0 hosts succeeded" under a green "applied" title.
 *
 * So: prefer the named list when there is one, fall back to the counts when
 * there is not, and keep nulls when the server reported neither. A response
 * that says nothing about coverage must stay distinguishable from one that says
 * it reached nobody, because only the second is a fact.
 */
export function readFanout(result: unknown): FanoutReport {
  const envelope = (typeof result === "object" && result !== null ? result : {}) as FanoutEnvelope;
  const detail = typeof envelope.detail === "string" ? envelope.detail.trim() : "";

  if (Array.isArray(envelope.hosts)) {
    // `ok` must be explicitly true. An entry the console cannot read is not a
    // host that took the write.
    const hosts: FanoutHost[] = envelope.hosts.map((entry) => {
      const host = (typeof entry === "object" && entry !== null ? entry : {}) as FanoutHost;
      return {
        name: typeof host.name === "string" && host.name ? host.name : "unnamed host",
        ok: host.ok === true,
        status: host.status,
        error: typeof host.error === "string" ? host.error : undefined
      };
    });
    return {
      hosts,
      applied: hosts.filter((host) => host.ok).length,
      total: hosts.length,
      detail
    };
  }

  return {
    hosts: [],
    applied: typeof envelope.applied === "number" ? envelope.applied : null,
    total: typeof envelope.total === "number" ? envelope.total : null,
    detail
  };
}

/**
 * Turns a fan-out report into what the operator is told.
 *
 * Only one branch here may be toned as success, and it requires the server to
 * have stated a non-zero coverage that was fully applied. The old rule was
 * `failed === 0`, which an EMPTY host list satisfies: a write that touched no
 * host at all raised the same green "applied" toast as one that touched every
 * host, and mid-incident that is the difference between an estate an operator
 * believes is contained and one that is not.
 */
export function summarizeFanout(label: string, report: FanoutReport): {
  ok: boolean;
  title: string;
  body: string;
} {
  const { hosts, applied, total, detail } = report;
  const trailer = detail ? ` ${detail}` : "";

  if (total === null) {
    return {
      ok: false,
      title: `${label}: coverage unknown`,
      body: `The server did not report which hosts this reached, so it cannot be confirmed applied.${trailer}`
    };
  }
  if (total === 0) {
    return {
      ok: false,
      title: `${label}: no hosts`,
      body: `This reached no hosts — 0/0 succeeded, so nothing on the estate changed.${trailer}`
    };
  }

  if (applied === null) {
    // The server named a target count and then said nothing about how many of
    // them took it. `applied ?? 0` turned that silence into "0/3 succeeded" —
    // a specific claim of total failure the server never made, and the same
    // class of lie as the 0/0-as-success this function was written to kill.
    // Unknown reads as unknown.
    return {
      ok: false,
      title: `${label}: coverage unknown`,
      body: `The server said this targeted ${total} host${total === 1 ? "" : "s"} but did not say how many took it, so it cannot be confirmed applied.${trailer}`
    };
  }

  const success = applied;
  const failures = hosts
    .filter((host) => !host.ok)
    .map((host) => `${host.name} (${host.error || host.status || "error"})`)
    .join(", ");

  if (failures === "" && success >= total) {
    return {
      ok: true,
      title: `${label} applied`,
      body: `${success}/${total} hosts succeeded.${trailer}`
    };
  }
  return {
    ok: false,
    title: `${label}: partial`,
    body: failures
      ? `${success}/${total} succeeded; failures: ${failures}${trailer}`
      : `${success}/${total} succeeded; the server did not name the hosts that failed.${trailer}`
  };
}

/**
 * How long a threshold write LASTS, read off the one field that says so.
 *
 * The multi-tenant control plane stores a ladder as the tenant's policy only
 * when the write named no targets, and reports which it did in
 * `stored_for_tenant` (controlplane/choke.go). That distinction is not
 * cosmetic: `reconcileLadders` re-pushes the tenant policy to every agent whose
 * reported ladder differs from it, every two minutes. So a TARGETED ladder is
 * applied honestly, acked honestly — and then, on any tenant that has a stored
 * ladder, reconciled away within one pass of that timer. The
 * reconciler's own comment describes the operator who "watches it revert within
 * two minutes with nothing anywhere saying why"; nothing in the console read
 * the field, so the toast said "applied" and stopped there.
 *
 * Strictly boolean, like every other capability field the console reads: the
 * single-tenant engine has no tenant policy and no reconciler and sends no such
 * field, and inventing a durability caveat for it would be as untrue as
 * omitting one here.
 */
export interface LadderPersistence {
  /** The server said this ladder is not the tenant's and will be reconciled back. */
  temporary: boolean;
  /** What the operator is told about durability; "" when the server said nothing. */
  note: string;
}

export function readLadderPersistence(result: unknown, targets: string[] | null): LadderPersistence {
  const envelope = (typeof result === "object" && result !== null ? result : {}) as {
    stored_for_tenant?: unknown;
  };
  const stored = envelope.stored_for_tenant;
  if (typeof stored !== "boolean") {
    return { temporary: false, note: "" };
  }
  if (stored) {
    return {
      temporary: false,
      note: "Stored as this tenant's ladder, so an agent that enrols later inherits it."
    };
  }
  if (targets !== null) {
    const count = targets.length;
    // Conditional, because the server's answer is. `stored_for_tenant: false`
    // says this ladder is not the tenant's; it does not say whether the tenant
    // HAS one. reconcileLadders skips a tenant with no stored ladder
    // (ThresholdsFor errors and the deployed ladder stands), so promising a
    // revert outright would be a second untrue reading traded for the first.
    // What is certain — this is not the tenant's ladder, and any tenant ladder
    // will win — is stated as certain, and the timing is named because two
    // minutes is the reconciler's own cadence.
    return {
      temporary: true,
      note:
        `Applied to the ${count} selected host${count === 1 ? "" : "s"} only, and NOT stored as this tenant's ladder. ` +
        "If this tenant has a stored ladder, the control plane pushes it back over any host that differs, " +
        "so expect these hosts to revert within about two minutes. Apply to all hosts to change the ladder itself."
    };
  }
  // Untargeted and unstored: the live fleet did take it, and nothing will
  // revert it — there is no stored policy to reconcile against. The caveat is
  // about the NEXT agent, so it is stated without being toned as a failure.
  return {
    temporary: false,
    note:
      "Applied to the agents running now, but the server could not record it as the tenant's ladder: " +
      "an agent that enrols later starts on the ladder its deploy configured."
  };
}

/**
 * The ladder reading beside the threshold inputs, qualified by how many hosts
 * it was computed from.
 *
 * "Majority 5/10/20/40" over a single reporting host is a majority of one — a
 * comparative reading on a fleet with nothing to compare, which on a
 * single-agent tenant is the only reading there is. It says which it is.
 */
export function ladderReading(reportingHosts: number, majorityThresholds: Thresholds | null): string {
  if (reportingHosts === 0 || !majorityThresholds) {
    return "No host reported a ladder";
  }
  if (reportingHosts === 1) {
    return `One host reporting · ${thresholdKey(majorityThresholds)}`;
  }
  return `Majority of ${reportingHosts} · ${thresholdKey(majorityThresholds)}`;
}

export type MergedDecision = Decision & { _host: string };
export type MergedAlert = Alert & { _host: string };
