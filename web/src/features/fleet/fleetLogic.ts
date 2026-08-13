import type {
  Alert,
  ChokeState,
  Decision,
  DerivedFleet,
  DriftResult,
  FleetDevice,
  FleetKpis,
  FleetPeer,
  HostResult,
  Thresholds
} from "./types";

export const EMPTY_KPIS: FleetKpis = {
  total: 0,
  healthy: 0,
  enforcing: 0,
  killed: 0,
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

export function detectDrift(stateResults: Array<HostResult<ChokeState>>): DriftResult {
  const okRows = stateResults.filter((row) => row.ok && row.data);
  return {
    mode: majority(okRows.map((row) => row.data?.mode ?? "?")),
    kill: majority(okRows.map((row) => (row.data?.kill_switched ? "on" : "off"))),
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

    if (reachable && data) {
      kpis.healthy += 1;
      kpis.tracked += data.tracked ?? 0;
      if (data.mode === "enforcing") {
        kpis.enforcing += 1;
      }
      if (data.kill_switched) {
        kpis.killed += 1;
      }
      // Three outcomes, not two. A host that does not chain centrally, or
      // reports no audit block at all, is NOT a host with a broken chain —
      // counting it as one told an operator their tamper-evidence had failed.
      const audit = data.audit;
      if (!audit || audit.supported === false) {
        kpis.auditUnsupported += 1;
      } else if (audit.ok) {
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
    const driftKill = reachable && (data?.kill_switched ? "on" : "off") !== drift.kill;
    const driftThresholds = reachable && thresholdKey(data?.thresholds) !== drift.thresholds;
    if (driftMode || driftKill || driftThresholds) {
      kpis.drift += 1;
    }

    return {
      peer,
      result,
      reachable,
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

export function summarizeFanout(label: string, hosts: Array<HostResult<unknown>>): {
  ok: boolean;
  title: string;
  body: string;
} {
  const total = hosts.length;
  const success = hosts.filter((host) => host.ok).length;
  const failed = total - success;
  if (failed === 0) {
    return {
      ok: true,
      title: `${label} applied`,
      body: `${success}/${total} hosts succeeded.`
    };
  }
  const failures = hosts
    .filter((host) => !host.ok)
    .map((host) => `${host.name} (${host.error || host.status || "error"})`)
    .join(", ");
  return {
    ok: false,
    title: `${label}: partial`,
    body: `${success}/${total} succeeded; failures: ${failures}`
  };
}

export type MergedDecision = Decision & { _host: string };
export type MergedAlert = Alert & { _host: string };
