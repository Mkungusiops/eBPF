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
import { ApiError, getJSON, postForm, postJSON } from "../../lib/api";

type AnyRecord = Record<string, unknown>;

const EMPTY_WHOAMI: SocWhoami = { user: "operator", host: "localhost" };
const EMPTY_VERSION: SocVersion = { sha: "" };
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

const ENDPOINTS = {
  whoami: "/api/whoami",
  version: "/api/version",
  alerts: "/api/alerts",
  events: "/api/events",
  decisions: "/api/decisions?limit=1",
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

  for (const [key, result] of entries) {
    statuses[key] = result.status;
    if (!result.ok && result.error && result.error !== "aborted") {
      errors[key] = result.error;
    }
  }

  return {
    snapshot: {
      whoami: normalizeWhoami(map.whoami.data),
      version: normalizeVersion(map.version.data),
      alerts: unwrapList(map.alerts.data, ["alerts", "items", "data"]).map(normalizeAlert).slice(0, 200),
      events: unwrapList(map.events.data, ["events", "items", "data"]).map(normalizeEvent).slice(0, 500),
      decisions: unwrapList(map.decisions.data, ["decisions", "items", "data"]).map(normalizeDecision).slice(0, 20),
      policies: unwrapList(map.policies.data, ["policies", "items", "data"]).map(normalizePolicy),
      policyStats: unwrapList(map.policyStats.data, ["stats", "policies", "items", "data"]).map(normalizePolicyStat),
      attacks: unwrapList(map.attacks.data, ["attacks", "items", "data"]).map(normalizeAttack),
      honeypots: unwrapList(map.honeypots.data, ["honeypots", "files", "items", "data"]).map(normalizeHoneypot),
      health: normalizeHealth(map.health.data)
    },
    errors,
    statuses
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

export function runSocAttack(id: string): Promise<unknown> {
  const form = new URLSearchParams();
  form.set("id", id);
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
  return postJSON("/api/choke/jail", {
    pids: alert.pid ? [alert.pid] : [],
    binary: alert.pid ? undefined : alert.process,
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
    policyName: asOptionalString(pick(record, "policy_name", "PolicyName", "policy", "Policy")),
    severity: normalizeOptionalSeverity(pick(record, "severity", "Severity", "level", "Level")),
    path: asOptionalString(pick(record, "path", "Path", "file", "File", "filename", "Filename")),
    remoteIp: asOptionalString(pick(record, "remote_ip", "remoteIp", "RemoteIP", "source_ip", "SourceIP")),
    destIp: asOptionalString(pick(record, "dest_ip", "destIp", "DestIP", "destination_ip", "DestinationIP")),
    destPort: asOptionalNumber(pick(record, "dest_port", "destPort", "DestPort", "port", "Port")),
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
    ok: asOptionalBoolean(pick(record, "ok", "OK", "success", "Success"))
  };
}

function normalizeWhoami(value: unknown): SocWhoami {
  const record = asRecord(value);
  return {
    user: asOptionalString(pick(record, "user", "username", "Username", "name", "Name")) || EMPTY_WHOAMI.user,
    host:
      asOptionalString(pick(record, "host", "hostname", "Hostname", "engine_host", "EngineHost")) ||
      EMPTY_WHOAMI.host,
    role: asOptionalString(pick(record, "role", "Role"))
  };
}

function normalizeVersion(value: unknown): SocVersion {
  const record = asRecord(value);
  return {
    sha: asOptionalString(pick(record, "sha", "SHA", "version", "Version", "build", "Build")) || "",
    startedAt: asOptionalString(pick(record, "started_at", "startedAt", "StartTime", "start_time"))
  };
}

function normalizePolicy(value: unknown): SocPolicy {
  const record = asRecord(value);
  const rawSensors = unwrapList(pick(record, "sensors", "Sensors", "kprobes", "Kprobes"), ["items"]);
  return {
    name: asOptionalString(pick(record, "name", "Name", "policy_name", "PolicyName")) || "unnamed-policy",
    description: asOptionalString(pick(record, "description", "Description")),
    mitre: asOptionalString(pick(record, "mitre", "MITRE", "mitre_id", "MitreID")),
    yaml: asOptionalString(pick(record, "yaml", "YAML", "source", "Source")),
    sensors: rawSensors.map((item) => asOptionalString(item)).filter((item): item is string => Boolean(item))
  };
}

function normalizePolicyStat(value: unknown): SocPolicyStat {
  const record = asRecord(value);
  return {
    name: asOptionalString(pick(record, "name", "Name", "policy", "Policy")) || "policy",
    posts: asNumber(pick(record, "posts", "Posts", "npost", "NPost", "count", "Count"), 0),
    ratePerMin: asOptionalNumber(pick(record, "rate_per_min", "ratePerMin", "RatePerMin", "rate")),
    memoryBytes: asOptionalNumber(pick(record, "memory_bytes", "memoryBytes", "MemoryBytes")),
    status: asOptionalString(pick(record, "status", "Status"))
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
