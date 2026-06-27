import type {
  Alert,
  BucketEntry,
  CgroupMap,
  CgroupValue,
  ChokeAction,
  ChokeStateName,
  CircuitEntry,
  Decision,
  SysProcEntry,
  Thresholds,
} from "./types";

export const STATE_ORDER: ChokeStateName[] = ["pristine", "throttled", "tarpit", "quarantined", "severed"];

export const ACTIONS: ChokeAction[] = ["throttle", "tarpit", "quarantine", "sever"];

export const DEFAULT_THRESHOLDS: Thresholds = {
  throttle_at: 10,
  tarpit_at: 30,
  quarantine_at: 60,
  sever_at: 100,
};

export interface SearchPredicate {
  key: string;
  op: "=" | ">" | ">=" | "<" | "<=";
  value: string;
}

export interface ParsedSearch {
  text: string;
  predicates: SearchPredicate[];
}

export function parseSearch(raw: string): ParsedSearch | null {
  const query = raw.trim();
  if (!query) return null;

  const tokens: string[] = [];
  const re = /"([^"]+)"|'([^']+)'|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(query)) !== null) {
    tokens.push(match[1] || match[2] || match[3]);
  }

  const predicates: SearchPredicate[] = [];
  const bare: string[] = [];
  for (const token of tokens) {
    const colon = token.indexOf(":");
    if (colon > 0) {
      const key = token.slice(0, colon).toLowerCase();
      let value = token.slice(colon + 1);
      let op: SearchPredicate["op"] = "=";
      const opMatch = value.match(/^(>=|<=|>|<)(.+)$/);
      if (opMatch) {
        op = opMatch[1] as SearchPredicate["op"];
        value = opMatch[2];
      }
      predicates.push({ key, op, value });
    } else {
      bare.push(token);
    }
  }

  return { predicates, text: bare.join(" ") };
}

function compareNumber(actual: number, op: SearchPredicate["op"], expected: number): boolean {
  if (Number.isNaN(expected)) return true;
  if (op === ">") return actual > expected;
  if (op === ">=") return actual >= expected;
  if (op === "<") return actual < expected;
  if (op === "<=") return actual <= expected;
  return actual === expected;
}

export function circuitMatches(entry: CircuitEntry, parsed: ParsedSearch | null): boolean {
  if (!parsed) return true;
  for (const predicate of parsed.predicates) {
    const value = predicate.value.toLowerCase();
    let ok = true;
    switch (predicate.key) {
      case "pid":
        ok = compareNumber(entry.pid || 0, predicate.op, Number(predicate.value));
        break;
      case "uid":
        ok = compareNumber(entry.uid || 0, predicate.op, Number(predicate.value));
        break;
      case "score":
        ok = compareNumber(entry.score || 0, predicate.op, Number(predicate.value));
        break;
      case "binary":
      case "process":
        ok = (entry.binary || "").toLowerCase().includes(value);
        break;
      case "state":
        ok = (entry.state || "").toLowerCase() === value;
        break;
      case "exec":
      case "exec_id":
        ok = (entry.exec_id || "").toLowerCase().includes(value);
        break;
      case "origin":
        ok = originLabel(entry).toLowerCase().includes(value);
        break;
      default:
        ok = true;
    }
    if (!ok) return false;
  }

  if (!parsed.text) return true;
  const text = parsed.text.toLowerCase();
  if (/^\d{1,7}$/.test(parsed.text) && (entry.pid || 0) === Number(parsed.text)) return true;
  return [
    entry.pid,
    entry.uid,
    entry.binary,
    entry.exec_id,
    entry.args,
    entry.state,
    originLabel(entry),
  ]
    .join(" ")
    .toLowerCase()
    .includes(text);
}

export function decisionMatches(decision: Decision, parsed: ParsedSearch | null): boolean {
  if (!parsed) return true;
  for (const predicate of parsed.predicates) {
    const value = predicate.value.toLowerCase();
    let ok = true;
    switch (predicate.key) {
      case "pid":
        ok = compareNumber(decision.pid || 0, predicate.op, Number(predicate.value));
        break;
      case "score":
        ok = compareNumber(decision.score || 0, predicate.op, Number(predicate.value));
        break;
      case "binary":
      case "process":
        ok = (decision.binary || "").toLowerCase().includes(value);
        break;
      case "state":
        ok =
          (decision.to_state || "").toLowerCase() === value ||
          (decision.from_state || "").toLowerCase() === value;
        break;
      case "action":
        ok = (decision.action || "").toLowerCase() === value;
        break;
      case "exec":
      case "exec_id":
        ok = (decision.exec_id || "").toLowerCase().includes(value);
        break;
      default:
        ok = true;
    }
    if (!ok) return false;
  }

  if (!parsed.text) return true;
  const text = parsed.text.toLowerCase();
  if (/^\d{1,7}$/.test(parsed.text) && (decision.pid || 0) === Number(parsed.text)) return true;
  return [
    decision.pid,
    decision.action,
    decision.binary,
    decision.exec_id,
    decision.reason,
    decision.to_state,
    decision.from_state,
  ]
    .join(" ")
    .toLowerCase()
    .includes(text);
}

export function tapeTextMatches(decision: Decision, raw: string): boolean {
  const query = raw.trim();
  if (!query) return true;
  const match = query.match(/^\/(.+)\/([dgimsuvy]*)$/);
  const haystack = [
    decision.action,
    decision.pid,
    decision.exec_id,
    decision.binary,
    decision.reason,
    decision.to_state,
  ].join(" ");
  if (match) {
    try {
      return new RegExp(match[1], match[2] || "i").test(haystack);
    } catch {
      return haystack.toLowerCase().includes(query.toLowerCase());
    }
  }
  return haystack.toLowerCase().includes(query.toLowerCase());
}

export function originLabel(entry: CircuitEntry): string {
  const origin = entry.origin;
  if (!origin) return "";
  if (origin.remote_ip) {
    return origin.remote_port ? `${origin.remote_ip}:${origin.remote_port}` : origin.remote_ip;
  }
  return origin.user || origin.fingerprint || origin.kind || "";
}

export function shortExec(execId?: string): string {
  if (!execId) return "-";
  return execId.length > 12 ? `${execId.slice(0, 12)}...` : execId;
}

export function basename(path?: string): string {
  if (!path) return "(unknown)";
  const idx = path.lastIndexOf("/");
  return idx >= 0 ? path.slice(idx + 1) || path : path;
}

export function formatTime(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleTimeString(undefined, { hour12: false });
}

export function formatRelative(value?: string | number): string {
  const time = typeof value === "number" ? value : value ? new Date(value).getTime() : 0;
  if (!time || Number.isNaN(time)) return "-";
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function formatUptime(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

export function stateForScore(score: number, thresholds: Thresholds = DEFAULT_THRESHOLDS): ChokeStateName {
  if (score >= thresholds.sever_at) return "severed";
  if (score >= thresholds.quarantine_at) return "quarantined";
  if (score >= thresholds.tarpit_at) return "tarpit";
  if (score >= thresholds.throttle_at) return "throttled";
  return "pristine";
}

export function countByState(entries: CircuitEntry[], thresholds?: Thresholds): Record<ChokeStateName, number> {
  const out: Record<ChokeStateName, number> = {
    pristine: 0,
    throttled: 0,
    tarpit: 0,
    quarantined: 0,
    severed: 0,
  };
  for (const entry of entries) {
    const state = entry.state && STATE_ORDER.includes(entry.state as ChokeStateName)
      ? (entry.state as ChokeStateName)
      : stateForScore(entry.score || 0, thresholds);
    out[state] += 1;
  }
  return out;
}

export function countCgroupPids(map: CgroupMap): number {
  return Object.values(map || {}).reduce((sum, value) => {
    if (Array.isArray(value)) return sum + value.length;
    if (Array.isArray(value?.pids)) return sum + value.pids.length;
    return sum + Number(value?.count || 0);
  }, 0);
}

export function getCgroupPids(value: CgroupValue | undefined): number[] {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.pids)) return value.pids;
  return [];
}

export function bucketizeDecisions(
  decisions: Decision[],
  nowMs: number,
  bucketSeconds: number,
  bucketCount: number,
  predicate?: (decision: Decision) => boolean,
): number[] {
  const out = new Array(bucketCount).fill(0);
  const bucketMs = bucketSeconds * 1000;
  const start = nowMs - bucketCount * bucketMs;
  for (const decision of decisions) {
    if (predicate && !predicate(decision)) continue;
    const time = decision.timestamp ? new Date(decision.timestamp).getTime() : 0;
    if (!time || time < start || time > nowMs) continue;
    const index = Math.min(bucketCount - 1, Math.floor((time - start) / bucketMs));
    if (index >= 0) out[index] += 1;
  }
  return out;
}

export function topK<T>(
  rows: T[],
  keyFn: (row: T) => string | undefined | null,
  limit: number,
): Array<{ key: string; count: number; sample: T }> {
  const map = new Map<string, { count: number; sample: T }>();
  for (const row of rows) {
    const key = keyFn(row);
    if (!key) continue;
    const current = map.get(key) || { count: 0, sample: row };
    current.count += 1;
    map.set(key, current);
  }
  return Array.from(map, ([key, value]) => ({ key, ...value }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export function summarizeAlerts(alerts: Alert[]): Map<string, number> {
  const map = new Map<string, number>();
  for (const alert of alerts) {
    if (!alert.exec_id) continue;
    map.set(alert.exec_id, (map.get(alert.exec_id) || 0) + 1);
  }
  return map;
}

export function classifyProc(entry: SysProcEntry): "kernel" | "system" | "user" {
  if (!entry.exe) return "kernel";
  return (entry.uid || 0) === 0 ? "system" : "user";
}

export function deriveProcSignals(entry: SysProcEntry): string[] {
  const out: string[] = [];
  const exe = (entry.exe || "").toLowerCase();
  const comm = (entry.comm || "").toLowerCase();
  const cmd = (entry.cmdline || "").toLowerCase();
  if ((entry.uid || 0) === 0 && entry.exe) out.push("root");
  if (/^(\/tmp|\/var\/tmp|\/dev\/shm)\//.test(exe)) out.push("tmpfs-binary");
  if (/^(bash|zsh|sh|dash|ash|fish|ksh)$/.test(comm)) out.push("shell");
  if (/^(curl|wget|nc|ncat|netcat|socat|ftp|tftp)$/.test(comm)) out.push("transfer");
  if (/^(python|python2|python3|perl|ruby|node|lua)$/.test(comm)) out.push("interpreter");
  if (/\/etc\/(passwd|shadow|sudoers|gshadow)\b/.test(cmd)) out.push("credential-file");
  if (/\/dev\/tcp\/|bash\s+-i\b|\bnc\s+(-l|-e|-c)\b|ncat\s+-e\b/.test(cmd)) out.push("reverse-shell");
  if (/\b(chmod\s+\+s|setcap\s+cap_)/.test(cmd)) out.push("priv-esc");
  if (/\bnmap\s|\bmasscan\s|nikto\s|gobuster\s|dirb\s/.test(cmd)) out.push("discovery");
  return out.slice(0, 6);
}

export function readJsonStorage<T>(key: string, fallback: T): T {
  if (typeof localStorage === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(key);
    return raw == null ? fallback : (JSON.parse(raw) as T);
  } catch {
    return fallback;
  }
}

export function writeJsonStorage<T>(key: string, value: T): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Storage quota/private mode failures are non-fatal.
  }
}

export function normalizeThresholds(thresholds?: Partial<Thresholds>): Thresholds {
  return {
    throttle_at: Number(thresholds?.throttle_at || DEFAULT_THRESHOLDS.throttle_at),
    tarpit_at: Number(thresholds?.tarpit_at || DEFAULT_THRESHOLDS.tarpit_at),
    quarantine_at: Number(thresholds?.quarantine_at || DEFAULT_THRESHOLDS.quarantine_at),
    sever_at: Number(thresholds?.sever_at || DEFAULT_THRESHOLDS.sever_at),
  };
}

export function thresholdsAscending(thresholds: Thresholds): boolean {
  return (
    thresholds.throttle_at > 0 &&
    thresholds.throttle_at < thresholds.tarpit_at &&
    thresholds.tarpit_at < thresholds.quarantine_at &&
    thresholds.quarantine_at < thresholds.sever_at
  );
}

export function bucketFlagsLabel(flags: number): string {
  if (flags & 8) return "sever";
  if (flags & 4) return "quarantine";
  if (flags & 2) return "tarpit";
  if (flags & 1) return "throttle";
  return "observe";
}

export function sortBuckets(rows: BucketEntry[]): BucketEntry[] {
  return [...rows].sort((a, b) => {
    const flagDiff = b.flags - a.flags;
    if (flagDiff !== 0) return flagDiff;
    return a.pid - b.pid;
  });
}
