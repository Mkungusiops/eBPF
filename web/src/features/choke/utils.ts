import type {
  Alert,
  BucketEntry,
  CgroupMap,
  CgroupValue,
  ChokeAction,
  ChokeState,
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

/**
 * Is this circuit holding something a thaw could release?
 *
 * Mirrors releasableState in engine/internal/controlplane/choke.go, which is
 * what a fleet release actually sweeps: pristine is not containment, and
 * severed is a process that already took a SIGKILL — calling that "released"
 * would be a claim about a dead process. Anything else counts, including a rung
 * this build does not recognise, because an unknown rung is far more likely to
 * be a new containment tier than a new form of idleness.
 *
 * Only the EXPLICIT state is read. A pristine row scoring above the quarantine
 * threshold is a process nobody has contained yet, and inferring containment
 * from its score would put its host into a release the operator did not ask for.
 */
export function isContainedState(state?: string): boolean {
  const value = (state || "").trim().toLowerCase();
  if (value === "") return false;
  return !["pristine", "watch", "watched", "none", "sever", "severed"].includes(value);
}

/**
 * The hosts this console can currently attribute containment to, de-duplicated
 * and stable-ordered so the sentence an operator reads before a release matches
 * the list that is sent.
 *
 * Empty has two meanings and the caller must handle both: the single-host
 * engine puts no `agent` on a circuit at all, and a fleet console showing no
 * contained process has nothing to name. Neither can be scoped, so neither may
 * be described to the operator as scoped.
 */
export function containedHosts(entries: CircuitEntry[]): string[] {
  const hosts = new Set<string>();
  for (const entry of entries) {
    if (!entry.agent || !isContainedState(entry.state)) continue;
    hosts.add(entry.agent);
  }
  return Array.from(hosts).sort();
}

/**
 * The radius one approval request actually asks for, in words an approver can
 * act on.
 *
 * The console used to print "the entire tenant" for every `scope: "fleet"`
 * request, so an approver clicking through a confirm for a one-host containment
 * was told they were arming the whole estate — and the next one, who really was
 * arming the whole estate, read the identical sentence. The control plane now
 * publishes `targets` (the named hosts) and `radius` (the same thing in words),
 * and this is the single place both are turned into that sentence, so the queue
 * row and the confirm dialog cannot drift apart.
 *
 * The unknown case is kept distinct on purpose. When the server publishes
 * neither field the radius was never recorded or has aged out of its ledger; it
 * says so rather than guessing, and so does this — naming the safe assumption
 * without dressing it up as a fact.
 */
export function approvalRadiusLabel(req: {
  scope?: string;
  targets?: string[];
  radius?: string;
  exec_id?: string;
  pid?: number;
}): string {
  if (req.scope !== "fleet") {
    return `${shortExec(req.exec_id || "")}${req.pid ? ` (pid ${req.pid})` : ""}`;
  }
  const targets = req.targets || [];
  if (targets.length > 0) {
    return `${targets.join(", ")} (${targets.length} host${targets.length === 1 ? "" : "s"})`;
  }
  const stated = (req.radius || "").trim();
  // "the whole tenant" is the server's own wording for an untargeted request;
  // anything else it states (e.g. "no host") is the request's real radius and
  // is passed through untouched.
  if (stated) return /tenant/i.test(stated) ? "the entire tenant" : stated;
  return "a radius this server did not report — assume the entire tenant";
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

/**
 * PIDs actually sitting in each enforcement cgroup, keyed by ladder state.
 *
 * This is the APPLIED half of the ladder — what the kernel received, as
 * distinct from what the engine decided. Only three rungs have a cgroup:
 * pristine is the absence of enforcement and a sever is a SIGKILL, so neither
 * has one to be in.
 */
export function appliedTierCounts(cgroups: CgroupMap): Partial<Record<string, number>> {
  return {
    throttled: getCgroupPids(cgroups?.["choke-throttled"]).length,
    tarpit: getCgroupPids(cgroups?.["choke-tarpit"]).length,
    quarantined: getCgroupPids(cgroups?.["choke-quarantined"]).length
  };
}

/**
 * Why decided and applied differ — in the operator's words, not the codebase's.
 *
 * A gap with no reason is the dangerous rendering: "7 decided, 0 applied" looks
 * identical whether enforcement is deliberately off or silently broken. Each
 * branch here names a specific, checkable posture; the fallback deliberately
 * refuses to reassure, because an unexplained gap IS the alarming case.
 */
export function enforcementGapReason(state: ChokeState | null | undefined): string {
  if (state?.kill_switched === true) {
    return "The kill-switch is engaged, so nothing reaches the kernel. Decisions are still recorded.";
  }
  if (state?.dry_run) {
    return "Dry-run: the ladder is evaluated and the kernel is deliberately left alone.";
  }
  if (state?.mode === "detect-only") {
    return "Detect-only: decisions are recorded, not applied to the kernel. Arm the plane to make them land.";
  }
  return "";
}

/**
 * How a decision row names who ordered it.
 *
 * "automatic" rather than an empty cell, because a blank is indistinguishable
 * from an unattributed action: a review cannot tell "the platform did this on
 * a score" from "we lost the record of who did this". One helper so the two
 * planes cannot word it differently — the engine has always sent `actor` and
 * the control plane only started receiving it with the decision uplink.
 */
export function actorLabel(actor: string | undefined): string {
  const a = (actor || "").trim();
  return a ? `by ${a}` : "automatic";
}

/**
 * A readable form of an agent id for a dense row.
 *
 * Agent ids are 32 hex characters prefixed "agent-", which is unreadable in a
 * kernel-map row and pushes the numbers that matter off the line. The tail is
 * kept rather than the head: the prefix is identical on every agent, so the
 * end is the part that distinguishes them.
 */
export function shortAgent(agentID?: string): string {
  const id = (agentID || "").replace(/^agent-/, "");
  return id.length > 8 ? `…${id.slice(-8)}` : id;
}
