import { ApiError, api as sharedApi, copyToClipboard, getJSON, postJSON, putJSON, readCookie } from "../../lib/api";
import type {
  Alert,
  BucketEntry,
  CgroupMap,
  ChokeAction,
  ChokeState,
  CircuitEntry,
  Decision,
  PolicyPreviewResponse,
  ProcessDetailPayload,
  SysProcDetail,
  SysProcEntry,
  Thresholds,
  Whoami,
} from "./types";

export { ApiError as ChokeApiError, copyToClipboard };

export function isDisabledError(error: unknown): error is ApiError {
  return error instanceof ApiError && error.status === 503;
}

async function apiBlob(path: string, init: RequestInit = {}): Promise<Blob> {
  const headers = new Headers(init.headers);
  const method = init.method || "GET";
  if (!["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase()) && path.startsWith("/api/")) {
    const csrf = readCookie("csrf_token");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: method === "GET" ? "no-store" : "default",
    ...init,
    headers,
  });
  if (response.status === 401) {
    window.location.href = "/login";
    throw new ApiError("unauthorized", response.status, null);
  }
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new ApiError(body || response.statusText || `HTTP ${response.status}`, response.status, body);
  }
  return response.blob();
}

export function getWhoami(): Promise<Whoami> {
  return getJSON<Whoami>("/api/whoami");
}

export function getChokeState(): Promise<ChokeState> {
  return getJSON<ChokeState>("/api/choke/state");
}

export function getCircuits(): Promise<CircuitEntry[]> {
  return getJSON<CircuitEntry[]>("/api/choke/circuits");
}

export function getBuckets(): Promise<BucketEntry[]> {
  return getJSON<BucketEntry[]>("/api/choke/buckets");
}

export function getCgroups(): Promise<CgroupMap> {
  return getJSON<CgroupMap>("/api/choke/cgroups");
}

export function getDecisions(limit = 200): Promise<Decision[]> {
  return getJSON<Decision[]>(`/api/decisions?limit=${encodeURIComponent(String(limit))}`);
}

export function getAlerts(limit = 200): Promise<Alert[]> {
  return getJSON<Alert[]>(`/api/alerts?limit=${encodeURIComponent(String(limit))}`);
}

export function getSystemHealth(): Promise<Record<string, unknown>> {
  return getJSON<Record<string, unknown>>("/api/system-health");
}

export function getProcess(execId: string): Promise<ProcessDetailPayload> {
  return getJSON<ProcessDetailPayload>(`/api/choke/process/${encodeURIComponent(execId)}`);
}

export function getProcesses(): Promise<SysProcEntry[]> {
  return getJSON<SysProcEntry[]>("/api/choke/processes");
}

export function getProc(pid: number): Promise<SysProcDetail> {
  return getJSON<SysProcDetail>(`/api/choke/proc/${encodeURIComponent(String(pid))}`);
}

export function updateThresholds(thresholds: Thresholds): Promise<unknown> {
  return putJSON("/api/choke/thresholds", thresholds);
}

/**
 * Outcome of a containment command, as the fleet control plane reports it.
 *
 * `ok` is the only thing that means the action actually landed. It is false
 * when every agent disowned the target (status STATUS_NOT_TARGET) — the
 * process is not on this fleet — and the request 409s with AMBIGUOUS_TARGET
 * when a sever could not be pinned to a single host.
 */
export interface ChokeActionResult {
  ok?: boolean;
  status?: string;
  detail?: string;
  agent?: string;
  applied_by?: string[];
  candidates?: string[];
  /**
   * Set when the action was HELD for change-control (threat-model EN-2): a
   * quarantine/sever needs a second operator to approve it. `ok` is false and
   * nothing has been applied — the action is queued, not done.
   */
  approval_required?: boolean;
  approval?: ApprovalRequest;
}

/**
 * A destructive action awaiting a second operator, and its audit record: who
 * asked, who decided, and what actually happened when it ran.
 */
export interface ApprovalRequest {
  id: string;
  tenant?: string;
  action: string;
  exec_id?: string;
  pid?: number;
  agent_id?: string;
  scope?: "target" | "fleet";
  reason?: string;
  requester?: string;
  created_at?: string;
  expires_at?: string;
  status: "pending" | "approved" | "denied" | "expired";
  approver?: string;
  decided_at?: string;
  decide_note?: string;
  outcome?: string;
  executed?: boolean;
  /** True when the viewer is the requester — they may not approve their own. */
  mine?: boolean;
}

export function getApprovals(): Promise<{ approvals?: ApprovalRequest[]; pending?: number; you?: string }> {
  return getJSON("/api/approvals");
}

export function decideApproval(id: string, approve: boolean, note?: string): Promise<ChokeActionResult> {
  return postJSON("/api/approvals/decide", { id, approve, note }) as Promise<ChokeActionResult>;
}

/**
 * Did a choke action actually land?
 *
 * The two deployments answer differently and BOTH must read correctly, because
 * this same bundle is served by the fleet console and by the single-host engine:
 *
 *   - the control plane returns an explicit `ok`, false when no agent applied
 *     (or `approval_required` when it was held for a second operator);
 *   - the engine has no `ok` at all — it returns `{applied: {...}}` and a
 *     non-2xx throws before we get here.
 *
 * So absence of `ok` means the legacy engine contract (applied), and only an
 * explicit `ok: false` means it did not land. Treating undefined as failure
 * would make the engine console report every successful sever as "NOT applied"
 * — the mirror image of the containment lie this reporting exists to remove.
 */
export function chokeApplied(result: ChokeActionResult | undefined): boolean {
  if (result?.approval_required) return false;
  return result?.ok !== false;
}

export function manualAction(body: {
  exec_id?: string;
  pid?: number;
  binary?: string;
  agent_id?: string;
  action: ChokeAction;
  reason: string;
  revert_after_seconds?: number;
}): Promise<ChokeActionResult> {
  return postJSON("/api/choke/manual", body) as Promise<ChokeActionResult>;
}

export function bulkManualAction(body: {
  targets: Array<{ exec_id?: string; pid?: number; binary?: string; agent_id?: string }>;
  action: ChokeAction;
  reason: string;
  revert_after_seconds?: number;
}): Promise<{ results?: Array<{ exec_id?: string; ok?: boolean; error?: string; detail?: string; agent?: string }> }> {
  return postJSON("/api/choke/bulk-manual", body);
}

export function forgetCircuits(execIds: string[]): Promise<unknown> {
  return postJSON("/api/choke/forget", { exec_ids: execIds });
}

export function thawQuarantine(reason: string): Promise<unknown> {
  return postJSON("/api/choke/thaw", { reason });
}

/**
 * Release ONE process back to pristine.
 *
 * Distinct from thawQuarantine above: without an exec_id the engine unfreezes
 * the whole quarantine tier and moves nobody out of it, so a per-process
 * "release" reported success and left the process quarantined. Passing the
 * target makes it a real per-process release.
 */
export function releaseProcess(
  execId: string,
  pid: number | undefined,
  reason: string,
  agentId?: string
): Promise<ChokeActionResult> {
  return postJSON("/api/choke/thaw", { exec_id: execId, pid, reason, agent_id: agentId }) as Promise<ChokeActionResult>;
}

export function toggleKillSwitch(on: boolean): Promise<unknown> {
  return postJSON("/api/choke/kill-switch", { on });
}

export function applyPreset(name: string, reason: string): Promise<unknown> {
  return postJSON("/api/choke/preset", { name, reason });
}

export function setMode(enforcing: boolean, reason: string): Promise<unknown> {
  return postJSON("/api/choke/mode", { enforcing, reason });
}

export function previewPolicy(yaml: string): Promise<PolicyPreviewResponse> {
  return postJSON<PolicyPreviewResponse>("/api/choke/policy/preview", { yaml });
}

export function annotateCircuit(execId: string, note: string): Promise<unknown> {
  return postJSON("/api/choke/annotate", { exec_id: execId, note });
}

export function jailProcesses(body: {
  pids?: number[];
  binary?: string;
  descendants?: boolean;
  action: ChokeAction;
  reason: string;
  revert_after_seconds?: number;
}): Promise<{ results?: Array<{ pid?: number; exec_id?: string; ok?: boolean; error?: string; state?: string }> }> {
  return postJSON("/api/choke/jail", body);
}

export function verifyChain(): Promise<Record<string, unknown>> {
  return getJSON<Record<string, unknown>>("/api/verify-chain");
}

export function forensicSnapshot(): Promise<Blob> {
  return apiBlob("/api/choke/forensic-snapshot");
}

export function getRaw<T = unknown>(path: string): Promise<T> {
  return sharedApi<T>(path);
}
