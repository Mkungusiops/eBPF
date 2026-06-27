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

export function manualAction(body: {
  exec_id?: string;
  pid?: number;
  binary?: string;
  action: ChokeAction;
  reason: string;
  revert_after_seconds?: number;
}): Promise<unknown> {
  return postJSON("/api/choke/manual", body);
}

export function bulkManualAction(body: {
  targets: Array<{ exec_id?: string; pid?: number; binary?: string }>;
  action: ChokeAction;
  reason: string;
  revert_after_seconds?: number;
}): Promise<{ results?: Array<{ exec_id?: string; ok?: boolean; error?: string }> }> {
  return postJSON("/api/choke/bulk-manual", body);
}

export function forgetCircuits(execIds: string[]): Promise<unknown> {
  return postJSON("/api/choke/forget", { exec_ids: execIds });
}

export function thawQuarantine(reason: string): Promise<unknown> {
  return postJSON("/api/choke/thaw", { reason });
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
