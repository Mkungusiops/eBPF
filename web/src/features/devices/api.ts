import type {
  DeviceDataPlaneState,
  DeviceFlowsResponse,
  DeviceJailRequest,
  DeviceJailResponse,
  DeviceKillSwitchResponse,
  DeviceModeResponse,
  DeviceThawRequest,
  DeviceThawResponse,
  DeviceEntry
} from "./types";

export class DevicesApiError extends Error {
  readonly status: number;
  readonly body: string;

  constructor(status: number, body: string) {
    super(body || `Request failed with status ${status}`);
    this.name = "DevicesApiError";
    this.status = status;
    this.body = body;
  }
}

export interface DevicesApiCallOptions {
  signal?: AbortSignal;
}

export interface DevicesApi {
  fetchState(options?: DevicesApiCallOptions): Promise<DeviceDataPlaneState>;
  fetchDevices(options?: DevicesApiCallOptions): Promise<DeviceEntry[]>;
  fetchFlows(mac: string, options?: DevicesApiCallOptions): Promise<DeviceFlowsResponse>;
  jailDevices(body: DeviceJailRequest): Promise<DeviceJailResponse>;
  thawDevices(body: DeviceThawRequest): Promise<DeviceThawResponse>;
  setMode(enforcing: boolean, reason: string): Promise<DeviceModeResponse>;
  setKillSwitch(on: boolean): Promise<DeviceKillSwitchResponse>;
}

export type ApiRequest = <T>(url: string, init?: RequestInit) => Promise<T>;

export function createDevicesApi(request: ApiRequest = defaultApiRequest): DevicesApi {
  return {
    fetchState: (options) => request<DeviceDataPlaneState>("/api/choke/device-state", options),
    fetchDevices: (options) => request<DeviceEntry[]>("/api/choke/devices", options),
    fetchFlows: (mac, options) =>
      request<DeviceFlowsResponse>(`/api/choke/device-flows?mac=${encodeURIComponent(mac)}`, options),
    jailDevices: (body) =>
      request<DeviceJailResponse>("/api/choke/device-jail", jsonPost(body)),
    thawDevices: (body) =>
      request<DeviceThawResponse>("/api/choke/device-thaw", jsonPost(body)),
    setMode: (enforcing, reason) =>
      request<DeviceModeResponse>("/api/choke/device-mode", jsonPost({ enforcing, reason })),
    setKillSwitch: (on) =>
      request<DeviceKillSwitchResponse>("/api/choke/device-kill-switch", jsonPost({ on }))
  };
}

export function isDisabledError(error: unknown): boolean {
  return hasStatus(error, 503);
}

export function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function jsonPost(body: unknown): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  };
}

async function defaultApiRequest<T>(url: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (isUnsafeApiRequest(url, method) && !headers.has("X-CSRF-Token")) {
    headers.set("X-CSRF-Token", csrfToken());
  }

  const response = await fetch(url, { ...init, method, headers });
  if (response.status === 401) {
    redirectToLogin();
    throw new DevicesApiError(response.status, "unauthorized");
  }

  const text = await response.text();
  if (!response.ok) {
    throw new DevicesApiError(response.status, text.trim());
  }
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

function isUnsafeApiRequest(url: string, method: string): boolean {
  return url.startsWith("/api/") && !["GET", "HEAD", "OPTIONS"].includes(method);
}

function csrfToken(): string {
  if (typeof document === "undefined") return "";
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

function redirectToLogin(): void {
  if (typeof window === "undefined") return;
  window.location.href = "/login";
}

function hasStatus(error: unknown, status: number): boolean {
  return (
    error instanceof DevicesApiError && error.status === status
  ) || (
    typeof error === "object" &&
    error !== null &&
    "status" in error &&
    Number((error as { status?: unknown }).status) === status
  );
}

