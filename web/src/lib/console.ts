// Console v2 client for the multi-tenant control plane. Auth is handled by the
// BFF (server-side OIDC; the browser holds only an HttpOnly session cookie, sent
// automatically because the console is served same-origin by the control plane).
// This module never sees a token.

import { api, type ApiOptions } from "./api";
import { parseWhoami, type TenantIdentity, type WhoamiResponse } from "./tenantCore";

/** Header the control plane reads to scope a read to the active tenant. */
export const TENANT_HEADER = "X-Tenant-Id";

/** fetchWhoami loads the operator identity from the BFF session. */
export async function fetchWhoami(): Promise<TenantIdentity> {
  const raw = await api<WhoamiResponse>("/api/whoami");
  return parseWhoami(raw);
}

/** A tenant-stamped telemetry record as the control plane returns it. */
export interface TelemetryRow {
  tenant: string;
  agent: string;
  kind: string;
  binary?: string;
  exec_id?: string;
  at: number; // unix nanoseconds
}

export interface TelemetryResponse {
  tenant: string;
  count: number;
  records: TelemetryRow[];
}

/**
 * fetchTelemetry reads the active tenant's recent events from the control
 * plane. The tenant is passed explicitly; the server still authorizes it against
 * the operator's grants (an unauthorized tenant reads back as a 404).
 */
export async function fetchTelemetry(tenant: string, limit = 50): Promise<TelemetryResponse> {
  return api<TelemetryResponse>(
    `/api/telemetry?tenant=${encodeURIComponent(tenant)}&limit=${limit}`
  );
}

export interface FleetAgent {
  agent_id: string;
  version: string;
  kernel: string;
  mode: string;
  last_seen: number; // unix nanoseconds
  buffer_depth: number;
  policy_version: string;
  choke_count: number;
  device_count: number;
}
export async function fetchFleet(tenant: string): Promise<{ tenant: string; count: number; agents: FleetAgent[] }> {
  return api(`/api/fleet?tenant=${encodeURIComponent(tenant)}`);
}

export interface ChokeRow {
  agent: string;
  binary: string;
  state: string;
  score: number;
  pid: number;
  exec_id: string;
}
export async function fetchChoke(tenant: string): Promise<{ tenant: string; count: number; chokes: ChokeRow[] }> {
  return api(`/api/choke?tenant=${encodeURIComponent(tenant)}`);
}

export interface DeviceRow {
  agent: string;
  mac: string;
  state: string;
  label: string;
}
export async function fetchDevices(tenant: string): Promise<{ tenant: string; count: number; devices: DeviceRow[] }> {
  return api(`/api/devices?tenant=${encodeURIComponent(tenant)}`);
}

export interface AlertRow {
  agent: string;
  severity: string;
  title: string;
  description: string;
  score: number;
  exec_id: string;
  at: number; // unix nanoseconds
}
export async function fetchAlerts(tenant: string, limit = 200): Promise<{ tenant: string; count: number; alerts: AlertRow[] }> {
  return api(`/api/alerts?tenant=${encodeURIComponent(tenant)}&limit=${limit}`);
}

export interface CommandResult {
  command_id: string;
  status: string; // STATUS_APPLIED | STATUS_REJECTED | ...
  detail: string;
}

export type ChokeTier = "throttle" | "tarpit" | "quarantine" | "sever";

// jailProcess / thawProcess dispatch a signed operator command to the agent
// over the control plane. The server authorizes `respond` per tenant (a denial
// is a 404); the UI only offers these when the operator can respond.
export async function jailProcess(tenant: string, agent: string, execId: string, pid: number, tier: ChokeTier): Promise<CommandResult> {
  return api<CommandResult>("/api/admin/command", {
    method: "POST",
    redirectOn401: false,
    body: { tenant, agent_id: agent, jail: { exec_id: execId, pid, tier } }
  });
}

export async function thawProcess(tenant: string, agent: string, execId: string, pid: number): Promise<CommandResult> {
  return api<CommandResult>("/api/admin/command", {
    method: "POST",
    redirectOn401: false,
    body: { tenant, agent_id: agent, thaw: { exec_id: execId, pid } }
  });
}

/** loginUrl is where the SPA sends the browser to begin the OIDC login (BFF). */
export function loginUrl(): string {
  return "/auth/login";
}

/**
 * logoutUrl is where the browser NAVIGATES to sign out. It must be a navigation,
 * not a fetch: the BFF ends the local session and then redirects to the IdP's
 * end-session endpoint, which clears the SSO cookie and sends the browser back.
 * A fetch would end the local session but silently leave the IdP logged in.
 */
export function logoutUrl(): string {
  return "/auth/logout";
}

/**
 * tenantApi stamps the active tenant onto a request so the control plane scopes
 * the read to it. The header is advisory: the server authorizes from the session
 * (authz) and validates the tenant against the operator's grants — this only
 * selects which authorized tenant to read.
 */
export async function tenantApi<T = unknown>(
  path: string,
  activeTenant: string | undefined,
  options: ApiOptions = {}
): Promise<T> {
  const headers = new Headers(options.headers);
  if (activeTenant) headers.set(TENANT_HEADER, activeTenant);
  return api<T>(path, { ...options, headers });
}
