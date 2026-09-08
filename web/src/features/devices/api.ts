import { ApiError, api as sharedApi, type ApiMethod, type ApiOptions } from "../../lib/api";
import { readCanRespond } from "../choke/canRespond";
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

/**
 * What the device console needs from /api/whoami: whether this account may
 * send containment writes at all.
 *
 * The device plane arms independently of the process plane — they are separate
 * commands to separate enforcers — but they are gated by the same grant, so the
 * field is read with the same predicate (see features/choke/canRespond.ts)
 * rather than reimplemented here.
 */
export interface DevicesWhoami {
  canRespond: boolean | null;
}

export interface DevicesApi {
  fetchState(options?: DevicesApiCallOptions): Promise<DeviceDataPlaneState>;
  fetchDevices(options?: DevicesApiCallOptions): Promise<DeviceEntry[]>;
  fetchFlows(mac: string, options?: DevicesApiCallOptions): Promise<DeviceFlowsResponse>;
  jailDevices(body: DeviceJailRequest): Promise<DeviceJailResponse>;
  thawDevices(body: DeviceThawRequest): Promise<DeviceThawResponse>;
  setMode(enforcing: boolean, reason: string): Promise<DeviceModeResponse>;
  /**
   * The audit reason is a REQUIRED parameter, not an optional courtesy: the
   * single-tenant engine refuses an engage whose reason is empty
   * (engine/internal/api/devchoke.go, handleChokeDeviceKillSwitch), because
   * engaging halts every device containment on the host — including one an
   * operator deliberately pressed — and the record of that may not be blank.
   * Required in the type so a new caller has to decide what it is sending
   * rather than discovering the refusal as a 400 in front of an operator.
   */
  setKillSwitch(on: boolean, reason: string): Promise<DeviceKillSwitchResponse>;
  /**
   * Optional so that the many hand-built fakes of this interface keep
   * compiling. A fake that omits it reports `canRespond: null`, which is the
   * single-tenant answer — controls armed — and therefore preserves exactly
   * the behaviour those fixtures were written against.
   */
  fetchWhoami?(options?: DevicesApiCallOptions): Promise<DevicesWhoami>;
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
    setKillSwitch: (on, reason = "") =>
      request<DeviceKillSwitchResponse>(
        "/api/choke/device-kill-switch",
        // Absent, never empty, when the operator said nothing — the same rule
        // the thaw path follows. A release with no reason is accepted by both
        // servers, and the single-tenant engine writes its own "kill-switch
        // released (no reason stated)" marker, which is the only thing in that
        // row telling a later reader nobody justified it. Posting "" would not
        // change what that server records, but sending a field the operator
        // never filled in is how invented justifications start.
        jsonPost({ on, ...(reason.trim() ? { reason: reason.trim() } : {}) })
      ),
    fetchWhoami: async (options) => ({
      canRespond: readCanRespond(await request<unknown>("/api/whoami", options))
    })
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

/**
 * EVERY device request goes out through the shared funnel (lib/api.ts).
 *
 * This client used to call fetch() directly, with a CSRF header and a 401
 * redirect of its own. What it did not have was the funnel's tenant scoping, so
 * every request it made — device-jail, device-thaw, device-kill-switch,
 * device-mode and the reads besides — left WITHOUT the `?tenant=` that names
 * the customer the console is pointed at. A provider operator who had switched
 * to customer B was therefore looking at B's devices while their chokes landed
 * on whichever customer the server resolves a tenant-less write to. That
 * failure does not announce itself: the request succeeds, on the wrong LAN.
 *
 * Delegating rather than re-applying tenantScopedPath here is the point. One
 * funnel means a change to the scoping rule — or a new unscoped path — reaches
 * the device plane the day it is written, with nothing for this file to
 * remember. It is also why the DEFAULT requester is the funnel-routed one:
 * DevicesRoute falls back to `createDevicesApi()` when it is handed no api
 * prop, so a bypass left in the default is one dropped prop away from being
 * the live path again.
 *
 * The failure is translated back into a DevicesApiError so the rest of this
 * feature keeps the error surface it was written against — and so the server's
 * own sentence survives: the funnel's ApiError reports `statusText` for a
 * text/plain body, which would have turned the engine's explanation of a
 * refused kill-switch into a bare "Bad Request" in the operator's toast.
 */
async function defaultApiRequest<T>(url: string, init: RequestInit = {}): Promise<T> {
  try {
    return await sharedApi<T>(url, toApiOptions(init));
  } catch (caught) {
    throw asDevicesError(caught);
  }
}

function toApiOptions(init: RequestInit): ApiOptions {
  const options: ApiOptions = {
    ...init,
    method: init.method as ApiMethod | undefined
  };

  // jsonPost hands over an already-serialised body because ApiRequest is a
  // RequestInit seam that a dozen test fakes are written against. The funnel
  // serialises what it is given, so the string is decoded back to the object it
  // came from rather than being stringified a second time into a JSON string.
  if (init.body != null) {
    options.body = decodeRequestBody(init.body);
  }

  return options;
}

function decodeRequestBody(body: BodyInit): unknown {
  if (typeof body !== "string") return body;
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return body;
  }
}

function asDevicesError(caught: unknown): unknown {
  if (!(caught instanceof ApiError)) return caught;
  // A refusal's own words first. The control plane answers JSON, which the
  // funnel has already reduced to its `error` field in the message; the
  // single-tenant engine answers text/plain, which arrives whole in `body` and
  // is the only place the reason is stated.
  const stated = typeof caught.body === "string" ? caught.body.trim() : "";
  return new DevicesApiError(caught.status, stated || caught.message);
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

