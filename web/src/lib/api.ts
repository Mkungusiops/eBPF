import {
  noteScopeFromResponse,
  pendingTenantHydration,
  tenantScopeApplies,
  tenantScopedPath,
  tenantScopeRefusal
} from "./tenantScope";

export type ApiMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

export interface ApiOptions extends Omit<RequestInit, "method" | "body"> {
  method?: ApiMethod;
  body?: unknown;
  form?: URLSearchParams | FormData;
  redirectOn401?: boolean;
}

export function readCookie(name: string): string {
  if (typeof document === "undefined") return "";
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return "";
}

function isUnsafe(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

async function parseBody(response: Response): Promise<unknown> {
  const type = response.headers.get("content-type") ?? "";
  if (type.includes("application/json")) {
    return response.json().catch(() => null);
  }
  return response.text().catch(() => "");
}

export async function api<T = unknown>(path: string, options: ApiOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers = new Headers(options.headers);

  let body: BodyInit | undefined;
  if (options.form) {
    body = options.form;
  } else if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(options.body);
  }

  if (path.startsWith("/api/") && isUnsafe(method)) {
    const csrf = readCookie("csrf_token");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }

  // WHICH CUSTOMER THIS REQUEST IS ABOUT — applied here, to reads and writes
  // alike, because here is the one place every feature's requests meet.
  //
  // The selection used to be read only by the SOC dashboard's own reads. That
  // left a provider console whose panels showed customer B while choke,
  // devices, fleet and settings read AND WROTE customer A: the operator saw B's
  // alerts, pressed sever, and the containment landed on A. Scoping the funnel
  // instead of twenty call sites is what makes the screen and the kill-switch
  // incapable of disagreeing — a new endpoint is scoped the day it is added,
  // and forgetting is no longer possible because there is nothing to remember.
  //
  // Applied at the moment the request goes out, not when the caller built the
  // path, so a write cannot carry a customer the operator has already left.
  // With no selection (the single-tenant engine, and every tenant-bound
  // operator) tenantScopedPath returns the path untouched; see UNSCOPED_PATHS
  // there for the account- and estate-level endpoints it never scopes.
  //
  // BUT THE SELECTION TAKES TWO ROUND TRIPS TO BECOME TRUSTWORTHY. A request
  // sent inside that window carries no tenant, and the control plane resolves a
  // tenant-less request to the account's default customer — so the page fills
  // with one customer's rows while the console is on its way to another, and a
  // containment fired there lands on a host nobody named. Requests that would
  // have carried the selection therefore wait for the boot driver to settle it;
  // whoami, the roster, the build and the estate summary never carry it, so
  // they are not held (which is also what keeps the two reads that LIFT the
  // barrier from waiting on it). Nothing waits at all on a console that started
  // no hydration — see beginTenantHydration.
  //
  // This is the SECOND line, not the first: app/render.tsx keeps the route
  // unmounted until the barrier settles, so a route's own reads are normally
  // issued after it and hold here for no time at all — which is what stops the
  // wait being charged to a caller's read deadline and reported as a gateway
  // that never answered. What still meets a live barrier here is everything
  // issued outside that gate (the shell's own furniture) and anything issued
  // while a retry has re-opened hydration under a mounted page.
  if (tenantScopeApplies(path)) {
    const hydrating = pendingTenantHydration();
    if (hydrating) await hydrating;
    // Hydration has settled and still cannot say which customer this console is
    // pointed at. A read may go out — the server's default is a real scope and
    // the shell banner says it is not the remembered one — but a write may not:
    // there is no honest version of firing containment at whichever customer
    // the server picks for a console that was told to point somewhere else.
    if (isUnsafe(method)) {
      const refusal = tenantScopeRefusal();
      if (refusal) throw new ApiError(refusal, 0, null);
    }
  }

  const response = await fetch(tenantScopedPath(path), {
    credentials: "same-origin",
    cache: method === "GET" ? "no-store" : "default",
    ...options,
    method,
    headers,
    body
  });

  if (response.status === 401 && options.redirectOn401 !== false) {
    window.location.href = "/login";
    throw new ApiError("unauthorized", response.status, null);
  }

  const parsed = await parseBody(response);
  // WHO IS ASKING, AND WHICH CUSTOMER THE SERVER RESOLVES THEM TO — carried by
  // whoami, read here rather than by a whoami request of the shell's own so the
  // banner on /choke, /devices and /fleet costs a tenant-bound console nothing.
  // See noteScopeFromResponse; it records two caption fields and grants
  // nothing.
  if (response.ok) noteScopeFromResponse(path, parsed);
  if (!response.ok) {
    const message =
      typeof parsed === "object" && parsed && "error" in parsed
        ? String((parsed as { error: unknown }).error)
        : response.statusText || `HTTP ${response.status}`;
    throw new ApiError(message, response.status, parsed);
  }

  return parsed as T;
}

export function getJSON<T>(path: string, options?: ApiOptions): Promise<T> {
  return api<T>(path, { ...options, method: "GET" });
}

export function postJSON<T>(path: string, body: unknown, options?: ApiOptions): Promise<T> {
  return api<T>(path, { ...options, method: "POST", body });
}

export function putJSON<T>(path: string, body: unknown, options?: ApiOptions): Promise<T> {
  return api<T>(path, { ...options, method: "PUT", body });
}

export function postForm<T>(path: string, form: URLSearchParams | FormData, options?: ApiOptions): Promise<T> {
  return api<T>(path, { ...options, method: "POST", form });
}

export async function copyToClipboard(value: string): Promise<boolean> {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
    return true;
  }
  const el = document.createElement("textarea");
  el.value = value;
  el.style.position = "fixed";
  el.style.opacity = "0";
  document.body.appendChild(el);
  el.select();
  const ok = document.execCommand("copy");
  document.body.removeChild(el);
  return ok;
}
