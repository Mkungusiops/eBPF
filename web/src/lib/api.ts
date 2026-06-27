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

  const response = await fetch(path, {
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
