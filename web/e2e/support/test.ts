import {
  expect,
  test as base,
  type APIRequestContext,
  type Page
} from "@playwright/test";

import {
  RUNTIME_CDN_PATTERNS,
  type UnsafeWriteEndpoint
} from "./contracts";

type ProcessGlobal = typeof globalThis & {
  process?: { env?: Record<string, string | undefined> };
};

export type EbpfEnv = {
  baseURL: string;
  targetVmURL?: string;
  username?: string;
  password?: string;
  expectEmbedded: boolean;
  runSafeAttack: boolean;
  runWrites: boolean;
};

export type HttpIssue = {
  url: string;
  status: number;
  resourceType: string;
};

export type BrowserDiagnostics = {
  consoleErrors: string[];
  pageErrors: string[];
  requestUrls: string[];
  httpIssues: HttpIssue[];
};

/**
 * Playwright's own storage-state shape, taken from the API rather than
 * re-declared. The hand-written version was structurally narrower (no
 * `expires`/`httpOnly`/`secure`/`sameSite`), so every spec that fed it back
 * into `browser.newContext({ storageState })` was a type error — invisible
 * until the e2e directory was brought into `tsc`.
 */
export type StorageState = Awaited<ReturnType<APIRequestContext["storageState"]>>;

export function readEbpfEnv(): EbpfEnv {
  const env = (globalThis as ProcessGlobal).process?.env ?? {};
  return {
    baseURL:
      env.EBPF_WEB_BASE_URL ?? env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:5173",
    targetVmURL: env.EBPF_TARGET_VM_URL,
    username: env.EBPF_E2E_USER,
    password: env.EBPF_E2E_PASSWORD,
    expectEmbedded: env.EBPF_EXPECT_EMBEDDED === "1",
    runSafeAttack: env.EBPF_E2E_RUN_SAFE_ATTACK === "1",
    runWrites: env.EBPF_E2E_RUN_WRITES === "1"
  };
}

export const test = base.extend<{ ebpf: EbpfEnv }>({
  ebpf: async ({}, use) => {
    await use(readEbpfEnv());
  }
});

export { expect };

/**
 * Reports whether a live engine is reachable behind the Vite proxy.
 *
 * Two specs in auth.spec.ts assert the ENGINE's auth contract (the 303 redirect
 * on bad credentials, the JSON 401 envelope) rather than the console's, so they
 * need a real backend on :8080. They had no guard, which made them pass on a
 * developer machine that happens to be running the local stack and fail in CI
 * with ECONNREFUSED — the mocked-API suite is supposed to need no backend at all.
 *
 * Probing rather than reading a flag is deliberate: the question is whether a
 * backend is actually answering, not whether someone remembered to set a
 * variable.
 */
export async function hasBackend(api: APIRequestContext): Promise<boolean> {
  try {
    const res = await api.get("/api/whoami", { failOnStatusCode: false, timeout: 3000 });
    // Status, not merely "did it resolve". The Vite dev server PROXIES /api to
    // the engine, so when nothing is listening it answers 502 itself rather than
    // refusing the connection — a try/catch alone sees a successful response and
    // concludes a backend exists. A live engine answers this route 401 by
    // contract; anything 5xx is the proxy reporting it could not reach one.
    return res.status() < 500;
  } catch {
    return false;
  }
}

export function hasCredentials(
  env: EbpfEnv
): env is EbpfEnv & { username: string; password: string } {
  return Boolean(env.username && env.password);
}

export async function loginByApi(
  api: APIRequestContext,
  env: EbpfEnv
): Promise<{ csrfToken: string; storageState: StorageState }> {
  if (!hasCredentials(env)) {
    throw new Error("EBPF_E2E_USER and EBPF_E2E_PASSWORD are required");
  }

  const response = await api.post("/api/login", {
    failOnStatusCode: false,
    form: { user: env.username, pass: env.password },
    maxRedirects: 0
  });

  expect(response.status(), await response.text()).toBe(303);

  const storageState = await api.storageState();
  const csrfToken = cookieValue(storageState, "csrf_token");
  const session = cookieValue(storageState, "soc_session");

  expect(session, "login did not set a session cookie").toBeTruthy();
  expect(csrfToken, "login did not set a CSRF cookie").toBeTruthy();

  return { csrfToken: csrfToken as string, storageState };
}

export function cookieValue(storageState: StorageState, name: string): string | undefined {
  return storageState.cookies.find((cookie) => cookie.name === name)?.value;
}

export function requestOptionsForEndpoint(endpoint: UnsafeWriteEndpoint) {
  return {
    failOnStatusCode: false,
    method: endpoint.method,
    // A form body is url-encoded, so Playwright's type only admits scalars.
    // The contract's bodies are `Record<string, unknown>` because the JSON
    // endpoints carry arrays and objects; narrowing here is what keeps the one
    // shared inventory usable by both encodings.
    ...(endpoint.encoding === "form"
      ? { form: endpoint.body as Record<string, string | number | boolean> }
      : { data: endpoint.body })
  };
}

export function attachBrowserDiagnostics(page: Page): BrowserDiagnostics {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const requestUrls: string[] = [];
  const httpIssues: HttpIssue[] = [];

  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(message.text());
    }
  });
  page.on("pageerror", (error) => {
    pageErrors.push(error.message);
  });
  page.on("request", (request) => {
    requestUrls.push(request.url());
  });
  page.on("response", (response) => {
    if (response.status() >= 400) {
      httpIssues.push({
        url: response.url(),
        status: response.status(),
        resourceType: response.request().resourceType()
      });
    }
  });

  return { consoleErrors, pageErrors, requestUrls, httpIssues };
}

export function expectNoReleaseBlockingBrowserErrors(
  diagnostics: BrowserDiagnostics,
  options: { allowOptionalDisabledApi503?: boolean } = {}
) {
  const allowedDisabledApiIssues = options.allowOptionalDisabledApi503
    ? diagnostics.httpIssues.filter(isExpectedOptionalDisabledApi503)
    : [];
  const releaseBlockingHttpIssues = diagnostics.httpIssues.filter(
    (issue) => !allowedDisabledApiIssues.includes(issue)
  );
  let remainingAllowedResource503ConsoleErrors = allowedDisabledApiIssues.length;
  const releaseBlockingConsoleErrors = diagnostics.consoleErrors.filter((message) => {
    if (
      remainingAllowedResource503ConsoleErrors > 0 &&
      /Failed to load resource: the server responded with a status of 503/.test(message)
    ) {
      remainingAllowedResource503ConsoleErrors -= 1;
      return false;
    }
    return true;
  });

  expect(releaseBlockingHttpIssues).toEqual([]);
  expect([...releaseBlockingConsoleErrors, ...diagnostics.pageErrors]).toEqual([]);
}

export function expectNoCdnRequests(requestUrls: string[]) {
  const cdnRequests = requestUrls.filter((rawUrl) => {
    try {
      const url = new URL(rawUrl);
      return RUNTIME_CDN_PATTERNS.some(
        (pattern) => pattern.test(url.hostname) || pattern.test(rawUrl)
      );
    } catch {
      return false;
    }
  });

  expect(cdnRequests).toEqual([]);
}

function isExpectedOptionalDisabledApi503(issue: HttpIssue): boolean {
  if (issue.status !== 503) return false;
  try {
    const path = new URL(issue.url).pathname;
    return [
      "/api/fleet/hosts",
      "/api/fleet/state",
      "/api/fleet/cgroups",
      "/api/fleet/decisions",
      "/api/fleet/alerts",
      "/api/fleet/devices",
      "/api/choke/device-state",
      "/api/choke/devices",
      "/api/choke/device-flows"
    ].includes(path);
  } catch {
    return false;
  }
}

export async function expectRouteRoot(page: Page) {
  await expect(page.locator("#root")).toBeAttached();
}

/**
 * A SOC sidebar TOOL button, disambiguated from the collapsible section header
 * that can carry the same name.
 *
 * "Settings" is both a nav item (under Manage) and a section header, so
 * `getByRole("button", { name: "Settings" })` is a strict-mode violation.
 * Resolving it with `.first()` would work only for as long as the two keep
 * their current DOM order, which is not a property any test should depend on.
 */
export function socNavItem(page: Page, label: string) {
  return page
    .getByRole("button", { name: label, exact: true })
    .and(page.locator("button.soc-sidebar-item"));
}

/** A SOC sidebar ROUTE link (Dashboard, Choke Gateway, Device Choke, Sign out). */
export function socNavLink(page: Page, label: string) {
  return page
    .getByRole("link", { name: label, exact: true })
    .and(page.locator("a.soc-sidebar-item"));
}

/**
 * The sidebar control for a SURFACE, resolved by what that control actually is.
 *
 * Most surfaces are opened by a button. The Fleet Console is opened by an
 * anchor — it is still `<a href="/fleet">` so bookmarks, the live probe's
 * sign-in target and the palette's route entry keep working, and a plain left
 * click opens the surface in place instead of navigating. Asking for it by the
 * wrong role does not fail loudly: `getByRole("button")` simply finds nothing,
 * which reads as "the surface is missing" in one caller and passes VACUOUSLY in
 * another that asserts a count of zero. So the contract carries `navIsLink` and
 * this helper honours it, rather than each call site guessing.
 */
export function socNavControl(page: Page, surface: { nav: string; navIsLink?: boolean }) {
  return surface.navIsLink ? socNavLink(page, surface.nav) : socNavItem(page, surface.nav);
}
