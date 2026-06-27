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

type StorageState = {
  cookies: Array<{ name: string; value: string; domain: string; path: string }>;
  origins: unknown[];
};

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

  const storageState = (await api.storageState()) as StorageState;
  const csrfToken = cookieValue(storageState, "csrf_token");
  const session = cookieValue(storageState, "soc_session");

  expect(session).toBeTruthy();
  expect(csrfToken).toBeTruthy();

  return { csrfToken, storageState };
}

export function cookieValue(storageState: StorageState, name: string): string | undefined {
  return storageState.cookies.find((cookie) => cookie.name === name)?.value;
}

export function requestOptionsForEndpoint(endpoint: UnsafeWriteEndpoint) {
  return {
    failOnStatusCode: false,
    method: endpoint.method,
    ...(endpoint.encoding === "form"
      ? { form: endpoint.body }
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
