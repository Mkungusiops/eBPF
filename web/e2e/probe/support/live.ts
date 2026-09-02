import {
  expect,
  test as base,
  type Browser,
  type BrowserContext,
  type Locator,
  type Page
} from "@playwright/test";

type ProcessGlobal = typeof globalThis & {
  process?: { env?: Record<string, string | undefined> };
};

/**
 * The two deployments this console serves, and how you get into each.
 *
 * They are NOT variations on a theme. They authenticate differently (a form
 * post to the engine's own /api/login versus an OIDC code flow through
 * Keycloak), they serve the SPA differently (go:embed in the engine binary
 * versus nginx from /var/www/console), and they answer several routes with
 * different JSON shapes. A probe that assumed one of them would either skip
 * silently or fail for the wrong reason on the other.
 */
export type DeploymentKind = "engine" | "controlplane";

export interface ProbeEnv {
  baseURL: string;
  kind: DeploymentKind;
  user?: string;
  password?: string;
  /** Second tenant's operator, for the isolation probe. */
  otherUser?: string;
  otherPassword?: string;
  otherTenant?: string;
  /**
   * The cross-tenant MSOC admin.
   *
   * Not a nicer analyst — a different KIND of principal. It is what makes the
   * isolation probes conclusive: a tenant analyst denied another tenant's data
   * gets a 404, which on its own is indistinguishable from a route that is
   * broken for everybody. The same path answering 200 for this operator is the
   * positive control that turns "denied" into a proven authorization decision.
   */
  adminUser?: string;
  adminPassword?: string;
  /**
   * A READ-ONLY operator: `read-only` in authz.go, tenant-bound, read but NOT
   * respond.
   *
   * The reason this persona matters more than the others: the control plane
   * publishes `can_respond` in whoami, and authz.CanRespond's own comment says
   * "The console uses it to enable/disable action controls" — but the console
   * never reads the field (normalizeWhoami picks user/host/role/
   * can_push_policy/policy_scope and stops). So a read-only operator is shown
   * every containment control fully enabled and every press is refused by the
   * server. Nothing can observe that without a read-only session to drive.
   */
  readOnlyUser?: string;
  readOnlyPassword?: string;
  /**
   * A `cross-tenant-responder`: cross-tenant reach, read + respond, but NOT the
   * msoc-admin role. It exists to prove the console keys off the CAPABILITY
   * rather than off the one role name it happens to know.
   */
  responderUser?: string;
  responderPassword?: string;
  /** Opt-in: probes that CHANGE estate state stay off unless this is set. */
  allowWrites: boolean;
}

export function readProbeEnv(): ProbeEnv {
  const env = (globalThis as ProcessGlobal).process?.env ?? {};
  const baseURL = env.PROBE_URL ?? "";
  const declared = env.PROBE_KIND as DeploymentKind | undefined;
  return {
    baseURL,
    // Inferred from the hostname when not declared, because getting this wrong
    // silently is worse than a wrong default: the sign-in flows differ.
    kind: declared ?? (/console/i.test(baseURL) ? "controlplane" : "engine"),
    user: env.PROBE_USER,
    password: env.PROBE_PASSWORD,
    otherUser: env.PROBE_OTHER_USER,
    otherPassword: env.PROBE_OTHER_PASSWORD,
    otherTenant: env.PROBE_OTHER_TENANT,
    adminUser: env.PROBE_ADMIN_USER,
    adminPassword: env.PROBE_ADMIN_PASSWORD,
    readOnlyUser: env.PROBE_RO_USER,
    readOnlyPassword: env.PROBE_RO_PASSWORD,
    responderUser: env.PROBE_XR_USER,
    responderPassword: env.PROBE_XR_PASSWORD,
    allowWrites: env.PROBE_ALLOW_WRITES === "1"
  };
}

export const test = base.extend<{ probe: ProbeEnv }>({
  probe: async ({}, use) => {
    await use(readProbeEnv());
  }
});

export { expect };

export function hasTarget(env: ProbeEnv): boolean {
  return Boolean(env.baseURL);
}

export function hasCredentials(env: ProbeEnv): env is ProbeEnv & { user: string; password: string } {
  return Boolean(env.baseURL && env.user && env.password);
}

export function hasSecondTenant(
  env: ProbeEnv
): env is ProbeEnv & { otherUser: string; otherPassword: string } {
  return Boolean(env.otherUser && env.otherPassword);
}

export function hasReadOnlyOperator(
  env: ProbeEnv
): env is ProbeEnv & { readOnlyUser: string; readOnlyPassword: string } {
  return Boolean(env.readOnlyUser && env.readOnlyPassword);
}

export function hasCrossTenantResponder(
  env: ProbeEnv
): env is ProbeEnv & { responderUser: string; responderPassword: string } {
  return Boolean(env.responderUser && env.responderPassword);
}

export function hasCrossTenantAdmin(
  env: ProbeEnv
): env is ProbeEnv & { adminUser: string; adminPassword: string } {
  return Boolean(env.adminUser && env.adminPassword);
}

/**
 * Signs in and lands on `path`.
 *
 * The engine posts a form to its own /api/login and lands wherever it was
 * asked. The control plane bounces to Keycloak on the SAME origin (nginx
 * proxies /realms) and comes back through /auth/callback — navigating during
 * that callback aborts the code exchange and leaves the browser silently
 * unauthenticated, which is why the redirect chain is waited out rather than
 * assumed.
 */
export async function signIn(
  page: Page,
  env: ProbeEnv,
  path = "/",
  who: { user: string; password: string } = { user: env.user ?? "", password: env.password ?? "" }
): Promise<void> {
  await page.goto(path, { waitUntil: "domcontentloaded" });

  const username = page.locator('input[name="username"], input[name="user"]').first();
  await username.waitFor({ state: "visible", timeout: 30_000 }).catch(() => undefined);

  // Whether a form appeared at all is worth recording. With a healthy cached
  // session it should not: a run that re-authenticates has a stale or
  // wrong-target state file, and knowing that from the report is the
  // difference between "the estate is fine" and four minutes of confusion.
  const hadToAuthenticate = (await username.count()) > 0;

  if (hadToAuthenticate) {
    await username.fill(who.user);
    await page.locator('input[name="password"], input[name="pass"]').first().fill(who.password);
    await page.locator('button[type="submit"], input[type="submit"]').first().click();

    const origin = new URL(env.baseURL).origin;
    await page
      .waitForURL((url) => url.origin === origin && !url.pathname.startsWith("/auth/") && !/\/realms\//.test(url.pathname), {
        timeout: 60_000
      })
      .catch(() => undefined);
  }

  if (new URL(page.url()).pathname !== path) {
    await page.goto(path, { waitUntil: "domcontentloaded" });
  }

  if (hadToAuthenticate) {
    try {
      test.info().annotations.push({
        type: "note",
        description:
          "signIn had to re-authenticate — the cached session was absent or dead. Expect boot-time 401s before this point."
      });
    } catch {
      // Called outside a test (globalSetup). Nothing to annotate; not an error.
    }
  }

  // Prove the session, or every assertion after this is about a login page.
  await expect
    .poll(
      async () => {
        const response = await page.request.get("/api/whoami", { failOnStatusCode: false });
        return response.status();
      },
      { timeout: 30_000, message: "sign-in did not produce an authenticated session" }
    )
    .toBe(200);
}

/**
 * A signed-in context of its own, for tests that need two identities at once.
 *
 * `storageState` is EXPLICITLY EMPTY. `browser.newContext()` inherits the
 * config's `use`, which carries the run's shared signed-in session — so
 * omitting it handed back a context that was already authenticated as the
 * FIRST operator. `signIn` then found no login form, skipped straight past it,
 * and both "tenants" resolved to the same one. The isolation spec's
 * precondition caught it; without that assertion the suite would have reported
 * a passing tenant-isolation proof while testing one operator twice.
 */
export async function signedInContext(
  browser: Browser,
  env: ProbeEnv,
  who: { user: string; password: string },
  path = "/"
): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({
    baseURL: env.baseURL,
    ignoreHTTPSErrors: true,
    viewport: { width: 1600, height: 1000 },
    storageState: { cookies: [], origins: [] },
    serviceWorkers: "block"
  });
  const page = await context.newPage();
  await signIn(page, env, path, who);
  return { context, page };
}

/** Whoami, normalised across the two deployments' different envelopes. */
export interface Whoami {
  user: string;
  host?: string;
  tenants?: string[];
  crossTenant?: boolean;
  canRespond?: boolean;
  canPushPolicy?: boolean;
  policyScope?: string;
}

export async function readWhoami(page: Page): Promise<Whoami> {
  const response = await page.request.get("/api/whoami");
  expect(response.status(), "whoami must answer for a signed-in operator").toBe(200);
  const body = (await response.json()) as Record<string, unknown>;
  return {
    user: String(body.user ?? body.subject ?? ""),
    host: body.host ? String(body.host) : undefined,
    tenants: Array.isArray(body.tenants) ? (body.tenants as string[]) : undefined,
    crossTenant: body.cross_tenant === true,
    canRespond: body.can_respond === true,
    canPushPolicy: body.can_push_policy === true,
    policyScope: body.policy_scope ? String(body.policy_scope) : undefined
  };
}

/**
 * Console noise that a live deployment legitimately produces.
 *
 * Kept short and specific on purpose: a permissive filter here is how a real
 * console error gets ignored for a year.
 */
export const LIVE_CONSOLE_NOISE = [
  /Download the React DevTools/i,
  // The PWA worker is blocked by the probe config, so its registration failure
  // is caused by the test harness, not by the deployment.
  /ServiceWorker|serviceWorker registration/i,
  // Chrome logs this for any favicon the page does not define at every size.
  /Failed to load resource: the server responded with a status of 404 \(\)$/
];

export function releaseBlocking(messages: string[]): string[] {
  return messages.filter((message) => !LIVE_CONSOLE_NOISE.some((pattern) => pattern.test(message)));
}

// ── reading a live surface ─────────────────────────────────────────────────
// Three shapes every probe spec needs, kept here so the suite has one idiom
// rather than one per file. Each was first written inline, twice.

/**
 * Poll `check` until it is true, and answer whether it got there — without
 * throwing, so the caller can collect a Failure instead of aborting the run.
 *
 * The suite's house rule is that a probe reports every problem it found, not
 * just the first. A bare `await expect(...)` ends the test at problem one and
 * throws away the rest of the sweep, which on a 40-second live navigation is
 * most of what the run was for.
 *
 * `intervals` is for a surface that settles in bursts rather than smoothly —
 * a d3 canvas mid-transition, say — where the default backoff samples at the
 * wrong moments.
 */
export async function settles(
  check: () => Promise<boolean>,
  timeout = 10_000,
  intervals?: number[]
): Promise<boolean> {
  return expect
    .poll(check, intervals ? { timeout, intervals } : { timeout })
    .toBe(true)
    .then(() => true)
    .catch(() => false);
}

/**
 * An element's text as authored, whitespace-collapsed.
 *
 * textContent, NEVER innerText. Chromium's innerText returns *rendered* text,
 * which applies CSS text-transform — and this console uppercases at least three
 * families of label in CSS (`.soc-sidebar-label`, `.enf-ladder-rung` /
 * `.soc-stat-label`, `span.soc-ack`). Comparing innerText against the casing in
 * the source therefore fails 100% of the time on a healthy console, which is
 * the exact class of fabricated finding this suite exists to avoid. All three
 * were found that way, in review, in drafts that looked right.
 */
export async function readText(target: Locator): Promise<string> {
  const raw = (await target.textContent({ timeout: 3_000 }).catch(() => null)) ?? "";
  return raw.replace(/\s+/g, " ").trim();
}

/** Whether an element carries a class, as a token — not as a substring. */
export async function hasClass(target: Locator, name: string): Promise<boolean> {
  const attr = (await target.getAttribute("class").catch(() => null)) ?? "";
  return attr.split(/\s+/).includes(name);
}
