import { PASSWORD_RULES } from "../../src/lib/passwordPolicy";
import { storageStatePath } from "./support/global-setup";
import { expect, hasCredentials, hasTarget, readProbeEnv, signIn, test } from "./support/live";

/**
 * The real sign-in surface of a live deployment.
 *
 * WHY IT EXISTS DESPITE globalSetup: the rest of the probe run reuses one
 * saved session, which is what stops the engine's own brute-force guard from
 * failing the suite. That saved session comes from a real sign-in, so the flow
 * is exercised — but nothing would ASSERT on it, and "keep at least one test
 * that drives the real form, or the login page goes untested" is the whole
 * reason storageState suites rot.
 *
 * DELIBERATELY FRUGAL WITH ATTEMPTS. The engine rate-limits /api/login at
 * 5/min/IP; between globalSetup and this file a run spends two. Adding more
 * would make consecutive runs fail on the guard rather than on the product,
 * which is the harness lying about the estate.
 */

const env = readProbeEnv();

test.describe("live sign-in", () => {
  test.skip(!hasTarget(env), "Set PROBE_URL to certify a deployment");

  test("the login surface is reachable and is not the console", async ({ browser }) => {
    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      storageState: { cookies: [], origins: [] },
      serviceWorkers: "block"
    });
    const page = await context.newPage();

    try {
      await page.goto("/login", { waitUntil: "domcontentloaded" });

      // Whichever deployment this is, an anonymous visitor must land on
      // something with a credential form — the engine's own page, or Keycloak.
      const username = page.locator('input[name="username"], input[name="user"]').first();
      await expect(username, "no credential field on the login surface").toBeVisible({ timeout: 30_000 });
      await expect(page.locator('input[name="password"], input[name="pass"]').first()).toBeVisible();

      // And it is NOT the console. A login page that renders the dashboard
      // chrome behind it has already leaked the estate's shape.
      await expect(page.locator('[data-panel="left-sidebar"]')).toHaveCount(0);
      await expect(page.locator('[data-panel="kpi-row"]')).toHaveCount(0);
    } finally {
      await context.close();
    }
  });

  /**
   * A wrong password that the CLIENT will actually let you submit.
   *
   * WHY THE PASSWORD LOOKS LIKE THAT: the engine's login page disables its
   * Sign-in button until the typed password satisfies the client-side policy
   * mirror in src/lib/passwordPolicy.ts (>=14 chars, >=1 upper, >=1 lower,
   * >=3 digits, >=3 specials). A plain wrong string such as
   * "definitely-not-the-password" has no uppercase, so the button never
   * becomes enabled — and `locator.click()` waits for actionability with no
   * actionTimeout configured, so it retries until the whole test times out and
   * blames the `finally` block 180 seconds later. This value violates none of
   * the rules, so the form posts and the SERVER does the rejecting, which is
   * what this test is actually about.
   *
   * Keycloak's form has no such gate, so this matters only on the engine — but
   * the value is policy-valid on both, so one string serves both deployments.
   */
  const SUBMITTABLE_WRONG_PASSWORD = "Wr0ng-Pa55word!#9";

  // Checked against the policy itself, not against a comment. If the rules are
  // ever tightened, this fails HERE with a clear message rather than
  // reintroducing the disabled-button hang in the test below.
  test("the wrong password this file uses is itself policy-valid", () => {
    const failing = PASSWORD_RULES.filter((rule) => !rule.test(SUBMITTABLE_WRONG_PASSWORD));
    expect(
      failing.map((rule) => rule.label),
      "SUBMITTABLE_WRONG_PASSWORD must satisfy every policy rule, or the engine's login button stays disabled and the sign-in tests hang instead of failing"
    ).toEqual([]);
  });

  test("the login form refuses to submit a password that cannot meet the policy", async ({ browser }) => {
    test.skip(env.kind !== "engine", "the engine renders the policy checklist; Keycloak does not");

    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      storageState: { cookies: [], origins: [] },
      serviceWorkers: "block"
    });
    const page = await context.newPage();

    try {
      await page.goto("/login", { waitUntil: "domcontentloaded" });
      const submit = page.locator('button[type="submit"], input[type="submit"]').first();
      await page.locator('input[name="user"]').first().fill(env.user!);

      // Policy-violating: no uppercase, no digits, no specials.
      await page.locator('input[name="pass"]').first().fill("notapolicypassword");
      await expect(
        submit,
        "a password that cannot satisfy the policy must not be submittable — the engine would reject it at startup anyway"
      ).toBeDisabled();

      // The checklist tells the operator WHICH rule is failing, rather than
      // leaving them clicking a dead button.
      await expect(page.locator("body")).toContainText(/uppercase/i);

      await page.locator('input[name="pass"]').first().fill(SUBMITTABLE_WRONG_PASSWORD);
      await expect(submit, "a policy-valid password must be submittable").toBeEnabled();
    } finally {
      await context.close();
    }
  });

  test("wrong credentials are refused, and the refusal says nothing useful", async ({ browser }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");

    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      storageState: { cookies: [], origins: [] },
      serviceWorkers: "block"
    });
    const page = await context.newPage();

    try {
      await page.goto("/login", { waitUntil: "domcontentloaded" });
      const username = page.locator('input[name="username"], input[name="user"]').first();
      await username.waitFor({ state: "visible", timeout: 30_000 });

      // A REAL username with a wrong password. Using a real one matters: a
      // deployment that distinguishes "no such user" from "wrong password" is
      // handing an attacker a user-enumeration oracle, and the only way to see
      // that is to compare the two.
      await username.fill(env.user!);
      await page.locator('input[name="password"], input[name="pass"]').first().fill(SUBMITTABLE_WRONG_PASSWORD);

      const submit = page.locator('button[type="submit"], input[type="submit"]').first();
      // Bounded, and asserted rather than waited on: if the button is disabled
      // this fails in seconds naming the reason, instead of hanging until the
      // test timeout and blaming whatever line the teardown happens to be on.
      await expect(submit, "the login button never became submittable").toBeEnabled({ timeout: 10_000 });
      await submit.click();

      // Never authenticated.
      await expect
        .poll(
          async () => (await page.request.get("/api/whoami", { failOnStatusCode: false })).status(),
          { timeout: 20_000, message: "a wrong password produced a session" }
        )
        .toBe(401);

      // Still on a login surface, and the message does not say which half was
      // wrong. Rate-limiting instead of a rejection is also a correct outcome.
      const body = (await page.locator("body").innerText()).toLowerCase();
      expect(page.url()).toMatch(/\/login|\/realms\/|\/auth\//);
      expect(
        /no such user|user does not exist|unknown user|account not found/.test(body),
        "the refusal distinguishes a bad username from a bad password — that is a user-enumeration oracle"
      ).toBe(false);
    } finally {
      await context.close();
    }
  });

  test("the session cookie is not readable by scripts and is scoped to this site", async ({ browser }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");

    // Uses the shared session's cookies rather than signing in again — through
    // storageStatePath(), never a literal. The path is keyed by target, and a
    // hardcoded copy of it here is how this spec ended up reading a file the
    // config no longer writes, failing the whole run with "Error reading
    // storage state".
    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      storageState: storageStatePath(env.baseURL, env.kind),
      serviceWorkers: "block"
    });
    const page = await context.newPage();

    try {
      await page.goto("/", { waitUntil: "domcontentloaded" });
      const cookies = await context.cookies(env.baseURL);

      const session = cookies.find((cookie) => /session/i.test(cookie.name));
      expect(session, `no session cookie among: ${cookies.map((c) => c.name).join(", ")}`).toBeTruthy();
      // HttpOnly is what stops an XSS in any panel from lifting the session.
      expect(session!.httpOnly, "the session cookie is readable by scripts").toBe(true);
      expect(session!.sameSite, "the session cookie is not same-site").not.toBe("None");
      if (env.baseURL.startsWith("https://")) {
        expect(session!.secure, "the session cookie is not marked Secure on an https deployment").toBe(true);
      }

      // The CSRF token is the DOUBLE-SUBMIT half and must be readable — it is
      // read back out of document.cookie and echoed in a header. Asserting that
      // explicitly keeps someone from "hardening" it into uselessness.
      const csrf = cookies.find((cookie) => /csrf/i.test(cookie.name));
      if (csrf) {
        expect(csrf.httpOnly, "the CSRF cookie must stay script-readable — the console echoes it in a header").toBe(
          false
        );
      }
    } finally {
      await context.close();
    }
  });

  /**
   * Sign-out DESTROYS a session, so this test must own the one it destroys.
   *
   * It signed in from the shared `storageState` first, and killing that session
   * server-side left every later spec in the run unauthenticated: fourteen 401s
   * in the browser console and a cascade of failures that looked like a broken
   * deployment. A test that mutates shared state and does not own it is the
   * harness lying about the estate — the exact class this suite exists to catch.
   *
   * The extra sign-in is affordable: globalSetup spends one and the bad-password
   * test spends one, so a whole run costs three against the engine's 5/min guard.
   */
  test("signing out ends the session", async ({ browser }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");

    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      storageState: { cookies: [], origins: [] },
      serviceWorkers: "block"
    });
    const page = await context.newPage();

    try {
      await signIn(page, env, "/", { user: env.user!, password: env.password! });

      // Both deployments hang sign-out off a link the console renders; the
      // engine at /api/logout, the control plane at /auth/logout (which also
      // ends the Keycloak session).
      const logout = env.kind === "controlplane" ? "/auth/logout" : "/api/logout";
      await page.goto(logout, { waitUntil: "domcontentloaded" }).catch(() => undefined);

      await expect
        .poll(
          async () => (await page.request.get("/api/whoami", { failOnStatusCode: false })).status(),
          { timeout: 30_000, message: "the session survived sign-out" }
        )
        .toBe(401);
    } finally {
      await context.close();
    }
  });
});
