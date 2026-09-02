import { expect, hasCredentials, hasSecondTenant, readProbeEnv, readWhoami, signedInContext, test } from "./support/live";

/**
 * Tenant isolation, proved from BOTH sides, in two real browsers.
 *
 * WHAT THIS PINS: the platform's central promise. Tenancy is enforced in four
 * layers (agent cert → ingest stamp → store partition → read-time authz), and
 * a customer's whole reason for trusting an MSSP is that none of them can be
 * talked around from a console session.
 *
 * WHY IT IS HERE AND NOT IN E2E, OR IN THE GO TESTS: the Go tests prove the
 * server refuses. What they cannot prove is that a real, signed-in operator
 * with a real cookie, driving the real console, never SEES the other tenant —
 * including through a panel that forgets to pass its tenant scope, or a cached
 * response, or a shared store in the frontend.
 *
 * SHAPE: Pattern C — two independent BrowserContexts, so the two sessions have
 * genuinely separate cookie jars. `context.newPage()` would share one session
 * and the test would prove nothing.
 */

const env = readProbeEnv();

test.describe("tenant isolation", () => {
  test.skip(env.kind !== "controlplane", "isolation is a control-plane property");
  test.skip(!hasCredentials(env), "Set PROBE_URL, PROBE_USER and PROBE_PASSWORD");
  test.skip(
    !hasSecondTenant(env),
    "Set PROBE_OTHER_USER, PROBE_OTHER_PASSWORD and PROBE_OTHER_TENANT to prove isolation from both sides"
  );
  test.describe.configure({ mode: "serial" });
  test.setTimeout(240_000);

  test("two operators in two tenants never see each other's estate", async ({ browser }) => {
    const a = await signedInContext(browser, env, { user: env.user!, password: env.password! });
    const b = await signedInContext(browser, env, { user: env.otherUser!, password: env.otherPassword! });

    try {
      const whoA = await readWhoami(a.page);
      const whoB = await readWhoami(b.page);

      // Precondition: they really are different tenants, or everything below
      // passes while testing nothing.
      expect(whoA.tenants?.[0], "operator A has no tenant").toBeTruthy();
      expect(whoB.tenants?.[0], "operator B has no tenant").toBeTruthy();
      expect(whoA.tenants?.[0], "both operators resolved to the SAME tenant").not.toBe(whoB.tenants?.[0]);

      const tenantA = whoA.tenants![0];
      const tenantB = whoB.tenants![0];

      // Each console names its own tenant and never the other's.
      for (const [page, own, foreign] of [
        [a.page, tenantA, tenantB],
        [b.page, tenantB, tenantA]
      ] as const) {
        await page.goto("/", { waitUntil: "domcontentloaded" });
        await expect(page.locator('[data-panel="top-bar"]')).toContainText(own);
        await expect(
          page.locator("body"),
          `a console scoped to ${own} rendered the name of ${foreign}`
        ).not.toContainText(foreign);
      }

      // The agents are disjoint. An agent id appearing in both fleets would
      // mean the read-time scope is not being applied.
      const agentsOf = async (page: (typeof a)["page"]) => {
        const response = await page.request.get("/api/fleet/hosts");
        const body = (await response.json()) as { hosts?: Array<{ name: string }> };
        return new Set((body.hosts ?? []).map((host) => host.name));
      };
      const agentsA = await agentsOf(a.page);
      const agentsB = await agentsOf(b.page);
      expect(agentsA.size, `${tenantA} reported no agents`).toBeGreaterThan(0);
      expect(agentsB.size, `${tenantB} reported no agents`).toBeGreaterThan(0);
      const shared = [...agentsA].filter((agent) => agentsB.has(agent));
      expect(shared, "the same agent appears in two tenants' fleets").toEqual([]);
    } finally {
      await a.context.close();
      await b.context.close();
    }
  });

  test("naming another tenant explicitly is refused, and reveals nothing by refusing", async ({ browser }) => {
    const a = await signedInContext(browser, env, { user: env.user!, password: env.password! });

    try {
      const whoA = await readWhoami(a.page);
      const foreign = env.otherTenant ?? "";
      test.skip(!foreign, "Set PROBE_OTHER_TENANT to name the tenant to attempt");
      expect(whoA.tenants, "operator A has no tenant scope").not.toContain(foreign);

      for (const path of [
        `/api/choke/circuits?tenant=${encodeURIComponent(foreign)}`,
        `/api/alerts?tenant=${encodeURIComponent(foreign)}`,
        `/api/telemetry?tenant=${encodeURIComponent(foreign)}`,
        `/api/fleet/hosts?tenant=${encodeURIComponent(foreign)}`
      ]) {
        const response = await a.page.request.get(path, { failOnStatusCode: false });

        // 404, never 403. A 403 confirms the tenant EXISTS, which is itself a
        // disclosure — an MSSP's customer list should not be enumerable from a
        // tenant analyst's session (threat model §6, side channels).
        //
        // 200 is tolerated ONLY when the response is scoped to the caller's own
        // tenant, i.e. the parameter was ignored rather than honoured. That is
        // a valid implementation; leaking the other tenant's rows is not.
        if (response.status() === 200) {
          const text = await response.text();
          expect(
            text.includes(foreign),
            `${path} answered 200 with ${foreign}'s data in the body`
          ).toBe(false);
          continue;
        }
        expect([401, 404], `${path} answered ${response.status()}`).toContain(response.status());
        expect(
          response.status(),
          `${path} answered 403, which confirms ${foreign} exists — the refusal must not be a side channel`
        ).not.toBe(403);
      }
    } finally {
      await a.context.close();
    }
  });

  test("a containment action cannot be aimed at another tenant", async ({ browser }) => {
    const a = await signedInContext(browser, env, { user: env.user!, password: env.password! });

    try {
      const foreign = env.otherTenant ?? "";
      test.skip(!foreign, "Set PROBE_OTHER_TENANT to name the tenant to attempt");

      // Sent with the console's own CSRF token, from the console's own origin —
      // so what is under test is the AUTHORIZATION decision, not the CSRF gate.
      const csrf = await a.page.evaluate(
        () => document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/)?.[1] ?? ""
      );
      const response = await a.page.request.post(
        `/api/choke/manual?tenant=${encodeURIComponent(foreign)}`,
        {
          failOnStatusCode: false,
          headers: { "content-type": "application/json", "X-CSRF-Token": csrf },
          data: {
            exec_id: "isolation-probe-does-not-exist",
            action: "throttle",
            reason: "isolation probe — must be refused"
          }
        }
      );

      // A write into another tenant must be refused outright. Throttle is the
      // gentlest rung on the ladder deliberately: if even that crosses the
      // boundary, every rung above it does too.
      expect(
        [400, 401, 404],
        `a cross-tenant containment write answered ${response.status()}`
      ).toContain(response.status());
      expect(response.status(), "a cross-tenant write must not be confirmed").not.toBe(200);
    } finally {
      await a.context.close();
    }
  });
});
