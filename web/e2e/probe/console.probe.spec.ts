import {
  expect,
  hasCredentials,
  readProbeEnv,
  readWhoami,
  signIn,
  test
} from "./support/live";

/**
 * The MULTI-TENANT control plane, specifically.
 *
 * These are the claims that are true here and NOT of the single-tenant engine:
 * an operator belongs to a tenant, a policy change reaches a fleet rather than
 * a host, "hosts" are enrolled agents rather than peer engines, and every read
 * is an authorization decision that must leave an audit record.
 *
 * WHY IT IS HERE AND NOT IN E2E: tenancy is enforced in four layers, none of
 * which exist in the frontend — the agent's client cert, the ingest stamp, the
 * store partition, and the read-time authz decision. A mock can only show the
 * console rendering whatever it is handed.
 */

const env = readProbeEnv();

test.describe("control plane", () => {
  test.skip(env.kind !== "controlplane", "PROBE_KIND=controlplane only");
  test.skip(!hasCredentials(env), "Set PROBE_URL, PROBE_USER and PROBE_PASSWORD");
  test.describe.configure({ mode: "serial" });

  test("the operator is scoped to a tenant, and the console says which", async ({ page }) => {
    await signIn(page, env);
    const whoami = await readWhoami(page);

    expect(whoami.tenants, "a control-plane operator must carry a tenant scope").toBeDefined();
    expect(whoami.tenants?.length ?? 0, "no tenant on the session").toBeGreaterThan(0);

    // A tenant analyst is NOT cross-tenant. If this ever flips for an ordinary
    // operator, the isolation guarantee is gone and nothing on screen says so.
    if (!/msoc|admin/i.test(whoami.user)) {
      expect(whoami.crossTenant, `${whoami.user} was granted cross-tenant access`).toBe(false);
    }

    await page.goto("/", { waitUntil: "domcontentloaded" });
    // The tenant is the "host" the console shows, which is what makes it
    // possible to tell at a glance whose estate is on screen.
    await expect(page.locator('[data-panel="top-bar"]')).toContainText(whoami.tenants![0]);
  });

  test("a policy change is described as reaching a fleet, not a host", async ({ page }) => {
    await signIn(page, env);
    const whoami = await readWhoami(page);
    expect(whoami.policyScope, "the control plane must state its policy scope").toBe("fleet");

    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "Policies", exact: true }).first().click();
    const modal = page.locator('[data-panel="detections-modal"]');
    await expect(modal).toBeVisible();

    if (whoami.canPushPolicy) {
      await modal.getByRole("button", { name: /Write or upload a detection/ }).click();
      // Dispatched and acked — never "applied". A fleet push cannot promise
      // convergence and the button must not imply that it can.
      await expect(modal.getByRole("button", { name: "Dispatch signed command" })).toBeVisible();
      await expect(modal.getByRole("button", { name: "Apply to this host" })).toHaveCount(0);
    }
  });

  test("the fleet view lists this tenant's enrolled agents", async ({ page }) => {
    await signIn(page, env, "/fleet");

    const response = await page.request.get("/api/fleet/hosts");
    expect(response.status()).toBe(200);
    const body = (await response.json()) as { hosts?: Array<{ name: string }> };
    const hosts = body.hosts ?? [];
    expect(hosts.length, "the control plane reported no agents for this tenant").toBeGreaterThan(0);

    // Every agent the API named is on screen. A fleet view that silently drops
    // a host is how an operator concludes a machine is not enrolled.
    for (const host of hosts) {
      await expect(page.locator("body"), `${host.name} is served but not rendered`).toContainText(host.name);
    }
  });

  test("sensor health names each agent and what it can contain", async ({ page }) => {
    await signIn(page, env);

    const response = await page.request.get("/api/sensor-health");
    expect(response.status()).toBe(200);
    const health = (await response.json()) as {
      agents?: Array<{ agent_id?: string; fresh?: boolean; containment?: { verdict?: string } }>;
      agents_total?: number;
      agents_fresh?: number;
    };
    const agents = health.agents ?? [];
    expect(agents.length, "no agents reporting to this control plane").toBeGreaterThan(0);

    // An agent that has stopped heart-beating must be counted as such. Reading
    // a silent agent as healthy is the failure that lets an estate go dark
    // while the console stays green.
    expect(health.agents_fresh ?? 0).toBeLessThanOrEqual(health.agents_total ?? agents.length);

    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "Sensor Health", exact: true }).first().click();
    const panel = page.locator('[data-panel="sensor-health-modal"]');
    await expect(panel).toBeVisible();
    for (const agent of agents) {
      if (agent.agent_id) await expect(panel).toContainText(agent.agent_id);
    }
  });

  test("the change-control queue reports its own state honestly", async ({ page }) => {
    await signIn(page, env, "/choke");

    const policy = await page.request.get("/api/approvals/policy", { failOnStatusCode: false });
    test.skip(policy.status() !== 200, "this deployment does not serve the approvals policy");
    const body = (await policy.json()) as {
      enabled?: boolean;
      requires_approval?: string[];
      never_gated?: string[];
    };

    // Both lists, always. A dual-control feature that publishes only what it
    // blocks reads as "this may block anything", and an on-call engineer who
    // believes that hesitates before containing a live threat.
    expect(Array.isArray(body.never_gated), "the never-gated list must be published").toBe(true);
    expect(body.never_gated ?? [], "release actions must never require a second operator").toEqual(
      expect.arrayContaining(["thaw"])
    );

    const queue = page.locator('[data-panel="approvals-queue"]');
    if (body.enabled) {
      // With change control ON the queue is a live surface; with it off the
      // panel must be absent rather than an empty box implying "nothing
      // pending" on a deployment where nothing is gated.
      await expect(queue).toBeVisible();
    } else {
      await expect(queue, "an approvals queue on a deployment with no gating implies a control that is not there").toHaveCount(0);
    }
  });

  test("the access trail records who read this tenant's estate", async ({ page }) => {
    await signIn(page, env);

    const response = await page.request.get("/api/operator-audit?limit=50", { failOnStatusCode: false });
    test.skip(response.status() !== 200, "this deployment does not serve the operator audit");
    const trail = (await response.json()) as {
      supported?: boolean;
      records?: Array<{ subject?: string; tenant_id?: string; cross_tenant?: boolean }>;
      viewing?: string;
    };

    if (trail.supported === false) {
      test.info().annotations.push({ type: "note", description: "operator audit is not supported here" });
      return;
    }

    const whoami = await readWhoami(page);
    const records = trail.records ?? [];
    expect(records.length, "the reads this probe just made left no audit record").toBeGreaterThan(0);

    // A tenant analyst must not be shown another tenant's access records —
    // the audit trail is itself tenant data.
    if (!whoami.crossTenant) {
      const foreign = records.filter(
        (record) => record.tenant_id && !whoami.tenants?.includes(record.tenant_id)
      );
      expect(foreign.map((r) => r.tenant_id), "the access trail leaked another tenant's records").toEqual([]);
    }
  });

  test("the assistant reports its own availability rather than failing silently", async ({ page }) => {
    await signIn(page, env);

    const response = await page.request.get("/api/assistant?surface=soc");
    // 200 with enabled:false — never a 404. A 404 is indistinguishable from a
    // routing bug and puts a red line in the console of a healthy deployment.
    expect(response.status(), "the capability endpoint must answer, enabled or not").toBe(200);
    const capability = (await response.json()) as { enabled?: boolean; agents?: unknown[] };

    // The field the console dereferences. Both servers send it unconditionally;
    // this is where that stops being an assumption.
    expect(
      Array.isArray(capability.agents),
      "the capability must always carry an agents array — the console dereferences it without a guard"
    ).toBe(true);

    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "Assistant", exact: true }).first().click();
    const sidebar = page.getByRole("complementary", { name: "Platform assistant" });
    await expect(sidebar).toBeVisible();
    if (capability.enabled) {
      await expect(sidebar, "an enabled assistant must state its read-only guarantee").toContainText("Read-only");
    } else {
      await expect(sidebar).toContainText(/not configured|unavailable/i);
    }
  });

  test("the audit chain reports gaps as gaps, not as breakage", async ({ page }) => {
    await signIn(page, env);

    const response = await page.request.get("/api/verify-chain", { failOnStatusCode: false });
    test.skip(response.status() !== 200, "this deployment does not serve chain verification");
    const chain = (await response.json()) as {
      ok?: boolean;
      broken?: number;
      incomplete?: number;
      scanned?: number;
      detail?: string;
    };

    // "Incomplete" (this server is missing records the agent still holds) and
    // "broken" (a record does not match its own hash) are different findings
    // with different severities, and only the second means tampering.
    if ((chain.incomplete ?? 0) > 0) {
      expect(chain.detail ?? "", "an incomplete chain must explain itself").not.toBe("");
      test.info().annotations.push({
        type: "note",
        description: `${chain.incomplete} agent chain(s) incomplete over ${chain.scanned ?? 0} records`
      });
    }
    expect(chain.broken ?? 0, "a record whose content does not match its own hash").toBe(0);
  });
});
