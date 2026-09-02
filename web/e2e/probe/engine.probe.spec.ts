import { expect, hasCredentials, readProbeEnv, readWhoami, signIn, test } from "./support/live";

/**
 * The SINGLE-TENANT engine, specifically.
 *
 * The claims that are true here and NOT of the control plane: this process IS
 * the host it defends, so a policy change is APPLIED rather than dispatched;
 * there is no tenant scope; and the console is served out of the binary itself
 * by go:embed rather than by nginx from a directory.
 *
 * That last one matters more than it sounds: `go build ./cmd/engine` compiles
 * happily and ships whatever was in web/dist at the time, so an engine can
 * serve a months-old console with no error anywhere. The asset probe below is
 * the only automated thing that can see it.
 */

const env = readProbeEnv();

test.describe("single-tenant engine", () => {
  test.skip(env.kind !== "engine", "PROBE_KIND=engine only");
  test.skip(!hasCredentials(env), "Set PROBE_URL, PROBE_USER and PROBE_PASSWORD");
  test.describe.configure({ mode: "serial" });

  test("reports itself as one host, with no tenant scope", async ({ page }) => {
    await signIn(page, env);
    const whoami = await readWhoami(page);

    expect(whoami.user).not.toBe("");
    // No tenants array: the engine IS the estate it can see. A console that
    // invented one would be claiming an isolation boundary that is not there.
    expect(whoami.tenants, "the engine must not claim a tenant scope").toBeUndefined();
    // Absent policy_scope means "host" — the narrower claim, and the correct
    // default for a server that has not grown the field.
    expect(whoami.policyScope ?? "host").toBe("host");
  });

  test("a policy change is described as applying to this host", async ({ page }) => {
    await signIn(page, env);
    const whoami = await readWhoami(page);

    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "Policies", exact: true }).first().click();
    const modal = page.locator('[data-panel="detections-modal"]');
    await expect(modal).toBeVisible();

    if (!whoami.canPushPolicy) {
      // No Tetragon connection: the surface must explain itself rather than
      // offering a control that cannot work.
      await expect(modal).toContainText(/no Tetragon connection/i);
      return;
    }
    await modal.getByRole("button", { name: /Write or upload a detection/ }).click();
    await expect(modal.getByRole("button", { name: "Apply to this host" })).toBeVisible();
    await expect(modal.getByRole("button", { name: "Dispatch signed command" })).toHaveCount(0);
  });

  test("the console it serves is the console that was built for it", async ({ page }) => {
    await signIn(page, env);

    // WHAT BUG THIS PINS: the engine embeds web/dist with go:embed, staged by
    // the Makefile's `web` target. Building with `go build` instead of
    // `make build-linux` compiles fine and ships a STALE console — no error,
    // no warning, and the only symptom is a UI that is missing a change
    // someone is sure they deployed.
    const html = await (await page.request.get("/")).text();
    const scripts = [...html.matchAll(/src="(\/assets\/[^"]+\.js)"/g)].map((match) => match[1]);
    expect(scripts.length, "the served shell references no built script").toBeGreaterThan(0);

    for (const script of scripts) {
      const response = await page.request.get(script, { failOnStatusCode: false });
      expect(response.status(), `${script} is referenced but not served`).toBe(200);
      expect(
        (await response.text()).length,
        `${script} is served empty — the embed staged nothing`
      ).toBeGreaterThan(1000);
    }

    // The filename carries a content hash, so recording it in the run makes a
    // "did my deploy land?" question answerable from the report alone.
    test.info().annotations.push({ type: "note", description: `served assets: ${scripts.join(", ")}` });
  });

  test("system health answers for the sensor this host actually runs", async ({ page }) => {
    await signIn(page, env);

    const response = await page.request.get("/api/system-health");
    expect(response.status()).toBe(200);
    const health = (await response.json()) as {
      tetragon?: { connected?: boolean };
      bpf?: { healthy?: boolean; attached_links?: number; expected_links?: number };
      store?: { backend?: string };
    };

    // Unlike the control plane, this process can see the kernel — so an
    // "unknown" here would be a real regression rather than an honest limit.
    expect(health.tetragon, "the engine must report its sensor connection").toBeDefined();
    expect(health.store?.backend, "the engine must name its store backend").toBeTruthy();

    if (health.bpf && health.bpf.healthy === false) {
      test.info().annotations.push({
        type: "warning",
        description: `BPF links degraded: ${health.bpf.attached_links ?? "?"} of ${health.bpf.expected_links ?? "?"} attached`
      });
    }
  });

  test("the fleet view is configured, and says so when it is not", async ({ page }) => {
    await signIn(page, env, "/fleet");

    const response = await page.request.get("/api/fleet/hosts", { failOnStatusCode: false });
    if (response.status() === 503) {
      // An unconfigured feature must read as unconfigured. Before the engine
      // defaulted its fleet list to itself on loopback, this whole route
      // answered 503 and rendered as a broken page rather than an unused one.
      await expect(page.locator("body")).toContainText(/not configured|unavailable|disabled/i);
      return;
    }
    expect(response.status()).toBe(200);
    const body = (await response.json()) as { hosts?: Array<{ name: string; url: string }> };
    expect((body.hosts ?? []).length, "the fleet list is served but empty").toBeGreaterThan(0);
    for (const host of body.hosts ?? []) {
      await expect(page.locator("body"), `${host.name} is served but not rendered`).toContainText(host.name);
    }
  });

  test("the audit chain verifies", async ({ page }) => {
    await signIn(page, env);
    const response = await page.request.get("/api/verify-chain", { failOnStatusCode: false });
    test.skip(response.status() !== 200, "this build does not serve chain verification");

    const chain = (await response.json()) as { ok?: boolean; total?: number };
    expect(chain.ok, "the containment audit chain does not verify on this host").toBe(true);
    test.info().annotations.push({ type: "note", description: `${chain.total ?? 0} audited decisions` });
  });
});
