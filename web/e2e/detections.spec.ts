import { installMockApi, RequestLog } from "./support/mock-api";
import { expect, socNavItem, test } from "./support/test";

/**
 * Detections — the only SOC surface that can change what the kernel enforces.
 *
 * WHAT THESE PIN:
 *
 *  - THE SURFACE IS GATED ON WHAT THE SERVER SAYS IT CAN DO, not on which
 *    plane the console guesses it is talking to. A deployment with no Tetragon
 *    connection reports can_push_policy false and must get an explanation, not
 *    a button that cannot work.
 *  - THE PROMISE DIFFERS BY SCOPE, and so must the words. A control-plane push
 *    is DISPATCHED to a fleet and acked; an engine push is APPLIED to one host
 *    and done. The console derived this from whether `tenants` was an array,
 *    which was wrong for exactly the operator most likely to push a policy.
 *  - A COVERAGE GAP IS ONLY CLAIMED WHERE THE KERNEL STATE WAS ACTUALLY READ.
 *    This shipped wrong: the single-tenant engine sends no `loaded_agents`, so
 *    every policy read as zero and the panel announced four missing detections
 *    on a host running all four.
 *  - ENFORCE CANNOT BE ARMED FROM HERE. An enforcing policy kills with no audit
 *    row, no reversal and no kill-switch.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: the gate is a prop derived from a
 * network response and rendered through two different vocabularies. What
 * matters is the words an operator reads and the request the button sends —
 * both browser facts.
 */

const KERNEL_KNOWN_POLICIES = [
  {
    name: "override-credential-read",
    description: "Credential access",
    mitre: "T1003",
    loaded_agents: 1,
    kernel_mode: "monitor",
    expected: true,
    yaml: "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: override-credential-read\n",
    yaml_source: "host"
  },
  {
    name: "outbound-connections",
    description: "Egress watch",
    mitre: "T1071",
    loaded_agents: 0,
    kernel_mode: "",
    expected: true,
    yaml: "",
    yaml_source: ""
  }
];

async function openDetections(page: import("@playwright/test").Page) {
  await page.goto("/");
  await socNavItem(page, "Policies").click();
  const modal = page.locator('[data-panel="detections-modal"]');
  await expect(modal).toBeVisible();
  return modal;
}

test.describe("Detections", () => {
  test("hides the authoring surface where the server cannot push, and says why", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/whoami": { user: "operator", host: "mock-host", can_push_policy: false }
      }
    });
    const modal = await openDetections(page);

    await expect(modal.getByRole("button", { name: /Write or upload a detection/ })).toHaveCount(0);
    await expect(modal).toContainText("no Tetragon connection");
    // And it points at the surface that can diagnose it, rather than leaving
    // the operator to guess.
    await expect(modal).toContainText("Sensor Health");
  });

  test("a fleet deployment promises dispatch, not convergence", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/whoami": {
          user: "op-adanian",
          host: "adanian-internal",
          can_push_policy: true,
          policy_scope: "fleet",
          tenants: ["adanian-internal"]
        }
      }
    });
    const modal = await openDetections(page);

    await modal.getByRole("button", { name: /Write or upload a detection/ }).click();
    await expect(modal.getByRole("button", { name: "Dispatch signed command" })).toBeVisible();
    await expect(modal.getByRole("button", { name: "Apply to this host" })).toHaveCount(0);
  });

  test("a single-host deployment promises application to this host", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        // The engine sends no policy_scope at all; absent must default to the
        // NARROWER claim, which is what this asserts.
        "/api/whoami": { user: "admin", host: "engine-host", can_push_policy: true }
      }
    });
    const modal = await openDetections(page);

    await modal.getByRole("button", { name: /Write or upload a detection/ }).click();
    await expect(modal.getByRole("button", { name: "Apply to this host" })).toBeVisible();
    await expect(modal.getByRole("button", { name: "Dispatch signed command" })).toHaveCount(0);
  });

  test("a push is gated on a name, a body and a reason, and carries all three", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, {
      recorder,
      routes: {
        "/api/whoami": { user: "admin", host: "engine-host", can_push_policy: true },
        "/api/policies": KERNEL_KNOWN_POLICIES,
        "/api/policies/push": { ok: true, applied: 1, host: "engine-host", outcome: { "e2e-detection": "applied" } }
      }
    });
    const modal = await openDetections(page);
    await modal.getByRole("button", { name: /Write or upload a detection/ }).click();

    const apply = modal.getByRole("button", { name: "Apply to this host" });
    await expect(apply, "an empty form must not be dispatchable").toBeDisabled();

    // Start from a template rather than a blank textarea: nobody arrives
    // knowing Tetragon's dialect, and the templates are the surface's answer.
    const templates = modal.locator(".soc-detections-chip");
    expect(await templates.count(), "no detection templates were offered").toBeGreaterThan(0);
    await templates.first().click();

    // Name and body are filled by the template; the reason still is not.
    await expect(apply, "a change with no reason must stay blocked").toBeDisabled();
    await modal.getByRole("textbox", { name: /Reason/ }).fill("CAB-1234: adding egress detection");
    await expect(apply).toBeEnabled();
    await apply.click();

    const pushes = recorder.matching(/^\/api\/policies\/push$/).filter((r) => r.method !== "GET");
    expect(pushes.length, "the push never reached the server").toBeGreaterThan(0);
    const body = JSON.parse(pushes[pushes.length - 1].body ?? "{}") as {
      reason?: string;
      policies?: Array<{ name?: string; yaml?: string; mode?: string }>;
    };
    expect(body.reason).toContain("CAB-1234");
    const pushed = body.policies?.[0];
    expect(pushed?.name, "the policy must be named").toBeTruthy();
    expect(String(pushed?.yaml ?? ""), "the policy body must travel with the push").toContain("TracingPolicy");
    // Monitor, over the wire — not merely promised in the copy above the
    // button. Arming enforce is what has no audit row and no reversal.
    expect(pushed?.mode, "a push from this surface must be monitor mode").toBe("monitor");
  });

  test("states that a push lands in monitor mode and that enforce is not available here", async ({ page }) => {
    await installMockApi(page, {
      routes: { "/api/whoami": { user: "admin", host: "engine-host", can_push_policy: true } }
    });
    const modal = await openDetections(page);
    await modal.getByRole("button", { name: /Write or upload a detection/ }).click();

    await expect(modal).toContainText("monitor");
    await expect(modal).toContainText(/Enforce cannot be set from here/i);
    await expect(modal).toContainText(/no audit row|no reversal|no kill-switch/i);
  });

  /**
   * WHAT BUG THIS PINS, verbatim from the code comment it protects: "the
   * single-tenant engine does not send loaded_agents, so every policy read as
   * 0 and the panel announced '4 expected detections not loaded on any host'
   * on a host running all four."
   */
  test("claims a missing detection only where the kernel state was actually read", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        // No loaded_agents and no kernel_mode: the server did not report kernel
        // state. Unknown must not be rendered as zero.
        "/api/policies": [
          { name: "override-credential-read", description: "Credential access", mitre: "T1003", expected: true },
          { name: "outbound-connections", description: "Egress watch", mitre: "T1071", expected: true }
        ]
      }
    });
    const modal = await openDetections(page);

    await expect(
      modal,
      "a deployment that cannot report kernel state must not be told it has a coverage gap"
    ).not.toContainText(/not loaded on any host/i);
  });

  test("names a genuinely missing detection when the kernel state says so", async ({ page }) => {
    await installMockApi(page, { routes: { "/api/policies": KERNEL_KNOWN_POLICIES } });
    const modal = await openDetections(page);

    // outbound-connections reports loaded_agents 0 with kernel state known —
    // that IS a gap, and the panel must name it.
    await expect(modal).toContainText("outbound-connections");
    await expect(modal).toContainText(/not loaded|missing/i);
  });
});
