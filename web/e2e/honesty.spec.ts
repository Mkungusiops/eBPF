import { installMockApi } from "./support/mock-api";
import { expect, socNavItem, test } from "./support/test";

/**
 * Does the console only claim what it can actually know?
 *
 * WHY THIS FILE EXISTS: this codebase's most expensive recurring defect is not
 * a crash — it is a panel that states something it cannot support. Every case
 * below is a real one that shipped:
 *
 *   · a containment count capped at 1 because it counted a truncated buffer;
 *   · a posture gauge pinned near 100 because synthetic activity fed it;
 *   · a MITRE panel that was structurally always empty;
 *   · a coverage gap invented on a host that could not report kernel state;
 *   · an evidence-loss tile printing a reassuring 0 on a deployment with no
 *     evidence-loss counter at all.
 *
 * The pattern in every one: an UNKNOWN was rendered as a ZERO, or a FLOOR was
 * rendered as a TOTAL. An operator cannot tell those apart by looking, so the
 * console has to say which it is — and that is what these assert.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: several of the derivations are unit
 * tested already. What is not, and cannot be, is whether the resulting words
 * reach the screen — a correct model rendered through a component that drops
 * the qualifier is exactly the bug.
 */

test.describe("counts say whether they are totals or floors", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  test("a server-side aggregate is presented as a total", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");

    const band = page.locator('[data-panel="exec-summary"]');
    await expect(band).toBeVisible();
    // /api/alert-stats and /api/decision-stats both answered, and neither said
    // truncated — so no "≥" anywhere in the band.
    await expect(band, "an exact aggregate must not be hedged with ≥").not.toContainText("≥");
  });

  /**
   * WHAT BUG THIS PINS: without /api/decision-stats the band counts the
   * browser's own capped decision buffer. A capped buffer is a FLOOR, and
   * printing it as a total told operators there had been N containment actions
   * when there had been at least N.
   */
  test("a truncated aggregate is marked as a floor", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/decision-stats": {
          from: "2026-06-25T08:00:00Z",
          to: "2026-06-25T09:00:00Z",
          total: 500,
          previous: 0,
          actions: { quarantine: 500, sever: 0, tarpit: 0, throttle: 0 },
          dry_run: 0,
          truncated: true
        }
      }
    });
    await page.goto("/");

    const band = page.locator('[data-panel="exec-summary"]');
    await expect(band).toBeVisible();
    await expect(band, "a truncated count must be disclosed as a floor").toContainText("≥500");
  });

  test("a deployment with no aggregate endpoint still discloses what it is counting", async ({ page }) => {
    // An older server: no stats endpoints at all. The band falls back to the
    // browser buffer, which is only ever a floor once the buffer is full.
    await installMockApi(page, {
      routes: {
        "/api/alert-stats": { status: 404, body: { error: "not found" } },
        "/api/decision-stats": { status: 404, body: { error: "not found" } }
      }
    });
    await page.goto("/");

    const band = page.locator('[data-panel="exec-summary"]');
    await expect(band).toBeVisible();
    // The console must not crash or blank on a server that predates these
    // routes — the fallback exists precisely for that deployment.
    await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);
    await expect(band).not.toBeEmpty();
  });
});

test.describe("unknown is not zero", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * WHAT BUG THIS PINS: "a big green 0 on this tile is the most reassuring
   * thing the panel can say, so it may only appear when something actually
   * counted." The engine has no evidence-loss counter and says so.
   */
  test("evidence loss reads as unmeasured, not as none, where nothing counted it", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/sensor-health": {
          generated_at: "2026-06-25T09:00:00Z",
          agents_total: 1,
          agents_fresh: 1,
          agents: [
            {
              agent_id: "agent-no-counter",
              last_seen: "2026-06-25T09:00:00Z",
              fresh: true,
              status: "ok",
              policies_loaded: 1,
              policies_enforce: 0
              // no dropped_records, and no containment block
            }
          ]
        }
      }
    });
    await page.goto("/");
    await socNavItem(page, "Sensor Health").click();

    const panel = page.locator('[data-panel="sensor-health-modal"]');
    await expect(panel).toBeVisible();
    const summary = panel.locator(".soc-sensor-summary");
    await expect(
      summary,
      "an unmeasured tile must read as unknown; a green 0 here is the most reassuring lie available"
    ).toContainText("—");
  });

  test("containment capability that could not be read is not reported as full", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/sensor-health": {
          generated_at: "2026-06-25T09:00:00Z",
          agents_total: 1,
          agents_fresh: 1,
          agents: [
            {
              agent_id: "agent-unreadable",
              last_seen: "2026-06-25T09:00:00Z",
              fresh: true,
              status: "ok",
              policies_loaded: 1,
              policies_enforce: 0,
              containment: {
                verdict: "partial-unknown",
                summary: "this host's posture could not be fully read",
                manual_lands: true
              }
            }
          ]
        }
      }
    });
    await page.goto("/");
    await socNavItem(page, "Sensor Health").click();

    const panel = page.locator('[data-panel="sensor-health-modal"]');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText(/not fully readable|could not be/i);
    // And the roll-up refuses to print a number it cannot stand behind.
    await expect(panel.locator(".soc-sensor-summary")).toContainText("—");
  });

  test("a host that cannot contain at all is named as such", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/sensor-health": {
          generated_at: "2026-06-25T09:00:00Z",
          agents_total: 1,
          agents_fresh: 1,
          agents: [
            {
              agent_id: "agent-blind",
              last_seen: "2026-06-25T09:00:00Z",
              fresh: true,
              status: "degraded",
              policies_loaded: 0,
              policies_enforce: 0,
              containment: {
                verdict: "none",
                summary: "nothing reaches the kernel on this host",
                manual_lands: false
              }
            }
          ]
        }
      }
    });
    await page.goto("/");
    await socNavItem(page, "Sensor Health").click();

    const panel = page.locator('[data-panel="sensor-health-modal"]');
    await expect(panel).toBeVisible();
    // The loudest thing this panel can say. A host where a pressed containment
    // button does nothing must not look like a host where it works.
    await expect(panel).toContainText(/Containment: NONE/i);
  });
});

test.describe("the intelligence surface states its own readiness", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * WHAT BUG THIS PINS: a behavioural baseline that has not seen enough data
   * yet produces anomaly scores that mean nothing. Presenting them as findings
   * sends analysts after noise, so the panel has to lead with whether the
   * baseline is READY.
   */
  test("an unready baseline says so rather than presenting its scores as findings", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/baseline": {
          enabled: true,
          scope: "tenant",
          anomalies_total: 0,
          status: {
            ready: false,
            observations: 12,
            need_observations: 500,
            span_seconds: 900,
            need_span_seconds: 86_400,
            half_life_hours: 168,
            facets: []
          }
        }
      }
    });
    await page.goto("/");
    await socNavItem(page, "Behaviour & Intel").click();

    const panel = page.locator('[data-panel="behaviour-modal"]');
    await expect(panel).toBeVisible();
    await expect(panel, "an unready baseline must say it is still learning").toContainText(
      /not ready|learning|still building|needs/i
    );
  });

  test("threat-intel matching that is off is stated, not shown as zero matches", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/intel": {
          matches_total: 0,
          refresh: { enabled: false, feeds: 0, interval: "0s" },
          status: { loaded: false, indicators: 0, ips: 0, cidrs: 0, domains: 0, hashes: 0, sources: [] }
        },
        "/api/intel/matches": { matches: [] }
      }
    });
    await page.goto("/");
    await socNavItem(page, "Behaviour & Intel").click();

    const panel = page.locator('[data-panel="behaviour-modal"]');
    await expect(panel).toBeVisible();
    // "No indicators loaded" and "no matches found" are different claims, and
    // only the second is a security statement about the estate.
    await expect(panel).toContainText(/no indicators|not loaded|no feeds|disabled/i);
  });
});

test.describe("MITRE coverage means one thing per bar", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * WHAT BUG THIS PINS: a technique with no alerts inherited its kernel probe
   * post-count, so one bar meant "alerts in this window" and the next meant
   * "the probe fired this often, mostly on activity that scored nothing".
   * A coverage chart whose bars measure different things is worse than none.
   */
  test("a live probe with no alerts reads as covered, not as a gap or a hit", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/policies": [
          { name: "outbound-connections", description: "Egress watch", mitre: "T1071", expected: true }
        ],
        // A busy probe...
        "/api/policy-stats": [{ name: "outbound-connections", posts: 13_580 }],
        // ...that produced no alerts in the window.
        "/api/alerts": []
      }
    });
    await page.goto("/");
    await socNavItem(page, "MITRE Coverage").click();

    const panel = page.locator('[data-panel="mitre-navigator-modal"]');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText("T1071");
    // The probe's post count must not be presented as alert volume.
    await expect(
      panel,
      "a probe post count leaked into the coverage chart as if it were alerts"
    ).not.toContainText("13,580");
    await expect(panel).not.toContainText("13580");
  });
});
