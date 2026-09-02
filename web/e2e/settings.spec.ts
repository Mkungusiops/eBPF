import { installMockApi, RequestLog } from "./support/mock-api";
import { expect, socNavItem, test } from "./support/test";

/**
 * Settings — the surface where "claiming more than you can do" costs the most.
 *
 * WHAT THESE PIN: a settings page is the one place where an operator changes a
 * value, sees no error, and believes the platform now behaves differently. This
 * console answers that by making every row DECLARE its lifecycle (live /
 * live-not-persisted / needs restart / set by deploy / not available yet) and
 * its scope, and by giving a control only to rows it can actually change. A row
 * that renders an editable-looking input next to "set by deploy" is the bug.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: settingsModel.ts is data and is
 * unit-testable; what is not is whether the six sections are reachable, whether
 * the pane actually swaps, and whether the guardrail/retention/change-control
 * controls are wired to the endpoints that persist them. Those are DOM and
 * network facts.
 */

const SECTIONS = [
  { title: "Noise", question: /keeps producing findings/i },
  { title: "Response", question: /When should the platform act/i },
  { title: "Guardrails", question: /never touch/i },
  { title: "Evidence", question: /How long do we keep it/i },
  { title: "Access", question: /second pair of eyes/i },
  { title: "Platform", question: /Where does this run/i }
];

async function openSettings(page: import("@playwright/test").Page) {
  await page.goto("/");
  await socNavItem(page, "Settings").click();
  const settings = page.locator('[data-panel="settings-modal"]');
  await expect(settings).toBeVisible();
  return settings;
}

test.describe("Settings", () => {
  test("navigates all six sections, each leading with its question", async ({ page }) => {
    await installMockApi(page);
    const settings = await openSettings(page);

    const nav = settings.getByRole("navigation", { name: "Settings sections" });
    await expect(nav).toBeVisible();

    for (const section of SECTIONS) {
      await nav.getByRole("button", { name: new RegExp(`^${section.title}`) }).click();
      // The heading, and the QUESTION under it. "When should the platform act?"
      // is findable; "circuit thresholds" is not, unless you already know the
      // answer — which is the point of leading with the question.
      await expect(settings.getByRole("heading", { name: section.title })).toBeVisible();
      await expect(settings).toContainText(section.question);
    }
  });

  test("every row declares a lifecycle and a scope", async ({ page }) => {
    await installMockApi(page);
    const settings = await openSettings(page);
    const nav = settings.getByRole("navigation", { name: "Settings sections" });

    // Case-insensitive on purpose: the badges are uppercased by CSS, and
    // `innerText` reports what is PAINTED. Asserting the source casing would
    // fail on a styling detail that no operator can perceive as wrong.
    const LIFECYCLES = /^(Live|Live · not saved|Needs restart|Set by deploy|Not available yet)$/i;
    const SCOPES = /^(per-tenant|platform-wide|this-host)$/i;

    let rowsSeen = 0;
    for (const section of SECTIONS) {
      await nav.getByRole("button", { name: new RegExp(`^${section.title}`) }).click();
      const rows = settings.locator(".soc-settings-row");
      const count = await rows.count();
      expect(count, `${section.title} rendered no rows`).toBeGreaterThan(0);

      for (let index = 0; index < count; index += 1) {
        const head = rows.nth(index).locator(".soc-settings-rowhead");
        const badges = await head.locator(".soc-settings-badge").allInnerTexts();
        expect(
          badges.length,
          `${section.title} row ${index} carries ${badges.length} badges, expected a lifecycle and a scope`
        ).toBe(2);
        expect(badges[0], `${section.title} row ${index} lifecycle`).toMatch(LIFECYCLES);
        expect(badges[1], `${section.title} row ${index} scope`).toMatch(SCOPES);
        rowsSeen += 1;
      }
    }
    // Anti-vacuity floor: at least one row per section actually reached the
    // badge assertions. Deliberately not pinned to today's exact total —
    // adding a setting is normal, and a test that fails for that reason gets
    // its number bumped without anyone reading it.
    expect(
      rowsSeen,
      "no settings rows were inspected, so the badge contract is untested"
    ).toBeGreaterThanOrEqual(SECTIONS.length);
  });

  test("guardrails list the always-protected floor and gate an addition behind a reason", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, { recorder });
    const settings = await openSettings(page);
    await settings.getByRole("navigation", { name: "Settings sections" }).getByRole("button", { name: /^Guardrails/ }).click();

    // The floor is what the platform refuses to contain no matter what the
    // operator asks for. It has to be VISIBLE: an SSH daemon missing from it is
    // how this project locked itself out of a host.
    await expect(settings).toContainText("Always protected");
    await expect(settings).toContainText("/usr/sbin/sshd");
    await expect(settings).toContainText("/usr/bin/sudo");

    const apply = settings.getByRole("button", { name: "Apply guardrails" });
    // Nothing staged yet, so there is nothing to apply — and the page says so
    // rather than offering a button that would send an unchanged list.
    await expect(apply).toBeDisabled();
    await expect(settings).toContainText("No change to apply.");

    await settings.getByLabel("Binary to protect").fill("/opt/monitoring/agent");
    await settings.getByLabel("Add protected binary").click();

    // Staged, not sent: adding a row is a local edit. The PUT is a separate,
    // deliberate act, because it dispatches to every agent in the tenant.
    expect(
      recorder.matching(/^\/api\/settings\/protected$/).filter((r) => r.method !== "GET"),
      "adding a row must not silently push to the fleet"
    ).toEqual([]);

    // A change with no reason is still refused: the audit chain is what makes a
    // guardrail change reviewable afterwards.
    await expect(apply).toBeDisabled();
    await settings.getByRole("textbox", { name: /Reason/ }).fill("jump hosts must never be contained");
    await expect(apply).toBeEnabled();
    await apply.click();

    const writes = recorder.matching(/^\/api\/settings\/protected$/).filter((r) => r.method !== "GET");
    expect(writes.length, "applying guardrails must reach the server").toBeGreaterThan(0);
    const sent = writes[writes.length - 1].body ?? "";
    expect(sent).toContain("/opt/monitoring/agent");
    expect(sent, "the reason must travel with the change").toContain("jump hosts must never be contained");
  });

  test("retention states what is kept, and that decisions are never pruned", async ({ page }) => {
    await installMockApi(page);
    const settings = await openSettings(page);
    await settings.getByRole("navigation", { name: "Settings sections" }).getByRole("button", { name: /^Evidence/ }).click();

    await expect(settings).toContainText("What this tenant actually keeps");
    // The audit chain outliving the telemetry it was made from is a property an
    // operator has to be able to read here, not infer.
    await expect(settings).toContainText(/decisions are never pruned/i);
    await expect(settings.getByLabel("Retention in days")).toBeVisible();
  });

  test("change control names what is gated and what never is", async ({ page }) => {
    await installMockApi(page);
    const settings = await openSettings(page);
    await settings.getByRole("navigation", { name: "Settings sections" }).getByRole("button", { name: /^Access/ }).click();

    // Both halves, always. A dual-control feature that only lists what it
    // blocks reads as "this may block anything", and an on-call engineer who
    // believes that will not reach for the thing that would contain a threat.
    await expect(settings).toContainText("quarantine");
    await expect(settings).toContainText("sever");
    await expect(settings).toContainText("thaw");
    await expect(settings).toContainText("throttle");
  });

  test("the access trail says whose access it can account for", async ({ page }) => {
    await installMockApi(page);
    const settings = await openSettings(page);
    await settings.getByRole("navigation", { name: "Settings sections" }).getByRole("button", { name: /^Access/ }).click();

    // Scope, stated. "This tenant" and "every tenant" are different claims and
    // an operator reading a compliance surface must not have to guess which.
    await expect(settings).toContainText(/This tenant|Every tenant/);
    await expect(settings).toContainText("90 days");
  });

  /**
   * WHAT BUG THIS PINS: an unsupported endpoint must read as "this deployment
   * does not serve it", never as "there is nothing to report". Those are
   * different claims and only one of them is safe to act on.
   */
  test("an unsupported access trail says so rather than showing an empty list", async ({ page }) => {
    await installMockApi(page, {
      routes: { "/api/operator-audit": { supported: false, records: [] } }
    });
    const settings = await openSettings(page);
    await settings.getByRole("navigation", { name: "Settings sections" }).getByRole("button", { name: /^Access/ }).click();

    await expect(settings).not.toContainText("90 days");
    await expect(settings).toContainText(/not|no |cannot|unavailable/i);
  });
});
