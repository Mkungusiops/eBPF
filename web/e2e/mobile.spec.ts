import { installMockApi } from "./support/mock-api";
import { expect, test } from "./support/test";

// Phone-sized viewport (iPhone 12 logical resolution). The whole console must
// fit without forcing horizontal page scroll, and the SOC sidebar must behave
// as a dismissible overlay drawer rather than burying content on load.
const PHONE = { width: 390, height: 844 };

const routes: Array<[string, string]> = [
  ["soc", "/"],
  ["login", "/login"],
  ["choke", "/choke"],
  ["devices", "/devices"],
  ["fleet", "/fleet"]
];

test.describe("mobile responsiveness", () => {
  test.use({ viewport: PHONE });

  for (const [name, path] of routes) {
    test(`${name} fits the phone viewport without horizontal overflow`, async ({ page }) => {
      await installMockApi(page);
      await page.goto(path);
      await page.waitForTimeout(400);

      const { docWidth, winWidth } = await page.evaluate(() => ({
        docWidth: document.documentElement.scrollWidth,
        winWidth: window.innerWidth
      }));
      expect(docWidth, `${name} should not overflow the viewport horizontally`).toBeLessThanOrEqual(winWidth + 1);
    });
  }

  test("SOC sidebar starts collapsed on phones and opens as a dismissible drawer", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");

    const route = page.locator(".soc-route");
    // Content must be visible on first load — the drawer is not pre-opened.
    await expect(route).not.toHaveClass(/sidebar-open/);

    await page.getByRole("button", { name: "Toggle sidebar" }).click();
    await expect(route).toHaveClass(/sidebar-open/);

    const scrim = page.getByRole("button", { name: "Close menu" });
    await expect(scrim).toBeVisible();

    // Tap the scrim in the area not covered by the drawer to dismiss it.
    await scrim.click({ position: { x: 340, y: 600 } });
    await expect(route).not.toHaveClass(/sidebar-open/);
  });
});
