import { PAGE_ROUTES, PROTECTED_PAGE_ROUTES } from "./support/contracts";
import {
  expect,
  expectRouteRoot,
  test
} from "./support/test";

test.describe("browser routes", () => {
  for (const route of PAGE_ROUTES) {
    test(`${route.name} route responds with an HTML shell`, async ({ page }) => {
      const response = await page.goto(route.path);

      expect(response?.status()).toBeLessThan(400);
      await expectRouteRoot(page);
    });
  }

  test("protected routes redirect unauthenticated users to login", async ({ page }) => {
    for (const route of PROTECTED_PAGE_ROUTES) {
      const response = await page.goto(route.path);

      expect(response?.status(), route.path).toBeLessThan(400);
      await expectRouteRoot(page);
      await expect(page).toHaveURL(/\/login/);
    }
  });
});
