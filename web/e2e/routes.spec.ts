import { PAGE_ROUTES, PROTECTED_PAGE_ROUTES } from "./support/contracts";
import {
  expect,
  expectRouteRoot,
  hasBackend,
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

  // The REDIRECT is issued by the engine, not the console: an unauthenticated
  // request to a protected path gets a 303 to /login from the server. With no
  // backend the Vite proxy answers 502 and no redirect ever happens, so this
  // belongs behind the same guard as the two auth specs — it asserts the
  // engine's contract, not the console's.
  test("protected routes redirect unauthenticated users to login", async ({ page, request }) => {
    test.skip(!(await hasBackend(request)), "needs a live engine on :8080");
    for (const route of PROTECTED_PAGE_ROUTES) {
      const response = await page.goto(route.path);

      expect(response?.status(), route.path).toBeLessThan(400);
      await expectRouteRoot(page);
      await expect(page).toHaveURL(/\/login/);
    }
  });
});
