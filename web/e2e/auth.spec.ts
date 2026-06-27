import { expect, hasCredentials, loginByApi, test } from "./support/test";

test.describe("auth", () => {
  test("/login loads without an existing session", async ({ page }) => {
    const response = await page.goto("/login");

    expect(response?.status()).toBeLessThan(400);
    await expect(page.locator("#root")).toBeAttached();
  });

  test("/login follows the shared platform theme preference", async ({ page }) => {
    await page.addInitScript(() => {
      window.localStorage.setItem("soc.theme", JSON.stringify("light"));
    });

    await page.goto("/login");

    await expect(page.locator("html")).toHaveClass(/theme-light/);
    await expect(page.locator("body")).toHaveClass(/theme-light/);
  });

  test("/login can toggle and persist the shared platform theme", async ({ page }) => {
    await page.addInitScript(() => {
      window.localStorage.setItem("soc.theme", JSON.stringify("light"));
    });

    await page.goto("/login");
    await page.getByRole("button", { name: "Switch to dark theme" }).click();

    await expect(page.locator("html")).toHaveClass(/theme-dark/);
    await expect(page.locator("body")).toHaveClass(/theme-dark/);
    await expect
      .poll(() => page.evaluate(() => window.localStorage.getItem("soc.theme")))
      .toBe(JSON.stringify("dark"));
  });

  test("/login advertises install metadata for Safari and manifest browsers", async ({ page }) => {
    await page.goto("/login");

    await expect(page.locator('link[rel="manifest"][href="/manifest.webmanifest"]').first()).toHaveAttribute("href", "/manifest.webmanifest");
    await expect(page.locator('link[rel="apple-touch-icon"][href="/apple-touch-icon.png"]').first()).toHaveAttribute("href", "/apple-touch-icon.png");
    await expect(page.locator('meta[name="mobile-web-app-capable"]').first()).toHaveAttribute("content", "yes");
    await expect(page.locator('meta[name="apple-mobile-web-app-capable"]').first()).toHaveAttribute("content", "yes");
    await expect(page.locator('meta[name="apple-mobile-web-app-title"]').first()).toHaveAttribute("content", "eBPF SOC");
    await expect(page.locator('meta[name="apple-mobile-web-app-status-bar-style"]').first()).toHaveAttribute("content", "black-translucent");
  });

  test("/login exposes iPhone install guidance when the native prompt is unavailable", async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        get: () =>
          "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
      });
      Object.defineProperty(navigator, "platform", {
        configurable: true,
        get: () => "iPhone",
      });
    });

    await page.goto("/login");
    await page.getByRole("button", { name: "Install app" }).click();

    await expect(page.getByRole("dialog", { name: "Install on iPhone" })).toBeVisible();
    await expect(page.getByText("Add to Home Screen")).toBeVisible();
    await expect(page.getByText("Deleting the web app removes it from Search.")).toBeVisible();
  });

  test("/login keeps Chrome and Edge on the native install path", async ({ page }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: "Install app" }).click();

    await expect(page.getByRole("button", { name: "Checking install" })).toBeVisible();
    await expect(page.getByRole("dialog", { name: "Install in Chrome or Edge" })).toBeVisible();
    await expect(page.getByText("Use Install app, not Add shortcut/bookmark.")).toBeVisible();
    await expect(page.getByText("In Safari, tap Share")).toHaveCount(0);
  });

  test("/login opens the native install prompt when the browser exposes it", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("button", { name: "Install app" })).toBeVisible();
    await page.evaluate(() => {
      const state = window as unknown as { __promptCalls: number };
      state.__promptCalls = 0;
      const event = new Event("beforeinstallprompt", { cancelable: true });
      Object.defineProperty(event, "prompt", {
        value: () => {
          state.__promptCalls += 1;
          return Promise.resolve();
        },
      });
      Object.defineProperty(event, "userChoice", {
        value: new Promise((resolve) => {
          window.setTimeout(() => resolve({ outcome: "dismissed", platform: "web" }), 300);
        }),
      });
      window.dispatchEvent(event);
    });

    await page.getByRole("button", { name: "Install app" }).click();

    await expect(page.getByRole("button", { name: "Opening install" })).toBeVisible();
    await expect.poll(() => page.evaluate(() => (window as unknown as { __promptCalls: number }).__promptCalls)).toBe(1);
  });

  test("bad credentials redirect back to the login error URL", async ({ request }) => {
    const response = await request.post("/api/login", {
      failOnStatusCode: false,
      form: { user: "definitely-not-a-user", pass: "definitely-not-a-password" },
      maxRedirects: 0
    });

    expect([303, 429]).toContain(response.status());
    if (response.status() === 303) {
      expect(response.headers().location).toContain("/login?err=1");
    }
  });

  test("unauthenticated API requests return the JSON 401 contract", async ({ request }) => {
    const response = await request.get("/api/whoami", { failOnStatusCode: false });

    expect(response.status()).toBe(401);
    expect(await response.json()).toEqual({
      error: "unauthorized",
      redirect: "/login"
    });
  });

  test("valid credentials set session and CSRF cookies", async ({ request, ebpf }) => {
    test.skip(!hasCredentials(ebpf), "Set EBPF_E2E_USER and EBPF_E2E_PASSWORD");

    const { csrfToken, storageState } = await loginByApi(request, ebpf);

    expect(csrfToken).toBeTruthy();
    expect(storageState.cookies.some((cookie) => cookie.name === "soc_session")).toBe(true);
    expect(storageState.cookies.some((cookie) => cookie.name === "csrf_token")).toBe(true);
  });

  test("login error query renders an operator-visible error", async ({ page }) => {
    await page.goto("/login?err=1");

    await expect(page.getByText("Invalid credentials.")).toBeVisible();
  });
});
