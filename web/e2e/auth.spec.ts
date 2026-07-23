import { expect, hasCredentials, loginByApi, test } from "./support/test";

async function suppressNativeInstallPrompt(page: Parameters<typeof test>[0]["page"]): Promise<void> {
  await page.addInitScript(() => {
    const originalAddEventListener = window.addEventListener.bind(window);
    window.addEventListener = ((type: string, listener: EventListenerOrEventListenerObject, options?: boolean | AddEventListenerOptions) => {
      if (type === "beforeinstallprompt") return;
      return originalAddEventListener(type, listener, options);
    }) as typeof window.addEventListener;
  });
}

async function allowOnlyMockInstallPrompt(page: Parameters<typeof test>[0]["page"]): Promise<void> {
  await page.addInitScript(() => {
    const originalAddEventListener = window.addEventListener.bind(window);
    window.addEventListener = ((type: string, listener: EventListenerOrEventListenerObject, options?: boolean | AddEventListenerOptions) => {
      if (type !== "beforeinstallprompt") return originalAddEventListener(type, listener, options);
      const wrapped = (event: Event) => {
        if (!(event as Event & { __ebpfTestPrompt?: boolean }).__ebpfTestPrompt) return;
        if (typeof listener === "function") listener.call(window, event);
        else listener.handleEvent(event);
      };
      return originalAddEventListener(type, wrapped, options);
    }) as typeof window.addEventListener;
  });
}

async function isBuiltLoginPage(page: Parameters<typeof test>[0]["page"]): Promise<boolean> {
  return (await page.locator('script[type="module"][src^="/assets/login-"]').count()) > 0;
}

async function waitForInstallButtonReady(page: Parameters<typeof test>[0]["page"]): Promise<void> {
  await page.waitForLoadState("networkidle").catch(() => undefined);
  if (await isBuiltLoginPage(page)) {
    await page
      .waitForFunction(
        () => {
          const ua = navigator.userAgent.toLowerCase();
          const iOS =
            /ipad|iphone|ipod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
          const chromium = /chrome|chromium|crios|edg|edga|edgios/.test(ua) && !/firefox|fxios/.test(ua);
          if (iOS || !chromium || !("serviceWorker" in navigator)) return true;
          return Boolean(navigator.serviceWorker.controller);
        },
        null,
        { timeout: 10000 },
      )
      .catch(() => undefined);
    await page.waitForLoadState("networkidle").catch(() => undefined);
  }
  await expect(page.getByRole("button", { name: "Install app" })).toBeVisible();
}

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

  // Theme follows the OS and only the OS: there is no in-app toggle and no
  // stored preference (see src/lib/theme.ts). This replaces the old
  // toggle-and-persist test, which asserted a control that no longer exists.
  test("/login follows the OS colour scheme, including a live change", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "light" });
    await page.goto("/login");
    await expect(page.locator("html")).toHaveClass(/theme-light/);
    await expect(page.locator("body")).toHaveClass(/theme-light/);

    // Flipping the OS appearance while the page is open must re-render it.
    await page.emulateMedia({ colorScheme: "dark" });
    await expect(page.locator("html")).toHaveClass(/theme-dark/);
    await expect(page.locator("body")).toHaveClass(/theme-dark/);

    // And no preference is persisted — the OS is the sole authority.
    expect(await page.evaluate(() => window.localStorage.getItem("soc.theme"))).toBeNull();
  });

  test("/login advertises install metadata for Safari and manifest browsers", async ({ page }) => {
    await page.goto("/login");

    await expect(page.locator('link[rel="manifest"][href="/manifest.webmanifest"]').first()).toHaveAttribute("href", "/manifest.webmanifest");
    await expect(page.locator('link[rel="apple-touch-icon"][href="/apple-touch-icon.png"]').first()).toHaveAttribute("href", "/apple-touch-icon.png");
    await expect(page.locator('script[src="/pwa-install-bridge.js"]').first()).toHaveAttribute("src", "/pwa-install-bridge.js");
    await expect(page.locator('meta[name="mobile-web-app-capable"]').first()).toHaveAttribute("content", "yes");
    await expect(page.locator('meta[name="apple-mobile-web-app-capable"]').first()).toHaveAttribute("content", "yes");
    await expect(page.locator('meta[name="apple-mobile-web-app-title"]').first()).toHaveAttribute("content", "eBPF SOC");
    await expect(page.locator('meta[name="apple-mobile-web-app-status-bar-style"]').first()).toHaveAttribute("content", "black-translucent");
  });

  test("/login exposes iPhone install guidance when the native prompt is unavailable", async ({ page }) => {
    await suppressNativeInstallPrompt(page);
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
    await waitForInstallButtonReady(page);
    await page.getByRole("button", { name: "Install app" }).click();

    await expect(page.getByRole("dialog", { name: "Install on iPhone or iPad" })).toBeVisible();
    await expect(page.getByText("Add to Home Screen")).toBeVisible();
    await expect(page.getByText("Open as Web App")).toBeVisible();
  });

  test("/login keeps Chrome and Edge on the native install path", async ({ page }) => {
    await suppressNativeInstallPrompt(page);
    await page.goto("/login");
    await waitForInstallButtonReady(page);
    await page.getByRole("button", { name: "Install app" }).click();

    await expect(page.getByRole("button", { name: "Checking install" })).toBeVisible();
    await expect(page.getByRole("dialog", { name: "Use a regular Edge or Chrome profile" })).toBeVisible();
    await expect(page.getByText("Install this site as an app")).toBeVisible();
    await expect(page.getByText("Private and Guest profiles")).toBeVisible();
    await expect(page.getByText("In Safari, tap Share")).toHaveCount(0);
  });

  test("/login exposes Android install guidance when the native prompt is unavailable", async ({ page }) => {
    await suppressNativeInstallPrompt(page);
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        get: () =>
          "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36 EdgA/135.0.0.0",
      });
      Object.defineProperty(navigator, "platform", {
        configurable: true,
        get: () => "Linux armv8l",
      });
    });

    await page.goto("/login");
    await waitForInstallButtonReady(page);
    await page.getByRole("button", { name: "Install app" }).click();

    await expect(page.getByRole("dialog", { name: "Install on Android" })).toBeVisible();
    await expect(page.getByText("normal Chrome or Edge tab")).toBeVisible();
    await expect(page.getByText("launcher and search")).toBeVisible();
  });

  test("/login opens the native install prompt when the browser exposes it", async ({ page }) => {
    await allowOnlyMockInstallPrompt(page);
    await page.goto("/login");
    await waitForInstallButtonReady(page);
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
          window.setTimeout(() => resolve({ outcome: "dismissed", platform: "web" }), 1500);
        }),
      });
      Object.defineProperty(event, "__ebpfTestPrompt", { value: true });
      window.dispatchEvent(event);
    });

    await page.getByRole("button", { name: "Install app" }).click();

    await expect(page.getByRole("button", { name: "Opening install" })).toBeVisible();
    await expect.poll(() => page.evaluate(() => (window as unknown as { __promptCalls: number }).__promptCalls)).toBe(1);
  });

  test("/login uses an install prompt captured before React mounts", async ({ page }) => {
    await page.addInitScript(() => {
      const originalAddEventListener = window.addEventListener.bind(window);
      let dispatched = false;
      window.addEventListener = ((type: string, listener: EventListenerOrEventListenerObject, options?: boolean | AddEventListenerOptions) => {
        const result = originalAddEventListener(type, listener, options);
        if (type === "beforeinstallprompt" && !dispatched) {
          dispatched = true;
          queueMicrotask(() => {
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
              value: Promise.resolve({ outcome: "accepted", platform: "web" }),
            });
            window.dispatchEvent(event);
          });
        }
        return result;
      }) as typeof window.addEventListener;
    });

    await page.goto("/login");
    test.skip(
      await isBuiltLoginPage(page),
      "production builds can reload once for first service-worker control; pre-mount capture is covered by the dev-server run",
    );
    await page.getByRole("button", { name: "Install app" }).click();

    await expect.poll(() => page.evaluate(() => (window as unknown as { __promptCalls: number }).__promptCalls)).toBe(1);
    await expect(page.getByRole("dialog", { name: "Use a regular Edge or Chrome profile" })).toHaveCount(0);
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
