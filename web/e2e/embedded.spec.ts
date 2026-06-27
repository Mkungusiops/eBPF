import { PAGE_ROUTES } from "./support/contracts";
import {
  attachBrowserDiagnostics,
  expect,
  expectNoCdnRequests,
  expectNoReleaseBlockingBrowserErrors,
  hasCredentials,
  loginByApi,
  test
} from "./support/test";

function extractRuntimeAssetPaths(html: string): string[] {
  const matches = [...html.matchAll(/(?:src|href)="([^"]+)"/g)];
  return matches
    .map((match) => match[1])
    .filter((path) => path.startsWith("/assets/") || path.startsWith("/_next/"));
}

test.describe("embedded asset contract", () => {
  test("login page has no external CDN/runtime dependency", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);

    await page.goto("/login");

    expectNoCdnRequests(diagnostics.requestUrls);
  });

  test("HTML responses are no-store when checking an embedded binary", async ({
    request,
    ebpf
  }) => {
    test.skip(!ebpf.expectEmbedded, "Set EBPF_EXPECT_EMBEDDED=1 for embedded binary checks");
    test.skip(!hasCredentials(ebpf), "Set EBPF_E2E_USER and EBPF_E2E_PASSWORD");

    await loginByApi(request, ebpf);

    for (const route of PAGE_ROUTES) {
      const response = await request.get(route.path);
      expect(response.status(), route.path).toBeLessThan(400);
      expect(response.headers()["cache-control"] ?? "", route.path).toContain("no-store");
    }
  });

  test("built static assets are immutable when checking an embedded binary", async ({
    request,
    ebpf
  }) => {
    test.skip(!ebpf.expectEmbedded, "Set EBPF_EXPECT_EMBEDDED=1 for embedded binary checks");
    test.skip(!hasCredentials(ebpf), "Set EBPF_E2E_USER and EBPF_E2E_PASSWORD");

    await loginByApi(request, ebpf);

    const html = await (await request.get("/login")).text();
    const assetPaths = extractRuntimeAssetPaths(html);

    expect(assetPaths.length, "expected built Vite/Next asset references").toBeGreaterThan(0);
    for (const assetPath of assetPaths) {
      const response = await request.get(assetPath);
      expect(response.status(), assetPath).toBeLessThan(400);
      expect(response.headers()["cache-control"] ?? "", assetPath).toContain("immutable");
    }
  });

  test("version endpoint exposes frontend deployment evidence", async ({ request, ebpf }) => {
    test.skip(!hasCredentials(ebpf), "Set EBPF_E2E_USER and EBPF_E2E_PASSWORD");

    await loginByApi(request, ebpf);

    const response = await request.get("/api/version");
    expect(response.status()).toBe(200);
    const body = (await response.json()) as { sha?: string; started_at?: string };
    expect(body.sha).toMatch(/^[a-f0-9]{12}$/);
    expect(body.started_at).toBeTruthy();
  });

  test("release-critical browser console stays clean on login", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);

    await page.goto("/login");

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });
});
