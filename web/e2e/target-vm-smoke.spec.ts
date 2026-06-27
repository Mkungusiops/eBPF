import { PAGE_ROUTES } from "./support/contracts";
import {
  attachBrowserDiagnostics,
  expect,
  expectNoCdnRequests,
  expectNoReleaseBlockingBrowserErrors,
  hasCredentials,
  loginByApi,
  readEbpfEnv,
  test
} from "./support/test";

const targetVmURL = readEbpfEnv().targetVmURL;

test.describe("target VM smoke", () => {
  test.skip(!targetVmURL, "Set EBPF_TARGET_VM_URL to run target VM certification smoke");
  test.use({ baseURL: targetVmURL ?? "http://127.0.0.1:5173" });

  test("captures route screenshots, console logs, network evidence, and version SHA", async ({
    browser,
    request,
    ebpf
  }) => {
    test.skip(!hasCredentials(ebpf), "Set EBPF_E2E_USER and EBPF_E2E_PASSWORD");

    const publicContext = await browser.newContext({ baseURL: targetVmURL });
    const loginPage = await publicContext.newPage();
    await loginPage.goto("/login");
    await loginPage.screenshot({
      path: test.info().outputPath("target-vm-login.png"),
      fullPage: true
    });
    await publicContext.close();

    const { storageState } = await loginByApi(request, ebpf);
    const context = await browser.newContext({
      baseURL: targetVmURL,
      storageState
    });
    const page = await context.newPage();
    const diagnostics = attachBrowserDiagnostics(page);

    for (const route of PAGE_ROUTES.filter((candidate) => !candidate.public)) {
      const response = await page.goto(route.path);
      expect(response?.status(), route.path).toBeLessThan(400);
      await page.screenshot({
        path: test.info().outputPath(`target-vm-${route.name}.png`),
        fullPage: true
      });
    }

    const versionResponse = await context.request.get("/api/version");
    expect(versionResponse.status()).toBe(200);
    const version = await versionResponse.json();
    await test.info().attach("api-version.json", {
      body: JSON.stringify(version, null, 2),
      contentType: "application/json"
    });

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics, {
      allowOptionalDisabledApi503: true
    });

    await context.close();
  });

  test("safe attack smoke is opt-in for target certification", async ({ request, ebpf }) => {
    test.skip(!ebpf.runSafeAttack, "Set EBPF_E2E_RUN_SAFE_ATTACK=1 to execute safe attack smoke");
    test.skip(!hasCredentials(ebpf), "Set EBPF_E2E_USER and EBPF_E2E_PASSWORD");

    const { csrfToken } = await loginByApi(request, ebpf);
    const attacks = await request.get("/api/attacks");
    expect(attacks.status()).toBe(200);
    const attackList = (await attacks.json()) as Array<{ id?: string }>;
    const firstAttack = attackList.find((attack) => attack.id);

    expect(firstAttack?.id).toBeTruthy();

    const response = await request.post("/api/run-attack", {
      failOnStatusCode: false,
      form: { id: firstAttack?.id ?? "" },
      headers: { "X-CSRF-Token": csrfToken }
    });

    expect(response.status()).toBeLessThan(500);
  });

  test("representative choke write is opt-in for target certification", async ({
    request,
    ebpf
  }) => {
    test.skip(!ebpf.runWrites, "Set EBPF_E2E_RUN_WRITES=1 to execute write smoke");
    test.skip(!hasCredentials(ebpf), "Set EBPF_E2E_USER and EBPF_E2E_PASSWORD");

    const { csrfToken } = await loginByApi(request, ebpf);
    const response = await request.post("/api/choke/policy/preview", {
      data: { yaml: "apiVersion: cilium.io/v1alpha1\nkind: ChokePolicy\n" },
      failOnStatusCode: false,
      headers: { "X-CSRF-Token": csrfToken }
    });

    expect(response.status()).toBeLessThan(500);
  });
});
