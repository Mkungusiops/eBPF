import { UNSAFE_WRITE_ENDPOINTS } from "./support/contracts";
import {
  expect,
  hasCredentials,
  loginByApi,
  requestOptionsForEndpoint,
  test
} from "./support/test";

test.describe("csrf", () => {
  test("every unsafe write rejects a missing CSRF token", async ({ request, ebpf }) => {
    test.skip(!hasCredentials(ebpf), "Set EBPF_E2E_USER and EBPF_E2E_PASSWORD");

    await loginByApi(request, ebpf);

    for (const endpoint of UNSAFE_WRITE_ENDPOINTS) {
      const response = await request.fetch(
        endpoint.path,
        requestOptionsForEndpoint(endpoint)
      );

      expect(response.status(), `${endpoint.method} ${endpoint.path} should be stopped by auth middleware`).toBe(403);
      expect(await response.text()).toContain("csrf");
    }
  });

  test("unsafe write inventory matches the 22-route certification contract", () => {
    expect(UNSAFE_WRITE_ENDPOINTS).toHaveLength(22);
  });
});
