import {
  FORM_ENCODED_WRITE_PATHS,
  UNSAFE_WRITE_ENDPOINTS
} from "../../e2e/support/contracts";

describe("API certification contract", () => {
  it("tracks all 21 CSRF-protected write endpoints", () => {
    expect(UNSAFE_WRITE_ENDPOINTS).toHaveLength(21);
    expect(new Set(UNSAFE_WRITE_ENDPOINTS.map((endpoint) => endpoint.path)).size).toBe(21);
  });

  it("keeps only run-attack form-encoded among CSRF-protected writes", () => {
    const formEncodedPaths = UNSAFE_WRITE_ENDPOINTS.filter(
      (endpoint) => endpoint.encoding === "form"
    ).map((endpoint) => endpoint.path);

    expect(formEncodedPaths).toEqual([...FORM_ENCODED_WRITE_PATHS]);
  });

  it("keeps every device and fleet write JSON-encoded", () => {
    const jsonWritePaths = UNSAFE_WRITE_ENDPOINTS.filter(
      (endpoint) => endpoint.encoding === "json"
    ).map((endpoint) => endpoint.path);

    expect(jsonWritePaths).toContain("/api/choke/device-jail");
    expect(jsonWritePaths).toContain("/api/choke/device-thaw");
    expect(jsonWritePaths).toContain("/api/choke/device-mode");
    expect(jsonWritePaths).toContain("/api/choke/device-kill-switch");
    expect(jsonWritePaths).toContain("/api/fleet/device-jail");
  });
});
