import { UNSAFE_WRITE_ENDPOINTS } from "../../e2e/support/contracts";

describe("CSRF certification contract", () => {
  it("does not include safe methods in the unsafe write inventory", () => {
    expect(UNSAFE_WRITE_ENDPOINTS.every((endpoint) => ["POST", "PUT"].includes(endpoint.method))).toBe(
      true
    );
  });

  it("covers process choke, device choke, fleet, and SOC write surfaces", () => {
    const paths = UNSAFE_WRITE_ENDPOINTS.map((endpoint) => endpoint.path);

    expect(paths.some((path) => path.startsWith("/api/choke/device-"))).toBe(true);
    expect(paths.some((path) => path.startsWith("/api/choke/") && !path.includes("device-"))).toBe(
      true
    );
    expect(paths.some((path) => path.startsWith("/api/fleet/"))).toBe(true);
    expect(paths).toContain("/api/run-attack");
  });

  it("uses PUT only where the backend route contract permits it", () => {
    const putPaths = UNSAFE_WRITE_ENDPOINTS.filter((endpoint) => endpoint.method === "PUT").map(
      (endpoint) => endpoint.path
    );

    expect(putPaths).toEqual(["/api/choke/thresholds", "/api/fleet/thresholds"]);
  });
});
