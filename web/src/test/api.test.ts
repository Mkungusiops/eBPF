import {
  FORM_ENCODED_WRITE_PATHS,
  UNSAFE_WRITE_ENDPOINTS
} from "../../e2e/support/contracts";

describe("API certification contract", () => {
  /**
   * 21, not the 22 this asserted until now.
   *
   * The inventory lost `/api/choke/policy/preview` on 2026-08-27 when BOTH
   * servers deleted the route along with the console surface that called it —
   * `handleChokePolicyPreview` still exists in engine/internal/api/choke.go but
   * is mounted by no mux, and controlplane/choke.go records the same removal.
   * A CSRF assertion against an unrouted path can only ever pass, because the
   * middleware rejects an unsafe method before routing happens, so it proved
   * nothing. The count stayed at 22 here and this file has been failing since.
   *
   * The number is a floor as much as a total: every one of the 21 is a route
   * one of the two servers actually mounts, so a new write endpoint that skips
   * the inventory — and therefore skips the CSRF proof in csrf.spec.ts — fails
   * this test rather than shipping unproven.
   */
  it("tracks all 21 CSRF-protected write endpoints", () => {
    expect(UNSAFE_WRITE_ENDPOINTS).toHaveLength(21);
    expect(new Set(UNSAFE_WRITE_ENDPOINTS.map((endpoint) => endpoint.path)).size).toBe(21);
    expect(
      UNSAFE_WRITE_ENDPOINTS.map((endpoint) => endpoint.path),
      "policy/preview is routed by neither server; asserting CSRF on it can only pass"
    ).not.toContain("/api/choke/policy/preview");
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
