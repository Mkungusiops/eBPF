import { describe, expect, it } from "vitest";
import { planeIsActive } from "../features/devices/DevicesRoute";

/**
 * The device console must never claim an enforcement plane it does not have.
 *
 * "noop" means no tc program is attached: the ladder still moves and the device
 * table still reads back "severed", but no packet is touched. That is the right
 * configuration for a host with no bridge to sit inline on — claiming otherwise
 * is not.
 *
 * This predicate existed twice with two different answers. The version that
 * excluded "noop" drove one status dot; the version that treated "noop" as
 * healthy drove the header integrity readout, `auditOk`, and the EXPORTED
 * EVIDENCE BUNDLE, which recorded `data_plane: "active"` for a plane that
 * cannot enforce. Measured live: the production single-tenant engine reports
 * `data_plane=noop links=0`.
 */
describe("a data plane is only active if it can drop a packet", () => {
  it("noop is not active — it is bookkeeping only", () => {
    expect(planeIsActive("noop")).toBe(false);
  });

  it("disabled is not active", () => {
    expect(planeIsActive("disabled")).toBe(false);
  });

  it("unknown is not active — on an auditable artefact, uncertainty is not a yes", () => {
    expect(planeIsActive(undefined)).toBe(false);
    expect(planeIsActive(null)).toBe(false);
    expect(planeIsActive("")).toBe(false);
  });

  it("a real attached plane is active", () => {
    for (const plane of ["tc", "tc-clsact", "active", "ebpf"]) {
      expect(planeIsActive(plane), `${plane} should count as active`).toBe(true);
    }
  });
});
