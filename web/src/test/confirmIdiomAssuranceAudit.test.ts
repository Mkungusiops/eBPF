import { describe, expect, it } from "vitest";

import { buildDeviceAssuranceHtml, buildDeviceEvidenceBundle } from "../features/devices/assuranceReport";
import { buildDeviceMetrics } from "../features/devices/metrics";
import type { DeviceDataPlaneState } from "../features/devices/types";

/**
 * THE BOARD REPORT DOES NOT CARRY A FIELD THAT CAN NEVER HAVE A VALUE.
 *
 * The report computed an "audit rows" string — carefully, distinguishing a null
 * count from a zero one — and never printed it. Emitting it would have put a
 * permanent "not counted" on a customer-facing artefact, because
 * CommandMetrics.auditRows is structurally null on this plane: metrics.ts sets
 * it null for every device deployment, since nothing counts audit rows for the
 * device gateway. That is the structurally-empty-panel defect in printed form —
 * a board reader sees an audit measure that looks unreported rather than one
 * that does not exist here — so the string was removed instead.
 *
 * This test pins both halves: the input really is always null, and the report
 * says nothing about a count it cannot make. If a real count ever reaches
 * CommandMetrics for devices, this test is the place that says to print it.
 */

const state = {
  enforcing: true,
  kill_switched: false,
  data_plane: "tc",
  links_attached: 2,
  frames_seen: 1234,
  tracked: 9,
  counts: { pristine: 7, throttled: 1, tarpit: 0, quarantined: 1, severed: 0 }
} as unknown as DeviceDataPlaneState;

const devices = [
  { mac: "02:00:00:00:00:01", state: "pristine", hostname: "cam-01", protected: true },
  { mac: "02:00:00:00:00:02", state: "quarantined", hostname: "nvr-02" }
];

function report() {
  const { metrics, countsByRung, protectedCount } = buildDeviceMetrics(state, devices, null);
  return {
    metrics,
    html: buildDeviceAssuranceHtml({
      metrics,
      counts: countsByRung,
      links: 2,
      frames: 1234,
      protectedCount,
      devices,
      when: new Date("2026-09-07T12:00:00Z")
    })
  };
}

describe("the device assurance report and the audit-row count it cannot make", () => {
  it("has no audit-row count to print in the first place", () => {
    expect(report().metrics.auditRows, "an audit count now exists — print it in the report").toBeNull();
  });

  it("prints neither the count nor a permanent placeholder for it", () => {
    const { html } = report();
    expect(html).not.toMatch(/audit rows/i);
    expect(html, "a board report cannot carry a field that always reads 'not counted'").not.toContain("not counted");
  });

  it("still reports what it can actually evidence", () => {
    const { html } = report();
    // The removal took a dead string out, not a measurement.
    expect(html).toContain("Containment ladder");
    expect(html).toContain("Devices tracked");
    expect(html).toContain("Coverage");
    expect(html).toMatch(/Links attached/);
  });

  it("keeps the evidence bundle's own honesty untouched", () => {
    const { metrics, countsByRung, protectedCount } = buildDeviceMetrics(state, devices, null);
    const bundle = buildDeviceEvidenceBundle({
      metrics,
      countsByRung,
      state,
      planeHealthy: true,
      protectedCount,
      devices,
      when: new Date("2026-09-07T12:00:00Z")
    });
    // The bundle never claimed an audit-row count either, and it still records
    // the verdict AND what it was derived from.
    expect(Object.keys(bundle)).not.toContain("audit_rows");
    expect(bundle.data_plane).toBe("active");
    expect(bundle.data_plane_reported).toBe("tc");
  });
});
