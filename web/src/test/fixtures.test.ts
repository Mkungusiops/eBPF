import {
  chokeStateSnapshot,
  deviceProtectedMacFailure,
  deviceStateActive,
  deviceStateDisabled,
  expiredSessionResponse,
  fakeModeStreamFrames,
  fleetFanoutSuccess,
  fleetPartialFailure,
  missingCsrfResponse,
  representativeAlerts,
  representativeDecisions,
  representativeProcessLineage,
  requiredFixtureNames
} from "../../e2e/support/fixtures";

describe("test fixture inventory", () => {
  it("covers the certification fixture set from the plan", () => {
    expect(requiredFixtureNames).toHaveLength(12);
  });

  it("includes representative stream, alert, lineage, and decision data", () => {
    expect(fakeModeStreamFrames.map((frame) => frame.type)).toEqual([
      "heartbeat",
      "event",
      "alert",
      "decision"
    ]);
    expect(representativeAlerts.length).toBeGreaterThan(0);
    expect(representativeProcessLineage.exec_id).toBeTruthy();
    expect(representativeDecisions.length).toBeGreaterThan(0);
  });

  it("includes choke, fleet, device, auth, and CSRF edge fixtures", () => {
    expect(chokeStateSnapshot.thresholds.critical).toBe(40);
    expect(fleetFanoutSuccess.hosts.every((host) => host.ok)).toBe(true);
    expect(fleetPartialFailure.hosts.some((host) => !host.ok)).toBe(true);
    expect(deviceStateActive.mode).toBe("enforcing");
    expect(deviceStateDisabled.status).toBe(503);
    expect(deviceProtectedMacFailure.results[0].ok).toBe(false);
    expect(expiredSessionResponse.status).toBe(401);
    expect(missingCsrfResponse.status).toBe(403);
  });
});
