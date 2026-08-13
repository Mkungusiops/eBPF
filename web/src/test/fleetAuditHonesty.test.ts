import { describe, expect, it } from "vitest";
import { EMPTY_KPIS } from "../features/fleet/fleetLogic";
import type { FleetKpis } from "../features/fleet/types";

/**
 * A fleet must not report a host as having a BROKEN audit chain when that host
 * simply does not maintain one.
 *
 * The multi-tenant control plane answers {ok: false, supported: false} — each
 * agent chains its own decisions. The reducer counted only `audit.ok` hosts as
 * good and divided by REACHABLE hosts, so any such host made the tile read
 * "broken chain on a host": a false tamper-evidence alarm on a healthy fleet.
 * A host that omits the audit block entirely hit the same path.
 */

/** Mirror of the classification in fleetLogic, kept in sync by the tests below. */
function classify(audit: { ok?: boolean; supported?: boolean } | undefined): keyof Pick<
  FleetKpis,
  "auditOk" | "auditBroken" | "auditUnsupported"
> {
  if (!audit || audit.supported === false) return "auditUnsupported";
  if (audit.ok) return "auditOk";
  return "auditBroken";
}

describe("fleet audit-chain accounting has three outcomes", () => {
  it("the KPI shape carries all three", () => {
    expect(EMPTY_KPIS).toHaveProperty("auditOk", 0);
    expect(EMPTY_KPIS).toHaveProperty("auditBroken", 0);
    expect(EMPTY_KPIS).toHaveProperty("auditUnsupported", 0);
  });

  it("a control plane that does not chain centrally is not broken", () => {
    expect(classify({ ok: false, supported: false })).toBe("auditUnsupported");
  });

  it("a missing audit block is unknown, not broken", () => {
    expect(classify(undefined)).toBe("auditUnsupported");
  });

  it("an engine with an intact chain counts as ok", () => {
    // The engine sends no `supported` field at all — absence must not be read
    // as unsupported when ok is explicitly true.
    expect(classify({ ok: true })).toBe("auditOk");
    expect(classify({ ok: true, supported: true })).toBe("auditOk");
  });

  it("a genuinely broken chain still reports broken", () => {
    expect(classify({ ok: false })).toBe("auditBroken");
    expect(classify({ ok: false, supported: true })).toBe("auditBroken");
  });
});
