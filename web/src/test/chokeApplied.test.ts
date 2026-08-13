import { describe, expect, it } from "vitest";
import { chokeApplied } from "../features/choke/api";

// One bundle is served by BOTH the fleet control plane and the single-host
// engine, and they report success differently. Getting this wrong is a
// containment-honesty bug in one direction or the other.
describe("chokeApplied", () => {
  it("treats the engine's shape (no ok field) as applied", () => {
    // The engine returns {applied:{...}} and throws on non-2xx. Reading a
    // missing `ok` as failure made every successful sever report "NOT applied".
    expect(chokeApplied({} as never)).toBe(true);
    expect(chokeApplied({ status: undefined } as never)).toBe(true);
  });

  it("honours the control plane's explicit ok:false", () => {
    expect(chokeApplied({ ok: false, status: "STATUS_NOT_TARGET" })).toBe(false);
  });

  it("treats ok:true as applied", () => {
    expect(chokeApplied({ ok: true, status: "STATUS_APPLIED" })).toBe(true);
  });

  it("never reports a held action as applied", () => {
    // Change-control (EN-2): queued for a second operator, nothing dispatched.
    expect(chokeApplied({ ok: false, approval_required: true })).toBe(false);
    expect(chokeApplied({ approval_required: true })).toBe(false);
  });

  it("is false-safe on a missing response", () => {
    expect(chokeApplied(undefined)).toBe(true); // 2xx with an empty body = engine applied
  });
});
