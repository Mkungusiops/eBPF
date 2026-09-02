import { describe, expect, it } from "vitest";
import { actorLabel } from "../features/choke/utils";

/**
 * "Who ordered this" is the first question a post-incident review asks, and
 * the console had no answer. The engine has always sent `actor`; the console's
 * Decision type never declared it, so it was dropped. The control plane never
 * received it at all, because decisions had no uplink.
 */
describe("a decision row says who ordered it", () => {
  it("names the operator on a manual action", () => {
    expect(actorLabel("op-adanian")).toBe("by op-adanian");
  });

  it("says automatic rather than leaving a blank", () => {
    // The dangerous rendering. An empty cell is indistinguishable from an
    // unattributed action: a review cannot tell "the platform did this on a
    // score" from "we lost the record of who did this".
    expect(actorLabel(undefined)).toBe("automatic");
    expect(actorLabel("")).toBe("automatic");
    expect(actorLabel("   ")).toBe("automatic");
  });
});
