import { describe, expect, it } from "vitest";
import { emptyBecause } from "../features/soc/rows";

/**
 * An empty panel is read as "nothing happened". At a five-minute window on a
 * live estate that is wrong — this rig had 2 alerts in 5m and 1,841 in 24h, so
 * every context panel rendered an empty state with the data one click away.
 *
 * Telling the operator to "widen the range" is advice. Telling them how many
 * they are not looking at is a fact, and it is the difference between a panel
 * people learn to ignore and one that points somewhere.
 */
describe("an empty panel says WHY it is empty", () => {
  it("names how much sits outside the window", () => {
    const msg = emptyBecause("scored processes", 1839, "alerts");
    expect(msg).toContain("1,839 alerts");
    expect(msg).toMatch(/outside it/);
    expect(msg).toMatch(/Widen the range/);
  });

  it("does not claim data exists when none does", () => {
    // The other half. Inventing "widen the range" on a genuinely empty estate
    // sends an analyst hunting for something that was never there.
    const msg = emptyBecause("scored processes", 0, "alerts");
    expect(msg).toBe("No scored processes recorded yet on this estate.");
    expect(msg).not.toMatch(/Widen/);
  });

  it("formats large counts so they are readable at a glance", () => {
    expect(emptyBecause("indicators", 3671507, "events")).toContain("3,671,507");
  });
});
