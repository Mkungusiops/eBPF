import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StateLadder } from "../features/choke/components";
import { enforcementGapReason, appliedTierCounts } from "../features/choke/utils";

/**
 * "7 throttled" beside "0, empty" in a separate panel reads as a bug. It was
 * detect-only working exactly as designed — and the console never said so.
 * A gap between what was DECIDED and what the kernel RECEIVED must always
 * carry its reason, because the benign causes and the alarming one look
 * identical without it.
 */
describe("the ladder shows decided against applied", () => {
  it("names detect-only as the reason nothing reached the kernel", () => {
    render(
      <StateLadder
        counts={{ throttled: 7 }}
        applied={{ throttled: 0 }}
        gapReason={enforcementGapReason({ mode: "detect-only" })}
      />
    );
    expect(screen.getByText(/Detect-only: decisions are recorded, not applied/)).toBeTruthy();
  });

  it("refuses to reassure when the gap has no known cause", () => {
    // The dangerous rendering. An unexplained gap is the alarming case, so the
    // fallback must not read as "probably fine".
    render(<StateLadder counts={{ throttled: 3 }} applied={{ throttled: 0 }} gapReason="" />);
    expect(screen.getByText(/treat enforcement as unconfirmed/)).toBeTruthy();
  });

  it("says nothing when decided and applied agree", () => {
    render(<StateLadder counts={{ throttled: 2 }} applied={{ throttled: 2 }} gapReason="" />);
    expect(screen.queryByText(/unconfirmed|Detect-only/)).toBeNull();
  });

  it("shows a dash, not a zero, where no cgroup exists", () => {
    // A sever is a SIGKILL and pristine is the absence of enforcement, so
    // neither has a cgroup to be in. A 0 there would be a false claim.
    const { container } = render(
      <StateLadder counts={{ severed: 1, pristine: 4 }} applied={{ throttled: 0 }} gapReason="" />
    );
    const applied = Array.from(container.querySelectorAll(".choke-ladder-applied")).map((n) => n.textContent);
    expect(applied[0]).toBe("—"); // pristine
    expect(applied[applied.length - 1]).toBe("—"); // severed
  });

  it("stays a single-column ladder when applied state is unknown", () => {
    const { container } = render(<StateLadder counts={{ throttled: 1 }} />);
    expect(container.querySelector(".choke-ladder-head")).toBeNull();
    expect(container.querySelector(".choke-ladder-applied")).toBeNull();
  });
});

describe("the gap reason names the specific posture", () => {
  it("puts the kill-switch ahead of the mode, because it overrides it", () => {
    expect(enforcementGapReason({ mode: "enforcing", kill_switched: true })).toMatch(/kill-switch is engaged/);
  });

  it("distinguishes dry-run from detect-only", () => {
    expect(enforcementGapReason({ mode: "enforcing", dry_run: true })).toMatch(/Dry-run/);
    expect(enforcementGapReason({ mode: "detect-only" })).toMatch(/Detect-only/);
  });

  it("offers nothing when the plane is armed and nothing explains a gap", () => {
    expect(enforcementGapReason({ mode: "enforcing" })).toBe("");
  });
});

describe("applied counts read the real cgroups", () => {
  it("maps each enforcement cgroup to its ladder rung", () => {
    const counts = appliedTierCounts({
      "choke-throttled": [1, 2, 3],
      "choke-tarpit": [],
      "choke-quarantined": [9]
    } as never);
    expect(counts).toEqual({ throttled: 3, tarpit: 0, quarantined: 1 });
  });
});
